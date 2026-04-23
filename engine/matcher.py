"""DataComponent matcher with 2-tier gate, composite scoring, and evidence gate.

Tier 1 -- Candidate Gate
    For each DC, check whether the event passes either:
      a) Log-source gate: Logstash enrichment maps the event to this DC,
         or the normalised log-source name matches a DC log_source entry.
      b) Semantic gate: cosine similarity between the event embedding and
         the DC embedding exceeds ``semantic_gate_threshold``.

    Only DCs that pass at least one gate proceed to Tier 2.

Tier 2 -- Composite Scoring
    Uses ScoringEngine to compute a weighted combination of five signals:
    S_sem, S_ls, S_kw, S_fld, S_cat.  The log-source signal S_ls scales
    with *line affinity*: cosine similarity between the event and the best
    MITRE ``log_sources`` row (matching Name) for that DataComponent, plus
    token overlap when embeddings are unavailable.

Tier 3 -- Evidence Gate (generic, non-hardcoded)
    The matcher counts the number of *independent* evidence channels that
    contributed substantively to the composite. "Channel" is one of:
    semantic ≥ gate, keyword ≥ threshold, field > 0, category > 0, and
    optionally the log-source signal if operator policy treats routing
    hints as evidence. If fewer than ``min_independent_signals`` channels
    fired, the composite is capped at ``weak_evidence_cap`` and the match
    is tagged ``weak_evidence=True`` so downstream stages (correlation,
    alerting, RL policy) can treat it conservatively.

    This encodes a single principle that is not tied to any DC, message,
    or deployment: *an alert should not rest on a single weak signal*.
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional, Pattern, Sequence, Set, Tuple

import numpy as np

from .embeddings import EmbeddingEngine, log_source_name_matches_observed
from .models import CandidateMatch, DataComponentProfile, NormalizedEvent
from .scorer import ScoringEngine


class DataComponentMatcher:
    """Matches normalised events against DC profiles using 3-tier scoring."""

    def __init__(
        self,
        profiles: Sequence[DataComponentProfile],
        scoring_weights: Dict[str, float],
        candidate_threshold: float,
        high_confidence_threshold: float,
        embedding_engine: Optional[EmbeddingEngine] = None,
        semantic_gate_threshold: float = 0.25,
        log_source_families: Optional[Dict[str, str]] = None,
        evidence_policy: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.profiles = list(profiles)
        self._profile_by_id = {p.id: p for p in self.profiles}
        self.candidate_threshold = candidate_threshold
        self.high_confidence_threshold = high_confidence_threshold
        self.semantic_gate_threshold = semantic_gate_threshold
        self.embedding_engine = embedding_engine

        policy = dict(evidence_policy or {})
        self.min_independent_signals = int(policy.get("min_independent_signals", 1))
        self.log_source_counts_as_evidence = bool(
            policy.get("log_source_counts_as_evidence", True)
        )
        self.weak_evidence_cap = float(policy.get("weak_evidence_cap", 1.0))
        self.keyword_evidence_threshold = float(
            policy.get("keyword_evidence_threshold", 0.0)
        )
        self.semantic_evidence_threshold = float(
            policy.get("semantic_evidence_threshold", max(semantic_gate_threshold, 0.0))
        )
        self.min_event_text_length = int(policy.get("min_event_text_length", 0))
        self.require_substantive_original_message = bool(
            policy.get("require_substantive_original_message", False)
        )
        self.min_original_log_message_chars = max(
            0, int(policy.get("min_original_log_message_chars", 0)),
        )
        # Alerts must rest on *content* signals (narrative similarity / keyword
        # coverage), not on routing/structural metadata alone.  When enabled,
        # matches whose evidence contains none of ``content_signal_names`` are
        # tagged weak and capped by ``weak_evidence_cap``.
        self.require_content_signal = bool(
            policy.get("require_content_signal", False)
        )
        self.content_signal_names: Set[str] = {
            str(x).lower()
            for x in (policy.get("content_signal_names") or ["semantic", "keyword"])
        }
        self._reject_message_res: List[Pattern[str]] = []
        for pat in policy.get("reject_original_message_patterns") or []:
            if not isinstance(pat, str) or not pat.strip():
                continue
            try:
                self._reject_message_res.append(re.compile(pat))
            except re.error:
                continue

        # e.g. ``{"severity": 1}`` — if ``severity`` is present and numeric,
        # values below the floor are treated as non-alerting (informational
        # bootstrap/heartbeat rows). Fields absent on the event are ignored.
        self._numeric_field_floors: Dict[str, float] = {}
        _floors = policy.get("numeric_field_floors")
        if isinstance(_floors, dict):
            for k, v in _floors.items():
                if k is None:
                    continue
                try:
                    self._numeric_field_floors[str(k)] = float(v)
                except (TypeError, ValueError):
                    continue

        # When semantic cosine is below this ceiling (ambiguous "related" band),
        # cap the keyword channel so generic multi-token vendor vocabulary on a
        # line cannot push the composite over ``alert_threshold`` without
        # stronger narrative alignment.  Set to 0.0 to disable.
        self.semantic_soft_ceiling: float = float(policy.get("semantic_soft_ceiling", 0.0) or 0.0)
        self.keyword_max_score_when_semantic_soft: float = float(
            policy.get("keyword_max_score_when_semantic_soft", 0.4) or 0.4,
        )

        self.scorer = ScoringEngine(
            weights=scoring_weights,
            embedding_engine=embedding_engine,
            log_source_families=log_source_families,
            log_source_max_score=float(policy.get("log_source_max_score", 1.0)),
            keyword_min_hits_for_full_credit=int(
                policy.get("keyword_min_hits_for_full_credit", 3)
            ),
            keyword_single_hit_credit=float(
                policy.get("keyword_single_hit_credit", 0.25)
            ),
            min_event_text_length=self.min_event_text_length,
        )

    def passes_substantive_message_policy(self, event: NormalizedEvent) -> bool:
        """Length / quality checks on the indexed body before scoring.

        ``reject_original_message_patterns`` catches pipeline defects (e.g. literal
        Logstash ``%{field}`` placeholders) without naming specific technologies.
        """
        body = (event.original_log_message or "").strip()
        for rx in self._reject_message_res:
            if rx.search(body):
                return False
        if not self.require_substantive_original_message:
            return True
        return len(body) >= self.min_original_log_message_chars

    def passes_numeric_field_floor_policy(self, event: NormalizedEvent) -> bool:
        """When configured, reject events whose structured numeric fields are below floor.

        This filters informational alarm rows (e.g. ``severity: 0``) without
        deployment-specific string matching.  Field names are compared
        case-insensitively so that pipelines which mirror lowercase ``severity``
        to the MITRE ``Severity`` field name (or vice versa) still trip the
        floor without requiring the operator to duplicate entries.
        """
        if not self._numeric_field_floors:
            return True
        # Build a case-insensitive view so "severity" matches "Severity",
        # "SEVERITY", etc.  Nested dotted keys (e.g. ``parsed_process_alarm.severity``)
        # also feed into this lookup via the promoted_field_roots rules.
        fields_ci: Dict[str, Any] = {}
        for k, v in event.fields.items():
            key = str(k).lower()
            if key not in fields_ci:
                fields_ci[key] = v
        for field, floor in self._numeric_field_floors.items():
            raw = event.fields.get(field)
            if raw is None:
                raw = fields_ci.get(str(field).lower())
            if raw is None:
                continue
            try:
                val = float(raw)
            except (TypeError, ValueError):
                continue
            if val < floor:
                return False
        return True

    def match_event(
        self,
        event: NormalizedEvent,
        log_embedding: Optional[np.ndarray] = None,
    ) -> List[CandidateMatch]:
        """Match event to DataComponents.

        Pass ``log_embedding`` when the caller already encoded ``event.embedding_text``
        (e.g. batch encoding in ``process_hits``) to avoid redundant model work.
        """
        if not self.passes_substantive_message_policy(event):
            return []
        if not self.passes_numeric_field_floor_policy(event):
            return []

        if log_embedding is None and self.embedding_engine and self.embedding_engine.available:
            log_embedding = self.embedding_engine.embed_text(event.embedding_text)

        enriched_ids = set(event.mitre_dc_candidates)

        sem_scores: Dict[str, float] = {}
        if log_embedding is not None and self.embedding_engine:
            sem_scores = self.embedding_engine.bulk_semantic_similarity(log_embedding)

        candidates: List[CandidateMatch] = []

        for profile in self.profiles:
            gate, gate_reason = self._passes_gate(
                event, profile, enriched_ids, sem_scores,
            )
            if not gate:
                continue

            candidate = self._score(
                event, profile, log_embedding,
                sem_scores.get(profile.id, 0.0),
                gate_reason,
            )
            if candidate.similarity_score >= self.candidate_threshold:
                candidates.append(candidate)

        def _rank_key(c: CandidateMatch) -> Tuple[float, float, float]:
            lm = c.evidence.get("line_match") or {}
            la = float(lm.get("line_affinity_similarity", 0.0))
            return (c.similarity_score, la, c.semantic_score)

        candidates.sort(key=_rank_key, reverse=True)

        if len(candidates) > 1:
            top = candidates[0].similarity_score
            for cand in candidates[1:]:
                if top - cand.similarity_score <= 0.10:
                    cand.is_ambiguous = True
                    candidates[0].is_ambiguous = True

        return candidates

    def _passes_gate(
        self,
        event: NormalizedEvent,
        profile: DataComponentProfile,
        enriched_ids: Set[str],
        sem_scores: Dict[str, float],
    ) -> Tuple[bool, str]:
        """Tier 1: check if either gate passes for this DC."""
        if profile.id in enriched_ids:
            return True, "logstash_enrichment"

        src = event.log_source_normalized.lower()
        for ls in profile.log_sources:
            if src == ls.name.lower():
                return True, f"log_source_exact:{ls.name}"
            if ":" in src and ":" in ls.name.lower():
                if src.split(":")[0] == ls.name.lower().split(":")[0]:
                    return True, f"log_source_prefix:{ls.name}"

        sem = sem_scores.get(profile.id, 0.0)
        if sem >= self.semantic_gate_threshold:
            return True, f"semantic:{sem:.3f}"

        return False, ""

    def _score(
        self,
        event: NormalizedEvent,
        profile: DataComponentProfile,
        log_embedding: Optional[np.ndarray],
        precomputed_sem: float,
        gate_reason: str,
    ) -> CandidateMatch:
        ls_names = [ls.name for ls in profile.log_sources]
        line_body = (event.original_log_message or "").strip() or event.log_message
        event_text_for_line = (
            line_body + " " + " ".join(
                str(v) for v in event.fields.values() if v is not None
            )
        )
        line_emb_aff = -1.0
        line_emb_name = ""
        line_emb_ch = ""
        if self.embedding_engine is not None and log_embedding is not None:
            line_emb_aff, line_emb_name, line_emb_ch = (
                self.embedding_engine.log_source_line_affinity(
                    log_embedding,
                    profile.id,
                    event.log_source_normalized,
                    profile,
                )
            )

        ls_score, ls_evidence, ls_line_meta = self.scorer.score_log_source(
            event.mitre_dc_candidates,
            event.log_source_normalized,
            profile.id,
            ls_names,
            profile=profile,
            line_embedding_affinity=line_emb_aff,
            line_affinity_name=line_emb_name,
            line_affinity_channel=line_emb_ch,
            event_text_for_line_match=event_text_for_line,
        )

        sem_score = precomputed_sem
        if sem_score <= 0.0 and log_embedding is not None:
            sem_score = self.scorer.score_semantic(log_embedding, profile.id)
        sem_score = max(0.0, sem_score)

        # Prefer full embedding text so keyword coverage uses the same signal as semantics.
        event_text = (event.embedding_text or "").strip()
        if not event_text:
            event_text = event.log_message + " " + " ".join(
                str(v) for v in event.fields.values() if v is not None
            )
        logstash_kw = event.mitre_keyword_hits.get(profile.id)
        kw_score, kw_hits = self.scorer.score_keywords(
            event_text,
            profile.id,
            profile.keywords,
            logstash_kw,
            field_values=event.fields,
        )

        kw_used = float(kw_score)
        soft_cap_meta: Optional[Dict[str, Any]] = None
        if (
            self.semantic_soft_ceiling > 0.0
            and sem_score < self.semantic_soft_ceiling
            and kw_used > self.keyword_max_score_when_semantic_soft
        ):
            kw_capped = min(kw_used, self.keyword_max_score_when_semantic_soft)
            if kw_capped < kw_used - 1e-9:
                soft_cap_meta = {
                    "applied": True,
                    "semantic_soft_ceiling": self.semantic_soft_ceiling,
                    "keyword_max_score_when_semantic_soft": self.keyword_max_score_when_semantic_soft,
                    "keyword_match_before_cap": round(kw_used, 4),
                    "keyword_match_after_cap": round(kw_capped, 4),
                }
            kw_used = kw_capped

        fld_score, fld_hits = self.scorer.score_fields(
            set(event.fields.keys()), profile.fields,
        )

        cat_score, cat_hits = self.scorer.score_categories(
            set(event.categories or []), profile.categories,
        )

        signal_scores = {
            "semantic_match": sem_score,
            "log_source_match": ls_score,
            "keyword_match": kw_used,
            "field_match": fld_score,
            "category_match": cat_score,
        }
        similarity = self.scorer.compute_composite(signal_scores)

        evidence_count, evidence_flags = self._count_evidence_signals(
            sem_score=sem_score,
            ls_score=ls_score,
            kw_score=kw_used,
            fld_score=fld_score,
            cat_score=cat_score,
        )

        weak_evidence = evidence_count < self.min_independent_signals
        missing_content = (
            self.require_content_signal
            and not (self.content_signal_names & set(evidence_flags))
        )
        if missing_content:
            weak_evidence = True
        if weak_evidence and self.weak_evidence_cap < 1.0:
            similarity = round(min(similarity, self.weak_evidence_cap), 4)

        confidence_tier = "low"
        if similarity >= self.high_confidence_threshold:
            confidence_tier = "high"
        elif similarity >= 0.50:
            confidence_tier = "medium"

        evidence = {
            "matched_log_source": ls_evidence,
            "matched_keywords": kw_hits,
            "matched_fields": fld_hits,
            "matched_categories": cat_hits,
            "semantic_similarity": round(sem_score, 4),
            "evidence_signals": evidence_flags,
            "evidence_signal_count": evidence_count,
        }
        if soft_cap_meta is not None:
            evidence["soft_semantic_keyword_cap"] = soft_cap_meta
        if ls_line_meta:
            evidence["line_match"] = ls_line_meta
        else:
            # When line embedding affinity is unavailable, attach the catalog row
            # whose Name matches the observed log source (explainability).
            for ls in profile.log_sources:
                if log_source_name_matches_observed(event.log_source_normalized, ls.name):
                    evidence["catalog_alignment"] = {
                        "datacomponent_log_source_name": ls.name,
                        "datacomponent_log_source_channel": ls.channel[:1200],
                    }
                    break
        if weak_evidence:
            evidence["weak_evidence"] = True
        if missing_content:
            evidence["missing_content_signal"] = True

        return CandidateMatch(
            match_id=str(uuid.uuid4()),
            datacomponent_id=profile.id,
            datacomponent_name=profile.name,
            similarity_score=similarity,
            signal_scores=signal_scores,
            evidence=evidence,
            confidence_tier=confidence_tier,
            event=event,
            semantic_score=sem_score,
            gate_passed=gate_reason,
            evidence_signal_count=evidence_count,
            weak_evidence=weak_evidence,
        )

    def _count_evidence_signals(
        self,
        *,
        sem_score: float,
        ls_score: float,
        kw_score: float,
        fld_score: float,
        cat_score: float,
    ) -> Tuple[int, List[str]]:
        """Count independent evidence channels for a match.

        A channel is considered to have contributed only if it exceeds a
        minimum threshold. Log-source is conditionally counted because,
        for many pipelines, log-source assignment is a routing decision
        (via Logstash enrichment) and not independent corroboration.
        """
        flags: List[str] = []
        if sem_score >= self.semantic_evidence_threshold and sem_score > 0:
            flags.append("semantic")
        if kw_score > self.keyword_evidence_threshold:
            flags.append("keyword")
        if fld_score > 0:
            flags.append("field")
        if cat_score > 0:
            flags.append("category")
        if self.log_source_counts_as_evidence and ls_score > 0:
            flags.append("log_source")
        return len(flags), flags
