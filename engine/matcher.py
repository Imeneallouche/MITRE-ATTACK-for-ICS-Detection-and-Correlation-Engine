"""DataComponent matcher with 2-tier gate and semantic similarity scoring.

Tier 1 -- Candidate Gate
    For each DC, check whether the event passes either:
      a) Log-source gate: Logstash enrichment maps the event to this DC,
         or the normalised log-source name matches a DC log_source entry.
      b) Semantic gate: cosine similarity between the event embedding and
         the DC embedding exceeds ``semantic_gate_threshold``.

    Only DCs that pass at least one gate proceed to Tier 2.

Tier 2 -- Composite Scoring
    Uses ScoringEngine to compute a weighted combination of five signals:
    S_sem, S_ls, S_kw, S_fld, S_cat.
"""
from __future__ import annotations

import uuid
from typing import Dict, List, Optional, Sequence, Set, Tuple

import numpy as np

from .embeddings import EmbeddingEngine
from .models import CandidateMatch, DataComponentProfile, NormalizedEvent
from .scorer import ScoringEngine


class DataComponentMatcher:
    """Matches normalised events against DC profiles using 2-tier scoring."""

    def __init__(
        self,
        profiles: Sequence[DataComponentProfile],
        scoring_weights: Dict[str, float],
        candidate_threshold: float,
        high_confidence_threshold: float,
        embedding_engine: Optional[EmbeddingEngine] = None,
        semantic_gate_threshold: float = 0.25,
        log_source_families: Optional[Dict[str, str]] = None,
    ) -> None:
        self.profiles = list(profiles)
        self._profile_by_id = {p.id: p for p in self.profiles}
        self.candidate_threshold = candidate_threshold
        self.high_confidence_threshold = high_confidence_threshold
        self.semantic_gate_threshold = semantic_gate_threshold
        self.embedding_engine = embedding_engine

        self.scorer = ScoringEngine(
            weights=scoring_weights,
            embedding_engine=embedding_engine,
            log_source_families=log_source_families,
        )

    def match_event(self, event: NormalizedEvent) -> List[CandidateMatch]:
        log_embedding = None
        if self.embedding_engine and self.embedding_engine.available:
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

        candidates.sort(key=lambda c: c.similarity_score, reverse=True)

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
        ls_score, ls_evidence = self.scorer.score_log_source(
            event.mitre_dc_candidates,
            event.log_source_normalized,
            profile.id,
            ls_names,
        )

        sem_score = precomputed_sem
        if sem_score <= 0.0 and log_embedding is not None:
            sem_score = self.scorer.score_semantic(log_embedding, profile.id)
        sem_score = max(0.0, sem_score)

        event_text = event.log_message + " " + " ".join(
            str(v) for v in event.fields.values() if v is not None
        )
        logstash_kw = event.mitre_keyword_hits.get(profile.id)
        kw_score, kw_hits = self.scorer.score_keywords(
            event_text, profile.id, profile.keywords, logstash_kw,
        )

        fld_score, fld_hits = self.scorer.score_fields(
            set(event.fields.keys()), profile.fields,
        )

        cat_score, cat_hits = self.scorer.score_categories(
            set(event.categories or []), profile.categories,
        )

        signal_scores = {
            "semantic_match": sem_score,
            "log_source_match": ls_score,
            "keyword_match": kw_score,
            "field_match": fld_score,
            "category_match": cat_score,
        }
        similarity = self.scorer.compute_composite(signal_scores)

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
        }

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
        )
