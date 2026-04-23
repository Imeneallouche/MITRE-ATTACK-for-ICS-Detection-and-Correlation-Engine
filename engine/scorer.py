"""Hierarchical scoring model for DataComponent matching.

Scoring Pipeline
================
Tier 1 -- Candidate Gate
    A DC becomes a candidate if *either* gate fires:
      - Log-source gate: ``log_source_normalized`` maps to the DC via the
        Logstash enrichment or a normalised-name match.
      - Semantic gate: ``cosine_sim(embed(log), embed(DC)) >= gate_threshold``

Tier 2 -- Composite Score
    For each candidate the composite similarity S(event, dc) is:

        S = w_sem * S_sem + w_ls * S_ls + w_kw * S_kw
          + w_fld * S_fld + w_cat * S_cat

    Signals:
      S_sem  -- Cosine similarity between log and DC embeddings [0, 1]
      S_ls   -- Graduated log-source match (1.0 exact, 0.8 prefix, 0.5 family)
      S_kw   -- Keyword coverage with specificity and IDF weighting
      S_fld  -- Field overlap (Jaccard)
      S_cat  -- Category overlap (Jaccard)

The composite is then passed to the evidence gate in the matcher which
caps the score when too few independent signals contributed to it; this
mirrors how a human analyst treats "one routing hint + one generic token"
as insufficient justification for an alert.
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

from .embeddings import EmbeddingEngine, log_source_name_matches_observed
from .models import DataComponentProfile


def jaccard(set_a: Set[str], set_b: Set[str]) -> float:
    if not set_a and not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union else 0.0


def token_set_similarity(a: str, b: str) -> float:
    """Jaccard similarity on whitespace token sets (fallback when embeddings off)."""
    ta = set(_normalize_text(a).split())
    tb = set(_normalize_text(b).split())
    if not ta and not tb:
        return 0.0
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def max_log_source_line_token_affinity(
    event_text: str,
    event_log_source: str,
    profile: DataComponentProfile,
) -> Tuple[float, str, str]:
    """Best token overlap between the event and a name-aligned (Name, Channel) row."""
    best = 0.0
    best_name = ""
    best_ch = ""
    ev_src = event_log_source.strip().lower()
    for ls in profile.log_sources:
        if not log_source_name_matches_observed(ev_src, ls.name):
            continue
        line = f"{ls.name} {ls.channel}"
        sim = token_set_similarity(event_text, line)
        if sim > best:
            best = sim
            best_name = ls.name
            best_ch = ls.channel
    return best, best_name, best_ch


def overlap_ratio(hits: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return min(hits / total, 1.0)


def idf_weight(doc_freq: int, total_docs: int) -> float:
    if total_docs <= 0 or doc_freq <= 0:
        return 1.0
    return math.log(total_docs / doc_freq) / math.log(total_docs)


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


# Keyword evidence must be grounded in the *actual log message the system
# emitted*, not in routing / telemetry metadata that Logstash and Filebeat
# attach to every document (file paths, service/program names, host IDs,
# agent metadata, flow IDs, byte counters, ...).  Those fields systematically
# carry vendor/platform tokens (e.g. ``tomcat`` in ``log.file.path``,
# ``openplc`` in ``container.name``, ``5156`` in a machine-generated ID) and,
# if allowed to anchor keyword hits, they produce a steady stream of false
# positives on every benign boot / heartbeat line.
#
# The authoritative anchor is therefore the original indexed message body.
# ``score_fields`` already credits structured field overlap with a DC's
# ``searchable_indexes.fields``; the keyword signal should remain *narrative*.


def _build_keyword_anchor_text(
    event_body: str,
    field_values: Optional[Dict[str, Any]] = None,  # kept for call-site stability
) -> str:
    """Return the normalised body anchor used for every keyword hit check.

    The ``field_values`` argument is accepted for backwards compatibility with
    earlier call sites but is intentionally ignored: field overlap is the
    ``score_fields`` signal's responsibility, not the keyword signal's.  This
    keeps the keyword score text-grounded and prevents routing metadata from
    systematically inflating it.
    """
    return event_body or ""


def _keyword_hit_anchored(hit: str, body_anchor: str) -> bool:
    """Credit a keyword only when it appears in the observed log message body.

    Pipelines routinely attach per-DC ``mitre_keyword_hits`` that are not all
    literally present in the log line (the Logstash tagger scans every field),
    and the DC catalog lists vendor tokens that also appear in file paths and
    process names.  Requiring a body match eliminates both classes of leakage
    while keeping the policy free of deployment-specific rules.

    Rules:
    * Tokens shorter than 2 chars never count.
    * Digit-only tokens must appear as a whole-number run in the body (so
      ``"5156"`` matches ``"event 5156 denied"`` but not some machine ID
      whose last four digits happen to be 5156).
    * Alphabetic / mixed tokens use ASCII word-boundary matching.
    """
    raw = (hit or "").strip()
    if len(raw) < 2:
        return False
    hn = _normalize_text(raw)
    if not hn:
        return False
    body = _normalize_text(body_anchor)
    if not body:
        return False

    if hn.isdigit():
        if f" {hn} " in f" {body} ":
            return True
        return hn in re.sub(r"[^\d]", " ", f" {body} ").split()

    try:
        return (
            re.search(
                r"(?<![a-z0-9])" + re.escape(hn) + r"(?![a-z0-9])",
                body,
            )
            is not None
        )
    except re.error:
        return False


class ScoringEngine:
    """Computes multi-signal similarity scores for DC matching."""

    def __init__(
        self,
        weights: Dict[str, float],
        embedding_engine: Optional[EmbeddingEngine] = None,
        *,
        dc_doc_frequencies: Optional[Dict[str, int]] = None,
        total_doc_count: int = 0,
        log_source_families: Optional[Dict[str, str]] = None,
        log_source_max_score: float = 1.0,
        keyword_min_hits_for_full_credit: int = 3,
        keyword_single_hit_credit: float = 0.25,
        min_event_text_length: int = 0,
    ) -> None:
        self.weights = weights
        self.embedding_engine = embedding_engine
        self._dc_df = dc_doc_frequencies or {}
        self._total_docs = total_doc_count
        self.log_source_families: Dict[str, str] = {
            str(k).lower(): str(v).lower()
            for k, v in (log_source_families or {}).items()
            if v
        }
        self.log_source_max_score = max(0.0, min(1.0, float(log_source_max_score)))
        self.keyword_min_hits_for_full_credit = max(1, int(keyword_min_hits_for_full_credit))
        self.keyword_single_hit_credit = max(0.0, min(1.0, float(keyword_single_hit_credit)))
        self.min_event_text_length = max(0, int(min_event_text_length))

    def score_semantic(
        self,
        log_embedding: Optional[np.ndarray],
        dc_id: str,
    ) -> float:
        """Cosine similarity between the log embedding and the DC embedding."""
        if self.embedding_engine is None or log_embedding is None:
            return 0.0
        return max(0.0, self.embedding_engine.semantic_similarity(log_embedding, dc_id))

    def score_log_source(
        self,
        event_dc_candidates: List[str],
        event_log_source: str,
        profile_id: str,
        profile_log_source_names: List[str],
        *,
        profile: Optional[DataComponentProfile] = None,
        line_embedding_affinity: float = -1.0,
        line_affinity_name: str = "",
        line_affinity_channel: str = "",
        event_text_for_line_match: str = "",
    ) -> Tuple[float, str, Dict[str, Any]]:
        """Graduated log-source matching with optional line-level affinity.

        When ``profile`` is supplied, affinity between the *observed* log text
        and the best matching MITRE ``log_sources`` row (same Name as the
        site's ``log_source_normalized``) scales the score. This separates
        DataComponents that share the same pipeline-derived candidate list.

        Returns:
            (score, evidence_string, line_match_meta)
            line_match_meta maps keys such as line_affinity_similarity and
            datacomponent_log_source_* for alert explainability (empty dict if N/A).

        ``log_source_max_score`` caps the signal so that, by default,
        log-source alone cannot saturate the composite: corroboration from
        semantic / keyword / field / category signals is required. The cap
        is configurable; set to 1.0 to preserve historical behaviour.
        """
        cap = self.log_source_max_score
        src = event_log_source.lower()

        affinity = -1.0
        aff_name = line_affinity_name
        aff_ch = line_affinity_channel
        if profile is not None and event_text_for_line_match.strip():
            tok_aff, tn, tc = max_log_source_line_token_affinity(
                event_text_for_line_match, event_log_source, profile,
            )
            if line_embedding_affinity >= 0.0:
                combined = max(line_embedding_affinity, tok_aff)
                if line_embedding_affinity >= tok_aff:
                    aff_name = line_affinity_name or tn
                    aff_ch = line_affinity_channel or tc
                else:
                    aff_name, aff_ch = tn, tc
            else:
                combined = tok_aff
                aff_name, aff_ch = tn, tc
            affinity = combined if combined > 1e-9 else -1.0

        def _line_meta(sim: float) -> Dict[str, Any]:
            return {
                "line_affinity_similarity": round(float(sim), 6),
                "datacomponent_log_source_name": aff_name,
                "datacomponent_log_source_channel": aff_ch,
            }

        def _catalog_row(name: str) -> Tuple[str, str]:
            if profile is None or not name:
                return name, ""
            for ls in profile.log_sources:
                if ls.name == name:
                    return ls.name, ls.channel or ""
            return name, ""

        def _affinity_scaled_score(
            raw_cap: float,
            kind: str,
            catalog_name: str = "",
            catalog_channel: str = "",
        ) -> Tuple[float, str, Dict[str, Any]]:
            if profile is None:
                return raw_cap, kind, {}
            # No embedding/token line affinity: still attach the catalog row so
            # alerts always expose which MITRE log source name/channel matched.
            if affinity < 0.0:
                if catalog_name:
                    ch = catalog_channel
                    ch_snip = (ch[:160] + "…") if len(ch) > 160 else ch
                    ev = (
                        f"{kind}; dc_log_source_name={catalog_name!r}; "
                        f"dc_channel={ch_snip!r}"
                    )
                    return raw_cap, ev, {
                        "line_affinity_similarity": 0.0,
                        "datacomponent_log_source_name": catalog_name,
                        "datacomponent_log_source_channel": ch,
                    }
                return raw_cap, kind, {}
            a = max(0.0, min(1.0, affinity))
            scaled = round(raw_cap * a, 4)
            ch_snip = (aff_ch[:160] + "…") if len(aff_ch) > 160 else aff_ch
            ev = (
                f"{kind}; line_affinity={a:.4f}; dc_log_source_name={aff_name!r}; "
                f"dc_channel={ch_snip!r}"
            )
            return scaled, ev, _line_meta(a)

        if profile_id in event_dc_candidates:
            base_ev = f"logstash_enrichment:{event_log_source}->{profile_id}"
            # Enrichment is a pipeline *hypothesis*, not content evidence.  Scale by
            # line affinity (embedding when available, else token overlap); no floor
            # so a DC that shares neither narrative nor tokens with the event earns
            # nothing even if Logstash routed the log to it.  This keeps the log
            # source signal *content-driven*.
            if affinity >= 0.0:
                a = max(0.0, min(1.0, affinity))
                scaled = round(cap * a, 4)
                ch_snip = (aff_ch[:160] + "…") if len(aff_ch) > 160 else aff_ch
                ev = (
                    f"{base_ev}; line_affinity={a:.4f}; "
                    f"dc_log_source_name={aff_name!r}; dc_channel={ch_snip!r}"
                )
                return scaled, ev, _line_meta(a)
            # No catalog text to compare against (profile has no log_sources) —
            # fall back to the nominal cap so routing is not entirely discarded.
            return cap, base_ev, {}

        for name in profile_log_source_names:
            if src == name.lower():
                cn, cc = _catalog_row(name)
                return _affinity_scaled_score(cap, f"exact_match:{name}", cn, cc)

        for name in profile_log_source_names:
            nl = name.lower()
            if ":" in src and ":" in nl:
                if src.split(":")[0] == nl.split(":")[0]:
                    cn, cc = _catalog_row(name)
                    return _affinity_scaled_score(
                        round(0.8 * cap, 4), f"prefix_match:{name}", cn, cc,
                    )

        src_family = self.log_source_families.get(src, "")
        if src_family:
            for name in profile_log_source_names:
                other_family = self.log_source_families.get(name.lower(), "")
                if other_family and src_family == other_family:
                    cn, cc = _catalog_row(name)
                    return _affinity_scaled_score(
                        round(0.5 * cap, 4),
                        f"family_match:{name}({src_family})",
                        cn,
                        cc,
                    )

        return 0.0, "", {}

    @staticmethod
    def _protocol_token_values(fields: Optional[Dict[str, Any]]) -> Set[str]:
        """Values that label L4/L7 protocol and should not double-count as lexical DC keywords."""
        out: Set[str] = set()
        if not fields:
            return out
        for key in ("app_proto", "proto", "protocol", "icmp_type"):
            v = fields.get(key)
            if v is None or v == "":
                continue
            out.add(_normalize_text(str(v)))
        return out

    def score_keywords(
        self,
        event_text: str,
        profile_id: str,
        profile_keywords: List[str],
        logstash_keyword_hits: Optional[List[str]] = None,
        *,
        field_values: Optional[Dict[str, Any]] = None,
    ) -> Tuple[float, List[str]]:
        """Coverage-based keyword score with a short-text floor.

        Keyword score encodes *how much* of the DC's vocabulary appears in
        the event, not whether any single generic vendor token is present.
        Key design points:

        * Short/empty event text yields no keyword credit even if Logstash
          asserted a hit (a single generic token like ``"apache"`` on an
          empty body is not evidence of DC behaviour).
        * A single hit contributes at most ``keyword_single_hit_credit``;
          full credit requires ``keyword_min_hits_for_full_credit`` hits.
        * Hits are further scaled by the DC's inverse document frequency
          when corpus statistics are available, down-weighting DCs whose
          keyword lists are generic.
        """
        hits = list(logstash_keyword_hits or [])
        text = event_text or ""
        text_length = len(text.strip())
        body_anchor = _build_keyword_anchor_text(text, field_values)

        if not hits and profile_keywords:
            if text_length >= self.min_event_text_length:
                hits = [
                    kw for kw in profile_keywords
                    if _keyword_hit_anchored(kw, body_anchor) and len(kw) > 2
                ]

        proto_vals = self._protocol_token_values(field_values)
        if proto_vals and hits:
            hits = [h for h in hits if _normalize_text(str(h)) not in proto_vals]

        if not hits:
            return 0.0, []

        # Drop enrichment-only hits that are not literally present in the
        # observed log message body.  Field-level overlap is the ``score_fields``
        # signal's responsibility; the keyword signal must remain narrative.
        hits = [
            h for h in hits
            if _keyword_hit_anchored(str(h), body_anchor)
        ]
        if not hits:
            return 0.0, []

        # Short / empty events: treat enrichment-provided hits as non-evidence.
        if text_length < self.min_event_text_length:
            return 0.0, hits

        n = len(hits)
        if n == 1:
            base = self.keyword_single_hit_credit
        else:
            base = min(1.0, n / float(self.keyword_min_hits_for_full_credit))

        if profile_keywords:
            coverage = overlap_ratio(n, len(profile_keywords))
            base = max(base, coverage)

        if self._dc_df and self._total_docs > 1:
            df = self._dc_df.get(profile_id, self._total_docs)
            base *= idf_weight(df, self._total_docs)

        return round(max(0.0, min(1.0, base)), 4), hits

    def score_fields(
        self,
        event_field_keys: Set[str],
        profile_fields: List[str],
    ) -> Tuple[float, List[str]]:
        if not profile_fields:
            return 0.0, []
        event_lower = {k.lower() for k in event_field_keys}
        profile_lower = {f.lower() for f in profile_fields}
        overlap = event_lower & profile_lower
        if not overlap:
            return 0.0, []
        score = jaccard(overlap, profile_lower)
        return round(score, 4), sorted(overlap)

    def score_categories(
        self,
        event_categories: Set[str],
        profile_categories: List[str],
    ) -> Tuple[float, List[str]]:
        if not profile_categories:
            return 0.0, []
        profile_set = {c.lower() for c in profile_categories}
        event_set = {c.lower() for c in event_categories}
        overlap = event_set & profile_set
        if not overlap:
            return 0.0, []
        score = jaccard(overlap, profile_set)
        return round(score, 4), sorted(overlap)

    def compute_composite(self, signal_scores: Dict[str, float]) -> float:
        """Weighted linear combination of all signals."""
        total = 0.0
        for signal, weight in self.weights.items():
            total += signal_scores.get(signal, 0.0) * weight
        return round(max(0.0, min(1.0, total)), 4)
