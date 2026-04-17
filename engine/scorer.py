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

from .embeddings import EmbeddingEngine


def jaccard(set_a: Set[str], set_b: Set[str]) -> float:
    if not set_a and not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union else 0.0


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
    ) -> Tuple[float, str]:
        """Graduated log-source matching.

        Returns:
            (score, evidence_string)
            max_score  -- exact match via Logstash enrichment or name
            0.8 * max  -- prefix match (e.g. ``linux:auth`` vs ``linux:*``)
            0.5 * max  -- same family (e.g. ``linux:daemon`` and ``linux:syslog``)
            0.0        -- no match

        ``log_source_max_score`` caps the signal so that, by default,
        log-source alone cannot saturate the composite: corroboration from
        semantic / keyword / field / category signals is required. The cap
        is configurable; set to 1.0 to preserve historical behaviour.
        """
        cap = self.log_source_max_score
        if profile_id in event_dc_candidates:
            return cap, f"logstash_enrichment:{event_log_source}->{profile_id}"

        src = event_log_source.lower()
        for name in profile_log_source_names:
            if src == name.lower():
                return cap, f"exact_match:{name}"

        for name in profile_log_source_names:
            nl = name.lower()
            if ":" in src and ":" in nl:
                if src.split(":")[0] == nl.split(":")[0]:
                    return round(0.8 * cap, 4), f"prefix_match:{name}"

        src_family = self.log_source_families.get(src, "")
        if src_family:
            for name in profile_log_source_names:
                other_family = self.log_source_families.get(name.lower(), "")
                if other_family and src_family == other_family:
                    return round(0.5 * cap, 4), f"family_match:{name}({src_family})"

        return 0.0, ""

    def score_keywords(
        self,
        event_text: str,
        profile_id: str,
        profile_keywords: List[str],
        logstash_keyword_hits: Optional[List[str]] = None,
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
        hits = logstash_keyword_hits or []
        text = event_text or ""
        text_length = len(text.strip())

        if not hits and profile_keywords:
            text_lower = _normalize_text(text)
            if text_length >= self.min_event_text_length:
                hits = [
                    kw for kw in profile_keywords
                    if _normalize_text(kw) in text_lower and len(kw) > 2
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
