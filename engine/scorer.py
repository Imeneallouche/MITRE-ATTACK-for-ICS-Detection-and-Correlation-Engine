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
      S_kw   -- Keyword overlap ratio with IDF weighting
      S_fld  -- Field overlap (Jaccard)
      S_cat  -- Category overlap (Jaccard)

Confidence
==========
    confidence = min(1, S * alpha_asset) + corr_boost + chain_boost

    alpha_asset = 1.0 for known ICS assets, (1 - penalty) otherwise.
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
            1.0  -- exact match via Logstash enrichment or name
            0.8  -- prefix match (e.g. ``linux:auth`` vs ``linux:*``)
            0.5  -- same family (e.g. ``linux:daemon`` and ``linux:syslog``)
            0.0  -- no match
        """
        if profile_id in event_dc_candidates:
            return 1.0, f"logstash_enrichment:{event_log_source}->{profile_id}"

        src = event_log_source.lower()
        for name in profile_log_source_names:
            if src == name.lower():
                return 1.0, f"exact_match:{name}"

        for name in profile_log_source_names:
            nl = name.lower()
            if ":" in src and ":" in nl:
                if src.split(":")[0] == nl.split(":")[0]:
                    return 0.8, f"prefix_match:{name}"

        src_family = self.log_source_families.get(src, "")
        if src_family:
            for name in profile_log_source_names:
                other_family = self.log_source_families.get(name.lower(), "")
                if other_family and src_family == other_family:
                    return 0.5, f"family_match:{name}({src_family})"

        return 0.0, ""

    def score_keywords(
        self,
        event_text: str,
        profile_id: str,
        profile_keywords: List[str],
        logstash_keyword_hits: Optional[List[str]] = None,
    ) -> Tuple[float, List[str]]:
        if logstash_keyword_hits:
            n = len(logstash_keyword_hits)
            # Hits are already scoped to this DC by Logstash; dividing by the full
            # profile keyword list (often dozens of terms) collapses the score.
            ratio = min(1.0, n / 4.0)
            if profile_keywords:
                ratio = max(ratio, overlap_ratio(n, min(len(profile_keywords), 20)))
            score = min(1.0, ratio)
            return score, logstash_keyword_hits

        if not profile_keywords:
            return 0.0, []

        text_lower = _normalize_text(event_text)
        hits = [kw for kw in profile_keywords
                if _normalize_text(kw) in text_lower and len(kw) > 2]

        base_score = overlap_ratio(len(hits), len(profile_keywords))

        if self._dc_df and self._total_docs > 1:
            df = self._dc_df.get(profile_id, self._total_docs)
            base_score *= idf_weight(df, self._total_docs)

        return round(base_score, 4), hits

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
