"""Mathematically grounded scoring model for DataComponent matching.

Scoring Formula
===============
The composite similarity S(event, dc) is a weighted linear combination
of five independent signals:

    S = w_ls · S_ls  +  w_kw · S_kw  +  w_fld · S_fld
      + w_cat · S_cat +  w_ch · S_ch

Each signal is normalised to [0, 1]:

S_ls  – Log-source match (binary 0/1 from Logstash enrichment or name match)
S_kw  – Keyword similarity:  |K_hit| / |K_profile|
         where K_hit are matched keywords and K_profile is the DC keyword set.
         Uses Aho-Corasick for O(n) multi-pattern matching when available.
S_fld – Field overlap (Jaccard):  |F_event ∩ F_dc| / |F_event ∪ F_dc|
S_cat – Category overlap (Jaccard):  |C_event ∩ C_dc| / |C_event ∪ C_dc|
S_ch  – Channel fuzzy match (token-ratio)

Confidence
==========
After correlation, the final confidence is:

    C = min(1, S · α_asset) + corr_boost + chain_boost

α_asset = 1.0 if the asset is a known ICS asset, (1 − penalty) otherwise.

IDF-Rarity Adjustment (optional)
================================
If DC document-frequency statistics are available:

    S_kw_adj = S_kw × log(N / df(dc)) / log(N)

This gives higher weight to keywords from rare DCs.
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import ahocorasick
    _HAS_AC = True
except ImportError:
    ahocorasick = None  # type: ignore
    _HAS_AC = False


def jaccard(set_a: Set[str], set_b: Set[str]) -> float:
    """Jaccard similarity coefficient for two sets."""
    if not set_a and not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union else 0.0


def overlap_ratio(hits: int, total: int) -> float:
    """Simple overlap ratio clamped to [0, 1]."""
    if total <= 0:
        return 0.0
    return min(hits / total, 1.0)


def idf_weight(doc_freq: int, total_docs: int) -> float:
    """Inverse-document-frequency weight, normalised to [0, 1]."""
    if total_docs <= 0 or doc_freq <= 0:
        return 1.0
    return math.log(total_docs / doc_freq) / math.log(total_docs)


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


class AhoCorasickMatcher:
    """Multi-pattern keyword matcher using Aho-Corasick automaton.

    Falls back to sequential search if the ahocorasick library is absent.
    """

    def __init__(self, keywords: List[str]) -> None:
        self._keywords = [_normalize_text(k) for k in keywords if k]
        self._automaton = None
        if _HAS_AC and self._keywords:
            self._automaton = ahocorasick.Automaton()
            for idx, kw in enumerate(self._keywords):
                self._automaton.add_word(kw, (idx, kw))
            self._automaton.make_automaton()

    def search(self, text: str) -> List[str]:
        text_lower = _normalize_text(text)
        if self._automaton is not None:
            seen = set()
            hits = []
            for _, (idx, kw) in self._automaton.iter(text_lower):
                if idx not in seen:
                    seen.add(idx)
                    hits.append(kw)
            return hits
        return [kw for kw in self._keywords if kw in text_lower]


class ScoringEngine:
    """Computes multi-signal similarity scores for DC matching."""

    def __init__(
        self,
        weights: Dict[str, float],
        *,
        dc_doc_frequencies: Optional[Dict[str, int]] = None,
        total_doc_count: int = 0,
    ) -> None:
        self.weights = weights
        self._dc_df = dc_doc_frequencies or {}
        self._total_docs = total_doc_count
        self._kw_matchers: Dict[str, AhoCorasickMatcher] = {}

    def precompile_keywords(self, dc_id: str, keywords: List[str]) -> None:
        self._kw_matchers[dc_id] = AhoCorasickMatcher(keywords)

    def score_log_source(
        self,
        event_dc_candidates: List[str],
        event_log_source: str,
        profile_id: str,
        profile_log_source_names: List[str],
    ) -> Tuple[float, str]:
        if profile_id in event_dc_candidates:
            return 1.0, f"logstash_enrichment:{event_log_source}->{profile_id}"

        src = event_log_source.lower()
        for name in profile_log_source_names:
            if src == name.lower():
                return 1.0, f"exact_match:{name}"
            if ":" in src and ":" in name.lower():
                if src.split(":")[0] == name.lower().split(":")[0]:
                    return 0.7, f"prefix_match:{name}"
        return 0.0, ""

    def score_keywords(
        self,
        event_text: str,
        profile_id: str,
        profile_keywords: List[str],
        logstash_keyword_hits: Optional[List[str]] = None,
    ) -> Tuple[float, List[str]]:
        if logstash_keyword_hits:
            denom = max(len(profile_keywords), 1)
            score = overlap_ratio(len(logstash_keyword_hits), denom)
            return score, logstash_keyword_hits

        if not profile_keywords:
            return 0.0, []

        matcher = self._kw_matchers.get(profile_id)
        if matcher:
            hits = matcher.search(event_text)
        else:
            text_lower = _normalize_text(event_text)
            hits = [kw for kw in profile_keywords if _normalize_text(kw) in text_lower]

        base_score = overlap_ratio(len(hits), len(profile_keywords))

        if self._dc_df and self._total_docs > 1:
            df = self._dc_df.get(profile_id, self._total_docs)
            base_score *= idf_weight(df, self._total_docs)

        return round(base_score, 4), hits

    def score_fields(
        self,
        event_field_keys: Set[str],
        profile_fields: List[str],
        ics_fields: Optional[List[str]] = None,
    ) -> Tuple[float, List[str]]:
        event_lower = {k.lower() for k in event_field_keys}

        check_fields = ics_fields if ics_fields else profile_fields
        if not check_fields:
            return 0.0, []

        profile_lower = {f.lower() for f in check_fields}
        overlap = event_lower & profile_lower
        if not overlap:
            if profile_fields and not ics_fields:
                return 0.0, []
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

    def score_channel(
        self, event_text: str, profile_channels: List[str]
    ) -> Tuple[float, str]:
        if not profile_channels:
            return 0.0, ""

        text_norm = _normalize_text(event_text)
        best_score = 0.0
        best_channel = ""

        for ch in profile_channels:
            if not ch or ch.lower() == "none":
                continue
            ch_norm = _normalize_text(ch)
            if ch_norm in text_norm:
                return 1.0, ch

            tokens = [t for t in re.split(r"[^a-zA-Z0-9_:/.-]+", ch_norm) if len(t) > 2]
            stops = {"none", "event", "events", "log", "logs", "and", "with", "for", "the"}
            tokens = [t for t in tokens if t not in stops]
            if not tokens:
                continue
            matched = sum(1 for t in tokens if t in text_norm)
            ratio = matched / len(tokens)
            score = 1.0 if ratio >= 0.8 else (0.7 if ratio >= 0.6 else (0.4 if ratio >= 0.4 else 0.0))
            if score > best_score:
                best_score = score
                best_channel = ch

        return best_score, best_channel

    def compute_composite(self, signal_scores: Dict[str, float]) -> float:
        total = 0.0
        for signal, weight in self.weights.items():
            total += signal_scores.get(signal, 0.0) * weight
        return round(max(0.0, min(1.0, total)), 4)
