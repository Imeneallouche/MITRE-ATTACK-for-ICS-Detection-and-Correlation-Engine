from __future__ import annotations

import re
import uuid
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from .feature_extractor import infer_categories
from .models import CandidateMatch, DataComponentProfile, NormalizedEvent


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def _tokenize_channel(channel: str) -> List[str]:
    clean = re.sub(r"[^a-zA-Z0-9_:/.-]+", " ", channel.lower())
    tokens = [t for t in clean.split() if len(t) > 2]
    stop = {"none", "event", "events", "log", "logs", "and", "with", "for", "the"}
    return [t for t in tokens if t not in stop]


def fuzzy_channel_match(text: str, channel: str) -> float:
    if not channel or channel.lower() == "none":
        return 0.0
    txt = _normalize(text)
    channel_norm = _normalize(channel)
    if channel_norm in txt:
        return 1.0

    tokens = _tokenize_channel(channel)
    if not tokens:
        return 0.0
    matched = sum(1 for t in tokens if t in txt)
    ratio = matched / len(tokens)
    if ratio >= 0.8:
        return 1.0
    if ratio >= 0.6:
        return 0.7
    if ratio >= 0.4:
        return 0.4
    return 0.0


class DataComponentMatcher:
    def __init__(
        self,
        profiles: Sequence[DataComponentProfile],
        scoring_weights: Dict[str, float],
        candidate_threshold: float,
        high_confidence_threshold: float,
    ) -> None:
        self.profiles = list(profiles)
        self.weights = scoring_weights
        self.candidate_threshold = candidate_threshold
        self.high_confidence_threshold = high_confidence_threshold

    def match_event(self, event: NormalizedEvent) -> List[CandidateMatch]:
        candidates: List[CandidateMatch] = []
        for profile in self.profiles:
            candidate = self._score_event_against_profile(event, profile)
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

    def _score_event_against_profile(self, event: NormalizedEvent, profile: DataComponentProfile) -> CandidateMatch:
        source_score, source_evidence = self._score_log_source(event, profile)
        keyword_score, keyword_hits = self._score_keywords(event, profile)
        field_score, field_hits = self._score_fields(event, profile)
        category_score, category_hits = self._score_categories(event, profile)
        channel_score, channel_hit = self._score_channel(event, profile)

        signal_scores = {
            "log_source_match": source_score,
            "keyword_match": keyword_score,
            "field_match": field_score,
            "category_match": category_score,
            "channel_match": channel_score,
        }

        similarity = 0.0
        for key, weight in self.weights.items():
            similarity += signal_scores.get(key, 0.0) * float(weight)
        similarity = max(0.0, min(1.0, round(similarity, 4)))

        confidence_tier = "low"
        if similarity >= self.high_confidence_threshold:
            confidence_tier = "high"
        elif similarity >= 0.60:
            confidence_tier = "medium"

        evidence = {
            "matched_log_source": source_evidence,
            "matched_keywords": keyword_hits,
            "matched_fields": field_hits,
            "matched_categories": category_hits,
            "matched_channel": channel_hit,
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
        )

    def _score_log_source(self, event: NormalizedEvent, profile: DataComponentProfile) -> Tuple[float, str]:
        src = event.log_source_normalized.lower()
        best_score = 0.0
        matched = ""
        for ls in profile.log_sources:
            name = ls.name.lower()
            if src == name:
                return 1.0, ls.name
            # Prefix family match: e.g., auditd:SYSCALL vs auditd:EXECVE.
            if ":" in src and ":" in name and src.split(":")[0] == name.split(":")[0]:
                if 0.7 > best_score:
                    best_score = 0.7
                    matched = ls.name
        return best_score, matched

    def _score_keywords(self, event: NormalizedEvent, profile: DataComponentProfile) -> Tuple[float, List[str]]:
        if not profile.keywords:
            return 0.0, []
        text = _normalize(event.log_message + " " + " ".join(map(str, event.fields.values())))
        hits = []
        for keyword in profile.keywords:
            kw = _normalize(str(keyword))
            if kw and kw in text:
                hits.append(keyword)
        return min(len(hits) / max(len(profile.keywords), 1), 1.0), hits

    def _score_fields(self, event: NormalizedEvent, profile: DataComponentProfile) -> Tuple[float, List[str]]:
        if not profile.fields:
            return 0.0, []
        event_fields = {str(k).lower() for k in event.fields.keys()}
        hits = []
        for field_name in profile.fields:
            if field_name.lower() in event_fields:
                hits.append(field_name)
        return min(len(hits) / max(len(profile.fields), 1), 1.0), hits

    def _score_categories(self, event: NormalizedEvent, profile: DataComponentProfile) -> Tuple[float, List[str]]:
        inferred = set(infer_categories(event.log_type, event.log_source_normalized, event.log_message))
        profile_cats = set(x.lower() for x in profile.categories)
        overlap = inferred.intersection(profile_cats)
        return (1.0 if overlap else 0.0), sorted(overlap)

    def _score_channel(self, event: NormalizedEvent, profile: DataComponentProfile) -> Tuple[float, str]:
        text = event.log_message + " " + " ".join(f"{k}={v}" for k, v in event.fields.items())
        best = 0.0
        best_channel = ""
        for ls in profile.log_sources:
            score = fuzzy_channel_match(text, ls.channel)
            if score > best:
                best = score
                best_channel = ls.channel
        return best, best_channel
