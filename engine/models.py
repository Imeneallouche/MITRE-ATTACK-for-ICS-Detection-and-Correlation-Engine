from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class LogSourceEntry:
    name: str
    channel: str


@dataclass
class DataComponentProfile:
    id: str
    name: str
    description: str
    platforms: List[str]
    log_source_types: List[str]
    categories: List[str]
    fields: List[str]
    keywords: List[str]
    log_sources: List[LogSourceEntry]
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedEvent:
    document_id: str
    es_index: str
    timestamp: datetime
    asset_id: str
    asset_name: str
    asset_ip: Optional[str]
    zone: Optional[str]
    log_type: str
    log_source_normalized: str
    log_message: str
    fields: Dict[str, Any]
    raw_source: Dict[str, Any]
    mitre_dc_candidates: List[str] = field(default_factory=list)
    mitre_keyword_hits: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class CandidateMatch:
    match_id: str
    datacomponent_id: str
    datacomponent_name: str
    similarity_score: float
    signal_scores: Dict[str, float]
    evidence: Dict[str, Any]
    confidence_tier: str
    event: NormalizedEvent
    is_ambiguous: bool = False


@dataclass
class CorrelationGroup:
    group_id: str
    asset_id: str
    asset_name: str
    first_timestamp: datetime
    last_timestamp: datetime
    matches: List[CandidateMatch] = field(default_factory=list)
    chain_ids: List[str] = field(default_factory=list)
    chain_depth: int = 1
    aggregate_score: float = 0.0

    def add_match(self, match: CandidateMatch) -> None:
        self.matches.append(match)
        if match.event.timestamp > self.last_timestamp:
            self.last_timestamp = match.event.timestamp


@dataclass
class DetectionAlert:
    datacomponent: str
    datacomponent_id: Optional[str]
    asset_id: Optional[str]
    asset_name: Optional[str]
    es_index: str
    document_id: str
    timestamp: str
    matched_fields: Dict[str, Any]
    similarity_score: float
    evidence_snippet: str
    log_message: str
    rule_or_pattern: str
    detection_id: str
    detection_metadata: Dict[str, Any]
