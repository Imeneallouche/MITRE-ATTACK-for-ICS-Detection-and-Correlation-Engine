"""Data models for the ICS Detection and Correlation Engine.

All structured data flowing through the pipeline is defined here:
events, matches, correlations, alerts, and technique mappings.
"""
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
    embedding_text: str = ""
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
    is_ics_asset: bool = False
    asset_role: str = ""
    categories: List[str] = field(default_factory=list)
    mitre_dc_candidates: List[str] = field(default_factory=list)
    mitre_keyword_hits: Dict[str, List[str]] = field(default_factory=dict)
    embedding_text: str = ""


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
    semantic_score: float = 0.0
    gate_passed: str = ""
    # Number of independent corroborating evidence channels (semantic / keyword /
    # field / category / optionally log-source). Used by correlation to avoid
    # inflating confidence for long runs of under-supported matches.
    evidence_signal_count: int = 0
    weak_evidence: bool = False


@dataclass
class TechniqueAttribution:
    """Technique inferred from the knowledge graph for an alert."""
    technique_id: str
    technique_name: str
    probability: float
    tactics: List[str] = field(default_factory=list)
    mitigations: List[Dict[str, str]] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    software: List[str] = field(default_factory=list)
    targeted_assets: List[str] = field(default_factory=list)
    detection_strategy: str = ""
    analytics_used: List[str] = field(default_factory=list)
    graph_path: str = ""
    reasoning: str = ""


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
    technique_sequence: List[str] = field(default_factory=list)

    def add_match(self, match: CandidateMatch) -> None:
        self.matches.append(match)
        if match.event.timestamp > self.last_timestamp:
            self.last_timestamp = match.event.timestamp


@dataclass
class DetectionAlert:
    detection_id: str
    timestamp: str
    datacomponent: str
    datacomponent_id: Optional[str]
    asset_id: Optional[str]
    asset_name: Optional[str]
    asset_ip: Optional[str]
    zone: Optional[str]
    is_ics_asset: bool
    es_index: str
    document_id: str
    log_message: str
    evidence_snippet: str

    similarity_score: float
    confidence_tier: str
    signal_scores: Dict[str, float]
    matched_fields: Dict[str, Any]
    matched_keywords: List[str]
    matched_categories: List[str]
    matched_log_source: str
    matched_channel: str

    semantic_score: float
    gate_reason: str

    technique: Optional[TechniqueAttribution]
    alternative_techniques: List[TechniqueAttribution]

    correlation_group_id: str
    chain_ids: List[str]
    chain_depth: int
    correlation_boost: float
    chain_boost: float
    event_count_in_group: int
    technique_sequence: List[str]

    detection_metadata: Dict[str, Any]
