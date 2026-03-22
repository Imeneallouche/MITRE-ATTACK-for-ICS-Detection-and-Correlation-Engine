from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from .models import CandidateMatch, CorrelationGroup, DetectionAlert


class AlertBuilder:
    def __init__(self, suppress_window_seconds: int = 60) -> None:
        self.suppress_window_seconds = suppress_window_seconds
        self._recent_keys: Dict[str, datetime] = {}

    def build_alert(
        self,
        match: CandidateMatch,
        group: CorrelationGroup,
        boosts: Dict[str, float],
        strategy: str,
        threshold: float,
        sources_used: List[str],
        related_matches: Optional[List[CandidateMatch]] = None,
    ) -> Optional[DetectionAlert]:
        suppression_key = self._suppression_key(match)
        if self._is_suppressed(suppression_key, match.event.timestamp):
            return None

        matched_fields = _extract_matched_fields(match)
        rule = match.evidence.get("matched_log_source") or match.event.log_source_normalized
        channel = match.evidence.get("matched_channel") or ""
        if channel and channel != "None":
            rule = f"{rule} / {channel}"

        confidence_basis = {
            "signal_scores": match.signal_scores,
            "correlation_boost": boosts.get("correlation_boost", 0.0),
            "chain_boost": boosts.get("chain_boost", 0.0),
            "confidence_tier": match.confidence_tier,
        }

        metadata: Dict[str, Any] = {
            "strategy": strategy,
            "threshold": str(threshold),
            "confidence": confidence_basis,
            "correlation_window": f"{self.suppress_window_seconds}s",
            "sources_used": sources_used,
            "correlation_group_id": group.group_id,
            "chain_sequence": group.chain_ids,
            "chain_depth": group.chain_depth,
            "is_ambiguous": match.is_ambiguous,
        }

        if related_matches:
            metadata["related_datacomponents"] = [
                {"id": m.datacomponent_id, "name": m.datacomponent_name, "score": m.similarity_score}
                for m in related_matches
                if m.datacomponent_id != match.datacomponent_id
            ]

        if match.event.asset_id in {"unknown", "", None}:
            metadata["unknown_asset"] = True

        alert = DetectionAlert(
            datacomponent=match.datacomponent_name,
            datacomponent_id=match.datacomponent_id,
            asset_id=match.event.asset_id,
            asset_name=match.event.asset_name,
            es_index=match.event.es_index,
            document_id=match.event.document_id,
            timestamp=match.event.timestamp.isoformat(),
            matched_fields=matched_fields,
            similarity_score=round(min(group.aggregate_score, 1.0), 4),
            evidence_snippet=_snippet(match.event.log_message),
            log_message=match.event.log_message,
            rule_or_pattern=rule,
            detection_id=str(uuid.uuid4()),
            detection_metadata=metadata,
        )

        self._recent_keys[suppression_key] = match.event.timestamp
        return alert

    def _suppression_key(self, match: CandidateMatch) -> str:
        raw = f"{match.event.asset_id}|{match.datacomponent_id}|{_snippet(match.event.log_message, 120)}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _is_suppressed(self, key: str, ts: datetime) -> bool:
        prev = self._recent_keys.get(key)
        if prev is None:
            return False
        delta = (ts - prev).total_seconds()
        return delta < self.suppress_window_seconds


def alert_to_document(alert: DetectionAlert) -> Dict[str, Any]:
    return asdict(alert)


def _snippet(message: str, limit: int = 200) -> str:
    if len(message) <= limit:
        return message
    return message[: limit - 3] + "..."


def _extract_matched_fields(match: CandidateMatch) -> Dict[str, Any]:
    fields = {}
    for f in match.evidence.get("matched_fields", []):
        for key, value in match.event.fields.items():
            if key.lower() == str(f).lower():
                fields[key] = value
    # Backfill key context if direct field overlap was small.
    for key in ("src_ip", "dst_ip", "auth_user", "syslog_program", "event_type", "alert.signature"):
        if key in match.event.fields and key not in fields:
            fields[key] = match.event.fields[key]
    return fields
