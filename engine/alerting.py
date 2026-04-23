"""Alert builder with full explainability and technique attribution.

Each alert includes:
- The triggering log(s)
- Matched DataComponent(s) with feature-level evidence
- Similarity and confidence scores, including semantic similarity detail
- Gate reason explaining why the DC was considered
- Correlation context (group, chain, repeat)
- Probable MITRE ATT&CK for ICS technique from the knowledge graph
- Mitigations, threat groups, and software from the graph
- Reasoning explaining why the technique was selected
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .models import (
    CandidateMatch,
    CorrelationGroup,
    DetectionAlert,
    TechniqueAttribution,
)
from .technique_mapper import TechniqueMapper, TechniqueMappingResult


class AlertBuilder:

    def __init__(
        self,
        technique_mapper: Optional[TechniqueMapper] = None,
        *,
        suppress_window_seconds: int = 60,
        idempotent_alert_ids: bool = True,
        per_asset_dc_rate_window_seconds: int = 0,
        per_asset_dc_rate_max_alerts: int = 0,
    ) -> None:
        self.suppress_window_seconds = suppress_window_seconds
        self.idempotent_alert_ids = idempotent_alert_ids
        # Second-level rate limit per ``(asset_id, datacomponent_id)`` — blocks
        # bursts of *differently-worded* alerts (e.g. process-alarm rows whose
        # numeric fields drift each cycle, keeping the message fingerprint
        # unique).  ``0`` disables (legacy behaviour).
        self.per_asset_dc_rate_window_seconds = max(0, int(per_asset_dc_rate_window_seconds))
        self.per_asset_dc_rate_max_alerts = max(0, int(per_asset_dc_rate_max_alerts))
        self._rate_limit_history: Dict[str, List[datetime]] = {}
        self._recent_keys: Dict[str, datetime] = {}
        self._technique_mapper = technique_mapper

    def build_alert(
        self,
        match: CandidateMatch,
        group: CorrelationGroup,
        boosts: Dict[str, float],
        *,
        strategy: str,
        threshold: float,
        sources_used: List[str],
        related_matches: Optional[List[CandidateMatch]] = None,
    ) -> Optional[DetectionAlert]:
        suppression_key = self._suppression_key(match)
        if self._is_suppressed(suppression_key, match.event.timestamp):
            return None
        if self._is_rate_limited(match):
            return None

        technique_result = self._map_technique(match)
        primary_technique = self._to_attribution(technique_result)
        alt_techniques = [
            self._to_attribution_candidate(c)
            for c in (technique_result.candidates[1:4] if technique_result else [])
        ]

        if primary_technique and primary_technique.technique_id not in group.technique_sequence:
            group.technique_sequence.append(primary_technique.technique_id)

        corr_boost = boosts.get("correlation_boost", 0.0)
        chain_boost = boosts.get("chain_boost", 0.0)
        final_score = min(1.0, group.aggregate_score)

        metadata: Dict[str, Any] = {
            "strategy": strategy,
            "threshold": threshold,
            "graph_available": technique_result.graph_available if technique_result else False,
            "sources_used": sources_used,
            "is_ambiguous": match.is_ambiguous,
            "evidence_signal_count": match.evidence_signal_count,
            "evidence_signals": match.evidence.get("evidence_signals", []),
            "weak_evidence": match.weak_evidence,
        }

        if related_matches:
            metadata["related_datacomponents"] = [
                {"id": m.datacomponent_id, "name": m.datacomponent_name, "score": m.similarity_score}
                for m in related_matches
                if m.datacomponent_id != match.datacomponent_id
            ]

        if match.event.asset_id in {"unknown", "", None}:
            metadata["unknown_asset"] = True

        matched_channel = ""
        sem_detail = match.evidence.get("semantic_similarity", 0.0)
        ls_ev = str(match.evidence.get("matched_log_source", "") or "")
        line_match = match.evidence.get("line_match") or {}
        catalog_align = match.evidence.get("catalog_alignment") or {}
        dc_ls_name = str(line_match.get("datacomponent_log_source_name", "") or "") or str(
            catalog_align.get("datacomponent_log_source_name", "") or "",
        )
        dc_ls_ch = str(line_match.get("datacomponent_log_source_channel", "") or "") or str(
            catalog_align.get("datacomponent_log_source_channel", "") or "",
        )
        if match.gate_passed.startswith("logstash"):
            matched_channel = (
                f"dc={match.datacomponent_id} ({match.datacomponent_name}); "
                f"gate=logstash_enrichment; log_source_match={ls_ev}"
            )
        elif isinstance(sem_detail, (int, float)) and sem_detail > 0:
            matched_channel = f"semantic_cosine:{sem_detail:.4f}; {ls_ev}".strip()
        elif ls_ev:
            matched_channel = ls_ev
        if dc_ls_name or dc_ls_ch:
            ch_snip = dc_ls_ch[:200] + ("…" if len(dc_ls_ch) > 200 else "")
            extra = f"dc_catalog_name={dc_ls_name!r}; dc_catalog_channel={ch_snip!r}"
            matched_channel = f"{matched_channel}; {extra}" if matched_channel else extra

        emb = (match.event.embedding_text or "").strip()
        orig = (match.event.original_log_message or "").strip()
        trig = orig or (match.event.log_message or "").strip() or emb
        similarity_evidence: Dict[str, Any] = {
            "signal_scores": dict(match.signal_scores),
            "semantic_similarity": match.evidence.get("semantic_similarity"),
            "gate_passed": match.gate_passed,
            "matched_log_source_evidence": match.evidence.get("matched_log_source"),
            "line_match": line_match or None,
            "catalog_alignment": catalog_align or None,
            "composite_similarity": match.similarity_score,
            "embedding_text_preview": emb[:2048] + ("…" if len(emb) > 2048 else ""),
            "indexed_log_message": orig,
        }
        sk = match.evidence.get("soft_semantic_keyword_cap")
        if sk:
            similarity_evidence["soft_semantic_keyword_cap"] = sk
            metadata["soft_semantic_keyword_cap"] = sk

        metadata["triggering_event"] = {
            "log_message": trig,
            "log_type": match.event.log_type,
            "log_source_normalized": match.event.log_source_normalized,
            "embedding_text_preview": similarity_evidence.get("embedding_text_preview"),
            "datacomponent_id": match.datacomponent_id,
            "datacomponent_name": match.datacomponent_name,
            "datacomponent_log_source_name": dc_ls_name,
            "datacomponent_log_source_channel": dc_ls_ch,
            "gate_reason": match.gate_passed,
        }
        if self.idempotent_alert_ids:
            raw_id = (
                f"ics-alert-v1|{match.event.es_index}|{match.event.document_id}|"
                f"{match.datacomponent_id}"
            )
            stable = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()
        else:
            stable = str(uuid.uuid4())

        alert = DetectionAlert(
            detection_id=stable,
            timestamp=match.event.timestamp.isoformat(),
            datacomponent=match.datacomponent_name,
            datacomponent_id=match.datacomponent_id,
            asset_id=match.event.asset_id,
            asset_name=match.event.asset_name,
            asset_ip=match.event.asset_ip,
            zone=match.event.zone,
            is_ics_asset=match.event.is_ics_asset,
            es_index=match.event.es_index,
            document_id=match.event.document_id,
            log_message=trig,
            evidence_snippet=_snippet(trig),
            triggering_log=trig,
            observed_log_source=str(match.event.log_source_normalized or ""),
            datacomponent_log_source_name=dc_ls_name,
            datacomponent_log_source_channel=dc_ls_ch,
            similarity_evidence=similarity_evidence,
            similarity_score=round(final_score, 4),
            confidence_tier=match.confidence_tier,
            signal_scores=match.signal_scores,
            matched_fields=_extract_matched_fields(match),
            matched_keywords=match.evidence.get("matched_keywords", []),
            matched_categories=match.evidence.get("matched_categories", []),
            matched_log_source=match.evidence.get("matched_log_source", ""),
            matched_channel=matched_channel,
            semantic_score=round(match.semantic_score, 4),
            gate_reason=match.gate_passed,
            technique=primary_technique,
            alternative_techniques=alt_techniques,
            correlation_group_id=group.group_id,
            chain_ids=group.chain_ids,
            chain_depth=group.chain_depth,
            correlation_boost=corr_boost,
            chain_boost=chain_boost,
            event_count_in_group=len(group.matches),
            technique_sequence=group.technique_sequence,
            detection_metadata=metadata,
        )

        self._recent_keys[suppression_key] = match.event.timestamp
        return alert

    def _map_technique(self, match: CandidateMatch) -> Optional[TechniqueMappingResult]:
        if self._technique_mapper is None:
            return None
        return self._technique_mapper.map_technique(
            dc_id=match.datacomponent_id,
            dc_name=match.datacomponent_name,
            asset_role=match.event.asset_role,
            asset_zone=match.event.zone or "",
        )

    @staticmethod
    def _to_attribution(result: Optional[TechniqueMappingResult]) -> Optional[TechniqueAttribution]:
        if not result or not result.best:
            return None
        b = result.best
        return TechniqueAttribution(
            technique_id=b.technique_id,
            technique_name=b.technique_name,
            probability=b.probability,
            tactics=list(b.tactics),
            mitigations=b.mitigations,
            groups=b.groups,
            software=b.software,
            targeted_assets=b.targeted_assets,
            detection_strategy=b.detection_strategy,
            analytics_used=list(b.analytics_used),
            graph_path=b.graph_path,
            reasoning=b.reasoning,
        )

    @staticmethod
    def _to_attribution_candidate(candidate) -> TechniqueAttribution:
        return TechniqueAttribution(
            technique_id=candidate.technique_id,
            technique_name=candidate.technique_name,
            probability=candidate.probability,
            tactics=list(candidate.tactics),
            mitigations=candidate.mitigations,
            groups=candidate.groups,
            software=candidate.software,
            targeted_assets=candidate.targeted_assets,
            detection_strategy=candidate.detection_strategy,
            analytics_used=list(candidate.analytics_used),
            graph_path=candidate.graph_path,
            reasoning=candidate.reasoning,
        )

    def _suppression_key(self, match: CandidateMatch) -> str:
        raw = f"{match.event.asset_id}|{match.datacomponent_id}|{_snippet(match.event.log_message, 120)}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _is_suppressed(self, key: str, ts: datetime) -> bool:
        prev = self._recent_keys.get(key)
        if prev is None:
            return False
        delta = (ts - prev).total_seconds()
        return delta < self.suppress_window_seconds

    def _is_rate_limited(self, match: CandidateMatch) -> bool:
        """Return True when ``(asset_id, datacomponent_id)`` exceeded its quota.

        Uses a simple sliding window so that bursts of same-DC alerts (e.g. a
        storm of process-alarm rows after a simulation pushes a tank into an
        unstable range) collapse into at most ``max_alerts`` rows per
        ``window_seconds`` without naming the DC or message.  The limiter is
        purely alert-side: correlation still sees every underlying event.
        """
        if self.per_asset_dc_rate_max_alerts <= 0 or self.per_asset_dc_rate_window_seconds <= 0:
            return False
        key = f"{match.event.asset_id}|{match.datacomponent_id}"
        now = match.event.timestamp
        window = timedelta(seconds=self.per_asset_dc_rate_window_seconds)
        history = self._rate_limit_history.get(key, [])
        history = [t for t in history if now - t <= window]
        if len(history) >= self.per_asset_dc_rate_max_alerts:
            self._rate_limit_history[key] = history
            return True
        history.append(now)
        self._rate_limit_history[key] = history
        return False


def alert_to_document(alert: DetectionAlert) -> Dict[str, Any]:
    """Serialise a DetectionAlert to an Elasticsearch-friendly dict."""
    doc = asdict(alert)
    return doc


def _snippet(message: str, limit: int = 200) -> str:
    if len(message) <= limit:
        return message
    return message[: limit - 3] + "..."


def _extract_matched_fields(match: CandidateMatch) -> Dict[str, Any]:
    """Return only the event fields whose keys overlap the DC's profile."""
    fields: Dict[str, Any] = {}
    for f in match.evidence.get("matched_fields", []):
        target = str(f).lower()
        for key, value in match.event.fields.items():
            if key.lower() == target:
                fields[key] = value
    return fields
