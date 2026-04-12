"""Knowledge-graph-driven MITRE ATT&CK for ICS technique inference.

Given a DataComponent match, this module determines the most probable
technique using the Neo4j graph structure and contextual signals.

Probability model
-----------------
For each technique *t* reachable from a DataComponent *dc* in the graph:

    raw(t) = path_weight(dc→t) × (1 + α_group × group_usage(t))
                                × (1 + α_asset × asset_relevance(t, event))

    P(t | dc, event) = raw(t) / Σ_t' raw(t')

where:
- path_weight: number of distinct Analytic nodes linking dc to t
- group_usage: number of threat groups known to use t  (normalised)
- asset_relevance: 1 if the targeted MITRE Asset matches the GRFICS
  asset role (PLC ↔ PLC, EWS ↔ Engineering Workstation, etc.), else 0.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .neo4j_client import DCTechniqueMapping, MitigationInfo, Neo4jClient, TechniqueInfo

LOG = logging.getLogger("ics-detector.technique")

GRFICS_ASSET_ROLE_MAP: Dict[str, List[str]] = {
    "plc": ["Programmable Logic Controller (PLC)", "Controller", "Field Controller/RTU/PLC/IED"],
    "simulation": ["Field Controller/RTU/PLC/IED", "Control Server", "Safety Instrumented System/Protection Relay"],
    "hmi": ["Human-Machine Interface", "Control Server", "SCADA Server"],
    "ews": ["Engineering Workstation", "Control Server"],
    "router": ["Control Server", "Engineering Workstation"],
}


@dataclass
class TechniqueCandidate:
    technique_id: str
    technique_name: str
    probability: float
    raw_score: float
    tactics: Tuple[str, ...]
    analytics_used: Tuple[str, ...]
    detection_strategy: str
    mitigations: List[Dict[str, str]]
    groups: List[str]
    software: List[str]
    targeted_assets: List[str]
    reasoning: str
    graph_path: str


@dataclass
class TechniqueMappingResult:
    datacomponent_id: str
    datacomponent_name: str
    candidates: List[TechniqueCandidate] = field(default_factory=list)
    best: Optional[TechniqueCandidate] = None
    graph_available: bool = False

    @property
    def has_mapping(self) -> bool:
        return self.best is not None


class TechniqueMapper:
    """Maps DataComponents to the most probable MITRE ATT&CK technique."""

    def __init__(
        self,
        neo4j: Neo4jClient,
        *,
        alpha_group: float = 0.3,
        alpha_asset: float = 0.5,
        max_candidates: int = 5,
        fallback_map: Optional[Dict[str, List[Dict[str, str]]]] = None,
    ) -> None:
        self._neo4j = neo4j
        self._alpha_group = alpha_group
        self._alpha_asset = alpha_asset
        self._max_candidates = max_candidates
        self._fallback = fallback_map or {}

    def map_technique(
        self,
        dc_id: str,
        dc_name: str,
        *,
        asset_role: str = "",
        asset_zone: str = "",
    ) -> TechniqueMappingResult:
        result = TechniqueMappingResult(
            datacomponent_id=dc_id,
            datacomponent_name=dc_name,
            graph_available=self._neo4j.available and self._neo4j.cache.warm,
        )

        mappings = self._neo4j.get_techniques_for_dc(dc_id)
        if not mappings:
            return self._apply_fallback(result, dc_id, dc_name)

        max_group_count = max(
            (self._get_technique_group_count(m.technique.id) for m in mappings),
            default=1,
        ) or 1

        scored: List[Tuple[float, DCTechniqueMapping]] = []
        for m in mappings:
            group_count = self._get_technique_group_count(m.technique.id)
            norm_group = group_count / max_group_count

            asset_rel = self._asset_relevance(m.technique.id, asset_role)

            raw = m.path_weight * (1 + self._alpha_group * norm_group) * (1 + self._alpha_asset * asset_rel)
            scored.append((raw, m))

        total = sum(s for s, _ in scored) or 1.0
        scored.sort(key=lambda x: x[0], reverse=True)

        for raw, m in scored[: self._max_candidates]:
            prob = raw / total
            mitigations = self._neo4j.get_mitigations_for_technique(m.technique.id)
            groups = self._neo4j.get_groups_for_technique(m.technique.id)
            software = self._neo4j.get_software_for_technique(m.technique.id)
            assets = self._neo4j.get_assets_for_technique(m.technique.id)

            reasoning = self._build_reasoning(m, prob, groups, asset_role)
            graph_path = (
                f"DataComponent({dc_id}) <-[USES]- "
                f"Analytic({','.join(m.analytics)}) <-[CONTAINS]- "
                f"DetectionStrategy({m.detection_strategy}) -[DETECTS]-> "
                f"Technique({m.technique.id})"
            )

            candidate = TechniqueCandidate(
                technique_id=m.technique.id,
                technique_name=m.technique.name,
                probability=round(prob, 4),
                raw_score=round(raw, 4),
                tactics=m.technique.tactics,
                analytics_used=m.analytics,
                detection_strategy=m.detection_strategy,
                mitigations=[{"id": mi.id, "name": mi.name} for mi in mitigations[:5]],
                groups=groups[:5],
                software=software[:5],
                targeted_assets=assets[:5],
                reasoning=reasoning,
                graph_path=graph_path,
            )
            result.candidates.append(candidate)

        if result.candidates:
            result.best = result.candidates[0]

        return result

    def _get_technique_group_count(self, technique_id: str) -> int:
        info = self._neo4j.get_technique_info(technique_id)
        return info.group_count if info else 0

    def _asset_relevance(self, technique_id: str, asset_role: str) -> float:
        if not asset_role:
            return 0.0
        targeted = self._neo4j.get_assets_for_technique(technique_id)
        if not targeted:
            return 0.0
        role_assets = GRFICS_ASSET_ROLE_MAP.get(asset_role.lower(), [])
        for ra in role_assets:
            for ta in targeted:
                if ra.lower() in ta.lower() or ta.lower() in ra.lower():
                    return 1.0
        return 0.0

    def _build_reasoning(
        self,
        mapping: DCTechniqueMapping,
        prob: float,
        groups: List[str],
        asset_role: str,
    ) -> str:
        parts = [
            f"Technique {mapping.technique.id} ({mapping.technique.name}) "
            f"is reachable via {len(mapping.analytics)} analytic(s) "
            f"through {mapping.detection_strategy}.",
        ]
        if groups:
            parts.append(f"Used by {len(groups)} threat group(s): {', '.join(groups[:3])}.")
        if mapping.technique.tactics:
            parts.append(f"Tactic(s): {', '.join(mapping.technique.tactics)}.")
        if asset_role:
            parts.append(f"Asset role '{asset_role}' considered for relevance weighting.")
        parts.append(f"Probability: {prob:.1%}.")
        return " ".join(parts)

    def _apply_fallback(
        self, result: TechniqueMappingResult, dc_id: str, dc_name: str
    ) -> TechniqueMappingResult:
        fb_entries = self._fallback.get(dc_id, [])
        if not fb_entries:
            return result

        for entry in fb_entries[: self._max_candidates]:
            candidate = TechniqueCandidate(
                technique_id=entry.get("technique_id", "unknown"),
                technique_name=entry.get("technique_name", "Unknown"),
                probability=float(entry.get("probability", 0.5)),
                raw_score=0.0,
                tactics=tuple(entry.get("tactics", [])),
                analytics_used=(),
                detection_strategy="fallback",
                mitigations=[],
                groups=[],
                software=[],
                targeted_assets=[],
                reasoning=f"Fallback mapping: {dc_id} -> {entry.get('technique_id')} (graph unavailable).",
                graph_path="N/A (fallback)",
            )
            result.candidates.append(candidate)

        if result.candidates:
            result.best = result.candidates[0]
        return result
