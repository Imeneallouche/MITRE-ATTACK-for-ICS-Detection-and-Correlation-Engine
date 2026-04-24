"""Hierarchical Neo4j retriever for the mitigation pipeline.

Wraps :class:`engine.neo4j_client.Neo4jClient` so Layer D never touches
the driver directly.  Two retrieval modes are supported:

* **flat** — given a list of techniques, fetch their mitigations,
  groups, software, assets.
* **hierarchical** — given an alert, first resolve techniques from the
  alert's DataComponent, score the techniques via tactic-level
  evidence, then drill down into mitigations.  This is the
  H-TechniqueRAG-style retrieval described in the architecture doc.
"""
from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

LOG = logging.getLogger("learning.layer_d.kg")

try:
    # Re-use the engine's existing Neo4j client (cached, well-tested).
    from engine.neo4j_client import (
        DCTechniqueMapping, MitigationInfo, Neo4jClient, TechniqueInfo,
    )
except Exception:  # pragma: no cover - allow standalone use
    Neo4jClient = None  # type: ignore
    DCTechniqueMapping = None  # type: ignore
    MitigationInfo = None  # type: ignore
    TechniqueInfo = None  # type: ignore


@dataclass
class RetrievedContext:
    techniques: List[Dict[str, Any]] = field(default_factory=list)
    mitigations: List[Dict[str, Any]] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    software: List[str] = field(default_factory=list)
    targeted_assets: List[str] = field(default_factory=list)
    raw_paths: List[Dict[str, Any]] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.techniques or self.mitigations)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "techniques": self.techniques,
            "mitigations": self.mitigations,
            "groups": self.groups,
            "software": self.software,
            "targeted_assets": self.targeted_assets,
            "raw_paths": self.raw_paths,
        }


class KnowledgeGraphRetriever:
    """Wraps Neo4jClient for Layer D's needs."""

    def __init__(
        self,
        client: Optional["Neo4jClient"] = None,
        *,
        max_techniques: int = 5,
        max_mitigations_per_technique: int = 8,
        include_groups: bool = True,
        include_software: bool = True,
        include_assets: bool = True,
        tactic_top_k: int = 3,
    ) -> None:
        self.client = client
        self.max_techniques = int(max_techniques)
        self.max_mitigations = int(max_mitigations_per_technique)
        self.include_groups = bool(include_groups)
        self.include_software = bool(include_software)
        self.include_assets = bool(include_assets)
        self.tactic_top_k = int(tactic_top_k)

    @property
    def available(self) -> bool:
        return bool(self.client and getattr(self.client, "available", False))

    # ── Public retrieval API ──────────────────────────────────────────
    def retrieve_for_dc(self, dc_id: str) -> RetrievedContext:
        ctx = RetrievedContext()
        if not self.available:
            return ctx
        mappings = self.client.get_techniques_for_dc(dc_id)[: self.max_techniques]
        return self._materialise(mappings, ctx)

    def retrieve_for_techniques(
        self,
        technique_ids: Sequence[str],
        *,
        dc_id: Optional[str] = None,
    ) -> RetrievedContext:
        """Resolve a known list of technique ids to full context."""
        ctx = RetrievedContext()
        if not self.available:
            return ctx
        # Pull a candidate set from each DC and filter by id; if no dc is
        # known, fall back to walking technique_details.
        seen: "OrderedDict[str, DCTechniqueMapping]" = OrderedDict()
        if dc_id:
            for mapping in self.client.get_techniques_for_dc(dc_id):
                if mapping.technique.id in technique_ids and mapping.technique.id not in seen:
                    seen[mapping.technique.id] = mapping
        for tid in technique_ids:
            if tid in seen:
                continue
            info = self.client.get_technique_info(tid)
            if info is None:
                continue
            seen[tid] = DCTechniqueMapping(
                datacomponent_id=dc_id or "",
                technique=info,
                analytics=tuple(),
                detection_strategy="",
                path_weight=0.0,
            )
            if len(seen) >= self.max_techniques:
                break
        return self._materialise(list(seen.values())[: self.max_techniques], ctx)

    # ── Hierarchical retrieval (tactic → technique → mitigation) ──────
    def retrieve_hierarchical(
        self,
        *,
        dc_id: str,
        predicted_tactics: Sequence[str] = (),
        predicted_techniques: Sequence[str] = (),
    ) -> RetrievedContext:
        if not self.available:
            return RetrievedContext()

        candidates = self.client.get_techniques_for_dc(dc_id)
        if not candidates:
            return self.retrieve_for_techniques(predicted_techniques)

        scored: List[Tuple[float, "DCTechniqueMapping"]] = []
        tac_set = {t.lower() for t in predicted_tactics if t}
        tech_set = {t.upper() for t in predicted_techniques if t}
        for mapping in candidates:
            score = float(mapping.path_weight)
            tac_overlap = len(tac_set & {tac.lower() for tac in mapping.technique.tactics}) if tac_set else 0
            score += 1.5 * tac_overlap
            if mapping.technique.id.upper() in tech_set:
                score += 3.0
            scored.append((score, mapping))
        scored.sort(key=lambda t: t[0], reverse=True)
        keep = [m for _, m in scored[: self.max_techniques]]
        return self._materialise(keep, RetrievedContext())

    # ── Internals ──────────────────────────────────────────────────────
    def _materialise(
        self,
        mappings: Iterable["DCTechniqueMapping"],
        ctx: RetrievedContext,
    ) -> RetrievedContext:
        techniques: List[Dict[str, Any]] = []
        mitigations: List[Dict[str, Any]] = []
        seen_mits: Dict[str, bool] = {}
        groups, software, assets = [], [], []

        for mapping in mappings:
            tech = mapping.technique
            entry = {
                "id": tech.id,
                "name": tech.name,
                "description": tech.description,
                "url": tech.url,
                "tactics": list(tech.tactics),
                "platforms": list(tech.platforms),
                "data_sources": list(tech.data_sources),
                "analytics": list(mapping.analytics),
                "detection_strategy": mapping.detection_strategy,
                "path_weight": mapping.path_weight,
            }
            techniques.append(entry)

            ctx.raw_paths.append({
                "datacomponent_id": mapping.datacomponent_id,
                "technique_id": tech.id,
                "analytics": list(mapping.analytics),
                "detection_strategy": mapping.detection_strategy,
            })

            for m in self.client.get_mitigations_for_technique(tech.id)[: self.max_mitigations]:
                if m.id in seen_mits:
                    continue
                seen_mits[m.id] = True
                mitigations.append({
                    "id": m.id, "name": m.name, "description": m.description,
                    "techniques": [tech.id],
                })
            if self.include_groups:
                for g in self.client.get_groups_for_technique(tech.id):
                    if g not in groups:
                        groups.append(g)
            if self.include_software:
                for s in self.client.get_software_for_technique(tech.id):
                    if s not in software:
                        software.append(s)
            if self.include_assets:
                for a in self.client.get_assets_for_technique(tech.id):
                    if a not in assets:
                        assets.append(a)

        ctx.techniques = techniques
        ctx.mitigations = mitigations
        ctx.groups = groups
        ctx.software = software
        ctx.targeted_assets = assets
        return ctx
