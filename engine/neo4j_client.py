"""Neo4j knowledge-graph client for MITRE ATT&CK for ICS.

Provides cached lookups that map DataComponents to Techniques,
Tactics, Mitigations, Software, and Groups using the v18 schema:

    DataComponent <-[USES]- Analytic <-[CONTAINS]- DetectionStrategy -[DETECTS]-> Technique

The client degrades gracefully when Neo4j is unreachable by returning
empty results and logging warnings.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

LOG = logging.getLogger("ics-detector.neo4j")

try:
    from neo4j import GraphDatabase
except ImportError:
    GraphDatabase = None  # type: ignore


@dataclass(frozen=True)
class TechniqueInfo:
    id: str
    name: str
    description: str
    url: str
    tactics: Tuple[str, ...]
    platforms: Tuple[str, ...]
    data_sources: Tuple[str, ...]
    group_count: int = 0
    asset_count: int = 0
    mitigation_count: int = 0


@dataclass(frozen=True)
class MitigationInfo:
    id: str
    name: str
    description: str


@dataclass(frozen=True)
class DCTechniqueMapping:
    """Result of traversing DC -> Analytic -> DetectionStrategy -> Technique."""
    datacomponent_id: str
    technique: TechniqueInfo
    analytics: Tuple[str, ...]
    detection_strategy: str
    path_weight: float


@dataclass
class GraphCache:
    """Thread-safe in-memory cache for graph query results."""
    dc_to_techniques: Dict[str, List[DCTechniqueMapping]] = field(default_factory=dict)
    technique_to_mitigations: Dict[str, List[MitigationInfo]] = field(default_factory=dict)
    technique_to_tactics: Dict[str, List[str]] = field(default_factory=dict)
    technique_details: Dict[str, TechniqueInfo] = field(default_factory=dict)
    technique_to_groups: Dict[str, List[str]] = field(default_factory=dict)
    technique_to_software: Dict[str, List[str]] = field(default_factory=dict)
    technique_to_assets: Dict[str, List[str]] = field(default_factory=dict)
    all_dc_ids: FrozenSet[str] = frozenset()
    _lock: threading.Lock = field(default_factory=threading.Lock)
    warm: bool = False

    def get_techniques(self, dc_id: str) -> List[DCTechniqueMapping]:
        with self._lock:
            return list(self.dc_to_techniques.get(dc_id, []))

    def get_mitigations(self, technique_id: str) -> List[MitigationInfo]:
        with self._lock:
            return list(self.technique_to_mitigations.get(technique_id, []))

    def get_technique(self, technique_id: str) -> Optional[TechniqueInfo]:
        with self._lock:
            return self.technique_details.get(technique_id)


class Neo4jClient:
    """Manages a connection to the MITRE ATT&CK for ICS knowledge graph."""

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        *,
        enabled: bool = True,
        cache_ttl_seconds: int = 3600,
    ) -> None:
        self._uri = uri
        self._enabled = enabled and bool(uri)
        self._driver = None
        self.cache = GraphCache()
        self._cache_ttl = cache_ttl_seconds

        if not self._enabled:
            LOG.info("Neo4j integration disabled (no URI configured).")
            return

        if GraphDatabase is None:
            LOG.warning(
                "neo4j Python driver not installed. "
                "Install with: pip install neo4j. Falling back to offline mode."
            )
            self._enabled = False
            return

        try:
            self._driver = GraphDatabase.driver(uri, auth=(username, password))
            self._driver.verify_connectivity()
            LOG.info("Connected to Neo4j at %s", uri)
        except Exception:
            LOG.exception("Failed to connect to Neo4j at %s. Falling back to offline mode.", uri)
            self._enabled = False
            self._driver = None

    @property
    def available(self) -> bool:
        return self._enabled and self._driver is not None

    def close(self) -> None:
        if self._driver:
            self._driver.close()
            self._driver = None

    def warm_cache(self) -> None:
        """Pre-load the full DC -> Technique mapping and supporting data."""
        if not self.available:
            LOG.debug("Neo4j not available; skipping cache warmup.")
            return
        try:
            self._load_dc_technique_mappings()
            self._load_technique_details()
            self._load_mitigations()
            self._load_group_usage()
            self._load_software_usage()
            self._load_asset_targeting()
            self.cache.warm = True
            LOG.info(
                "Neo4j cache warmed: %d DCs mapped to techniques, %d techniques loaded.",
                len(self.cache.dc_to_techniques),
                len(self.cache.technique_details),
            )
        except Exception:
            LOG.exception("Error warming Neo4j cache. Graph features will be limited.")

    def _run_query(self, query: str, **params: Any) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        with self._driver.session() as session:
            result = session.run(query, **params)
            return [dict(record) for record in result]

    def _load_dc_technique_mappings(self) -> None:
        query = """
        MATCH (dc:DataComponent)<-[:USES]-(a:Analytic)<-[:CONTAINS]-(ds:DetectionStrategy)-[:DETECTS]->(t:Technique)
        OPTIONAL MATCH (tac:Tactic)-[:USES]->(t)
        WITH dc, a, ds, t, collect(DISTINCT tac.name) AS tactics
        RETURN dc.id AS dc_id,
               t.id AS technique_id,
               t.name AS technique_name,
               t.description AS technique_desc,
               t.url AS technique_url,
               t.platforms AS platforms,
               t.data_sources AS data_sources,
               a.id AS analytic_id,
               a.name AS analytic_name,
               ds.id AS ds_id,
               ds.name AS ds_name,
               tactics
        """
        rows = self._run_query(query)

        dc_map: Dict[str, Dict[str, Dict]] = {}
        for row in rows:
            dc_id = row["dc_id"]
            t_id = row["technique_id"]
            if dc_id not in dc_map:
                dc_map[dc_id] = {}
            if t_id not in dc_map[dc_id]:
                dc_map[dc_id][t_id] = {
                    "technique_id": t_id,
                    "technique_name": row["technique_name"] or "",
                    "technique_desc": row["technique_desc"] or "",
                    "technique_url": row["technique_url"] or "",
                    "tactics": set(row.get("tactics") or []),
                    "platforms": tuple(row.get("platforms") or []),
                    "data_sources": tuple(row.get("data_sources") or []),
                    "analytics": set(),
                    "ds_id": row["ds_id"],
                    "ds_name": row["ds_name"] or "",
                }
            entry = dc_map[dc_id][t_id]
            entry["analytics"].add(row.get("analytic_id", ""))
            if row.get("tactics"):
                entry["tactics"].update(row["tactics"])

        with self.cache._lock:
            for dc_id, tech_map in dc_map.items():
                mappings = []
                for t_id, info in tech_map.items():
                    tech = TechniqueInfo(
                        id=t_id,
                        name=info["technique_name"],
                        description=info["technique_desc"][:500],
                        url=info["technique_url"],
                        tactics=tuple(sorted(info["tactics"])),
                        platforms=info["platforms"],
                        data_sources=info["data_sources"],
                    )
                    weight = len(info["analytics"])
                    mappings.append(DCTechniqueMapping(
                        datacomponent_id=dc_id,
                        technique=tech,
                        analytics=tuple(sorted(info["analytics"])),
                        detection_strategy=info["ds_name"],
                        path_weight=float(weight),
                    ))
                mappings.sort(key=lambda m: m.path_weight, reverse=True)
                self.cache.dc_to_techniques[dc_id] = mappings
            self.cache.all_dc_ids = frozenset(dc_map.keys())

    def _load_technique_details(self) -> None:
        query = """
        MATCH (t:Technique)
        OPTIONAL MATCH (tac:Tactic)-[:USES]->(t)
        WITH t, collect(DISTINCT tac.name) AS tactics
        OPTIONAL MATCH (g:Group)-[:USES]->(t)
        WITH t, tactics, count(DISTINCT g) AS group_count
        OPTIONAL MATCH (t)-[:TARGETS]->(a:Asset)
        WITH t, tactics, group_count, count(DISTINCT a) AS asset_count
        OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
        RETURN t.id AS id, t.name AS name, t.description AS description,
               t.url AS url, t.platforms AS platforms,
               t.data_sources AS data_sources,
               tactics, group_count, asset_count,
               count(DISTINCT m) AS mitigation_count
        """
        rows = self._run_query(query)
        with self.cache._lock:
            for row in rows:
                info = TechniqueInfo(
                    id=row["id"],
                    name=row.get("name") or "",
                    description=(row.get("description") or "")[:500],
                    url=row.get("url") or "",
                    tactics=tuple(row.get("tactics") or []),
                    platforms=tuple(row.get("platforms") or []),
                    data_sources=tuple(row.get("data_sources") or []),
                    group_count=row.get("group_count", 0),
                    asset_count=row.get("asset_count", 0),
                    mitigation_count=row.get("mitigation_count", 0),
                )
                self.cache.technique_details[row["id"]] = info

    def _load_mitigations(self) -> None:
        query = """
        MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique)
        RETURN t.id AS technique_id,
               m.id AS mitigation_id,
               m.name AS mitigation_name,
               m.description AS mitigation_desc
        """
        rows = self._run_query(query)
        result: Dict[str, List[MitigationInfo]] = {}
        for row in rows:
            t_id = row["technique_id"]
            if t_id not in result:
                result[t_id] = []
            result[t_id].append(MitigationInfo(
                id=row["mitigation_id"],
                name=row.get("mitigation_name") or "",
                description=(row.get("mitigation_desc") or "")[:300],
            ))
        with self.cache._lock:
            self.cache.technique_to_mitigations = result

    def _load_group_usage(self) -> None:
        query = """
        MATCH (g:Group)-[:USES]->(t:Technique)
        RETURN t.id AS technique_id, collect(DISTINCT g.name) AS groups
        """
        rows = self._run_query(query)
        with self.cache._lock:
            for row in rows:
                self.cache.technique_to_groups[row["technique_id"]] = row["groups"]

    def _load_software_usage(self) -> None:
        query = """
        MATCH (s:Software)-[:USES]->(t:Technique)
        RETURN t.id AS technique_id, collect(DISTINCT s.name) AS software
        """
        rows = self._run_query(query)
        with self.cache._lock:
            for row in rows:
                self.cache.technique_to_software[row["technique_id"]] = row["software"]

    def _load_asset_targeting(self) -> None:
        query = """
        MATCH (t:Technique)-[:TARGETS]->(a:Asset)
        RETURN t.id AS technique_id, collect(DISTINCT a.name) AS assets
        """
        rows = self._run_query(query)
        with self.cache._lock:
            for row in rows:
                self.cache.technique_to_assets[row["technique_id"]] = row["assets"]

    def get_techniques_for_dc(self, dc_id: str) -> List[DCTechniqueMapping]:
        return self.cache.get_techniques(dc_id)

    def get_mitigations_for_technique(self, technique_id: str) -> List[MitigationInfo]:
        return self.cache.get_mitigations(technique_id)

    def get_technique_info(self, technique_id: str) -> Optional[TechniqueInfo]:
        return self.cache.get_technique(technique_id)

    def get_groups_for_technique(self, technique_id: str) -> List[str]:
        with self.cache._lock:
            return list(self.cache.technique_to_groups.get(technique_id, []))

    def get_software_for_technique(self, technique_id: str) -> List[str]:
        with self.cache._lock:
            return list(self.cache.technique_to_software.get(technique_id, []))

    def get_assets_for_technique(self, technique_id: str) -> List[str]:
        with self.cache._lock:
            return list(self.cache.technique_to_assets.get(technique_id, []))
