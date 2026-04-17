"""Configuration loader for the ICS Detection Engine.

The engine is fully data-driven: every environment-specific behaviour
(field aliases, category rules, log-source families, correlation chains,
technique fallbacks, asset role map, etc.) is read from the YAML config.
The loader normalises shapes so consumers can rely on stable types.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml


@dataclass
class EngineConfig:
    raw: Dict[str, Any]

    # ── Engine ─────────────────────────────────────────────────────────────

    @property
    def polling_interval_seconds(self) -> int:
        return int(self.raw["engine"]["polling_interval_seconds"])

    @property
    def batch_size(self) -> int:
        return int(self.raw["engine"]["batch_size"])

    @property
    def checkpoint_file(self) -> Path:
        return Path(self.raw["engine"]["checkpoint_file"])

    @property
    def excluded_asset_ids(self) -> List[str]:
        raw = self.raw.get("engine", {}).get("excluded_asset_ids")
        if isinstance(raw, list):
            return [str(x) for x in raw if x]
        return []

    # ── Thresholds ─────────────────────────────────────────────────────────

    @property
    def candidate_threshold(self) -> float:
        return float(self.raw["thresholds"]["candidate_threshold"])

    @property
    def alert_threshold(self) -> float:
        return float(self.raw["thresholds"]["alert_threshold"])

    @property
    def high_confidence_threshold(self) -> float:
        return float(self.raw["thresholds"]["high_confidence_threshold"])

    @property
    def unknown_asset_penalty(self) -> float:
        return float(self.raw["thresholds"]["unknown_asset_penalty"])

    # ── Alerting policy (optional ambiguity filter; suppression rules) ─────
    # Suppression rules default empty; RL or external policy can inject rules.

    @property
    def alerting(self) -> Dict[str, Any]:
        return self.raw.get("alerting", {}) or {}

    @property
    def skip_ambiguous_within_margin(self) -> bool:
        return bool(self.alerting.get("skip_if_ambiguous_within_margin", False))

    @property
    def ambiguous_score_margin(self) -> float:
        return float(self.alerting.get("ambiguous_score_margin", 0.05))

    @property
    def alert_suppression_rules(self) -> List[Dict[str, Any]]:
        raw = self.raw.get("alert_suppression_rules")
        if isinstance(raw, list):
            return raw
        return []

    # ── Scoring policy (evidence gate, keyword specificity, log-source cap) ─
    #
    # Purpose: a *generic*, non-hardcoded safeguard that an alert should not
    # rest on a single weak signal. The policy is pure math on the signal
    # vector -- no DC, message, or environment-specific rules -- so it
    # composes cleanly with any future RL / benign-behaviour model that
    # wants to further suppress or re-score alerts.
    #
    # Keys (all optional, with sensible defaults):
    #   min_independent_signals:        minimum number of non-zero signal
    #                                   channels required for full credit
    #   log_source_counts_as_evidence:  whether to count log-source as a
    #                                   corroborating channel (False by
    #                                   default because Logstash enrichment
    #                                   is usually a routing decision, not
    #                                   independent evidence)
    #   weak_evidence_cap:              max composite similarity allowed
    #                                   when fewer than the minimum signals
    #                                   are present
    #   keyword_evidence_threshold:     minimum keyword_match to count the
    #                                   keyword channel as evidence
    #   semantic_evidence_threshold:    minimum semantic_match to count the
    #                                   semantic channel as evidence
    #                                   (defaults to semantic_gate_threshold)
    #   min_event_text_length:          minimum trimmed length of log text
    #                                   for keyword credit
    #   log_source_max_score:           cap on log-source signal value
    #                                   (1.0 keeps historical behaviour)
    #   keyword_min_hits_for_full_credit, keyword_single_hit_credit:
    #                                   shape of the keyword specificity
    #                                   curve

    @property
    def scoring_policy(self) -> Dict[str, Any]:
        raw = self.raw.get("scoring", {}) or {}
        if not isinstance(raw, dict):
            return {}
        policy = dict(raw.get("evidence_policy") or {})
        policy.setdefault(
            "log_source_max_score",
            float(raw.get("log_source", {}).get("max_score", 1.0))
            if isinstance(raw.get("log_source"), dict)
            else 1.0,
        )
        kw_cfg = raw.get("keywords") or {}
        if isinstance(kw_cfg, dict):
            if "min_hits_for_full_credit" in kw_cfg:
                policy.setdefault(
                    "keyword_min_hits_for_full_credit",
                    int(kw_cfg["min_hits_for_full_credit"]),
                )
            if "single_hit_credit" in kw_cfg:
                policy.setdefault(
                    "keyword_single_hit_credit", float(kw_cfg["single_hit_credit"]),
                )
        return policy

    # ── Scoring ────────────────────────────────────────────────────────────

    @property
    def scoring_weights(self) -> Dict[str, float]:
        return {k: float(v) for k, v in self.raw["scoring_weights"].items()}

    @property
    def log_source_families(self) -> Dict[str, str]:
        raw = self.raw.get("log_source_families")
        if isinstance(raw, dict):
            return {str(k).lower(): str(v).lower() for k, v in raw.items() if v}
        return {}

    # ── Correlation ────────────────────────────────────────────────────────

    @property
    def correlation(self) -> Dict[str, Any]:
        return self.raw.get("correlation", {})

    @property
    def correlation_chain_rules(self) -> List[Tuple[str, str]]:
        raw = self.correlation.get("chain_rules") or []
        rules: List[Tuple[str, str]] = []
        for entry in raw:
            if isinstance(entry, (list, tuple)) and len(entry) == 2:
                rules.append((str(entry[0]), str(entry[1])))
        return rules

    @property
    def correlation_network_datacomponents(self) -> List[str]:
        raw = self.correlation.get("network_datacomponents") or []
        return [str(x) for x in raw if x]

    # ── Normalization ──────────────────────────────────────────────────────

    @property
    def normalization(self) -> Dict[str, Any]:
        return self.raw.get("normalization", {}) or {}

    # ── Elasticsearch ──────────────────────────────────────────────────────

    @property
    def es_hosts(self) -> List[str]:
        env = os.environ.get("ELASTICSEARCH_HOSTS", "").strip()
        if env:
            return [h.strip() for h in env.split(",") if h.strip()]
        return list(self.raw["elasticsearch"]["hosts"])

    @property
    def es_source_index_pattern(self) -> str:
        return str(self.raw["elasticsearch"]["source_index_pattern"])

    @property
    def es_alert_index_pattern(self) -> str:
        return str(self.raw["elasticsearch"]["alert_index_pattern"])

    @property
    def es_correlation_index_pattern(self) -> str:
        return str(self.raw["elasticsearch"]["correlation_index_pattern"])

    @property
    def datacomponents_dir(self) -> Path:
        return Path(self.raw["paths"]["datacomponents_dir"])

    @property
    def assets_file(self) -> Path:
        return Path(self.raw["paths"]["assets_file"])

    # ── Neo4j ──────────────────────────────────────────────────────────────

    @property
    def neo4j_enabled(self) -> bool:
        neo = self.raw.get("neo4j", {})
        return bool(neo.get("enabled", False))

    @property
    def neo4j_uri(self) -> str:
        return str(self.raw.get("neo4j", {}).get("uri", ""))

    @property
    def neo4j_username(self) -> str:
        return str(self.raw.get("neo4j", {}).get("username", "neo4j"))

    @property
    def neo4j_password(self) -> str:
        return str(self.raw.get("neo4j", {}).get("password", ""))

    @property
    def neo4j_cache_ttl(self) -> int:
        return int(self.raw.get("neo4j", {}).get("cache_ttl_seconds", 3600))

    # ── Technique mapper ───────────────────────────────────────────────────

    @property
    def technique_mapper(self) -> Dict[str, Any]:
        return self.raw.get("technique_mapper", {}) or {}

    @property
    def technique_asset_role_map(self) -> Dict[str, List[str]]:
        raw = self.technique_mapper.get("asset_role_map") or {}
        if not isinstance(raw, dict):
            return {}
        out: Dict[str, List[str]] = {}
        for k, v in raw.items():
            if isinstance(v, list):
                out[str(k).lower()] = [str(x) for x in v]
        return out

    @property
    def technique_fallback(self) -> Dict[str, List[Dict[str, Any]]]:
        raw = self.technique_mapper.get("fallback") or {}
        if not isinstance(raw, dict):
            return {}
        out: Dict[str, List[Dict[str, Any]]] = {}
        for dc, entries in raw.items():
            if isinstance(entries, list):
                out[str(dc)] = [e for e in entries if isinstance(e, dict)]
        return out

    # ── Embeddings ─────────────────────────────────────────────────────────

    @property
    def embeddings_enabled(self) -> bool:
        return bool(self.raw.get("embeddings", {}).get("enabled", True))

    @property
    def embedding_model(self) -> str:
        return str(self.raw.get("embeddings", {}).get("model", "BAAI/bge-small-en-v1.5"))

    @property
    def embedding_device(self) -> str:
        return str(self.raw.get("embeddings", {}).get("device", "cpu"))

    @property
    def semantic_gate_threshold(self) -> float:
        return float(self.raw.get("embeddings", {}).get("semantic_gate_threshold", 0.25))


def load_config(path: Path) -> EngineConfig:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return EngineConfig(raw=data)
