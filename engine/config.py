"""Configuration loader for the ICS Detection Engine."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import yaml


@dataclass
class EngineConfig:
    raw: Dict[str, Any]

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

    @property
    def scoring_weights(self) -> Dict[str, float]:
        return {k: float(v) for k, v in self.raw["scoring_weights"].items()}

    @property
    def correlation(self) -> Dict[str, Any]:
        return self.raw["correlation"]

    @property
    def es_hosts(self) -> List[str]:
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

    @property
    def technique_mapper(self) -> Dict[str, Any]:
        return self.raw.get("technique_mapper", {})


def load_config(path: Path) -> EngineConfig:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return EngineConfig(raw=data)
