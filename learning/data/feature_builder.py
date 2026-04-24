"""Turn an engine alert (or correlation entry) into a numeric feature row.

This module is the *only* place that knows the alert schema; every
downstream learner depends on it through :class:`AlertFeatures`.  The
goal is to produce features that:

1. carry enough information to separate true and false positives
   without leaking the operator's window labels;
2. degrade gracefully if a sub-block is missing (older alerts);
3. compose with text embeddings — the structured features are returned
   alongside an optional text snippet that downstream layers can encode
   with the engine's existing :class:`engine.embeddings.EmbeddingEngine`.
"""
from __future__ import annotations

import hashlib
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

LOG = logging.getLogger("learning.features")


# Numeric scalars in display order; the layer-A model uses *exactly* this
# layout, so changes here require retraining the classifier.
_SCALAR_FIELDS: Tuple[str, ...] = (
    "similarity_score",
    "semantic_match",
    "keyword_match",
    "log_source_match",
    "asset_id_score",
    "evidence_count",
    "keyword_hits",
    "is_correlated",
    "correlation_size",
    "correlation_aggregate",
    "is_repeat",
    "repeat_index",
    "asset_role_known",
    "datacomponent_known",
    "tactic_count",
    "technique_count",
    "log_text_length",
    "hour_of_day",
    "day_of_week",
    "is_weekend",
)


@dataclass
class AlertFeatures:
    """Structured + textual features describing one alert."""

    alert_id: str
    timestamp: datetime
    asset_id: str
    datacomponent: str
    technique_ids: List[str] = field(default_factory=list)
    tactic_ids: List[str] = field(default_factory=list)
    log_text: str = ""
    src_ips: List[str] = field(default_factory=list)
    dest_ips: List[str] = field(default_factory=list)
    raw_alert: Dict[str, Any] = field(default_factory=dict)
    scalar: np.ndarray = field(default_factory=lambda: np.zeros(len(_SCALAR_FIELDS), dtype=np.float32))

    def fingerprint(self) -> str:
        h = hashlib.sha1()
        h.update(self.asset_id.encode("utf-8", errors="ignore"))
        h.update(b"|")
        h.update(self.datacomponent.encode("utf-8", errors="ignore"))
        h.update(b"|")
        h.update(self.log_text.encode("utf-8", errors="ignore"))
        return h.hexdigest()


class FeatureBuilder:
    """Produce :class:`AlertFeatures` from raw alert dictionaries."""

    @classmethod
    def scalar_field_names(cls) -> Tuple[str, ...]:
        return _SCALAR_FIELDS

    def __init__(self, *, asset_role_map: Optional[Dict[str, str]] = None) -> None:
        self.asset_role_map = {k.lower(): str(v) for k, v in (asset_role_map or {}).items()}

    # ── Public API ─────────────────────────────────────────────────────
    def build(self, alert: Dict[str, Any]) -> AlertFeatures:
        ts = self._extract_ts(alert)
        asset = str(alert.get("asset_id") or alert.get("asset") or "unknown").lower()
        dc = str(alert.get("datacomponent") or alert.get("data_component") or "DC0000").upper()
        techniques = self._extract_list(alert, "technique_ids", "techniques")
        tactics = self._extract_list(alert, "tactic_ids", "tactics")
        log_text = self._extract_text(alert)
        src_ips = self._extract_list(alert, "src_ips", "source_ips")
        dest_ips = self._extract_list(alert, "dest_ips", "destination_ips")

        scalar = self._build_scalar(alert, ts=ts, log_text=log_text,
                                    techniques=techniques, tactics=tactics,
                                    asset=asset, dc=dc)

        return AlertFeatures(
            alert_id=str(alert.get("alert_id") or alert.get("_id") or alert.get("id") or ""),
            timestamp=ts,
            asset_id=asset,
            datacomponent=dc,
            technique_ids=[t.upper() for t in techniques],
            tactic_ids=[t.lower() for t in tactics],
            log_text=log_text,
            src_ips=[str(ip) for ip in src_ips],
            dest_ips=[str(ip) for ip in dest_ips],
            raw_alert=alert,
            scalar=scalar,
        )

    # ── Internals ──────────────────────────────────────────────────────
    @staticmethod
    def _extract_ts(alert: Dict[str, Any]) -> datetime:
        for key in ("@timestamp", "first_seen", "last_seen", "timestamp"):
            v = alert.get(key)
            if not v:
                continue
            if isinstance(v, datetime):
                return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
            s = str(v)
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            try:
                return datetime.fromisoformat(s)
            except ValueError:
                continue
        return datetime.now(timezone.utc)

    @staticmethod
    def _extract_list(alert: Dict[str, Any], *keys: str) -> List[str]:
        for k in keys:
            v = alert.get(k)
            if isinstance(v, list):
                return [str(x) for x in v if x]
            if isinstance(v, str) and v:
                return [v]
        return []

    @staticmethod
    def _extract_text(alert: Dict[str, Any]) -> str:
        for key in ("log_message", "message", "snippet", "raw_message"):
            v = alert.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
        evt = alert.get("event") or {}
        if isinstance(evt, dict):
            v = evt.get("message")
            if isinstance(v, str) and v.strip():
                return v.strip()
        return ""

    def _build_scalar(
        self,
        alert: Dict[str, Any],
        *,
        ts: datetime,
        log_text: str,
        techniques: List[str],
        tactics: List[str],
        asset: str,
        dc: str,
    ) -> np.ndarray:
        signals = alert.get("signals") or {}
        if not isinstance(signals, dict):
            signals = {}
        evidence = alert.get("evidence") or {}
        if not isinstance(evidence, dict):
            evidence = {}
        correlation = alert.get("correlation") or {}
        if not isinstance(correlation, dict):
            correlation = {}

        # Cross-source field aliases (engine has changed names over time).
        sim = float(alert.get("similarity_score")
                    or signals.get("similarity_score")
                    or alert.get("score") or 0.0)
        sem = float(signals.get("semantic_match")
                    or signals.get("semantic_score")
                    or alert.get("semantic_match") or 0.0)
        kw = float(signals.get("keyword_match")
                   or signals.get("keyword_score")
                   or alert.get("keyword_match") or 0.0)
        log_src = float(signals.get("log_source_match")
                        or signals.get("log_source_score")
                        or alert.get("log_source_match") or 0.0)
        asset_score = float(signals.get("asset_id_match")
                            or signals.get("asset_id_score")
                            or alert.get("asset_id_score") or 0.0)
        evidence_count = float(evidence.get("count")
                               or len(evidence.get("signals") or []) or 0)
        kw_hits = float(evidence.get("keyword_hits")
                        or alert.get("keyword_hits") or 0)

        is_corr = 1.0 if correlation else 0.0
        corr_size = float(correlation.get("group_size")
                          or correlation.get("size")
                          or len(correlation.get("members") or []) or 0)
        corr_agg = float(correlation.get("aggregate_score")
                         or correlation.get("group_score") or 0.0)

        is_repeat = float(alert.get("is_repeat") or 0.0)
        repeat_idx = float(alert.get("repeat_index") or 0.0)

        asset_role_known = 1.0 if asset in self.asset_role_map else 0.0
        dc_known = 1.0 if dc.upper().startswith("DC") and dc.upper() != "DC0000" else 0.0

        log_len = float(min(len(log_text), 4096))
        hour = float(ts.hour)
        dow = float(ts.weekday())
        is_weekend = 1.0 if ts.weekday() >= 5 else 0.0

        v = np.array([
            sim, sem, kw, log_src, asset_score,
            evidence_count, kw_hits,
            is_corr, corr_size, corr_agg,
            is_repeat, repeat_idx,
            asset_role_known, dc_known,
            float(len(tactics)), float(len(techniques)),
            log_len, hour, dow, is_weekend,
        ], dtype=np.float32)

        # Sanity: clamp non-finite values so downstream tensors stay clean.
        np.nan_to_num(v, copy=False, nan=0.0, posinf=1e6, neginf=-1e6)
        return v

    # ── Light text encoder fallback ────────────────────────────────────
    @staticmethod
    def hash_text_features(text: str, dim: int = 256) -> np.ndarray:
        """Cheap hashing-trick text encoder used when sentence embeddings
        are not available (e.g. inside unit tests)."""
        vec = np.zeros(dim, dtype=np.float32)
        if not text:
            return vec
        tokens = [t for t in text.lower().replace("\n", " ").split(" ") if t]
        if not tokens:
            return vec
        for tok in tokens:
            h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
            vec[h % dim] += 1.0
        norm = float(np.linalg.norm(vec))
        if norm > 0:
            vec /= norm
        return vec
