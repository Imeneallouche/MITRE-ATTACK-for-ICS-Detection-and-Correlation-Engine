"""Build labelled datasets for layers A and B from labels + alerts."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

from .alert_loader import AlertLoader
from .feature_builder import AlertFeatures, FeatureBuilder
from .label_store import LabelStore, WindowLabel

LOG = logging.getLogger("learning.dataset")


@dataclass
class LabelledExample:
    features: AlertFeatures
    label: int            # 1 = under_attack window, 0 = benign window, -1 = unlabelled
    chain_id: Optional[str] = None
    technique_list: List[str] = field(default_factory=list)
    window_id: Optional[int] = None
    weight: float = 1.0


class LabelledDatasetBuilder:
    """Join engine alerts with operator/Caldera window labels."""

    def __init__(
        self,
        *,
        label_store: LabelStore,
        feature_builder: FeatureBuilder,
        skew_seconds: float = 15.0,
        ambiguous_threshold_seconds: float = 30.0,
    ) -> None:
        self.label_store = label_store
        self.feature_builder = feature_builder
        self.skew_seconds = float(skew_seconds)
        self.ambiguous_threshold_seconds = float(ambiguous_threshold_seconds)

    # ── Build from in-memory alerts (offline) ──────────────────────────
    def build_from_alerts(
        self,
        alerts: Iterable[Dict[str, Any]],
        *,
        keep_unlabelled: bool = False,
    ) -> List[LabelledExample]:
        labels = self.label_store.all()
        examples: List[LabelledExample] = []
        for alert in alerts:
            feat = self.feature_builder.build(alert)
            label, wid, chain, techs = self._lookup_label(feat.timestamp, labels)
            if label is None and not keep_unlabelled:
                continue
            examples.append(LabelledExample(
                features=feat,
                label=int(label) if label is not None else -1,
                chain_id=chain,
                technique_list=list(techs or []),
                window_id=wid,
                weight=1.0,
            ))
        return examples

    # ── Build from Elasticsearch (uses AlertLoader) ────────────────────
    def build_from_es(
        self,
        loader: AlertLoader,
        index_pattern: str,
        *,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        max_results: int = 50_000,
        keep_unlabelled: bool = False,
    ) -> List[LabelledExample]:
        alerts = loader.fetch_alerts(
            index_pattern, since=since, until=until, max_results=max_results,
        )
        LOG.info("Loaded %d alerts from %s", len(alerts), index_pattern)
        return self.build_from_alerts(alerts, keep_unlabelled=keep_unlabelled)

    # ── Internals ──────────────────────────────────────────────────────
    def _lookup_label(
        self,
        ts: datetime,
        windows: Sequence[WindowLabel],
    ) -> Tuple[Optional[int], Optional[int], Optional[str], List[str]]:
        cover: Optional[Tuple[int, WindowLabel]] = None
        for idx, w in enumerate(windows):
            if w.covers(ts, skew_seconds=self.skew_seconds):
                cover = (idx, w)  # latest wins (overlap policy)
        if cover is None:
            return None, None, None, []
        idx, w = cover
        label = 1 if w.label == "under_attack" else 0
        return label, idx, w.chain_id, w.technique_list

    # ── Conversion helpers for Layer A / B ─────────────────────────────
    @staticmethod
    def to_matrix(examples: Sequence[LabelledExample]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        if not examples:
            return (np.zeros((0, 0), dtype=np.float32),
                    np.zeros((0,), dtype=np.int64),
                    np.zeros((0,), dtype=np.float32))
        X = np.stack([e.features.scalar for e in examples], axis=0)
        y = np.asarray([int(e.label) for e in examples], dtype=np.int64)
        w = np.asarray([float(e.weight) for e in examples], dtype=np.float32)
        return X, y, w

    @staticmethod
    def group_by_window(
        examples: Sequence[LabelledExample],
    ) -> Dict[int, List[LabelledExample]]:
        groups: Dict[int, List[LabelledExample]] = {}
        for ex in examples:
            if ex.window_id is None:
                continue
            groups.setdefault(ex.window_id, []).append(ex)
        for k in groups:
            groups[k].sort(key=lambda e: e.features.timestamp)
        return groups
