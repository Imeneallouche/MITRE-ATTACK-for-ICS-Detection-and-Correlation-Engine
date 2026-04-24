"""Layer A training loop (stand-alone)."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, List, Optional

from ..config import LearningConfig
from ..data import (
    AlertLoader, FeatureBuilder, LabelStore, LabelledDatasetBuilder,
)
from .classifier import AlertClassifier

LOG = logging.getLogger("learning.layer_a.train")


def train_layer_a(
    cfg: LearningConfig,
    *,
    es_hosts: Optional[List[str]] = None,
    fixture_path: Optional[Path] = None,
    asset_role_map: Optional[dict] = None,
) -> AlertClassifier:
    layer_a = cfg.layer_a
    if not layer_a.get("enabled", True):
        LOG.info("Layer A disabled in config; skipping training.")
        return AlertClassifier()

    label_store = LabelStore(cfg.path("labels_file"))
    if not label_store.all():
        raise RuntimeError(
            "No window labels available. Use scripts/learning/label_window.py "
            "or import a Caldera report first.",
        )

    fb = FeatureBuilder(asset_role_map=asset_role_map or {})
    builder = LabelledDatasetBuilder(
        label_store=label_store,
        feature_builder=fb,
        skew_seconds=cfg.labels.get("skew_seconds", 15),
        ambiguous_threshold_seconds=cfg.labels.get("ambiguous_threshold_seconds", 30),
    )

    if fixture_path is not None:
        alerts = AlertLoader.load_jsonl(fixture_path)
        examples = builder.build_from_alerts(alerts)
    else:
        loader = AlertLoader(hosts=es_hosts, scroll_size=cfg.es.get("scroll_size", 1000))
        examples = builder.build_from_es(loader, cfg.es.get("alert_index_pattern", "ics-alerts-*"))

    if not examples:
        raise RuntimeError("No labelled training examples produced.")

    min_n = int(layer_a.get("min_train_samples", 200))
    if len(examples) < min_n:
        LOG.warning("Only %d labelled examples (min %d). Training anyway.",
                    len(examples), min_n)

    X, y, w = LabelledDatasetBuilder.to_matrix(examples)

    clf = AlertClassifier(
        backend=layer_a.get("backend", "auto"),
        nnpu_prior=layer_a.get("nnpu_prior", 0.05),
        calibration=layer_a.get("calibration", "isotonic"),
        recall_floor_score=layer_a.get("recall_floor_score", 0.78),
        drift_cfg=layer_a.get("drift_detector"),
    )
    meta = clf.fit(X, y, sample_weight=w, val_split=0.2)
    LOG.info("Layer A training complete: %s", meta.get("validation"))

    out = cfg.path("layer_a_model")
    clf.save(out)
    LOG.info("Saved Layer A model to %s", out)
    return clf
