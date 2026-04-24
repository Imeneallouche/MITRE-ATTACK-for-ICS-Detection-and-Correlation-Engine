"""PU alert classifier with optional XGBoost backend and safety rails."""
from __future__ import annotations

import json
import logging
import os
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from ..data.feature_builder import AlertFeatures, FeatureBuilder
from .calibration import IsotonicProbabilityCalibrator
from .drift import DriftEvent, make_detector
from .nnpu import nnpu_sample_weights

LOG = logging.getLogger("learning.layer_a")


@dataclass
class ClassifierVerdict:
    """Output of :meth:`AlertClassifier.predict`."""

    p_true_positive: float
    raw_score: float
    decision: str           # "true_positive" | "false_positive" | "uncertain"
    used_safety_rail: bool = False
    drift_alarm: Optional[DriftEvent] = None
    feature_contribution: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = dict(p_true_positive=float(self.p_true_positive),
                 raw_score=float(self.raw_score),
                 decision=self.decision,
                 used_safety_rail=bool(self.used_safety_rail))
        if self.drift_alarm is not None:
            d["drift_alarm"] = {
                "index": self.drift_alarm.index,
                "statistic": self.drift_alarm.statistic,
                "mean": self.drift_alarm.mean,
                "note": self.drift_alarm.note,
            }
        if self.feature_contribution:
            d["top_features"] = self.feature_contribution
        return d


def _select_backend(name: str) -> Tuple[str, Any]:
    name = (name or "auto").lower()
    if name in ("xgboost", "auto"):
        try:
            from xgboost import XGBClassifier  # type: ignore
            return "xgboost", XGBClassifier
        except Exception:
            if name == "xgboost":
                LOG.warning("xgboost requested but unavailable; falling back to sklearn.")
    try:
        from sklearn.ensemble import HistGradientBoostingClassifier  # type: ignore
        return "sklearn", HistGradientBoostingClassifier
    except Exception as exc:
        raise RuntimeError(
            "Layer A requires either xgboost or scikit-learn to be installed.",
        ) from exc


class AlertClassifier:
    """Per-alert PU classifier with calibrated probability output."""

    def __init__(
        self,
        *,
        backend: str = "auto",
        nnpu_prior: float = 0.05,
        calibration: str = "isotonic",
        recall_floor_score: float = 0.78,
        drift_cfg: Optional[Dict[str, Any]] = None,
        feature_names: Optional[Sequence[str]] = None,
    ) -> None:
        self._backend_name, self._backend_cls = _select_backend(backend)
        self.nnpu_prior = float(nnpu_prior)
        self.calibration_kind = (calibration or "none").lower()
        self.recall_floor_score = float(recall_floor_score)
        self.feature_names: List[str] = list(feature_names or FeatureBuilder.scalar_field_names())
        self.calibrator = IsotonicProbabilityCalibrator() if self.calibration_kind == "isotonic" else None
        drift_cfg = drift_cfg or {}
        if drift_cfg.get("enabled", True):
            self.drift_detector = make_detector(
                drift_cfg.get("method", "page_hinkley"),
                delta=drift_cfg.get("delta", 0.005),
                threshold=drift_cfg.get("threshold", 50.0),
            )
        else:
            self.drift_detector = None
        self.model: Any = None
        self.training_meta: Dict[str, Any] = {}

    # ── Training ───────────────────────────────────────────────────────
    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        *,
        sample_weight: Optional[np.ndarray] = None,
        val_split: float = 0.2,
        random_state: int = 42,
    ) -> Dict[str, Any]:
        if X.shape[0] == 0:
            raise ValueError("AlertClassifier.fit: empty training set")
        if X.shape[1] != len(self.feature_names):
            raise ValueError(
                f"AlertClassifier.fit: feature count mismatch "
                f"({X.shape[1]} vs {len(self.feature_names)})",
            )

        rng = np.random.default_rng(random_state)
        n = X.shape[0]
        idx = np.arange(n)
        rng.shuffle(idx)
        n_val = max(1, int(n * float(val_split)))
        val_idx, tr_idx = idx[:n_val], idx[n_val:]
        X_tr, X_val = X[tr_idx], X[val_idx]
        y_tr, y_val = y[tr_idx], y[val_idx]

        # nnPU sample weighting on the *training* split only.
        weights = nnpu_sample_weights(y_tr, prior=self.nnpu_prior)
        if sample_weight is not None:
            weights *= sample_weight[tr_idx]

        if self._backend_name == "xgboost":
            self.model = self._backend_cls(
                n_estimators=300,
                max_depth=4,
                learning_rate=0.08,
                eval_metric="logloss",
                n_jobs=max(1, os.cpu_count() or 1),
                random_state=random_state,
                tree_method="hist",
                use_label_encoder=False,
            )
            self.model.fit(X_tr, y_tr, sample_weight=weights)
        else:
            self.model = self._backend_cls(
                max_iter=400,
                learning_rate=0.05,
                max_depth=6,
                random_state=random_state,
            )
            self.model.fit(X_tr, y_tr, sample_weight=weights)

        # Probability of the positive class on the held-out validation set.
        p_val = self._raw_proba(X_val)
        if self.calibrator is not None:
            self.calibrator.fit(p_val, y_val)

        # Lightweight metrics for the model card.
        from .metrics import binary_metrics  # local import to avoid cycle
        p_val_cal = self.calibrator.transform(p_val) if self.calibrator else p_val
        metrics = binary_metrics(y_val, p_val_cal)
        self.training_meta = {
            "backend": self._backend_name,
            "n_total": int(n),
            "n_positive": int((y == 1).sum()),
            "n_negative": int((y == 0).sum()),
            "nnpu_prior": self.nnpu_prior,
            "validation": metrics,
            "feature_names": list(self.feature_names),
            "recall_floor_score": self.recall_floor_score,
        }
        return self.training_meta

    # ── Prediction ─────────────────────────────────────────────────────
    def predict_one(self, features: AlertFeatures) -> ClassifierVerdict:
        if self.model is None:
            # Fail-open: defer to engine score.
            sim = float(features.scalar[0])
            decision = "true_positive" if sim >= self.recall_floor_score else "uncertain"
            return ClassifierVerdict(
                p_true_positive=sim, raw_score=sim,
                decision=decision, used_safety_rail=True,
            )

        x = features.scalar.reshape(1, -1)
        raw = float(self._raw_proba(x)[0])
        cal = float(self.calibrator.transform(np.array([raw]))[0]) if self.calibrator else raw

        sim = float(features.scalar[0])
        used_rail = False
        if sim >= self.recall_floor_score and cal < 0.5:
            cal = max(cal, sim)
            used_rail = True

        if cal >= 0.5:
            decision = "true_positive"
        elif cal <= 0.2:
            decision = "false_positive"
        else:
            decision = "uncertain"

        drift_alarm = None
        if self.drift_detector is not None:
            drift_alarm = self.drift_detector.update(cal)

        contrib = self._top_features(x[0])
        return ClassifierVerdict(
            p_true_positive=cal, raw_score=raw, decision=decision,
            used_safety_rail=used_rail, drift_alarm=drift_alarm,
            feature_contribution=contrib,
        )

    def predict_many(self, examples: Sequence[AlertFeatures]) -> List[ClassifierVerdict]:
        return [self.predict_one(e) for e in examples]

    # ── Persistence ────────────────────────────────────────────────────
    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "backend": self._backend_name,
            "model": pickle.dumps(self.model) if self.model is not None else None,
            "calibrator": self.calibrator.to_dict() if self.calibrator else None,
            "feature_names": self.feature_names,
            "nnpu_prior": self.nnpu_prior,
            "recall_floor_score": self.recall_floor_score,
            "training_meta": self.training_meta,
        }
        with path.open("wb") as fh:
            pickle.dump(payload, fh)
        # Also drop a sidecar JSON model card for inspection.
        card = {k: v for k, v in payload.items() if k not in {"model", "calibrator"}}
        card["calibrator_available"] = bool(self.calibrator and self.calibrator._iso is not None)
        with path.with_suffix(".card.json").open("w", encoding="utf-8") as fh:
            json.dump(card, fh, indent=2, default=str)

    @classmethod
    def load(cls, path: Path) -> "AlertClassifier":
        with Path(path).open("rb") as fh:
            payload = pickle.load(fh)
        inst = cls(
            backend=payload.get("backend", "auto"),
            nnpu_prior=payload.get("nnpu_prior", 0.05),
            calibration="isotonic" if payload.get("calibrator") else "none",
            recall_floor_score=payload.get("recall_floor_score", 0.78),
            feature_names=payload.get("feature_names"),
        )
        inst.model = pickle.loads(payload["model"]) if payload.get("model") else None
        if payload.get("calibrator") and inst.calibrator is not None:
            inst.calibrator = IsotonicProbabilityCalibrator.from_dict(payload["calibrator"])
        inst.training_meta = payload.get("training_meta", {})
        return inst

    # ── Internals ──────────────────────────────────────────────────────
    def _raw_proba(self, X: np.ndarray) -> np.ndarray:
        if hasattr(self.model, "predict_proba"):
            p = self.model.predict_proba(X)
            return p[:, 1].astype(np.float32)
        if hasattr(self.model, "decision_function"):
            d = self.model.decision_function(X)
            return (1.0 / (1.0 + np.exp(-d))).astype(np.float32)
        return np.full((X.shape[0],), 0.5, dtype=np.float32)

    def _top_features(self, x: np.ndarray, k: int = 5) -> Dict[str, float]:
        """Cheap, model-agnostic feature importance for explainability.

        We multiply the (z-normalised) feature value by the model's
        global feature importance (when available).  This is *not* a
        SHAP value but it is fast, deterministic and good enough for
        the alert UI's ``Why was this flagged?`` panel.
        """
        if self.model is None:
            return {}
        try:
            importances = getattr(self.model, "feature_importances_", None)
            if importances is None:
                return {}
            x_norm = np.tanh(x.astype(np.float32))  # bounded surrogate
            scores = (importances.astype(np.float32) * x_norm).tolist()
        except Exception:
            return {}
        order = np.argsort([-abs(s) for s in scores])[:k]
        return {self.feature_names[i]: float(scores[i]) for i in order}
