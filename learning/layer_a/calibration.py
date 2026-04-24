"""Probability calibration helpers for Layer A."""
from __future__ import annotations

import numpy as np
from typing import Optional

try:
    from sklearn.isotonic import IsotonicRegression  # type: ignore
except Exception:  # pragma: no cover
    IsotonicRegression = None  # type: ignore


class IsotonicProbabilityCalibrator:
    """Monotone calibration on validation predictions.

    Falls back to identity when sklearn is unavailable.
    """

    def __init__(self) -> None:
        self._iso: Optional[IsotonicRegression] = None

    def fit(self, p_raw: np.ndarray, y_true: np.ndarray) -> "IsotonicProbabilityCalibrator":
        if IsotonicRegression is None:
            return self
        p_raw = np.clip(np.asarray(p_raw, dtype=np.float64), 1e-6, 1 - 1e-6)
        y_true = np.asarray(y_true, dtype=np.float64)
        self._iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        self._iso.fit(p_raw, y_true)
        return self

    def transform(self, p_raw: np.ndarray) -> np.ndarray:
        if self._iso is None:
            return np.clip(np.asarray(p_raw, dtype=np.float32), 0.0, 1.0)
        return self._iso.predict(np.clip(p_raw, 1e-6, 1 - 1e-6)).astype(np.float32)

    def to_dict(self) -> dict:
        """Serialise the fitted estimator via pickle.

        sklearn's :class:`IsotonicRegression` has internal state (``f_``)
        that is *not* re-derivable from the public ``X_thresholds_`` /
        ``y_thresholds_`` arrays, so we round-trip the whole estimator.
        """
        if self._iso is None:
            return {"available": False}
        import base64
        import pickle as _pickle
        return {
            "available": True,
            "blob": base64.b64encode(_pickle.dumps(self._iso)).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "IsotonicProbabilityCalibrator":
        cal = cls()
        if not d.get("available") or IsotonicRegression is None:
            return cal
        import base64
        import pickle as _pickle
        blob = d.get("blob")
        if blob:
            try:
                cal._iso = _pickle.loads(base64.b64decode(blob.encode("ascii")))
            except Exception:
                cal._iso = None
        return cal
