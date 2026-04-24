"""Lightweight metrics for Layer A (no sklearn dependency required)."""
from __future__ import annotations

from typing import Dict

import numpy as np


def binary_metrics(y_true: np.ndarray, p: np.ndarray) -> Dict[str, float]:
    """Return precision/recall/F1/AUROC at threshold 0.5.

    AUROC is computed in O(n log n) via the Mann-Whitney U identity.
    """
    y = np.asarray(y_true).astype(np.int32)
    p = np.asarray(p).astype(np.float32)
    if y.size == 0:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0,
                "auroc": 0.5, "n": 0}

    pred = (p >= 0.5).astype(np.int32)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    f1 = 2 * prec * rec / max(prec + rec, 1e-9)

    pos = p[y == 1]
    neg = p[y == 0]
    if pos.size == 0 or neg.size == 0:
        auroc = 0.5
    else:
        order = np.argsort(p)
        ranks = np.empty_like(order, dtype=np.float64)
        ranks[order] = np.arange(1, p.size + 1)
        sum_pos = float(ranks[y == 1].sum())
        n_pos, n_neg = float(pos.size), float(neg.size)
        u = sum_pos - n_pos * (n_pos + 1) / 2.0
        auroc = float(u / (n_pos * n_neg))

    return {
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "auroc": float(auroc),
        "n": int(y.size),
        "n_positive": int((y == 1).sum()),
        "n_negative": int((y == 0).sum()),
    }
