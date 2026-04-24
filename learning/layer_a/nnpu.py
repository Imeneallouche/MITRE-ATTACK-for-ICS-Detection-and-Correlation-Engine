"""Non-negative PU (nnPU) sample reweighting.

We train an off-the-shelf gradient boosted classifier on weakly-labelled
data (positive = alert inside an ``under_attack`` window, negative =
alert inside a ``benign`` window).  Because positives are necessarily
contaminated by benign-looking events that fired during the attack, we
correct the loss with the nnPU estimator (Kiryo et al. 2017).

Concretely we reweight samples instead of changing the loss function so
this works with any sklearn-style ``fit(X, y, sample_weight=…)``.
"""
from __future__ import annotations

import numpy as np
from typing import Tuple


def nnpu_sample_weights(
    y: np.ndarray,
    *,
    prior: float,
    eps: float = 1e-6,
) -> np.ndarray:
    """Return sample weights that approximate the nnPU risk.

    Risk decomposition (binary cross-entropy):

        R_pu(g) = π * R_p^+(g) + max(0, R_u^-(g) - π * R_p^-(g))

    With weak negatives in our setting we treat ``y == 0`` as the
    *unlabelled* class.  The weights are:

        w(positive)      = prior
        w(unlabelled)    = (1 - prior * (n_p / n_u))

    clamped to be non-negative to prevent the over-fitting failure mode
    described in the original paper.
    """
    y = np.asarray(y).reshape(-1)
    n = y.shape[0]
    if n == 0:
        return np.zeros((0,), dtype=np.float32)

    n_pos = float(np.sum(y == 1))
    n_unl = float(np.sum(y == 0))
    if n_pos <= 0 or n_unl <= 0:
        return np.ones(n, dtype=np.float32)

    pi = float(max(min(prior, 1.0 - eps), eps))
    pos_w = pi
    unl_w = max(1.0 - pi * (n_pos / n_unl), 0.0)

    # Avoid degenerate case where unl_w -> 0 (all weight on a few positives).
    if unl_w < 1e-3:
        unl_w = 1e-3

    w = np.where(y == 1, pos_w, unl_w).astype(np.float32)
    # Renormalise so the average weight is 1 (keeps optimisation scale stable).
    w *= float(n) / max(float(w.sum()), eps)
    return w


def estimate_class_prior(scores: np.ndarray, *, alpha: float = 0.05) -> float:
    """KM2-style prior estimator from a scalar score (Ramaswamy 2016).

    We use it only as a fallback when the operator has not configured
    ``layer_a.nnpu_prior`` explicitly.  It assumes ``scores`` are the
    deterministic engine similarity scores on a held-out, mostly-benign
    sample.
    """
    s = np.sort(np.asarray(scores).reshape(-1))
    if s.size == 0:
        return alpha
    q_high = float(np.quantile(s, 1.0 - alpha))
    q_low = float(np.quantile(s, alpha))
    pi = max(min((s >= q_high).mean() / max((s >= q_low).mean(), 1e-6), 0.5), 0.001)
    return pi
