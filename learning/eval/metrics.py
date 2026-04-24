"""Evaluation metrics for the learning pipeline.

Layers measured here:

* Layer A — precision/recall/F1/AUROC at the alert level.
* Layer B — top-K technique accuracy, chain accuracy, sequence
  fidelity (fraction of attack windows whose dominant chain matches).
* Layer C — action distribution, weighted reward, deferral rate.
* Layer D — abstain rate, average mitigation count, KG-grounding rate
  (fraction of mitigations whose ID appeared in the retrieved context).
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np


def classification_metrics(y_true: Sequence[int], y_score: Sequence[float],
                           threshold: float = 0.5) -> Dict[str, float]:
    y = np.asarray(y_true, dtype=np.int32)
    p = np.asarray(y_score, dtype=np.float32)
    if y.size == 0:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "auroc": 0.5,
                "false_positive_rate": 0.0, "n": 0}
    pred = (p >= threshold).astype(np.int32)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    f1 = 2 * prec * rec / max(prec + rec, 1e-9)
    fpr = fp / max(fp + tn, 1)

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
        "precision": float(prec), "recall": float(rec),
        "f1": float(f1), "auroc": float(auroc),
        "false_positive_rate": float(fpr),
        "n": int(y.size),
        "n_positive": int((y == 1).sum()),
        "n_negative": int((y == 0).sum()),
    }


def sequence_metrics(
    predictions: Sequence[Dict[str, Any]],
    *,
    technique_top_k: Sequence[int] = (1, 3, 5),
) -> Dict[str, float]:
    """``predictions`` is a list of ``{"chain_id_true", "chain_id_pred",
    "techniques_true", "techniques_pred"}`` dicts."""
    if not predictions:
        return {"chain_accuracy": 0.0, "n": 0}

    chain_correct = sum(
        1 for p in predictions
        if str(p.get("chain_id_pred", "")) == str(p.get("chain_id_true", ""))
    )
    out: Dict[str, float] = {
        "n": int(len(predictions)),
        "chain_accuracy": chain_correct / len(predictions),
    }
    for k in technique_top_k:
        hits = 0
        for p in predictions:
            true = set(p.get("techniques_true") or [])
            pred_pairs = p.get("techniques_pred") or []
            top_k_ids = []
            for entry in pred_pairs[:k]:
                if isinstance(entry, dict):
                    top_k_ids.append(entry.get("id"))
                else:
                    top_k_ids.append(str(entry))
            if true and (set(top_k_ids) & true):
                hits += 1
        out[f"technique_top_{k}_recall"] = hits / max(len(predictions), 1)
    return out


def mitigation_metrics(reports: Sequence[Dict[str, Any]]) -> Dict[str, float]:
    if not reports:
        return {"n": 0, "abstain_rate": 0.0,
                "avg_mitigations": 0.0, "kg_grounding_rate": 0.0}
    abstain = 0
    total_mits = 0
    grounded = 0
    for r in reports:
        if r.get("abstained"):
            abstain += 1
            continue
        proposals = (r.get("proposals") or {}).get("recommended_mitigations") or []
        retrieved_ids = {m.get("id") for m in (r.get("retrieved") or {}).get("mitigations") or []}
        total_mits += len(proposals)
        for prop in proposals:
            if prop.get("mitigation_id") in retrieved_ids:
                grounded += 1
    n = len(reports)
    return {
        "n": int(n),
        "abstain_rate": abstain / n,
        "avg_mitigations": total_mits / max(n - abstain, 1),
        "kg_grounding_rate": grounded / max(total_mits, 1),
    }


def latency_buckets(
    latencies_seconds: Sequence[float],
    *,
    buckets: Sequence[float] = (10, 30, 60, 120, 300),
) -> Dict[str, float]:
    if not latencies_seconds:
        return {"n": 0}
    arr = np.asarray(latencies_seconds, dtype=np.float64)
    out: Dict[str, float] = {"n": int(arr.size)}
    out["median"] = float(np.median(arr))
    out["p95"] = float(np.percentile(arr, 95))
    out["p99"] = float(np.percentile(arr, 99))
    for b in buckets:
        out[f"<= {int(b)}s"] = float((arr <= b).mean())
    return out


def action_distribution(decisions: Sequence[Dict[str, Any]]) -> Dict[str, float]:
    if not decisions:
        return {}
    counts = Counter(d.get("final_action", "unknown") for d in decisions)
    n = float(sum(counts.values()))
    return {f"action_{k}": v / n for k, v in counts.items()}


def summarise_run(
    *,
    layer_a: Dict[str, Any],
    layer_b: Dict[str, Any],
    layer_c: Dict[str, Any],
    layer_d: Dict[str, Any],
    overall_latency: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "layer_a": layer_a,
        "layer_b": layer_b,
        "layer_c": layer_c,
        "layer_d": layer_d,
        "latency": overall_latency,
    }
