"""Offline evaluation harness — runs the orchestrator over a labelled
fixture and emits a JSON + CSV report grouped by chain."""
from __future__ import annotations

import csv
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..config import LearningConfig
from ..data import (
    AlertLoader, FeatureBuilder, LabelStore, LabelledDatasetBuilder,
)
from ..orchestrator import Orchestrator
from .metrics import (
    action_distribution,
    classification_metrics,
    latency_buckets,
    mitigation_metrics,
    sequence_metrics,
    summarise_run,
)

LOG = logging.getLogger("learning.eval.harness")


@dataclass
class EvalReport:
    summary: Dict[str, Any]
    per_chain: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    decisions: List[Dict[str, Any]] = field(default_factory=list)


class EvalHarness:
    def __init__(self, cfg: LearningConfig) -> None:
        self.cfg = cfg

    def run(
        self,
        *,
        fixture_path: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        es_hosts: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        cfg = self.cfg
        out_dir = Path(output_dir) if output_dir else cfg.path("metrics_dir")
        out_dir.mkdir(parents=True, exist_ok=True)
        label_store = LabelStore(cfg.path("labels_file"))
        labels = label_store.all()
        if not labels:
            raise RuntimeError("Cannot evaluate without window labels.")

        # ── Load alerts ───────────────────────────────────────────────
        if fixture_path is not None:
            alerts = AlertLoader.load_jsonl(fixture_path)
        else:
            loader = AlertLoader(hosts=es_hosts or [], scroll_size=cfg.es.get("scroll_size", 1000))
            alerts = loader.fetch_alerts(cfg.es.get("alert_index_pattern", "ics-alerts-*"))
        LOG.info("Loaded %d alerts for evaluation.", len(alerts))

        # ── Run orchestrator ──────────────────────────────────────────
        orch = Orchestrator.from_config(es_hosts=es_hosts)
        latencies: List[float] = []
        decisions: List[Dict[str, Any]] = []
        for alert in alerts:
            t0 = time.perf_counter()
            d = orch.process_alert(alert, run_layer_d=False)
            latencies.append(time.perf_counter() - t0)
            decisions.append(d.to_dict())

        # ── Map labels → ground truth per alert ───────────────────────
        fb = FeatureBuilder()
        builder = LabelledDatasetBuilder(label_store=label_store, feature_builder=fb)
        ground = builder.build_from_alerts(alerts, keep_unlabelled=True)
        labelled = [g for g in ground if g.label != -1]

        # Layer-A metrics
        y_true = [int(g.label == 1) for g in labelled]
        y_score = []
        for g, dec in zip(labelled, decisions[: len(labelled)]):
            y_score.append(float((dec.get("layer_a") or {}).get("p_true_positive", 0.0)))
        layer_a_m = classification_metrics(y_true, y_score)

        # Layer-B metrics: window-level chain prediction
        per_chain: Dict[str, Dict[str, Any]] = {}
        sequence_inputs: List[Dict[str, Any]] = []
        for window_id, items in builder.group_by_window(labelled).items():
            label = labels[window_id] if window_id < len(labels) else None
            if label is None:
                continue
            chain_id_true = label.chain_id or "__BENIGN__"
            techs_true = label.technique_list
            window_decs = [decisions[i] for i, ex in enumerate(labelled) if ex.window_id == window_id]
            preds = [d.get("layer_b") or {} for d in window_decs]
            chain_pred = "__UNKNOWN__"
            tech_pred = []
            for p in preds:
                if not p.get("available"):
                    continue
                if p.get("chain_id"):
                    chain_pred = p["chain_id"]
                tech_pred = p.get("techniques") or tech_pred
            sequence_inputs.append({
                "chain_id_true": chain_id_true,
                "chain_id_pred": chain_pred,
                "techniques_true": techs_true,
                "techniques_pred": tech_pred,
            })
            per_chain[chain_id_true] = {
                "n_alerts": len(window_decs),
                "techniques_true": techs_true,
                "techniques_pred": tech_pred,
                "chain_pred": chain_pred,
            }
        layer_b_m = sequence_metrics(
            sequence_inputs,
            technique_top_k=cfg.evaluation.get("technique_top_k", [1, 3, 5]),
        )

        # Layer-C action distribution
        layer_c_m = action_distribution(decisions)

        # Layer-D — only meaningful when run_layer_d=True; provide
        # placeholder when skipped.
        layer_d_m = mitigation_metrics([d.get("layer_d") or {} for d in decisions if d.get("layer_d")])
        latency_m = latency_buckets(
            latencies,
            buckets=cfg.evaluation.get("latency_seconds_buckets", [10, 30, 60, 120, 300]),
        )

        report = summarise_run(
            layer_a=layer_a_m, layer_b=layer_b_m,
            layer_c=layer_c_m, layer_d=layer_d_m,
            overall_latency=latency_m,
        )
        report["per_chain"] = per_chain

        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        json_path = out_dir / f"eval_{ts}.json"
        with json_path.open("w", encoding="utf-8") as fh:
            json.dump({"summary": report, "decisions": decisions}, fh, indent=2, default=str)
        LOG.info("Wrote evaluation report to %s", json_path)

        if cfg.evaluation.get("emit_csv_report", True):
            csv_path = out_dir / f"eval_{ts}.csv"
            with csv_path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(["chain_id", "n_alerts", "chain_pred",
                                 "techniques_true", "techniques_pred"])
                for chain_id, row in per_chain.items():
                    writer.writerow([
                        chain_id, row["n_alerts"], row["chain_pred"],
                        ";".join(row["techniques_true"]),
                        ";".join(t.get("id", "") if isinstance(t, dict) else str(t)
                                 for t in row["techniques_pred"]),
                    ])
            LOG.info("Wrote per-chain CSV to %s", csv_path)
        return report
