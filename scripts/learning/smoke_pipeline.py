#!/usr/bin/env python3
"""Self-contained smoke test for the `learning/` package.

This does not need ES, Neo4j, or any heavy ML deps — it exercises every
module with synthetic data so you can verify the wiring is sound after
``pip install -r requirements.txt``.

Run::

    python scripts/learning/smoke_pipeline.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _attack_alert(asset, dc, msg, ts, sim, sem, kw, ls=0.0,
                  techniques=None, src_ip=None) -> dict:
    return {
        "@timestamp": ts.isoformat(),
        "alert_id": f"{asset}-{dc}-{int(ts.timestamp())}",
        "asset_id": asset,
        "datacomponent": dc,
        "log_message": msg,
        "similarity_score": sim,
        "signals": {
            "semantic_match": sem, "keyword_match": kw,
            "log_source_match": ls, "asset_id_score": 0.5,
        },
        "evidence": {"count": 2 if sim > 0.5 else 1, "keyword_hits": 1 if kw > 0 else 0},
        "technique_ids": techniques or [],
        "src_ips": [src_ip] if src_ip else [],
    }


def main() -> int:
    print("== learning/ smoke test ==")
    from learning.config import load_config
    from learning.data import (
        AlertLoader, CalderaLoader, FeatureBuilder, LabelStore,
        LabelledDatasetBuilder,
    )
    from learning.data.label_store import WindowLabel
    from learning.layer_a import AlertClassifier
    from learning.layer_a.metrics import binary_metrics
    from learning.layer_c import (
        AVAR, RewardModel, TriageEnvironment, TriagePolicy,
    )
    from learning.layer_d import (
        KnowledgeGraphRetriever, MitigationPipeline,
    )
    from learning.orchestrator import Orchestrator

    cfg = load_config()
    print(f"  → loaded learning.yml from {cfg.paths.get('state_dir')}")

    with tempfile.TemporaryDirectory() as tmp:
        labels_path = Path(tmp) / "labels.jsonl"
        store = LabelStore(labels_path)

        now = datetime.now(timezone.utc).replace(microsecond=0)
        attack_start = now - timedelta(minutes=10)
        attack_end = now - timedelta(minutes=2)
        store.add_window(start=attack_start, end=attack_end,
                         label="under_attack", chain_id="Chain X",
                         technique_list=["T0812", "T0881", "T0836"],
                         attacker_assets=["kali"],
                         defender_assets=["plc", "hmi"],
                         source="smoke_test")
        store.add_window(start=now - timedelta(minutes=30),
                         end=now - timedelta(minutes=20),
                         label="benign", source="smoke_test")
        print(f"  → wrote 2 window labels to {labels_path}")

        # ── Build synthetic alerts ────────────────────────────────────
        alerts = []
        # Attack alerts (in window)
        attack_assets = ["plc", "hmi", "scada"]
        for i, asset in enumerate(attack_assets):
            ts = attack_start + timedelta(seconds=30 * (i + 1))
            alerts.append(_attack_alert(
                asset, "DC0038",
                f"OpenPLC user logged in successfully ({asset})",
                ts, sim=0.74, sem=0.61, kw=0.55, ls=1.0,
                techniques=["T0812"], src_ip="192.168.90.6",
            ))
        for i, asset in enumerate(["plc", "hmi"]):
            ts = attack_start + timedelta(minutes=2, seconds=30 * i)
            alerts.append(_attack_alert(
                asset, "DC0082",
                f"Modbus TCP connection established from 192.168.90.6 to {asset}",
                ts, sim=0.62, sem=0.55, kw=0.48,
                techniques=["T0866"], src_ip="192.168.90.6",
            ))
        # Benign alerts (in benign window)
        for i, asset in enumerate(["plc", "hmi"]):
            ts = (now - timedelta(minutes=25)) + timedelta(seconds=15 * i)
            alerts.append(_attack_alert(
                asset, "DC0038", f"watchdog heartbeat ok",
                ts, sim=0.32, sem=0.18, kw=0.10,
            ))
        # Outside any window — should be excluded from training
        alerts.append(_attack_alert(
            "router", "DC0078", "ICMP echo reply",
            now - timedelta(hours=2), sim=0.10, sem=0.05, kw=0.02,
        ))
        print(f"  → built {len(alerts)} synthetic alerts")

        # ── Dataset assembly ──────────────────────────────────────────
        fb = FeatureBuilder()
        builder = LabelledDatasetBuilder(label_store=store, feature_builder=fb)
        examples = builder.build_from_alerts(alerts)
        X, y, w = LabelledDatasetBuilder.to_matrix(examples)
        print(f"  → labelled examples: {len(examples)} (positives={int((y==1).sum())},"
              f" negatives={int((y==0).sum())})")
        assert len(examples) >= 5, "not enough labelled examples"

        # ── Layer A ───────────────────────────────────────────────────
        clf = AlertClassifier(backend="auto", nnpu_prior=0.4,
                              calibration="isotonic",
                              recall_floor_score=0.78)
        meta = clf.fit(X, y, sample_weight=w, val_split=0.34)
        print(f"  → Layer A trained: {meta['validation']}")
        verdicts = clf.predict_many([e.features for e in examples])
        scores = [v.p_true_positive for v in verdicts]
        print(f"  → Layer A scores: min={min(scores):.3f}, max={max(scores):.3f}")
        # Round-trip
        a_path = Path(tmp) / "layer_a.joblib"
        clf.save(a_path)
        clf2 = AlertClassifier.load(a_path)
        v2 = clf2.predict_one(examples[0].features)
        print(f"  → Layer A round-trip score: {v2.p_true_positive:.3f}")

        # ── Layer C ───────────────────────────────────────────────────
        avar = AVAR(Path(tmp) / "avar.jsonl", max_size=1000)
        reward = RewardModel({"accept_true_positive": 1.0,
                              "accept_false_positive": -1.0,
                              "defer_correct": 0.5,
                              "defer_incorrect": -0.2,
                              "downgrade_true_positive": -1.0,
                              "downgrade_false_positive": 0.3,
                              "upgrade_true_positive": 0.7,
                              "upgrade_false_positive": -0.5,
                              "analyst_workload_penalty": -0.05})
        env = TriageEnvironment(examples, reward_model=reward, avar=avar)
        policy = TriagePolicy(feature_dim=32, backend="linucb", alpha=1.0,
                              accept_safety_threshold=0.85,
                              ambiguity_band=(0.45, 0.55), avar=avar)
        for _ in range(200):
            state = env.reset(shuffle=True)
            for _ in range(min(20, len(examples))):
                decision = policy.decide(state, classifier_confidence=float(state[0]))
                action_idx = {n: i for i, n in enumerate(env.actions())}.get(decision.action, 0)
                next_state, r, done, _ = env.step(action_idx)
                policy.update(state, action_idx, r, next_state)
                if done:
                    break
                state = next_state
        c_path = Path(tmp) / "policy.pkl"
        policy.save(c_path)
        TriagePolicy.load(c_path, avar=avar)
        print("  → Layer C policy trained + round-tripped")

        # ── Layer D (KG offline + mock LLM) ───────────────────────────
        kg = KnowledgeGraphRetriever(client=None)
        pipeline = MitigationPipeline(kg=kg, vector=None, cfg=cfg.layer_d)
        report = pipeline.recommend(
            alert=alerts[0],
            layer_a_verdict={"p_true_positive": 0.81, "decision": "true_positive"},
            layer_b_attribution={"chain_id": "Chain X",
                                 "techniques": [{"id": "T0812"}, {"id": "T0866"}],
                                 "tactics": [{"id": "lateral-movement"}]},
            layer_c_decision={"action": "accept"},
        )
        assert report.abstained, "Expected abstain when KG is offline"
        print(f"  → Layer D abstained correctly (no KG available)")

        # ── Orchestrator end-to-end ───────────────────────────────────
        # Override paths so the orchestrator uses our temp artefacts.
        cfg.raw["paths"]["labels_file"] = str(labels_path)
        cfg.raw["paths"]["layer_a_model"] = str(a_path)
        cfg.raw["paths"]["layer_c_policy"] = str(c_path)
        cfg.raw["paths"]["state_dir"] = str(Path(tmp) / "state")
        cfg.raw["layer_b"]["enabled"] = False
        orch = Orchestrator(
            cfg, classifier=clf, attributor=None,
            triage=policy, mitigation=pipeline, avar=avar,
            feature_builder=fb,
        )
        decisions = orch.process_batch(alerts, run_layer_d=False)
        print(f"  → Orchestrator processed {len(decisions)} alerts; "
              f"actions={[d.final_action for d in decisions]}")

        # ── Evaluation harness ────────────────────────────────────────
        from learning.eval.metrics import classification_metrics
        m = classification_metrics(
            [int(e.label == 1) for e in examples],
            [v.p_true_positive for v in verdicts],
        )
        print(f"  → Layer A eval: {m}")
        # Caldera loader test (if a real Caldera file is present).
        cal_dir = Path(__file__).resolve().parents[2] / "Caldera Reports"
        if cal_dir.exists():
            chains = CalderaLoader(cal_dir).load_all()
            print(f"  → CalderaLoader parsed {len(chains)} chain(s) "
                  f"({[c.name for c in chains]})")

    print("\n✓ Smoke test passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
