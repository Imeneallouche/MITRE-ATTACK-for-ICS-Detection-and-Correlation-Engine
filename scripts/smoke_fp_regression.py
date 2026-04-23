"""Offline smoke test: verify all observed false-positive events no longer alert.

Reproduces the baseline events that were generating alerts after
``reset_stack.sh``:

  FP-1: ``DC0082`` on the idle HMI -> PLC Modbus TCP flow
        (Logstash tagged ``mitre_keyword_hits.DC0082: ["5156", "suricata"]``)
  FP-2: ``DC0109`` on the severity-0 bootstrap process alarm
        (Logstash parsed ``parsed_process_alarm.severity = 0``)
  FP-3: ``DC0038`` on HMI/ScadaLTS/Tomcat boot-time "Cache views initialized"
        log (vendor tokens ``tomcat`` / ``scadalts`` were credited via field
        values like ``log.file.path`` rather than the message body).

The script runs the *real* matcher against the DataComponent catalog and
prints, for each event, whether any candidate exceeds the alert threshold.
With the body-only anchoring + numeric-field-floor fixes in place, all three
events must yield zero alerts.  Use ``--embeddings`` to exercise the semantic
path with the production BAAI/bge-small-en-v1.5 model (identical to runtime).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Tuple

# Allow ``python scripts/smoke_fp_regression.py`` from project root.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.config import load_config
from engine.correlation import CorrelationConfig, CorrelationEngine
from engine.dc_loader import load_datacomponents
from engine.embeddings import EmbeddingEngine
from engine.feature_extractor import EventNormalizer, NormalizationRules
from engine.matcher import DataComponentMatcher


def _fp1_hit() -> dict:
    """Baseline HMI -> PLC Modbus flow that wrongly triggered DC0082 alerts."""
    return {
        "_id": "FP1-flow",
        "_index": "ics-suricata-2026.04.22",
        "_source": {
            "@timestamp": "2026-04-22T16:36:40.000Z",
            "log_type": "suricata",
            "log_source_normalized": "NSM:Flow",
            "message": "suricata flow TCP modbus 192.168.90.107 -> 192.168.95.2:502",
            "log_message": "suricata flow TCP modbus 192.168.90.107 -> 192.168.95.2:502",
            "asset_id": "router",
            "asset_name": "ICS Router/Firewall",
            "asset_ip": "192.168.95.200",
            "asset_zone": "perimeter",
            "src_ip": "192.168.90.107",
            "dest_ip": "192.168.95.2",
            "src_port": 59946,
            "dest_port": 502,
            "proto": "TCP",
            "app_proto": "modbus",
            "event_type": "flow",
            "flow": {
                "bytes_toserver": 416,
                "bytes_toclient": 307,
                "pkts_toserver": 6,
                "pkts_toclient": 4,
            },
            # Exact enrichment seen in the captured FP alert (see FP JSON).
            "mitre_dc_candidates": [
                "DC0002", "DC0021", "DC0059", "DC0078",
                "DC0082", "DC0085", "DC0102",
            ],
            "mitre_keyword_hits": {
                "DC0082": ["5156", "suricata"],
                "DC0085": ["suricata"],
                "DC0078": ["suricata"],
                "DC0107": ["etw"],
                "DC0108": ["41"],
            },
            # ID-like field whose stringified digits contain ``5156`` as a
            # bounded token -- this is what fooled the old anchor check.
            "flow_id": 51568742000013,
        },
    }


def _fp2_hit() -> dict:
    """``severity: 0`` bootstrap process alarm that wrongly triggered DC0109."""
    body = (
        '{"ts":1776875227,"alarm":"PROCESS_STATE","severity":0,'
        '"pressure_kpa":2700.00,"unit":"kPa","subsystem":"TE","phase":"bootstrap"}'
    )
    return {
        "_id": "FP2-alarm",
        "_index": "ics-process-2026.04.22",
        "_source": {
            "@timestamp": "2026-04-22T16:28:08.000Z",
            "log_type": "process_alarm",
            "log_source_normalized": "ics:process_alarm",
            "message": body,
            "log_message": body,
            "asset_id": "simulation",
            "asset_name": "ICS Simulation",
            "asset_ip": "192.168.95.10",
            "parsed_process_alarm": {
                "ts": 1776875227,
                "alarm": "PROCESS_STATE",
                "severity": 0,
                "pressure_kpa": 2700.00,
                "unit": "kPa",
                "subsystem": "TE",
                "phase": "bootstrap",
            },
            "Severity": "0",
            "CurrentValue": "2700.00",
            "TagName": "PROCESS_STATE",
            "ics.alarm_severity": "0",
            "ics.pressure_kpa": "2700.00",
            "ics.alarm_name": "PROCESS_STATE",
            "mitre_dc_candidates": ["DC0109", "DC0108", "DC0038"],
            "mitre_keyword_hits": {
                "DC0109": [
                    "pressure", "kpa", "reactor",
                    "PROCESS_STATE", "REACTOR_PRESSURE",
                ],
            },
        },
    }


def _fp3_hit() -> dict:
    """HMI ScadaLTS/Tomcat bootstrap line that wrongly triggered DC0038.

    The original alert was driven by keyword hits ``["tomcat", "scadalts"]``
    whose tokens live only in routing / service-name fields — not in the log
    body.  Body-only anchoring must suppress this.
    """
    body = (
        "INFO  2026-04-22T18:00:30,673 "
        "(com.serotonin.mango.MangoContextListener.initialized:181) "
        "- Cache views initialized"
    )
    return {
        "_id": "FP3-scadalts-cache",
        "_index": "ics-hmi-2026.04.22",
        "_source": {
            "@timestamp": "2026-04-22T18:00:30.000Z",
            "log_type": "hmi_supervisor",
            "log_source_normalized": "hmi:supervisor",
            "message": body,
            "log_message": body,
            "asset_id": "hmi",
            "asset_name": "HMI ScadaLTS",
            "asset_ip": "192.168.90.107",
            "asset_zone": "dmz-net",
            # Routing / telemetry fields that used to leak vendor tokens into
            # the keyword anchor.  With body-only anchoring these are ignored.
            "log.file.path": "/shared_logs/hmi/supervisor/tomcat.log",
            "service.name": "tomcat",
            "program": "scadalts",
            "container.name": "hmi_scadalts",
            "host.name": "hmi-scadalts",
            "mitre_dc_candidates": ["DC0038", "DC0067", "DC0060", "DC0032"],
            # Exactly what the Logstash tagger used to emit for this event.
            "mitre_keyword_hits": {
                "DC0038": ["tomcat", "scadalts"],
            },
        },
    }


def _tp_scada_login_hit() -> dict:
    """Chain 10 P2-4: SCADA-LTS default-credential login success via j_spring."""
    body = (
        "192.168.90.6 - admin [22/Apr/2026:16:38:00] "
        "\"POST /j_spring_security_check HTTP/1.1\" 200 "
        "login=success session=JSESSIONID"
    )
    return {
        "_id": "TP-scada-login",
        "_index": "ics-hmi-2026.04.22",
        "_source": {
            "@timestamp": "2026-04-22T16:38:00.000Z",
            "log_type": "hmi_catalina",
            "log_source_normalized": "hmi:catalina",
            "message": body,
            "log_message": body,
            "asset_id": "hmi",
            "asset_name": "HMI ScadaLTS",
            "asset_ip": "192.168.90.107",
            "src_ip": "192.168.90.6",
            "dest_ip": "192.168.90.107",
            "event.category": "authentication",
            "event.type": "start",
            "mitre_dc_candidates": ["DC0067", "DC0038"],
            "mitre_keyword_hits": {
                "DC0067": ["login", "session", "admin"],
            },
        },
    }


def _tp_modbus_attack_flow_hit() -> dict:
    """Chain 10 P3-3: Kali -> PLC modbus write during attack (distinct from baseline)."""
    body = "suricata flow TCP modbus 192.168.90.6 -> 192.168.95.2:502 write_register attack"
    return {
        "_id": "TP-modbus-attack",
        "_index": "ics-suricata-2026.04.22",
        "_source": {
            "@timestamp": "2026-04-22T16:39:00.000Z",
            "log_type": "suricata",
            "log_source_normalized": "NSM:Flow",
            "message": body,
            "log_message": body,
            "asset_id": "router",
            "asset_name": "ICS Router/Firewall",
            "asset_ip": "192.168.95.200",
            "src_ip": "192.168.90.6",
            "dest_ip": "192.168.95.2",
            "src_port": 53210,
            "dest_port": 502,
            "proto": "TCP",
            "app_proto": "modbus",
            "event_type": "flow",
            "flow": {
                "bytes_toserver": 2048,
                "bytes_toclient": 1024,
                "pkts_toserver": 28,
                "pkts_toclient": 22,
            },
            "mitre_dc_candidates": ["DC0078", "DC0082"],
            "mitre_keyword_hits": {
                "DC0082": ["modbus", "flow"],
                "DC0078": ["modbus", "flow"],
            },
        },
    }


def _tp_plc_start_hit() -> dict:
    """Chain 10 P2-7: PLC ``start`` action — must still alert (TP regression guard)."""
    body = (
        "192.168.90.6 - - [22/Apr/2026:16:40:00] \"GET /start_plc HTTP/1.1\" 200 "
        "Starting PLC program on openplc via /start_plc"
    )
    return {
        "_id": "TP-plc-start",
        "_index": "ics-plc-2026.04.22",
        "_source": {
            "@timestamp": "2026-04-22T16:40:00.000Z",
            "log_type": "plc_app",
            "log_source_normalized": "ics:plc_app",
            "message": body,
            "log_message": body,
            "asset_id": "plc",
            "asset_name": "OpenPLC",
            "asset_ip": "192.168.95.2",
            "src_ip": "192.168.90.6",
            "dest_ip": "192.168.95.2",
            "event.category": "process",
            "event.type": "state",
            "mitre_dc_candidates": ["DC0032", "DC0038"],
            "mitre_keyword_hits": {
                "DC0032": ["start", "start_plc"],
                "DC0038": ["openplc", "flask"],
            },
        },
    }


def _tp_process_alarm_hit() -> dict:
    """Chain-1 style high-severity pressure excursion — must still alert."""
    body = (
        '{"ts":1776875900,"alarm":"REACTOR_PRESSURE","severity":2,'
        '"pressure_kpa":2810.00,"unit":"kPa","subsystem":"TE","phase":"run"}'
    )
    return {
        "_id": "TP-alarm",
        "_index": "ics-process-2026.04.22",
        "_source": {
            "@timestamp": "2026-04-22T16:41:00.000Z",
            "log_type": "process_alarm",
            "log_source_normalized": "ics:process_alarm",
            "message": body,
            "log_message": body,
            "asset_id": "simulation",
            "asset_name": "ICS Simulation",
            "asset_ip": "192.168.95.10",
            "parsed_process_alarm": {
                "ts": 1776875900,
                "alarm": "REACTOR_PRESSURE",
                "severity": 2,
                "pressure_kpa": 2810.00,
                "unit": "kPa",
                "subsystem": "TE",
                "phase": "run",
            },
            "Severity": "2",
            "CurrentValue": "2810.00",
            "TagName": "REACTOR_PRESSURE",
            "mitre_dc_candidates": ["DC0109", "DC0108"],
            "mitre_keyword_hits": {
                "DC0109": ["pressure", "kpa", "REACTOR_PRESSURE", "PROCESS_STATE"],
            },
        },
    }


def run(with_embeddings: bool) -> int:
    cfg = load_config(Path(ROOT) / "config" / "detection.yml")
    profiles = load_datacomponents(cfg.datacomponents_dir)

    normalizer = EventNormalizer(rules=NormalizationRules.from_config(cfg.normalization))

    embedding_engine = None
    if with_embeddings:
        embedding_engine = EmbeddingEngine(
            model_name=cfg.embedding_model,
            device=cfg.embedding_device,
            enabled=True,
            encode_batch_size=cfg.embedding_encode_batch_size,
        )
        dc_texts = {p.id: p.embedding_text for p in profiles if p.embedding_text}
        embedding_engine.precompute_dc_embeddings(dc_texts)
        embedding_engine.precompute_log_source_line_embeddings(profiles)

    matcher = DataComponentMatcher(
        profiles=profiles,
        scoring_weights=cfg.scoring_weights,
        candidate_threshold=cfg.candidate_threshold,
        high_confidence_threshold=cfg.high_confidence_threshold,
        embedding_engine=embedding_engine,
        semantic_gate_threshold=cfg.semantic_gate_threshold,
        log_source_families=cfg.log_source_families,
        evidence_policy=cfg.scoring_policy,
    )

    threshold = cfg.alert_threshold
    raw = cfg.raw or {}
    thresholds_raw = raw.get("thresholds") or {}
    try:
        correlation_entry_threshold = float(
            thresholds_raw.get("correlation_entry_threshold", threshold),
        )
    except (TypeError, ValueError):
        correlation_entry_threshold = threshold
    correlation_entry_threshold = min(correlation_entry_threshold, threshold)

    def build_correlation() -> CorrelationEngine:
        corr_cfg = CorrelationConfig.build(
            window_seconds=int(cfg.correlation["window_seconds"]),
            repeat_count_escalation=int(cfg.correlation["repeat_count_escalation"]),
            per_event_correlation_boost=float(cfg.correlation["per_event_correlation_boost"]),
            max_correlation_boost=float(cfg.correlation["max_correlation_boost"]),
            chain_step_boost=float(cfg.correlation["chain_step_boost"]),
            decay_half_life_seconds=float(cfg.correlation.get("decay_half_life_seconds", 120.0)),
            chain_rules=cfg.correlation_chain_rules,
            network_datacomponents=cfg.correlation_network_datacomponents,
            accumulator=str(cfg.correlation.get("accumulator", "linear")),
            require_strong_match=bool(cfg.correlation.get("require_strong_match", False)),
        )
        return CorrelationEngine(cfg=corr_cfg)

    def evaluate(hit: dict) -> Tuple[str, float, list, str, Optional[object]]:
        """Return (dc_label, top_score, matched_keywords, reason, match_or_None)."""
        event = normalizer.normalize(hit)
        passes_body = matcher.passes_substantive_message_policy(event)
        passes_floor = matcher.passes_numeric_field_floor_policy(event)
        if not (passes_body and passes_floor):
            reason = (
                "substantive_msg=False" if not passes_body
                else "numeric_floor=False"
            )
            return "(filtered)", 0.0, [], reason, None
        matches = matcher.match_event(event)
        if not matches:
            return "(no candidate)", 0.0, [], "scored", None
        top = matches[0]
        return (
            f"{top.datacomponent_id} ({top.datacomponent_name})",
            float(top.similarity_score),
            list(top.evidence.get("matched_keywords", [])),
            "scored",
            top,
        )

    single_cases = [
        ("FP-1 Modbus baseline flow (should NOT alert)", _fp1_hit(), False),
        ("FP-2 severity:0 bootstrap alarm (should NOT alert)", _fp2_hit(), False),
        ("FP-3 ScadaLTS/Tomcat cache-init log (should NOT alert)", _fp3_hit(), False),
        ("TP severity:2 reactor pressure alarm (should alert)", _tp_process_alarm_hit(), True),
    ]

    print(f"alert_threshold = {threshold}")
    print(f"correlation_entry_threshold = {correlation_entry_threshold}")
    print(f"weak_evidence_cap = {cfg.scoring_policy.get('weak_evidence_cap')}")
    print(f"keyword_min_hits_for_full_credit = {cfg.scoring_policy.get('keyword_min_hits_for_full_credit')}")
    print("-" * 78)

    failures = 0

    # --- Scenario A: single-event FP/TP (no correlation context) ---
    for label, hit, expect_alert in single_cases:
        top_dc, top_score, matched_kw, reason, _ = evaluate(hit)
        would_alert = top_score >= threshold
        ok = would_alert == expect_alert
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print(
            f"[{status}] {label}\n"
            f"    top_match: {top_dc}  score={top_score:.4f}  "
            f"expected_alert={expect_alert} would_alert={would_alert}  "
            f"gate={reason}  kw={matched_kw}"
        )

    # --- Scenario B: Chain-10 multi-DC burst on the same attack surface ---
    # Each individual step may land below ``alert_threshold`` but the
    # correlation engine must lift *at least one* of them over the bar.
    print("-" * 78)
    print("[Scenario B] Chain-10 burst (should alert via correlation boost)")
    chain_hits = [
        ("scada_login", _tp_scada_login_hit()),
        ("modbus_attack", _tp_modbus_attack_flow_hit()),
        ("plc_start", _tp_plc_start_hit()),
    ]
    burst_corr = build_correlation()
    burst_alerts = 0
    burst_trace: list = []
    for step_name, hit in chain_hits:
        _, indiv_score, _, _, match = evaluate(hit)
        if match is None:
            burst_trace.append((step_name, indiv_score, 0.0, "skipped"))
            continue
        if indiv_score < correlation_entry_threshold:
            burst_trace.append((step_name, indiv_score, 0.0, "below_entry"))
            continue
        group, _boosts = burst_corr.process(match)
        agg = float(group.aggregate_score)
        would_alert = indiv_score >= threshold or agg >= threshold
        burst_trace.append((step_name, indiv_score, agg, "alert" if would_alert else "below_agg"))
        if would_alert:
            burst_alerts += 1
    ok = burst_alerts >= 1
    if not ok:
        failures += 1
    print(f"  {'PASS' if ok else 'FAIL'}  alerts_after_correlation={burst_alerts}")
    for step_name, s, a, st in burst_trace:
        print(f"      step={step_name:<14s}  indiv={s:.4f}  aggregate={a:.4f}  -> {st}")

    # --- Scenario C: same-DC repeat storm (idle DC0078 flows) ---
    # Diversity-driven accumulator must keep this below ``alert_threshold``
    # regardless of how many copies arrive.
    print("-" * 78)
    print("[Scenario C] DC0078 same-DC repeat storm (should NOT alert)")
    storm_corr = build_correlation()
    storm_alerts = 0
    for i in range(8):
        hit = _fp1_hit()
        # Make each event unique but structurally identical (same DC match).
        hit = {**hit, "_id": f"FP1-storm-{i}"}
        hit["_source"] = {
            **hit["_source"],
            "@timestamp": f"2026-04-22T16:50:{i:02d}.000Z",
        }
        _, indiv_score, _, _, match = evaluate(hit)
        if match is None or indiv_score < correlation_entry_threshold:
            continue
        group, _boosts = storm_corr.process(match)
        agg = float(group.aggregate_score)
        if indiv_score >= threshold or agg >= threshold:
            storm_alerts += 1
    ok = storm_alerts == 0
    if not ok:
        failures += 1
    print(f"  {'PASS' if ok else 'FAIL'}  alerts_after_8_repeats={storm_alerts}")

    print("-" * 78)
    print("FAILURES:", failures)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--embeddings", action="store_true",
        help="Exercise the semantic path with the production embedding model.",
    )
    args = parser.parse_args()
    return run(with_embeddings=args.embeddings)


if __name__ == "__main__":
    raise SystemExit(main())
