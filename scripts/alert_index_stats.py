#!/usr/bin/env python3
"""Offline helper: connect to Elasticsearch and summarize ``ics-alerts-*`` documents.

Reads hosts from ``config/detection.yml`` (or ``ELASTICSEARCH_HOSTS`` if set).
Run from the repository root::

    python scripts/alert_index_stats.py
    python scripts/alert_index_stats.py --sample 15 --index 'ics-alerts-*'
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from engine.config import load_config  # noqa: E402
from engine.es_client import ESClient  # noqa: E402


def _agg_safe(
    es: Any,
    index: str,
    body: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    try:
        return es.search(index=index, body=body)
    except Exception as exc:
        print(f"Aggregation query failed (index may differ from template): {exc}", file=sys.stderr)
        return None


def _print_terms(label: str, buckets: List[Dict[str, Any]]) -> None:
    print(f"\n{label}")
    if not buckets:
        print("  (none)")
        return
    for b in buckets:
        key = b.get("key")
        if key == "":
            key = "(empty)"
        print(f"  {key!s}: {b.get('doc_count', 0)}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sample and aggregate ICS alert documents in Elasticsearch.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=_REPO_ROOT / "config" / "detection.yml",
        help="Path to detection.yml (default: config/detection.yml under repo root).",
    )
    parser.add_argument(
        "--index",
        default=None,
        help="Index pattern (default: elasticsearch.alert_index_pattern from config).",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=8,
        help="Number of recent alert documents to print (default: 8).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text tables.",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    index = args.index or cfg.es_alert_index_pattern
    hosts = cfg.es_hosts
    timeout = int(cfg.raw.get("elasticsearch", {}).get("timeout_seconds", 30))

    es = ESClient(hosts=hosts, timeout_seconds=timeout).client

    count_body: Dict[str, Any] = {"query": {"match_all": {}}}
    try:
        count_res = es.count(index=index, body=count_body)
    except Exception as exc:
        print(f"Failed to reach Elasticsearch at {hosts!r}: {exc}", file=sys.stderr)
        return 1

    total = int(count_res.get("count", 0))
    out: Dict[str, Any] = {
        "index_pattern": index,
        "hosts": hosts,
        "document_count": total,
    }

    if total == 0:
        print(f"Index pattern {index!r}: 0 documents.")
        if args.json:
            print(json.dumps(out, indent=2))
        return 0

    agg_body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"match_all": {}},
        "aggs": {
            "by_datacomponent_id": {
                "terms": {"field": "datacomponent_id", "size": 30, "missing": "N/A"},
            },
            "by_observed_log_source": {
                "terms": {"field": "observed_log_source", "size": 25, "missing": "N/A"},
            },
            "by_confidence": {
                "terms": {"field": "confidence_tier", "size": 10, "missing": "N/A"},
            },
            "score": {"stats": {"field": "similarity_score"}},
            "min_ts": {"min": {"field": "timestamp"}},
            "max_ts": {"max": {"field": "timestamp"}},
        },
    }

    agg_res = _agg_safe(es, index, agg_body)
    if agg_res and "aggregations" in agg_res:
        aggs = agg_res["aggregations"]
        out["aggregations"] = aggs
        tmin = aggs.get("min_ts") or {}
        tmax = aggs.get("max_ts") or {}
        if tmin.get("value") is not None:
            out["timestamp_min"] = tmin.get("value_as_string") or tmin.get("value")
        if tmax.get("value") is not None:
            out["timestamp_max"] = tmax.get("value_as_string") or tmax.get("value")
        ss = aggs.get("score", {})
        if ss.get("count", 0):
            out["similarity_score"] = {
                "count": ss.get("count"),
                "min": ss.get("min"),
                "max": ss.get("max"),
                "avg": ss.get("avg"),
            }

    sample_body = {
        "size": max(1, min(args.sample, 500)),
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": [
            "timestamp",
            "datacomponent_id",
            "datacomponent",
            "similarity_score",
            "confidence_tier",
            "observed_log_source",
            "log_message",
            "triggering_log",
            "gate_reason",
            "evidence_snippet",
            "detection_metadata",
            "similarity_evidence",
        ],
        "query": {"match_all": {}},
    }
    try:
        sample_res = es.search(index=index, body=sample_body)
    except Exception as exc:
        print(f"Sample query failed: {exc}", file=sys.stderr)
        return 1

    hits = sample_res.get("hits", {}).get("hits", [])
    samples: List[Dict[str, Any]] = []
    short_message = 0
    for h in hits:
        src = h.get("_source") or {}
        lm = str(src.get("triggering_log") or src.get("log_message") or "").strip()
        if len(lm) < 8:
            short_message += 1
        samples.append(
            {
                "_index": h.get("_index"),
                "_id": h.get("_id"),
                "timestamp": src.get("timestamp"),
                "datacomponent_id": src.get("datacomponent_id"),
                "datacomponent": src.get("datacomponent"),
                "similarity_score": src.get("similarity_score"),
                "observed_log_source": src.get("observed_log_source"),
                "triggering_log_preview": lm[:240] + ("…" if len(lm) > 240 else ""),
                "gate_reason": src.get("gate_reason"),
            }
        )
    out["sample_documents"] = samples
    out["sample_short_message_count"] = short_message
    out["sample_size"] = len(samples)

    if args.json:
        print(json.dumps(out, indent=2, default=str))
        return 0

    print(f"Elasticsearch hosts: {hosts}")
    print(f"Index pattern: {index}")
    print(f"Document count: {total}")
    if out.get("timestamp_min"):
        print(f"Timestamp range: {out['timestamp_min']} .. {out['timestamp_max']}")
    sc = out.get("similarity_score")
    if sc:
        print(
            "similarity_score: "
            f"min={sc.get('min'):.4f} max={sc.get('max'):.4f} avg={sc.get('avg'):.4f} (n={sc.get('count')})",
        )

    if agg_res and "aggregations" in agg_res:
        aggs = agg_res["aggregations"]
        _print_terms(
            "Top datacomponent_id",
            aggs.get("by_datacomponent_id", {}).get("buckets", []),
        )
        _print_terms(
            "Top observed_log_source",
            aggs.get("by_observed_log_source", {}).get("buckets", []),
        )
        _print_terms(
            "confidence_tier",
            aggs.get("by_confidence", {}).get("buckets", []),
        )

    print(
        f"\nRecent sample ({len(samples)} docs, "
        f"{short_message} with triggering/log message < 8 chars):",
    )
    for i, s in enumerate(samples, 1):
        print(f"\n--- [{i}] {s.get('_index')} / {s.get('_id')}")
        print(f"    time: {s.get('timestamp')}")
        print(f"    DC: {s.get('datacomponent_id')} ({s.get('datacomponent')})")
        print(f"    score: {s.get('similarity_score')}  source: {s.get('observed_log_source')}")
        print(f"    gate: {s.get('gate_reason')}")
        print(f"    log: {s.get('triggering_log_preview')!r}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
