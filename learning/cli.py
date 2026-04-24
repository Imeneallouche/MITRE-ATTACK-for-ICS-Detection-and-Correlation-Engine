"""Command-line entry points for the learning package.

Examples
--------
::

    # Import a Caldera report into the label store.
    python -m learning.cli import-caldera --reports ./Caldera\\ Reports

    # Add a benign baseline window manually.
    python -m learning.cli add-label --start 2026-04-22T15:00:00Z \\
        --end 2026-04-22T15:30:00Z --label benign

    # Train each layer.
    python -m learning.cli train-layer-a --es-hosts http://localhost:9200
    python -m learning.cli train-layer-b --es-hosts http://localhost:9200
    python -m learning.cli train-layer-c --es-hosts http://localhost:9200

    # Score alerts in a JSONL file.
    python -m learning.cli score --fixture ./tmp/sample_alerts.jsonl

    # Run the FastAPI service.
    python -m learning.cli serve
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import load_config
from .data import (
    AlertLoader, CalderaLoader, FeatureBuilder, LabelStore,
)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s :: %(message)s",
    )


def _parse_dt(value: str) -> datetime:
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


# ── Commands ─────────────────────────────────────────────────────────
def cmd_import_caldera(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    label_store = LabelStore(cfg.path("labels_file"))
    reports_dir = Path(args.reports) if args.reports else cfg.path("caldera_reports_dir")
    chains = CalderaLoader(reports_dir).load_all()
    if not chains:
        print(f"No Caldera reports found under {reports_dir}", file=sys.stderr)
        return 1
    pad = int(args.pad_seconds)
    written = 0
    for chain in chains:
        wl = chain.to_window_label(
            defender_assets=args.defender_asset,
            pad_seconds=pad,
        )
        label_store.append(wl)
        written += 1
        print(f"  → wrote {wl.label} window for {wl.chain_id} "
              f"({wl.start.isoformat()} → {wl.end.isoformat()}, "
              f"{len(wl.technique_list)} techniques)")
    print(f"Imported {written} Caldera chain(s) into {cfg.path('labels_file')}")
    return 0


def cmd_add_label(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    store = LabelStore(cfg.path("labels_file"))
    wl = store.add_window(
        start=_parse_dt(args.start),
        end=_parse_dt(args.end),
        label=args.label,
        chain_id=args.chain_id,
        technique_list=args.technique or [],
        attacker_assets=args.attacker_asset or [],
        defender_assets=args.defender_asset or [],
        source=args.source,
        notes=args.notes or "",
    )
    print(json.dumps(wl.to_json(), indent=2))
    return 0


def cmd_list_labels(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    store = LabelStore(cfg.path("labels_file"))
    labels = store.all()
    print(json.dumps([wl.to_json() for wl in labels], indent=2))
    return 0


def cmd_train_layer_a(args: argparse.Namespace) -> int:
    from .layer_a.train import train_layer_a
    cfg = load_config(args.config)
    fixture = Path(args.fixture) if args.fixture else None
    train_layer_a(cfg, es_hosts=args.es_hosts or None, fixture_path=fixture)
    return 0


def cmd_train_layer_b(args: argparse.Namespace) -> int:
    from .layer_b.train import train_layer_b
    cfg = load_config(args.config)
    fixture = Path(args.fixture) if args.fixture else None
    engine_cfg = Path(args.engine_config) if args.engine_config else None
    train_layer_b(cfg, es_hosts=args.es_hosts or None,
                  fixture_path=fixture, engine_config_path=engine_cfg)
    return 0


def cmd_train_layer_c(args: argparse.Namespace) -> int:
    from .layer_c.train import train_layer_c
    cfg = load_config(args.config)
    fixture = Path(args.fixture) if args.fixture else None
    train_layer_c(cfg, es_hosts=args.es_hosts or None, fixture_path=fixture)
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    from .orchestrator import Orchestrator
    cfg_path = Path(args.config) if args.config else None
    orch = Orchestrator.from_config(cfg_path, es_hosts=args.es_hosts or None)
    if args.fixture:
        alerts = AlertLoader.load_jsonl(Path(args.fixture))
    else:
        decisions = orch.tick(run_layer_d=not args.no_layer_d)
        print(json.dumps([d.to_dict() for d in decisions], indent=2, default=str))
        return 0
    decisions = orch.process_batch(alerts, run_layer_d=not args.no_layer_d)
    print(json.dumps([d.to_dict() for d in decisions], indent=2, default=str))
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    from .eval.harness import EvalHarness
    cfg = load_config(args.config)
    out_dir = Path(args.out) if args.out else cfg.path("metrics_dir")
    fixture = Path(args.fixture) if args.fixture else None
    harness = EvalHarness(cfg)
    report = harness.run(fixture_path=fixture, output_dir=out_dir,
                         es_hosts=args.es_hosts or None)
    print(json.dumps(report, indent=2, default=str))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .api import serve
    serve(Path(args.config) if args.config else None,
          host=args.host, port=args.port, es_hosts=args.es_hosts or None)
    return 0


# ── Argument parsing ──────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="learning",
                                description="Learning-enhanced ICS detection toolkit.")
    p.add_argument("--config", type=str, default=None, help="Path to learning.yml")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("import-caldera", help="Import Caldera report(s) as window labels.")
    s.add_argument("--reports", type=str, default=None, help="Directory of *_report.json files.")
    s.add_argument("--pad-seconds", type=int, default=30)
    s.add_argument("--defender-asset", action="append", default=[])
    s.set_defaults(func=cmd_import_caldera)

    s = sub.add_parser("add-label", help="Add a single window label.")
    s.add_argument("--start", required=True)
    s.add_argument("--end", required=True)
    s.add_argument("--label", default="benign", choices=["benign", "under_attack"])
    s.add_argument("--chain-id", default=None)
    s.add_argument("--technique", action="append", default=[])
    s.add_argument("--attacker-asset", action="append", default=[])
    s.add_argument("--defender-asset", action="append", default=[])
    s.add_argument("--source", default="operator")
    s.add_argument("--notes", default="")
    s.set_defaults(func=cmd_add_label)

    s = sub.add_parser("list-labels", help="Dump all window labels as JSON.")
    s.set_defaults(func=cmd_list_labels)

    for layer in ("a", "b", "c"):
        s = sub.add_parser(f"train-layer-{layer}", help=f"Train Layer {layer.upper()}.")
        s.add_argument("--es-hosts", action="append", default=[])
        s.add_argument("--fixture", default=None,
                       help="JSONL fixture instead of pulling from ES.")
        if layer == "b":
            s.add_argument("--engine-config", default=None,
                           help="Path to detection.yml (used to derive technique→tactic map).")
        s.set_defaults(func={
            "a": cmd_train_layer_a,
            "b": cmd_train_layer_b,
            "c": cmd_train_layer_c,
        }[layer])

    s = sub.add_parser("score", help="Score alerts (fixture or via ES tick).")
    s.add_argument("--fixture", default=None, help="JSONL fixture of alerts.")
    s.add_argument("--es-hosts", action="append", default=[])
    s.add_argument("--no-layer-d", action="store_true")
    s.set_defaults(func=cmd_score)

    s = sub.add_parser("evaluate", help="Run the evaluation harness end-to-end.")
    s.add_argument("--fixture", default=None)
    s.add_argument("--out", default=None)
    s.add_argument("--es-hosts", action="append", default=[])
    s.set_defaults(func=cmd_evaluate)

    s = sub.add_parser("serve", help="Run the FastAPI service.")
    s.add_argument("--host", default=None)
    s.add_argument("--port", type=int, default=None)
    s.add_argument("--es-hosts", action="append", default=[])
    s.set_defaults(func=cmd_serve)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(getattr(args, "verbose", False))
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
