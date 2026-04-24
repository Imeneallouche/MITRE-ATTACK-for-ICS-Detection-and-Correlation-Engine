#!/usr/bin/env python3
"""Train Layers A → B → C in a single command."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from learning.config import load_config  # noqa: E402
from learning.layer_a.train import train_layer_a  # noqa: E402
from learning.layer_c.train import train_layer_c  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--config", default=None)
    p.add_argument("--es-hosts", action="append", default=[])
    p.add_argument("--fixture", default=None)
    p.add_argument("--engine-config", default=None)
    p.add_argument("--skip-b", action="store_true",
                   help="Skip Layer B training (useful when torch is missing).")
    args = p.parse_args()

    cfg = load_config(Path(args.config) if args.config else None)
    fixture = Path(args.fixture) if args.fixture else None

    print("\n[1/3] Training Layer A …")
    train_layer_a(cfg, es_hosts=args.es_hosts or None, fixture_path=fixture)

    if not args.skip_b:
        print("\n[2/3] Training Layer B …")
        from learning.layer_b.train import train_layer_b
        train_layer_b(
            cfg, es_hosts=args.es_hosts or None, fixture_path=fixture,
            engine_config_path=Path(args.engine_config) if args.engine_config else None,
        )
    else:
        print("\n[2/3] Skipping Layer B (--skip-b).")

    print("\n[3/3] Training Layer C …")
    train_layer_c(cfg, es_hosts=args.es_hosts or None, fixture_path=fixture)
    print("\nAll layers trained.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
