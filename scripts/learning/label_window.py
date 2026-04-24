#!/usr/bin/env python3
"""Convenience wrapper around `python -m learning.cli add-label`."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from learning.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(["add-label", *sys.argv[1:]]))
