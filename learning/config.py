"""Unified configuration for the ``learning`` package.

The configuration lives in ``config/learning.yml`` and is loaded into a
:class:`LearningConfig` dataclass with safe defaults so partial files do
not crash the importers.  All path values are resolved relative to the
project root unless absolute.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _resolve(path: str | Path) -> Path:
    p = Path(path)
    if p.is_absolute():
        return p
    return (PROJECT_ROOT / p).resolve()


@dataclass
class LearningConfig:
    """Top-level config object exposing typed accessors for each layer."""

    raw: Dict[str, Any] = field(default_factory=dict)

    # ── Path helpers ────────────────────────────────────────────────────
    @property
    def paths(self) -> Dict[str, Path]:
        raw = self.raw.get("paths", {}) or {}
        return {k: _resolve(v) for k, v in raw.items() if isinstance(v, (str, Path))}

    def path(self, key: str, default: Optional[str] = None) -> Path:
        p = self.paths.get(key)
        if p is None:
            if default is None:
                raise KeyError(f"learning.yml: missing path '{key}'")
            return _resolve(default)
        return p

    # ── Sub-blocks ─────────────────────────────────────────────────────
    def block(self, name: str) -> Dict[str, Any]:
        return dict(self.raw.get(name, {}) or {})

    @property
    def labels(self) -> Dict[str, Any]:
        return self.block("labels")

    @property
    def layer_a(self) -> Dict[str, Any]:
        return self.block("layer_a")

    @property
    def layer_b(self) -> Dict[str, Any]:
        return self.block("layer_b")

    @property
    def layer_c(self) -> Dict[str, Any]:
        return self.block("layer_c")

    @property
    def layer_d(self) -> Dict[str, Any]:
        return self.block("layer_d")

    @property
    def api(self) -> Dict[str, Any]:
        return self.block("api")

    @property
    def evaluation(self) -> Dict[str, Any]:
        return self.block("evaluation")

    @property
    def es(self) -> Dict[str, Any]:
        return self.block("elasticsearch")

    # ── Layer toggles (centralised) ────────────────────────────────────
    def is_enabled(self, layer: str) -> bool:
        block = getattr(self, layer, {}) if hasattr(self, layer) else {}
        if isinstance(block, dict):
            return bool(block.get("enabled", True))
        return True

    def ensure_state_dirs(self) -> None:
        """Create state directories used by every layer."""
        for key in ("state_dir", "metrics_dir"):
            p = self.paths.get(key)
            if p is not None:
                p.mkdir(parents=True, exist_ok=True)
        for key in ("layer_a_model", "layer_b_model", "layer_c_policy", "layer_b_vocab", "labels_file"):
            p = self.paths.get(key)
            if p is not None and p.parent and not p.parent.exists():
                p.parent.mkdir(parents=True, exist_ok=True)


def default_config_path() -> Path:
    env = os.environ.get("LEARNING_CONFIG_PATH")
    if env:
        return Path(env)
    return PROJECT_ROOT / "config" / "learning.yml"


def load_config(path: Optional[Path] = None) -> LearningConfig:
    """Read ``learning.yml`` and return a :class:`LearningConfig`.

    Missing keys fall back to in-code defaults; missing files raise.
    """
    cfg_path = Path(path) if path else default_config_path()
    if not cfg_path.exists():
        raise FileNotFoundError(f"learning config not found: {cfg_path}")
    with cfg_path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    cfg = LearningConfig(raw=raw)
    cfg.ensure_state_dirs()
    return cfg
