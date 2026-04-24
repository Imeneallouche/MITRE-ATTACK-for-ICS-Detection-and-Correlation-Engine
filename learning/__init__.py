"""Learning-enhanced ICS detection package.

This package layers four cooperating learning components on top of the
deterministic detection engine, following the architecture proposed in
``docs/Learning-Enhanced ICS Detection and Mitigation Recommendation.md``:

* **Layer A** — per-alert PU classifier (true-/false-positive scoring).
* **Layer B** — causal-window Transformer attack-chain attributor.
* **Layer C** — DRLHF / contextual-bandit alert-triage policy.
* **Layer D** — Neo4j-grounded multi-agent LLM mitigation pipeline.

Each layer is independently usable and degrades gracefully when its
heavy dependencies (``torch``, ``xgboost``, ``openai``, ``neo4j``) are
not installed.  The :class:`learning.orchestrator.Orchestrator` wires
the four layers together and is exposed via ``learning.api`` (FastAPI)
and ``learning.cli`` (command-line entry points).
"""
from __future__ import annotations

from .config import LearningConfig, load_config

__all__ = ["LearningConfig", "load_config"]
