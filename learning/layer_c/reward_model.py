"""Reward shaping for the Layer-C triage policy.

The reward combines (a) a *signed* confusion-matrix term — the policy is
rewarded for accepting true positives and rejecting false positives,
penalised for the inverse — with (b) an analyst workload term that
discourages always-defer policies, and (c) optional human feedback
weights pulled from the AVAR cache.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from .avar import AVAR

ACTIONS = ("accept", "defer_to_analyst", "downgrade", "upgrade")


@dataclass
class RewardSignals:
    is_true_positive: bool
    classifier_confidence: float
    analyst_confidence: float = 1.0
    analyst_verdict: Optional[str] = None


class RewardModel:
    def __init__(self, cfg: Mapping[str, Any]) -> None:
        self.cfg = dict(cfg or {})

    def get(self, key: str, default: float) -> float:
        return float(self.cfg.get(key, default))

    def reward(self, action: str, signals: RewardSignals) -> float:
        action = (action or "").lower()
        tp = bool(signals.is_true_positive)

        if action == "accept":
            base = self.get("accept_true_positive", 1.0) if tp else self.get("accept_false_positive", -1.5)
        elif action == "defer_to_analyst":
            base = self.get("defer_correct", 0.6) if signals.analyst_verdict in {"accept", "reject"} else self.get("defer_incorrect", -0.3)
            base += self.get("analyst_workload_penalty", -0.05)
        elif action == "downgrade":
            base = self.get("downgrade_true_positive", -1.0) if tp else self.get("downgrade_false_positive", 0.3)
        elif action == "upgrade":
            base = self.get("upgrade_true_positive", 0.7) if tp else self.get("upgrade_false_positive", -0.7)
        else:
            return 0.0

        # Scale by analyst confidence — high-confidence labels move the
        # reward more decisively than uncertain ones.
        return float(base) * float(max(0.1, signals.analyst_confidence))

    @classmethod
    def from_avar(cls, cfg: Mapping[str, Any], avar: Optional[AVAR]) -> "RewardModel":
        return cls(cfg)
