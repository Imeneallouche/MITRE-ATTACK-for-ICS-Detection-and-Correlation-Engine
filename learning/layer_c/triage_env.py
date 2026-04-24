"""Offline replay environment for Layer-C training.

We do **not** plug the policy into the live SCADA loop — it would create
a feedback shortcut that the model can exploit (per the safety analysis
in the architecture doc).  Instead we replay labelled alerts from the
training set and let the policy choose an action; the reward is
computed by :class:`RewardModel`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np

from ..data.dataset import LabelledExample
from .avar import AVAR
from .reward_model import ACTIONS, RewardModel, RewardSignals

LOG = logging.getLogger("learning.layer_c.env")


@dataclass
class EpisodeStep:
    state: np.ndarray
    action: int
    reward: float
    is_true_positive: bool
    classifier_confidence: float


class TriageEnvironment:
    """Sampling environment over labelled alert examples."""

    def __init__(
        self,
        examples: List[LabelledExample],
        *,
        reward_model: RewardModel,
        feature_dim: int = 32,
        avar: Optional[AVAR] = None,
        seed: int = 1234,
    ) -> None:
        self.examples = list(examples)
        if not self.examples:
            raise ValueError("TriageEnvironment: empty example list.")
        self.reward_model = reward_model
        self.feature_dim = int(feature_dim)
        self.avar = avar
        self.rng = np.random.default_rng(seed)
        self.n_actions = len(ACTIONS)
        self._cursor = 0

    @staticmethod
    def actions() -> Tuple[str, ...]:
        return ACTIONS

    # ── State construction ─────────────────────────────────────────────
    def _state(self, ex: LabelledExample) -> np.ndarray:
        """Concatenate engine signals + meta into a fixed-size state vector.

        Layout (max ``feature_dim``):

            [scalar engine features ... | classifier_confidence (placeholder)
             | analyst_seen | repeat_index]
        """
        s = np.zeros(self.feature_dim, dtype=np.float32)
        n = min(ex.features.scalar.shape[0], self.feature_dim - 4)
        s[:n] = ex.features.scalar[:n]
        s[-4] = float(min(len(ex.technique_list), 8))
        s[-3] = float(1 if ex.chain_id else 0)
        if self.avar:
            from .avar import AVAR as _AVAR
            fp = _AVAR.fingerprint(
                {
                    "asset_id": ex.features.asset_id,
                    "datacomponent": ex.features.datacomponent,
                    "log_message": ex.features.log_text,
                },
                self.avar.fingerprint_fields,
            )
            s[-2] = 1.0 if self.avar.get(fp) else 0.0
        s[-1] = float(min(int(ex.features.scalar[10]), 64))  # repeat_index
        return s

    def reset(self, shuffle: bool = True) -> np.ndarray:
        if shuffle:
            self.rng.shuffle(self.examples)
        self._cursor = 0
        return self._state(self.examples[0])

    def sample(self, batch_size: int = 64) -> List[Tuple[np.ndarray, LabelledExample]]:
        idx = self.rng.integers(0, len(self.examples), size=batch_size)
        return [(self._state(self.examples[int(i)]), self.examples[int(i)]) for i in idx]

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, EpisodeStep]:
        if self._cursor >= len(self.examples):
            self._cursor = 0
        ex = self.examples[self._cursor]
        state = self._state(ex)
        action_name = ACTIONS[max(0, min(int(action), self.n_actions - 1))]
        signals = RewardSignals(
            is_true_positive=(ex.label == 1),
            classifier_confidence=float(ex.features.scalar[0]),
            analyst_confidence=1.0,
            analyst_verdict="accept" if ex.label == 1 else "reject",
        )
        reward = self.reward_model.reward(action_name, signals)
        step = EpisodeStep(
            state=state, action=int(action), reward=float(reward),
            is_true_positive=signals.is_true_positive,
            classifier_confidence=signals.classifier_confidence,
        )
        self._cursor += 1
        done = self._cursor >= len(self.examples)
        next_state = state if done else self._state(self.examples[self._cursor])
        return next_state, float(reward), done, step
