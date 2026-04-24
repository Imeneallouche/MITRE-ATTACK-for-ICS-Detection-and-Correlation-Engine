"""Triage policy with multiple backends.

* ``linucb`` — contextual-bandit baseline (no torch needed; Li et al. 2010).
* ``dqn`` — Deep Q-Network (Mnih 2015), torch only.

The policy is wrapped with safety rails:

1. Always accept above ``accept_safety_threshold`` (Layer-A confidence).
2. Always defer inside the ambiguity band.
3. AVAR cache hits short-circuit with the analyst's recorded verdict.

These rails are *not* learned — they are deterministic guarantees so the
model can never silently downgrade a high-confidence engine alert.
"""
from __future__ import annotations

import json
import logging
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from ..data.feature_builder import AlertFeatures
from .avar import AVAR
from .reward_model import ACTIONS

LOG = logging.getLogger("learning.layer_c.policy")

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
except Exception:  # pragma: no cover
    torch = None  # type: ignore
    nn = None  # type: ignore


@dataclass
class TriageDecision:
    action: str
    confidence: float
    rationale: str
    used_safety_rail: bool = False
    avar_hit: bool = False
    q_values: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "confidence": float(self.confidence),
            "rationale": self.rationale,
            "used_safety_rail": bool(self.used_safety_rail),
            "avar_hit": bool(self.avar_hit),
            "q_values": [float(q) for q in self.q_values],
        }


# ── LinUCB backend ───────────────────────────────────────────────────
class _LinUCB:
    """Standard disjoint LinUCB (one model per action)."""

    def __init__(self, n_actions: int, feature_dim: int, alpha: float = 1.0) -> None:
        self.n_actions = int(n_actions)
        self.d = int(feature_dim)
        self.alpha = float(alpha)
        self.A = [np.eye(self.d, dtype=np.float64) for _ in range(self.n_actions)]
        self.b = [np.zeros(self.d, dtype=np.float64) for _ in range(self.n_actions)]

    def select(self, x: np.ndarray) -> Tuple[int, np.ndarray]:
        x = x.astype(np.float64)
        scores = np.zeros(self.n_actions, dtype=np.float64)
        for a in range(self.n_actions):
            A_inv = np.linalg.inv(self.A[a])
            theta = A_inv @ self.b[a]
            mean = float(theta @ x)
            ucb = self.alpha * float(np.sqrt(max(x @ A_inv @ x, 0.0)))
            scores[a] = mean + ucb
        return int(np.argmax(scores)), scores

    def update(self, x: np.ndarray, action: int, reward: float) -> None:
        x = x.astype(np.float64)
        self.A[action] += np.outer(x, x)
        self.b[action] += float(reward) * x

    def state(self) -> Dict[str, Any]:
        return {"A": [a.tolist() for a in self.A], "b": [b.tolist() for b in self.b],
                "alpha": self.alpha, "n_actions": self.n_actions, "d": self.d}

    @classmethod
    def from_state(cls, st: Dict[str, Any]) -> "_LinUCB":
        inst = cls(int(st["n_actions"]), int(st["d"]), float(st.get("alpha", 1.0)))
        inst.A = [np.asarray(a, dtype=np.float64) for a in st["A"]]
        inst.b = [np.asarray(b, dtype=np.float64) for b in st["b"]]
        return inst


# ── Deep Q backend ───────────────────────────────────────────────────
class _DQN(nn.Module if nn is not None else object):  # type: ignore[misc]
    def __init__(self, feature_dim: int, n_actions: int) -> None:
        if torch is None:
            raise RuntimeError("DQN backend requires PyTorch.")
        super().__init__()
        self.body = nn.Sequential(
            nn.Linear(feature_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 128),
            nn.ReLU(),
        )
        self.head = nn.Linear(128, n_actions)

    def forward(self, x: "torch.Tensor") -> "torch.Tensor":
        return self.head(self.body(x))


# ── Public policy ────────────────────────────────────────────────────
class TriagePolicy:
    """Triage policy with safety rails."""

    def __init__(
        self,
        *,
        feature_dim: int = 32,
        backend: str = "linucb",
        alpha: float = 1.0,
        learning_rate: float = 3e-4,
        gamma: float = 0.95,
        accept_safety_threshold: float = 0.85,
        ambiguity_band: Tuple[float, float] = (0.45, 0.55),
        avar: Optional[AVAR] = None,
    ) -> None:
        self.feature_dim = int(feature_dim)
        self.backend = (backend or "linucb").lower()
        self.alpha = float(alpha)
        self.learning_rate = float(learning_rate)
        self.gamma = float(gamma)
        self.accept_safety_threshold = float(accept_safety_threshold)
        self.ambiguity_band = (float(ambiguity_band[0]), float(ambiguity_band[1]))
        self.avar = avar
        self.n_actions = len(ACTIONS)
        self._linucb: Optional[_LinUCB] = None
        self._dqn: Optional[_DQN] = None
        self._dqn_optim = None
        self._init_backend()

    def _init_backend(self) -> None:
        if self.backend in {"linucb", "auto"} and (self.backend == "linucb" or torch is None):
            self._linucb = _LinUCB(self.n_actions, self.feature_dim, alpha=self.alpha)
            self.backend = "linucb"
            return
        if self.backend in {"dqn", "ppo"}:
            if torch is None:
                LOG.warning("Torch not available; falling back to LinUCB.")
                self._linucb = _LinUCB(self.n_actions, self.feature_dim, alpha=self.alpha)
                self.backend = "linucb"
                return
            self._dqn = _DQN(self.feature_dim, self.n_actions)
            self._dqn_optim = torch.optim.Adam(self._dqn.parameters(), lr=self.learning_rate)

    # ── Inference ──────────────────────────────────────────────────────
    def decide(
        self,
        state: np.ndarray,
        *,
        classifier_confidence: float,
        alert: Optional[Dict[str, Any]] = None,
    ) -> TriageDecision:
        # Safety rail 1: AVAR cache hit (highest priority).
        if self.avar is not None and alert is not None:
            fp = AVAR.fingerprint(alert, self.avar.fingerprint_fields)
            cached = self.avar.get(fp)
            if cached is not None:
                return TriageDecision(
                    action=cached.verdict,
                    confidence=float(cached.confidence),
                    rationale=f"AVAR cache hit ({cached.note or 'analyst-confirmed'})",
                    used_safety_rail=True,
                    avar_hit=True,
                )

        # Safety rail 2: high confidence -> always accept.
        if classifier_confidence >= self.accept_safety_threshold:
            return TriageDecision(
                action="accept",
                confidence=float(classifier_confidence),
                rationale=f"classifier confidence {classifier_confidence:.2f} >= safety threshold",
                used_safety_rail=True,
            )

        # Safety rail 3: ambiguity band -> always defer.
        lo, hi = self.ambiguity_band
        if lo <= classifier_confidence <= hi:
            return TriageDecision(
                action="defer_to_analyst",
                confidence=float(classifier_confidence),
                rationale=f"classifier confidence {classifier_confidence:.2f} in ambiguity band",
                used_safety_rail=True,
            )

        # Otherwise: ask the policy.
        x = np.asarray(state, dtype=np.float32).reshape(-1)[: self.feature_dim]
        if x.shape[0] < self.feature_dim:
            pad = np.zeros(self.feature_dim - x.shape[0], dtype=np.float32)
            x = np.concatenate([x, pad])

        if self.backend == "linucb" and self._linucb is not None:
            action, scores = self._linucb.select(x)
            q_values = scores.tolist()
        elif self.backend in {"dqn", "ppo"} and self._dqn is not None:
            with torch.no_grad():
                q = self._dqn(torch.from_numpy(x).unsqueeze(0))
                q_values = q.squeeze(0).cpu().numpy().tolist()
                action = int(np.argmax(q_values))
        else:  # pragma: no cover - shouldn't happen
            return TriageDecision("accept", float(classifier_confidence),
                                  "no policy backend available", used_safety_rail=True)

        action_name = ACTIONS[action]
        return TriageDecision(
            action=action_name,
            confidence=float(np.clip(classifier_confidence, 0.0, 1.0)),
            rationale=f"{self.backend} policy",
            q_values=list(q_values),
        )

    # ── Training ───────────────────────────────────────────────────────
    def update(self, state: np.ndarray, action: int, reward: float,
               next_state: Optional[np.ndarray] = None) -> None:
        x = np.asarray(state, dtype=np.float32).reshape(-1)[: self.feature_dim]
        if x.shape[0] < self.feature_dim:
            x = np.concatenate([x, np.zeros(self.feature_dim - x.shape[0], dtype=np.float32)])
        if self.backend == "linucb" and self._linucb is not None:
            self._linucb.update(x, action, reward)
            return
        if self._dqn is not None and torch is not None:
            x_t = torch.from_numpy(x).unsqueeze(0)
            q = self._dqn(x_t)
            q_a = q[0, action]
            target = torch.tensor(float(reward), dtype=q.dtype)
            if next_state is not None:
                with torch.no_grad():
                    next_x = np.asarray(next_state, dtype=np.float32).reshape(-1)[: self.feature_dim]
                    if next_x.shape[0] < self.feature_dim:
                        next_x = np.concatenate([next_x, np.zeros(self.feature_dim - next_x.shape[0], dtype=np.float32)])
                    nq = self._dqn(torch.from_numpy(next_x).unsqueeze(0))
                    target = target + self.gamma * nq.max()
            loss = F.mse_loss(q_a, target)
            self._dqn_optim.zero_grad()
            loss.backward()
            self._dqn_optim.step()

    # ── Persistence ────────────────────────────────────────────────────
    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: Dict[str, Any] = {
            "backend": self.backend,
            "feature_dim": self.feature_dim,
            "accept_safety_threshold": self.accept_safety_threshold,
            "ambiguity_band": list(self.ambiguity_band),
        }
        if self._linucb is not None:
            payload["linucb_state"] = self._linucb.state()
        if self._dqn is not None and torch is not None:
            buf = self._dqn.state_dict()
            payload["dqn_state"] = {k: v.cpu().numpy().tolist() for k, v in buf.items()}
        with path.open("wb") as fh:
            pickle.dump(payload, fh)

    @classmethod
    def load(cls, path: Path, *, avar: Optional[AVAR] = None) -> "TriagePolicy":
        with Path(path).open("rb") as fh:
            payload = pickle.load(fh)
        inst = cls(
            feature_dim=int(payload.get("feature_dim", 32)),
            backend=payload.get("backend", "linucb"),
            accept_safety_threshold=payload.get("accept_safety_threshold", 0.85),
            ambiguity_band=tuple(payload.get("ambiguity_band", (0.45, 0.55))),
            avar=avar,
        )
        if "linucb_state" in payload:
            inst._linucb = _LinUCB.from_state(payload["linucb_state"])
        if "dqn_state" in payload and torch is not None and inst._dqn is not None:
            sd = {k: torch.tensor(v) for k, v in payload["dqn_state"].items()}
            inst._dqn.load_state_dict(sd)
            inst._dqn.eval()
        return inst
