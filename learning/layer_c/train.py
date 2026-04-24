"""Layer C training entry point (offline replay)."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from ..config import LearningConfig
from ..data import (
    AlertLoader, FeatureBuilder, LabelStore, LabelledDatasetBuilder,
)
from .avar import AVAR
from .reward_model import RewardModel
from .triage_env import TriageEnvironment
from .triage_policy import TriagePolicy

LOG = logging.getLogger("learning.layer_c.train")


def train_layer_c(
    cfg: LearningConfig,
    *,
    es_hosts: Optional[List[str]] = None,
    fixture_path: Optional[Path] = None,
) -> TriagePolicy:
    layer_c = cfg.layer_c
    if not layer_c.get("enabled", True):
        raise RuntimeError("Layer C disabled in config.")

    label_store = LabelStore(cfg.path("labels_file"))
    if not label_store.all():
        raise RuntimeError("No window labels available; cannot train Layer C.")

    fb = FeatureBuilder()
    builder = LabelledDatasetBuilder(label_store=label_store, feature_builder=fb)
    if fixture_path is not None:
        alerts = AlertLoader.load_jsonl(fixture_path)
        examples = builder.build_from_alerts(alerts)
    else:
        loader = AlertLoader(hosts=es_hosts, scroll_size=cfg.es.get("scroll_size", 1000))
        examples = builder.build_from_es(loader, cfg.es.get("alert_index_pattern", "ics-alerts-*"))
    if not examples:
        raise RuntimeError("No labelled examples for Layer C.")

    avar_cfg = layer_c.get("avar") or {}
    avar: Optional[AVAR] = None
    if avar_cfg.get("enabled", True):
        avar = AVAR(
            cfg.path("state_dir") / "avar.jsonl",
            max_size=int(avar_cfg.get("max_size", 10_000)),
            fingerprint_fields=avar_cfg.get("fingerprint_fields") or ("asset_id", "datacomponent", "log_message"),
        )

    reward = RewardModel(layer_c.get("reward") or {})
    env = TriageEnvironment(
        examples,
        reward_model=reward,
        feature_dim=int((layer_c.get("policy") or {}).get("feature_dim", 32)),
        avar=avar,
    )
    policy_cfg = layer_c.get("policy") or {}
    policy = TriagePolicy(
        feature_dim=int(policy_cfg.get("feature_dim", 32)),
        backend=policy_cfg.get("backend", "linucb"),
        alpha=float(policy_cfg.get("alpha", 1.0)),
        learning_rate=float(policy_cfg.get("learning_rate", 3e-4)),
        gamma=float(policy_cfg.get("gamma", 0.95)),
        accept_safety_threshold=float(layer_c.get("accept_safety_threshold", 0.85)),
        ambiguity_band=tuple(layer_c.get("ambiguity_band", (0.45, 0.55))),
        avar=avar,
    )

    iterations = int(policy_cfg.get("train_iterations", 2000))
    state = env.reset(shuffle=True)
    for step in range(iterations):
        action_name_to_idx = {n: i for i, n in enumerate(env.actions())}
        decision = policy.decide(state, classifier_confidence=float(state[0]))
        action_idx = action_name_to_idx.get(decision.action, 0)
        next_state, reward_val, done, _ = env.step(action_idx)
        policy.update(state, action_idx, reward_val, next_state)
        state = next_state if not done else env.reset(shuffle=True)
        if (step + 1) % 500 == 0:
            LOG.info("Layer C train step %d/%d", step + 1, iterations)

    policy.save(cfg.path("layer_c_policy"))
    return policy
