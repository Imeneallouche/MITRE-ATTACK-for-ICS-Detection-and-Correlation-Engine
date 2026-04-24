"""End-to-end orchestrator wiring layers A → B → C → D.

The orchestrator is the *only* place that knows about the engine's
runtime configuration, the Neo4j client, and the user's window labels.
Higher-level surfaces (the FastAPI server and the CLI) only talk to
:class:`Orchestrator`.
"""
from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

from .config import LearningConfig, load_config
from .data import (
    AlertFeatures,
    AlertLoader,
    FeatureBuilder,
    LabelStore,
)
from .layer_a import AlertClassifier, ClassifierVerdict
from .layer_c import AVAR, RewardModel, TriageDecision, TriagePolicy
from .layer_d import (
    KnowledgeGraphRetriever, MitigationPipeline, MitigationReport, VectorRetriever,
)

LOG = logging.getLogger("learning.orchestrator")

# Layer B is optional; importing it triggers torch which we may not have.
try:
    from .layer_b import ChainAttributor, ChainPrediction
    _HAS_LAYER_B = True
except Exception:  # pragma: no cover
    ChainAttributor = None  # type: ignore
    ChainPrediction = None  # type: ignore
    _HAS_LAYER_B = False


@dataclass
class OrchestratedDecision:
    alert_id: str
    timestamp: datetime
    asset_id: str
    datacomponent: str
    layer_a: Dict[str, Any] = field(default_factory=dict)
    layer_b: Dict[str, Any] = field(default_factory=dict)
    layer_c: Dict[str, Any] = field(default_factory=dict)
    layer_d: Optional[Dict[str, Any]] = None
    final_action: str = "accept"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
            "asset_id": self.asset_id,
            "datacomponent": self.datacomponent,
            "layer_a": self.layer_a,
            "layer_b": self.layer_b,
            "layer_c": self.layer_c,
            "layer_d": self.layer_d,
            "final_action": self.final_action,
        }


class Orchestrator:
    """Top-level facade exposing :meth:`process_alert`, :meth:`process_batch`
    and :meth:`tick` (Elasticsearch polling)."""

    def __init__(
        self,
        cfg: LearningConfig,
        *,
        classifier: Optional[AlertClassifier] = None,
        attributor: Optional["ChainAttributor"] = None,
        triage: Optional[TriagePolicy] = None,
        mitigation: Optional[MitigationPipeline] = None,
        avar: Optional[AVAR] = None,
        feature_builder: Optional[FeatureBuilder] = None,
        alert_loader: Optional[AlertLoader] = None,
        last_seen_ts: Optional[datetime] = None,
    ) -> None:
        self.cfg = cfg
        self.classifier = classifier
        self.attributor = attributor
        self.triage = triage
        self.mitigation = mitigation
        self.avar = avar
        self.feature_builder = feature_builder or FeatureBuilder()
        self.alert_loader = alert_loader
        self.last_seen_ts = last_seen_ts

        # Per-asset rolling window for Layer B sequence assembly.
        self._asset_window_seconds = float((cfg.layer_b or {}).get("window_seconds", 600))
        self._max_seq_len = int((cfg.layer_b or {}).get("max_seq_len", 64))
        self._asset_buffers: Dict[str, Deque[AlertFeatures]] = defaultdict(
            lambda: deque(maxlen=self._max_seq_len)
        )

        self._action_to_idx = {"accept": 0, "defer_to_analyst": 1, "downgrade": 2, "upgrade": 3}

    # ── Construction helpers ───────────────────────────────────────────
    @classmethod
    def from_config(
        cls,
        cfg_path: Optional[Path] = None,
        *,
        es_hosts: Optional[List[str]] = None,
        engine_neo4j_client: Optional[Any] = None,
        load_models: bool = True,
    ) -> "Orchestrator":
        cfg = load_config(cfg_path)
        # Load persisted artefacts where available.
        classifier = None
        if load_models and cfg.is_enabled("layer_a"):
            try:
                classifier = AlertClassifier.load(cfg.path("layer_a_model"))
            except Exception as exc:
                LOG.warning("Layer A model not loaded: %s", exc)

        attributor = None
        if load_models and cfg.is_enabled("layer_b") and _HAS_LAYER_B:
            try:
                attributor = ChainAttributor.load(
                    cfg.path("layer_b_model"),
                    cfg.path("layer_b_vocab"),
                    device=(cfg.layer_b or {}).get("device", "auto"),
                )
            except Exception as exc:
                LOG.warning("Layer B model not loaded: %s", exc)

        avar_cfg = (cfg.layer_c or {}).get("avar") or {}
        avar = None
        if avar_cfg.get("enabled", True):
            avar = AVAR(
                cfg.path("state_dir") / "avar.jsonl",
                max_size=int(avar_cfg.get("max_size", 10_000)),
                fingerprint_fields=avar_cfg.get("fingerprint_fields") or ("asset_id", "datacomponent", "log_message"),
            )

        triage = None
        if load_models and cfg.is_enabled("layer_c"):
            try:
                triage = TriagePolicy.load(cfg.path("layer_c_policy"), avar=avar)
            except Exception as exc:
                LOG.warning("Layer C policy not loaded; using fresh LinUCB: %s", exc)
                policy_cfg = (cfg.layer_c or {}).get("policy") or {}
                triage = TriagePolicy(
                    feature_dim=int(policy_cfg.get("feature_dim", 32)),
                    backend=policy_cfg.get("backend", "linucb"),
                    alpha=float(policy_cfg.get("alpha", 1.0)),
                    accept_safety_threshold=float((cfg.layer_c or {}).get("accept_safety_threshold", 0.85)),
                    ambiguity_band=tuple((cfg.layer_c or {}).get("ambiguity_band", (0.45, 0.55))),
                    avar=avar,
                )

        mitigation = None
        if cfg.is_enabled("layer_d"):
            kg = KnowledgeGraphRetriever(
                client=engine_neo4j_client,
                **{k: v for k, v in ((cfg.layer_d or {}).get("retrieval") or {}).items()
                   if k in {"max_techniques", "max_mitigations_per_technique",
                            "include_groups", "include_software", "include_assets",
                            "tactic_top_k"}},
            )
            mitigation = MitigationPipeline(kg=kg, vector=None, cfg=cfg.layer_d)

        loader = None
        if es_hosts:
            loader = AlertLoader(hosts=es_hosts, scroll_size=cfg.es.get("scroll_size", 1000))

        return cls(cfg, classifier=classifier, attributor=attributor,
                   triage=triage, mitigation=mitigation, avar=avar,
                   alert_loader=loader)

    # ── Per-alert processing ───────────────────────────────────────────
    def process_alert(
        self,
        alert: Dict[str, Any],
        *,
        run_layer_d: bool = True,
    ) -> OrchestratedDecision:
        feat = self.feature_builder.build(alert)
        decision = OrchestratedDecision(
            alert_id=feat.alert_id,
            timestamp=feat.timestamp,
            asset_id=feat.asset_id,
            datacomponent=feat.datacomponent,
        )

        # ── Layer A ───────────────────────────────────────────────────
        verdict_a: ClassifierVerdict
        if self.classifier is not None:
            verdict_a = self.classifier.predict_one(feat)
        else:
            verdict_a = ClassifierVerdict(
                p_true_positive=float(feat.scalar[0]),
                raw_score=float(feat.scalar[0]),
                decision="uncertain",
                used_safety_rail=True,
            )
        decision.layer_a = verdict_a.to_dict()

        # ── Layer B ───────────────────────────────────────────────────
        layer_b_out: Dict[str, Any] = {"available": False}
        if self.attributor is not None:
            buf = self._asset_buffers[feat.asset_id]
            buf.append(feat)
            self._evict_old(buf, feat.timestamp)
            try:
                pred: ChainPrediction = self.attributor.predict(list(buf))
                layer_b_out = {"available": True, **pred.to_dict()}
            except Exception as exc:  # pragma: no cover
                LOG.warning("Layer B inference failed: %s", exc)
                layer_b_out = {"available": False, "error": str(exc)}
        decision.layer_b = layer_b_out

        # ── Layer C ───────────────────────────────────────────────────
        if self.triage is not None:
            state = self._build_state(feat, verdict_a)
            triage_dec = self.triage.decide(
                state,
                classifier_confidence=float(verdict_a.p_true_positive),
                alert=alert,
            )
        else:
            triage_dec = TriageDecision(
                action="accept", confidence=float(verdict_a.p_true_positive),
                rationale="no triage policy loaded",
                used_safety_rail=True,
            )
        decision.layer_c = triage_dec.to_dict()
        decision.final_action = triage_dec.action

        # ── Layer D ───────────────────────────────────────────────────
        if run_layer_d and self.mitigation is not None and triage_dec.action != "downgrade":
            try:
                report: MitigationReport = self.mitigation.recommend(
                    alert=alert,
                    layer_a_verdict=verdict_a.to_dict(),
                    layer_b_attribution=layer_b_out,
                    layer_c_decision=triage_dec.to_dict(),
                )
                decision.layer_d = report.to_dict()
            except Exception as exc:  # pragma: no cover
                LOG.warning("Layer D pipeline failed: %s", exc)
                decision.layer_d = {"error": str(exc)}
        return decision

    # ── Batch processing ───────────────────────────────────────────────
    def process_batch(
        self,
        alerts: Sequence[Dict[str, Any]],
        *,
        run_layer_d: bool = True,
    ) -> List[OrchestratedDecision]:
        # Sort by timestamp so per-asset windows accumulate in causal order.
        ordered = sorted(
            alerts,
            key=lambda a: AlertLoader.alert_timestamp(a) or datetime.now(timezone.utc),
        )
        return [self.process_alert(a, run_layer_d=run_layer_d) for a in ordered]

    # ── ES polling tick (used by the API server's background task) ────
    def tick(self, *, run_layer_d: bool = True) -> List[OrchestratedDecision]:
        if self.alert_loader is None:
            LOG.debug("Orchestrator.tick: no AlertLoader configured.")
            return []
        idx = self.cfg.es.get("alert_index_pattern", "ics-alerts-*")
        since = self.last_seen_ts
        alerts = self.alert_loader.fetch_alerts(
            idx, since=since,
            max_results=int(self.cfg.api.get("alerts_per_cycle", 200)),
        )
        if not alerts:
            return []
        decisions = self.process_batch(alerts, run_layer_d=run_layer_d)
        # Advance watermark to the latest alert seen.
        last_ts = max(
            (AlertLoader.alert_timestamp(a) or datetime.min.replace(tzinfo=timezone.utc)
             for a in alerts),
            default=datetime.now(timezone.utc),
        )
        self.last_seen_ts = last_ts
        return decisions

    # ── Analyst feedback ───────────────────────────────────────────────
    def submit_feedback(
        self,
        alert: Dict[str, Any],
        verdict: str,
        *,
        confidence: float = 1.0,
        note: str = "",
    ) -> Dict[str, Any]:
        if self.avar is None:
            raise RuntimeError("AVAR is disabled; cannot record analyst feedback.")
        v = self.avar.add_from_alert(alert, verdict, confidence=confidence, note=note)
        # Also update Layer-C policy weights so future similar alerts converge.
        if self.triage is not None and self.classifier is not None:
            feat = self.feature_builder.build(alert)
            verdict_a = self.classifier.predict_one(feat)
            state = self._build_state(feat, verdict_a)
            action_idx = self._action_to_idx.get(verdict, 0)
            reward = 1.0 if verdict in {"accept", "upgrade"} else -1.0
            self.triage.update(state, action_idx, reward)
        return v.to_json()

    # ── Internals ──────────────────────────────────────────────────────
    def _evict_old(self, buf: Deque[AlertFeatures], now: datetime) -> None:
        cutoff = now.timestamp() - self._asset_window_seconds
        while buf and buf[0].timestamp.timestamp() < cutoff:
            buf.popleft()

    def _build_state(self, feat: AlertFeatures, verdict: ClassifierVerdict):
        feature_dim = int(((self.cfg.layer_c or {}).get("policy") or {}).get("feature_dim", 32))
        from numpy import zeros, concatenate
        s = zeros(feature_dim, dtype="float32")
        n = min(feat.scalar.shape[0], feature_dim - 4)
        s[:n] = feat.scalar[:n]
        s[-4] = float(verdict.p_true_positive)
        s[-3] = float(verdict.raw_score)
        s[-2] = 1.0 if verdict.used_safety_rail else 0.0
        s[-1] = 1.0 if verdict.decision == "true_positive" else 0.0
        return s
