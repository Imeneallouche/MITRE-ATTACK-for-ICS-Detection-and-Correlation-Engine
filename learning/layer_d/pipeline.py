"""End-to-end Layer-D pipeline: retrieval → planner → generator → analyst → reflector."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .agents import (
    AgentTrace, AnalystAgent, GeneratorAgent, LLMClient, MockLLMClient,
    PlannerAgent, ReflectorAgent, make_client,
)
from .kg_retriever import KnowledgeGraphRetriever, RetrievedContext
from .vector_retriever import VectorRetriever

LOG = logging.getLogger("learning.layer_d.pipeline")


@dataclass
class MitigationReport:
    alert_id: str
    timestamp: datetime
    abstained: bool
    abstain_reason: str = ""
    plan: Dict[str, Any] = field(default_factory=dict)
    proposals: Dict[str, Any] = field(default_factory=dict)
    analyst: Dict[str, Any] = field(default_factory=dict)
    reflection: Dict[str, Any] = field(default_factory=dict)
    retrieved: Dict[str, Any] = field(default_factory=dict)
    traces: List[AgentTrace] = field(default_factory=list)
    requires_human_approval: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
            "abstained": self.abstained,
            "abstain_reason": self.abstain_reason,
            "plan": self.plan,
            "proposals": self.proposals,
            "analyst": self.analyst,
            "reflection": self.reflection,
            "retrieved": self.retrieved,
            "traces": [
                {"name": t.name, "prompt_chars": t.prompt_chars,
                 "response_chars": t.response_chars}
                for t in self.traces
            ],
            "requires_human_approval": self.requires_human_approval,
        }


class MitigationPipeline:
    """Full Layer-D pipeline (RAG + 4-agent loop) with safety rails."""

    def __init__(
        self,
        *,
        kg: KnowledgeGraphRetriever,
        vector: Optional[VectorRetriever] = None,
        llm: Optional[LLMClient] = None,
        cfg: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.kg = kg
        self.vector = vector
        self.cfg = dict(cfg or {})
        self.llm = llm or make_client(self.cfg.get("llm") or {})
        self.safety = self.cfg.get("safety") or {}
        self.retrieval_cfg = self.cfg.get("retrieval") or {}
        llm_cfg = self.cfg.get("llm") or {}
        temp = float(llm_cfg.get("temperature", 0.2))
        max_tok = int(llm_cfg.get("max_tokens", 1500))
        self.planner = PlannerAgent(self.llm, temperature=temp, max_tokens=max_tok)
        self.generator = GeneratorAgent(self.llm, temperature=temp, max_tokens=max_tok)
        self.analyst = AnalystAgent(self.llm, temperature=temp, max_tokens=max_tok)
        self.reflector = ReflectorAgent(self.llm, temperature=temp, max_tokens=max_tok)

    # ── Public API ─────────────────────────────────────────────────────
    def recommend(
        self,
        *,
        alert: Dict[str, Any],
        layer_a_verdict: Dict[str, Any],
        layer_b_attribution: Dict[str, Any],
        layer_c_decision: Dict[str, Any],
    ) -> MitigationReport:
        ts = datetime.now(timezone.utc)
        report = MitigationReport(
            alert_id=str(alert.get("alert_id") or alert.get("_id") or ""),
            timestamp=ts,
            abstained=False,
            requires_human_approval=bool(self.safety.get("require_human_approval", True)),
        )

        # ── 1. Retrieval ──────────────────────────────────────────────
        ctx = self._retrieve(alert=alert, layer_b_attribution=layer_b_attribution)
        report.retrieved = ctx.to_dict()

        if ctx.is_empty():
            report.abstained = bool(self.safety.get("abstain_on_empty_retrieval", True))
            report.abstain_reason = "No KG context retrieved for the alert."
            if report.abstained:
                LOG.info("Layer D abstaining for alert %s (empty retrieval).", report.alert_id)
                return report

        # ── 2. Planner ────────────────────────────────────────────────
        plan_trace = self.planner.run(
            alert=alert, layer_a_verdict=layer_a_verdict,
            layer_b_attribution=layer_b_attribution,
            layer_c_decision=layer_c_decision,
        )
        report.traces.append(plan_trace)
        report.plan = plan_trace.parsed

        # ── 3. Optional dense passages ────────────────────────────────
        passages: List[Dict[str, Any]] = []
        if self.vector is not None and self.vector and len(self.vector) > 0:
            try:
                passages = self.vector.query(
                    " ".join([t.get("name", "") for t in ctx.techniques]) or alert.get("log_message", ""),
                    top_k=int(self.retrieval_cfg.get("semantic_top_k", 6)),
                )
            except Exception as exc:  # pragma: no cover
                LOG.warning("Vector retrieval failed: %s", exc)

        # ── 4. Generator ──────────────────────────────────────────────
        gen_trace = self.generator.run(plan=plan_trace.parsed,
                                        retrieved_kg=ctx.to_dict(),
                                        retrieved_passages=passages)
        report.traces.append(gen_trace)
        report.proposals = gen_trace.parsed

        if gen_trace.parsed.get("abstain"):
            report.abstained = True
            report.abstain_reason = str(gen_trace.parsed.get("abstain_reason") or "Generator abstained.")
            return report

        # ── 5. Analyst critique ───────────────────────────────────────
        analyst_trace = self.analyst.run(proposals=gen_trace.parsed, alert=alert)
        report.traces.append(analyst_trace)
        report.analyst = analyst_trace.parsed

        # ── 6. Reflector / final report ───────────────────────────────
        reflect_trace = self.reflector.run(
            analyst_verdicts=analyst_trace.parsed,
            proposals=gen_trace.parsed,
            plan=plan_trace.parsed,
        )
        report.traces.append(reflect_trace)
        report.reflection = reflect_trace.parsed

        if bool(reflect_trace.parsed.get("request_human_override", False)):
            report.requires_human_approval = True

        return report

    # ── Retrieval orchestration ────────────────────────────────────────
    def _retrieve(
        self,
        *,
        alert: Dict[str, Any],
        layer_b_attribution: Dict[str, Any],
    ) -> RetrievedContext:
        dc = str(alert.get("datacomponent") or alert.get("data_component") or "").upper()
        techs = layer_b_attribution.get("techniques") or []
        tech_ids = [t["id"] if isinstance(t, dict) else str(t) for t in techs if t]
        tactics = [
            t["id"] if isinstance(t, dict) else str(t)
            for t in (layer_b_attribution.get("tactics") or [])
            if t
        ]
        if dc and (self.cfg.get("hierarchy") or {}).get("enabled", True):
            return self.kg.retrieve_hierarchical(
                dc_id=dc, predicted_tactics=tactics, predicted_techniques=tech_ids,
            )
        if tech_ids:
            return self.kg.retrieve_for_techniques(tech_ids, dc_id=dc or None)
        if dc:
            return self.kg.retrieve_for_dc(dc)
        return RetrievedContext()
