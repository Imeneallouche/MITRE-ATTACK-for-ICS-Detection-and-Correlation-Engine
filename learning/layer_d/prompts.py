"""Prompt templates for the multi-agent mitigation pipeline.

Every template is a plain ``str.format``-friendly string so it composes
with both the OpenAI/Ollama LLM backends and the deterministic mock
backend used in tests.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List


PLANNER_PROMPT = """\
You are a senior ICS/SCADA incident-response planner.  An ICS detection
engine just produced an alert.  Your job is to decompose the response
into 3–6 sequential investigation steps, each with a goal and the
specific data sources to consult.  Do NOT invent IPs, IDs, or
mitigations.

Return strict JSON in this format (no prose):
{{
  "incident_summary": "...",
  "investigation_plan": [
     {{"step": 1, "goal": "...", "data_sources": ["...", "..."]}}
  ],
  "open_questions": ["..."]
}}

Alert:
{alert_summary}

Layer-A verdict:
{layer_a_verdict}

Layer-B chain attribution:
{layer_b_attribution}

Layer-C triage decision:
{layer_c_decision}
"""


GENERATOR_PROMPT = """\
You are an ICS mitigation generator.  Use ONLY the knowledge below — do
NOT introduce mitigations, controls, or vendors that are not present in
the retrieved context.  If the retrieved context is empty, return an
empty list and an explicit "abstain" reason.

Return strict JSON:
{{
  "recommended_mitigations": [
     {{
       "mitigation_id": "MXXXX",
       "title": "...",
       "applies_to_techniques": ["TXXXX", ...],
       "rationale": "...",
       "implementation_steps": ["...", "..."],
       "rollback_plan": "...",
       "approval_required": true,
       "side_effects_on_process": ["..."],
       "evidence_paths": ["DC...", ...]
     }}
  ],
  "abstain": false,
  "abstain_reason": ""
}}

Investigation plan:
{plan}

Retrieved knowledge graph context:
{retrieved_kg}

Retrieved supporting passages:
{retrieved_passages}
"""


ANALYST_PROMPT = """\
You are a defensive ICS analyst reviewing the proposed mitigations.
Stress-test every recommendation against:

1. Process-safety side effects (e.g., emergency shutdowns, valve closures).
2. Operational continuity (does it interrupt a production cycle?).
3. False-positive risk: is the underlying alert actually a true positive?

For each recommendation in the input, return:
{{
  "mitigation_id": "MXXXX",
  "verdict": "approve" | "approve_with_conditions" | "reject",
  "conditions": ["..."],
  "risk_score": 0.0-1.0,
  "reasoning": "..."
}}

If the verdict for ALL mitigations is "reject", set ``request_human``
to true at the top level.

Input proposals:
{proposals}

Alert summary:
{alert_summary}
"""


REFLECTOR_PROMPT = """\
You are a reflection agent.  Compose a final report combining the
analyst's verdicts with operational context.  Output two narratives:

* ``technical_report``: ~200 words, includes specific KG paths.
* ``executive_summary``: ~80 words, no jargon, business impact framing.

Return strict JSON:
{{
  "technical_report": "...",
  "executive_summary": "...",
  "approved_mitigation_ids": ["MXXXX", ...],
  "blocked_mitigation_ids": ["MXXXX", ...],
  "request_human_override": true | false
}}

Analyst verdicts:
{analyst_verdicts}

Generator proposals:
{proposals}

Investigation plan:
{plan}
"""


def build_alert_summary(alert: Dict[str, Any]) -> str:
    return json.dumps({
        "asset_id": alert.get("asset_id"),
        "datacomponent": alert.get("datacomponent") or alert.get("data_component"),
        "log_message": (alert.get("log_message") or "")[:500],
        "techniques": alert.get("technique_ids") or alert.get("techniques") or [],
        "first_seen": alert.get("first_seen"),
        "last_seen": alert.get("last_seen"),
        "similarity_score": alert.get("similarity_score"),
    }, indent=2, default=str)
