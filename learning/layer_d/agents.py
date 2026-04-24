"""LLM client + four cooperating agents.

The architecture is intentionally vendor-agnostic:

* ``backend = "openai"``  — official OpenAI SDK (or compatible).
* ``backend = "ollama"``  — local Ollama HTTP server.
* ``backend = "mock"``    — deterministic templated output, used for
                            unit tests and offline runs.

Each agent receives the *raw* JSON-string response from the LLM and is
responsible for tolerantly parsing it (we never trust the LLM to return
strict JSON; we extract the first balanced object/array).
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from .prompts import (
    ANALYST_PROMPT,
    GENERATOR_PROMPT,
    PLANNER_PROMPT,
    REFLECTOR_PROMPT,
    build_alert_summary,
)

LOG = logging.getLogger("learning.layer_d.agents")


# ── LLM clients ────────────────────────────────────────────────────────
class LLMClient:
    """Unified, minimal LLM interface."""

    def chat(self, prompt: str, *, system: Optional[str] = None,
             temperature: float = 0.2, max_tokens: int = 1500) -> str:
        raise NotImplementedError


class OpenAIClient(LLMClient):
    def __init__(
        self,
        *,
        model: str = "gpt-4o-mini",
        api_key_env: str = "OPENAI_API_KEY",
        api_base_env: str = "OPENAI_BASE_URL",
        timeout_seconds: int = 60,
    ) -> None:
        try:
            from openai import OpenAI  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("openai package not installed") from exc
        api_key = os.environ.get(api_key_env)
        if not api_key:
            raise RuntimeError(f"OpenAI client requires env var {api_key_env}")
        kwargs: Dict[str, Any] = {"api_key": api_key, "timeout": timeout_seconds}
        base = os.environ.get(api_base_env)
        if base:
            kwargs["base_url"] = base
        self._client = OpenAI(**kwargs)
        self.model = model

    def chat(self, prompt: str, *, system: Optional[str] = None,
             temperature: float = 0.2, max_tokens: int = 1500) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = self._client.chat.completions.create(
            model=self.model, messages=messages,
            temperature=temperature, max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""


class OllamaClient(LLMClient):
    def __init__(self, *, model: str = "llama3", host: str = "http://localhost:11434",
                 timeout_seconds: int = 60) -> None:
        try:
            import requests  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise RuntimeError("requests package not installed") from exc
        self._requests = requests
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = int(timeout_seconds)

    def chat(self, prompt: str, *, system: Optional[str] = None,
             temperature: float = 0.2, max_tokens: int = 1500) -> str:
        body = {
            "model": self.model, "prompt": prompt, "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if system:
            body["system"] = system
        resp = self._requests.post(f"{self.host}/api/generate", json=body, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json().get("response", "")


class MockLLMClient(LLMClient):
    """Deterministic templated client for tests / no-network runs."""

    def chat(self, prompt: str, *, system: Optional[str] = None,
             temperature: float = 0.2, max_tokens: int = 1500) -> str:
        if "mitigation generator" in prompt.lower():
            mits = re.findall(r"\"id\"\s*:\s*\"(M\d{4})\"", prompt)
            techs = re.findall(r"(T\d{4})", prompt)
            mit_objs = [
                {
                    "mitigation_id": m, "title": f"KG-grounded mitigation {m}",
                    "applies_to_techniques": list(dict.fromkeys(techs))[:3],
                    "rationale": "Selected because it is linked in the KG to the predicted technique(s).",
                    "implementation_steps": [
                        "Document scope and affected assets.",
                        "Schedule maintenance window.",
                        "Apply control with rollback plan.",
                    ],
                    "rollback_plan": "Restore previous configuration via versioned change.",
                    "approval_required": True,
                    "side_effects_on_process": [],
                    "evidence_paths": ["DataComponent->Analytic->DetectionStrategy->Technique"],
                } for m in mits[:5]
            ]
            return json.dumps({
                "recommended_mitigations": mit_objs,
                "abstain": not mit_objs,
                "abstain_reason": "" if mit_objs else "No mitigations retrieved from KG.",
            })
        if "incident-response planner" in prompt.lower():
            return json.dumps({
                "incident_summary": "Possible ICS attack chain progression detected.",
                "investigation_plan": [
                    {"step": 1, "goal": "Confirm alert", "data_sources": ["ics-alerts-*"]},
                    {"step": 2, "goal": "Map asset role", "data_sources": ["assets.yml"]},
                    {"step": 3, "goal": "Pull surrounding events", "data_sources": ["ics-*"]},
                ],
                "open_questions": ["Was this expected operator activity?"]
            })
        if "defensive ics analyst" in prompt.lower():
            try:
                proposals = json.loads(re.search(r"Input proposals:\s*(\{.*?\})\s*Alert summary", prompt, re.S).group(1))
            except Exception:
                proposals = {"recommended_mitigations": []}
            verdicts = []
            for m in proposals.get("recommended_mitigations", []):
                verdicts.append({
                    "mitigation_id": m["mitigation_id"], "verdict": "approve_with_conditions",
                    "conditions": ["Notify control room", "Stage in test environment first"],
                    "risk_score": 0.25,
                    "reasoning": "Aligned with KG path; staged deployment recommended.",
                })
            return json.dumps({"verdicts": verdicts, "request_human": False})
        if "reflection agent" in prompt.lower():
            return json.dumps({
                "technical_report": "Layer-A flagged the alert as a true positive; Layer-B attributed techniques consistent with the operator playbook; Layer-D retrieved KG-grounded mitigations and recommended a staged deployment with rollback.",
                "executive_summary": "Detected likely ICS attack progression. Recommended controls are KG-grounded and require operator approval before deployment.",
                "approved_mitigation_ids": [],
                "blocked_mitigation_ids": [],
                "request_human_override": True,
            })
        return "{}"


def make_client(cfg: Mapping[str, Any]) -> LLMClient:
    backend = (cfg.get("backend") or "auto").lower()
    if backend == "openai":
        return OpenAIClient(
            model=cfg.get("model", "gpt-4o-mini"),
            api_key_env=cfg.get("api_key_env", "OPENAI_API_KEY"),
            api_base_env=cfg.get("api_base_env", "OPENAI_BASE_URL"),
            timeout_seconds=cfg.get("timeout_seconds", 60),
        )
    if backend == "ollama":
        return OllamaClient(model=cfg.get("model", "llama3"),
                            host=cfg.get("ollama_host", "http://localhost:11434"),
                            timeout_seconds=cfg.get("timeout_seconds", 60))
    if backend == "auto":
        if os.environ.get(cfg.get("api_key_env", "OPENAI_API_KEY")):
            try:
                return OpenAIClient(
                    model=cfg.get("model", "gpt-4o-mini"),
                    api_key_env=cfg.get("api_key_env", "OPENAI_API_KEY"),
                    api_base_env=cfg.get("api_base_env", "OPENAI_BASE_URL"),
                    timeout_seconds=cfg.get("timeout_seconds", 60),
                )
            except Exception as exc:
                LOG.warning("OpenAI client unavailable (%s); falling back to mock.", exc)
    return MockLLMClient()


# ── Agents ─────────────────────────────────────────────────────────────
def _safe_json(raw: str) -> Dict[str, Any]:
    """Pull the first balanced JSON object from an LLM response."""
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        pass
    # Strip code fences if present.
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.S)
    if fence:
        try:
            return json.loads(fence.group(1))
        except Exception:
            pass
    # Brace-balance scan.
    depth = 0
    start = -1
    for i, ch in enumerate(raw):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                snippet = raw[start:i + 1]
                try:
                    return json.loads(snippet)
                except Exception:
                    start = -1
                    continue
    return {}


@dataclass
class AgentTrace:
    name: str
    prompt_chars: int
    response_chars: int
    parsed: Dict[str, Any] = field(default_factory=dict)


class _BaseAgent:
    name = "base"

    def __init__(self, llm: LLMClient, *, temperature: float = 0.2,
                 max_tokens: int = 1500, system: Optional[str] = None) -> None:
        self.llm = llm
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.system = system

    def _call(self, prompt: str) -> AgentTrace:
        raw = self.llm.chat(prompt, system=self.system,
                             temperature=self.temperature,
                             max_tokens=self.max_tokens)
        parsed = _safe_json(raw)
        return AgentTrace(name=self.name, prompt_chars=len(prompt),
                          response_chars=len(raw or ""), parsed=parsed)


class PlannerAgent(_BaseAgent):
    name = "planner"

    def run(self, *, alert: Dict[str, Any], layer_a_verdict: Dict[str, Any],
            layer_b_attribution: Dict[str, Any],
            layer_c_decision: Dict[str, Any]) -> AgentTrace:
        prompt = PLANNER_PROMPT.format(
            alert_summary=build_alert_summary(alert),
            layer_a_verdict=json.dumps(layer_a_verdict, indent=2, default=str),
            layer_b_attribution=json.dumps(layer_b_attribution, indent=2, default=str),
            layer_c_decision=json.dumps(layer_c_decision, indent=2, default=str),
        )
        return self._call(prompt)


class GeneratorAgent(_BaseAgent):
    name = "generator"

    def run(self, *, plan: Dict[str, Any], retrieved_kg: Dict[str, Any],
            retrieved_passages: List[Dict[str, Any]]) -> AgentTrace:
        prompt = GENERATOR_PROMPT.format(
            plan=json.dumps(plan, indent=2, default=str),
            retrieved_kg=json.dumps(retrieved_kg, indent=2, default=str),
            retrieved_passages=json.dumps(retrieved_passages, indent=2, default=str),
        )
        return self._call(prompt)


class AnalystAgent(_BaseAgent):
    name = "analyst"

    def run(self, *, proposals: Dict[str, Any], alert: Dict[str, Any]) -> AgentTrace:
        prompt = ANALYST_PROMPT.format(
            proposals=json.dumps(proposals, indent=2, default=str),
            alert_summary=build_alert_summary(alert),
        )
        return self._call(prompt)


class ReflectorAgent(_BaseAgent):
    name = "reflector"

    def run(self, *, analyst_verdicts: Dict[str, Any], proposals: Dict[str, Any],
            plan: Dict[str, Any]) -> AgentTrace:
        prompt = REFLECTOR_PROMPT.format(
            analyst_verdicts=json.dumps(analyst_verdicts, indent=2, default=str),
            proposals=json.dumps(proposals, indent=2, default=str),
            plan=json.dumps(plan, indent=2, default=str),
        )
        return self._call(prompt)
