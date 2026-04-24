"""FastAPI service exposing the learning orchestrator.

Endpoints:

* ``POST /alerts/score``       — score a single alert dict.
* ``POST /alerts/batch``       — batch-score alerts.
* ``POST /alerts/feedback``    — record analyst verdict (writes to AVAR
                                  and updates the LinUCB / DQN policy).
* ``POST /labels``             — append a window label.
* ``GET  /labels``             — list window labels.
* ``GET  /health``             — readiness probe.
* ``POST /poll/tick``          — manually trigger an ES polling cycle.

All endpoints are JSON-only and return 200/400/500 with structured
error bodies.  CORS origins come from ``api.cors_origins`` in
``learning.yml``.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

LOG = logging.getLogger("learning.api")

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
except Exception as exc:  # pragma: no cover
    raise RuntimeError(
        "learning.api requires fastapi + pydantic. "
        "Install with: pip install fastapi uvicorn[standard]",
    ) from exc

from .config import load_config
from .data import LabelStore, WindowLabel
from .orchestrator import Orchestrator


class AlertPayload(BaseModel):
    alert: Dict[str, Any] = Field(..., description="Raw alert dict (engine schema).")
    run_layer_d: bool = True


class BatchPayload(BaseModel):
    alerts: List[Dict[str, Any]]
    run_layer_d: bool = True


class FeedbackPayload(BaseModel):
    alert: Dict[str, Any]
    verdict: str = Field(..., description="accept | reject | downgrade | upgrade")
    confidence: float = 1.0
    note: str = ""


class LabelPayload(BaseModel):
    start: datetime
    end: datetime
    label: str = "benign"
    chain_id: Optional[str] = None
    technique_list: List[str] = Field(default_factory=list)
    attacker_assets: List[str] = Field(default_factory=list)
    defender_assets: List[str] = Field(default_factory=list)
    source: str = "operator"
    notes: str = ""


def build_app(
    cfg_path: Optional[Path] = None,
    *,
    orchestrator: Optional[Orchestrator] = None,
    es_hosts: Optional[List[str]] = None,
    engine_neo4j_client: Optional[Any] = None,
) -> "FastAPI":
    cfg = load_config(cfg_path)
    if orchestrator is None:
        orchestrator = Orchestrator.from_config(
            cfg_path, es_hosts=es_hosts, engine_neo4j_client=engine_neo4j_client,
        )
    label_store = LabelStore(cfg.path("labels_file"))

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ARG001
        LOG.info("Learning API starting up.")
        yield
        LOG.info("Learning API shutting down.")

    app = FastAPI(title="ICS Learning Orchestrator", version="1.0.0", lifespan=lifespan)
    cors = cfg.api.get("cors_origins") or ["*"]
    app.add_middleware(
        CORSMiddleware, allow_origins=cors, allow_credentials=True,
        allow_methods=["*"], allow_headers=["*"],
    )

    @app.get("/health")
    async def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "layer_a": orchestrator.classifier is not None,
                "layer_b": orchestrator.attributor is not None,
                "layer_c": orchestrator.triage is not None,
                "layer_d": orchestrator.mitigation is not None,
                "avar_size": len(orchestrator.avar) if orchestrator.avar is not None else 0,
            },
        }

    @app.post("/alerts/score")
    async def score(payload: AlertPayload) -> Dict[str, Any]:
        try:
            decision = orchestrator.process_alert(
                payload.alert, run_layer_d=payload.run_layer_d,
            )
            return decision.to_dict()
        except Exception as exc:
            LOG.exception("score failed")
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/alerts/batch")
    async def batch(payload: BatchPayload) -> Dict[str, Any]:
        try:
            decisions = orchestrator.process_batch(
                payload.alerts, run_layer_d=payload.run_layer_d,
            )
            return {"count": len(decisions), "decisions": [d.to_dict() for d in decisions]}
        except Exception as exc:
            LOG.exception("batch failed")
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/alerts/feedback")
    async def feedback(payload: FeedbackPayload) -> Dict[str, Any]:
        if orchestrator.avar is None:
            raise HTTPException(status_code=400, detail="AVAR is disabled.")
        try:
            verdict = orchestrator.submit_feedback(
                payload.alert, payload.verdict,
                confidence=payload.confidence, note=payload.note,
            )
            return {"recorded": True, "verdict": verdict}
        except Exception as exc:
            LOG.exception("feedback failed")
            raise HTTPException(status_code=500, detail=str(exc))

    @app.post("/labels")
    async def add_label(payload: LabelPayload) -> Dict[str, Any]:
        try:
            wl = label_store.add_window(
                start=payload.start, end=payload.end, label=payload.label,
                chain_id=payload.chain_id, technique_list=payload.technique_list,
                attacker_assets=payload.attacker_assets,
                defender_assets=payload.defender_assets,
                source=payload.source, notes=payload.notes,
            )
            return {"recorded": True, "label": wl.to_json()}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/labels")
    async def list_labels() -> Dict[str, Any]:
        labels = label_store.all()
        return {"count": len(labels), "labels": [w.to_json() for w in labels]}

    @app.post("/poll/tick")
    async def poll_tick() -> Dict[str, Any]:
        try:
            decisions = orchestrator.tick()
            return {"count": len(decisions), "decisions": [d.to_dict() for d in decisions]}
        except Exception as exc:
            LOG.exception("tick failed")
            raise HTTPException(status_code=500, detail=str(exc))

    return app


def serve(
    cfg_path: Optional[Path] = None,
    *,
    host: Optional[str] = None,
    port: Optional[int] = None,
    es_hosts: Optional[List[str]] = None,
) -> None:
    try:
        import uvicorn
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("uvicorn is required to serve the API.") from exc
    cfg = load_config(cfg_path)
    app = build_app(cfg_path, es_hosts=es_hosts)
    uvicorn.run(
        app,
        host=host or cfg.api.get("host", "0.0.0.0"),
        port=int(port or cfg.api.get("port", 8090)),
        log_level=os.environ.get("LEARNING_LOG_LEVEL", "info").lower(),
    )
