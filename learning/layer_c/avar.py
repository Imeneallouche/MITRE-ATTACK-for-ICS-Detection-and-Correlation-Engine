"""Analyst-Validated Alert Repository (AVAR).

A small, persistent cache of analyst verdicts that the triage policy
uses both for *training* (offline replay of confirmed labels) and at
*inference* time (cache hits short-circuit the policy with the analyst's
recorded decision).  A cache hit is also a strong signal that the
deterministic engine and the model agree, so we still record it for
observability.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

LOG = logging.getLogger("learning.avar")


@dataclass
class AnalystVerdict:
    fingerprint: str
    verdict: str             # accept | reject | downgrade | upgrade
    confidence: float
    note: str = ""
    asset_id: str = ""
    datacomponent: str = ""
    log_message: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_json(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "verdict": self.verdict,
            "confidence": float(self.confidence),
            "note": self.note,
            "asset_id": self.asset_id,
            "datacomponent": self.datacomponent,
            "log_message": self.log_message,
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
        }

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "AnalystVerdict":
        ts_raw = d.get("timestamp")
        ts: datetime
        if isinstance(ts_raw, datetime):
            ts = ts_raw
        elif ts_raw:
            try:
                ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)
        return cls(
            fingerprint=str(d.get("fingerprint") or ""),
            verdict=str(d.get("verdict") or "accept"),
            confidence=float(d.get("confidence", 1.0)),
            note=str(d.get("note") or ""),
            asset_id=str(d.get("asset_id") or ""),
            datacomponent=str(d.get("datacomponent") or ""),
            log_message=str(d.get("log_message") or ""),
            timestamp=ts,
        )


class AVAR:
    """LRU-bounded persistent verdict cache."""

    def __init__(
        self,
        path: Path,
        *,
        max_size: int = 10_000,
        fingerprint_fields: Sequence[str] = ("asset_id", "datacomponent", "log_message"),
    ) -> None:
        self.path = Path(path)
        self.max_size = int(max_size)
        self.fingerprint_fields = tuple(fingerprint_fields)
        self._lock = threading.Lock()
        self._store: "OrderedDict[str, AnalystVerdict]" = OrderedDict()
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    @staticmethod
    def fingerprint(values: Dict[str, Any], fields: Sequence[str]) -> str:
        h = hashlib.sha1()
        for f in fields:
            v = values.get(f) or ""
            h.update(str(v).strip().lower().encode("utf-8", errors="ignore"))
            h.update(b"|")
        return h.hexdigest()

    # ── Persistence ────────────────────────────────────────────────────
    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        v = AnalystVerdict.from_json(json.loads(line))
                        self._store[v.fingerprint] = v
                    except Exception:
                        continue
        except Exception:  # pragma: no cover
            LOG.exception("AVAR: failed to load %s", self.path)

    def _persist(self) -> None:
        try:
            with self.path.open("w", encoding="utf-8") as fh:
                for v in self._store.values():
                    fh.write(json.dumps(v.to_json(), ensure_ascii=False) + "\n")
        except Exception:  # pragma: no cover
            LOG.exception("AVAR: failed to persist %s", self.path)

    # ── Operations ─────────────────────────────────────────────────────
    def get(self, fingerprint: str) -> Optional[AnalystVerdict]:
        with self._lock:
            v = self._store.get(fingerprint)
            if v is not None:
                self._store.move_to_end(fingerprint)
            return v

    def add(self, verdict: AnalystVerdict) -> None:
        with self._lock:
            self._store[verdict.fingerprint] = verdict
            self._store.move_to_end(verdict.fingerprint)
            while len(self._store) > self.max_size:
                self._store.popitem(last=False)
            self._persist()

    def add_from_alert(self, alert: Dict[str, Any], verdict: str, *,
                        confidence: float = 1.0, note: str = "") -> AnalystVerdict:
        fp = self.fingerprint(alert, self.fingerprint_fields)
        v = AnalystVerdict(
            fingerprint=fp, verdict=verdict, confidence=confidence,
            note=note,
            asset_id=str(alert.get("asset_id") or ""),
            datacomponent=str(alert.get("datacomponent") or alert.get("data_component") or ""),
            log_message=str(alert.get("log_message") or alert.get("message") or ""),
        )
        self.add(v)
        return v

    def all(self) -> List[AnalystVerdict]:
        with self._lock:
            return list(self._store.values())

    def __len__(self) -> int:
        return len(self._store)
