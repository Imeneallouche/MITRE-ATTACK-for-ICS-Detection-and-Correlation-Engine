"""Append-only JSONL store for environment-state window labels.

Each row is a dict on disk:

    {
      "start": "2026-04-22T16:30:00Z",
      "end":   "2026-04-22T17:05:00Z",
      "label": "under_attack" | "benign",
      "chain_id": "Chain 10" | null,
      "technique_list": ["T0812", "T0881", ...],
      "attacker_assets": ["kali", "router"],
      "defender_assets": ["plc", "hmi", "simulation"],
      "source": "operator" | "caldera" | "auto",
      "notes": "free-form string"
    }

The store is intentionally simple (line-oriented JSON, no DB) so that
operators can edit it by hand and version-control it alongside the
detection-engine config.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

LOG = logging.getLogger("learning.labels")


def _parse_dt(value: Any) -> datetime:
    """Robust UTC datetime parser (mirrors engine.feature_extractor)."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        s = value.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            pass
    raise ValueError(f"Unparseable timestamp: {value!r}")


@dataclass
class WindowLabel:
    """A single labelled time window."""

    start: datetime
    end: datetime
    label: str = "benign"
    chain_id: Optional[str] = None
    technique_list: List[str] = field(default_factory=list)
    attacker_assets: List[str] = field(default_factory=list)
    defender_assets: List[str] = field(default_factory=list)
    source: str = "operator"
    notes: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.start, datetime):
            self.start = _parse_dt(self.start)
        if not isinstance(self.end, datetime):
            self.end = _parse_dt(self.end)
        if self.end < self.start:
            raise ValueError("WindowLabel: end < start")
        self.label = (self.label or "benign").lower()
        if self.label not in {"benign", "under_attack"}:
            raise ValueError(f"label must be 'benign' or 'under_attack', got {self.label!r}")
        self.technique_list = [str(t).upper() for t in (self.technique_list or [])]
        self.attacker_assets = [str(a).lower() for a in (self.attacker_assets or [])]
        self.defender_assets = [str(a).lower() for a in (self.defender_assets or [])]

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()

    def covers(self, ts: datetime, *, skew_seconds: float = 0.0) -> bool:
        if not isinstance(ts, datetime):
            ts = _parse_dt(ts)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        delta = float(skew_seconds)
        return (self.start.timestamp() - delta) <= ts.timestamp() <= (self.end.timestamp() + delta)

    def to_json(self) -> Dict[str, Any]:
        d = asdict(self)
        d["start"] = self.start.astimezone(timezone.utc).isoformat()
        d["end"] = self.end.astimezone(timezone.utc).isoformat()
        return d

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "WindowLabel":
        return cls(
            start=_parse_dt(data["start"]),
            end=_parse_dt(data["end"]),
            label=data.get("label", "benign"),
            chain_id=data.get("chain_id"),
            technique_list=list(data.get("technique_list") or []),
            attacker_assets=list(data.get("attacker_assets") or []),
            defender_assets=list(data.get("defender_assets") or []),
            source=data.get("source", "operator"),
            notes=str(data.get("notes") or ""),
        )


class LabelStore:
    """File-backed append-only label store."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)

    # ── Persistence ────────────────────────────────────────────────────
    def append(self, label: WindowLabel) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(label.to_json(), ensure_ascii=False) + "\n")

    def all(self) -> List[WindowLabel]:
        if not self.path.exists():
            return []
        out: List[WindowLabel] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    out.append(WindowLabel.from_json(json.loads(raw_line)))
                except Exception as exc:  # pragma: no cover - log but continue
                    LOG.warning("labels.jsonl line %d unparseable: %s", line_no, exc)
        out.sort(key=lambda w: w.start)
        return out

    # ── Lookups ────────────────────────────────────────────────────────
    def find(self, ts: datetime, *, skew_seconds: float = 0.0) -> Optional[WindowLabel]:
        """Return the window covering ``ts`` (latest one wins for overlaps)."""
        if not isinstance(ts, datetime):
            ts = _parse_dt(ts)
        match: Optional[WindowLabel] = None
        for w in self.all():
            if w.covers(ts, skew_seconds=skew_seconds):
                match = w  # latest covering window wins
        return match

    def windows_in_range(
        self, start: datetime, end: datetime,
    ) -> List[WindowLabel]:
        if not isinstance(start, datetime):
            start = _parse_dt(start)
        if not isinstance(end, datetime):
            end = _parse_dt(end)
        return [
            w for w in self.all()
            if w.end >= start and w.start <= end
        ]

    # ── Convenience constructors ───────────────────────────────────────
    def add_window(
        self,
        *,
        start: datetime,
        end: datetime,
        label: str,
        chain_id: Optional[str] = None,
        technique_list: Optional[Iterable[str]] = None,
        attacker_assets: Optional[Iterable[str]] = None,
        defender_assets: Optional[Iterable[str]] = None,
        source: str = "operator",
        notes: str = "",
    ) -> WindowLabel:
        wl = WindowLabel(
            start=start, end=end, label=label, chain_id=chain_id,
            technique_list=list(technique_list or []),
            attacker_assets=list(attacker_assets or []),
            defender_assets=list(defender_assets or []),
            source=source, notes=notes,
        )
        self.append(wl)
        return wl
