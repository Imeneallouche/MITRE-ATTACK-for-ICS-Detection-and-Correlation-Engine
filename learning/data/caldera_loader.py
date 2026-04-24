"""Convert Caldera operation reports into ground-truth window labels.

Caldera saves an operation report as a JSON file in
``Caldera Reports/<Chain N>_report.json``.  For our purposes we only
need the host group (to discover attacker assets and IPs) and the
ordered ``links`` list (each link records the ability that was launched
along with its MITRE technique id and a UTC timestamp).

The loader produces:

* :class:`CalderaChain` — high-level summary (start, end, attacker,
  technique list).
* :class:`WindowLabel` (via :meth:`CalderaChain.to_window_label`) — the
  same chain rendered as a single labelled window suitable for feeding
  into the :class:`learning.data.label_store.LabelStore`.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .label_store import WindowLabel, _parse_dt

LOG = logging.getLogger("learning.caldera")


@dataclass
class CalderaLink:
    """One executed ability inside a Caldera chain."""

    decide: datetime
    finish: Optional[datetime]
    technique_id: str
    technique_name: str
    tactic: str
    ability_id: str
    plaintext_command: str
    status: int

    @property
    def ts(self) -> datetime:
        return self.finish or self.decide


@dataclass
class CalderaChain:
    """A complete Caldera operation chain."""

    name: str
    paw: str
    host: str
    attacker_ips: List[str]
    started_at: datetime
    ended_at: datetime
    links: List[CalderaLink] = field(default_factory=list)

    @property
    def technique_ids(self) -> List[str]:
        seen: Dict[str, bool] = {}
        ordered: List[str] = []
        for link in self.links:
            tid = link.technique_id.upper().strip()
            if not tid:
                continue
            if tid not in seen:
                seen[tid] = True
                ordered.append(tid)
        return ordered

    @property
    def tactic_ids(self) -> List[str]:
        seen: Dict[str, bool] = {}
        out: List[str] = []
        for link in self.links:
            t = (link.tactic or "").lower().strip()
            if t and t not in seen:
                seen[t] = True
                out.append(t)
        return out

    @property
    def duration_seconds(self) -> float:
        return (self.ended_at - self.started_at).total_seconds()

    def to_window_label(
        self,
        *,
        defender_assets: Optional[Sequence[str]] = None,
        pad_seconds: int = 30,
    ) -> WindowLabel:
        """Render this chain as a single labelled time window.

        ``pad_seconds`` extends the window on both sides so that
        Caldera-induced events that arrive a few seconds late (Filebeat
        + Logstash + ES ingestion lag) still fall inside the label.
        """
        return WindowLabel(
            start=self.started_at - timedelta(seconds=pad_seconds),
            end=self.ended_at + timedelta(seconds=pad_seconds),
            label="under_attack",
            chain_id=self.name,
            technique_list=self.technique_ids,
            attacker_assets=[self.host] + list(self.attacker_ips),
            defender_assets=list(defender_assets or []),
            source="caldera",
            notes=f"{len(self.links)} abilities across {len(self.tactic_ids)} tactics",
        )


class CalderaLoader:
    """Parses Caldera operation report JSON files."""

    def __init__(self, reports_dir: Path) -> None:
        self.reports_dir = Path(reports_dir)

    # ── Public API ─────────────────────────────────────────────────────
    def load_all(self) -> List[CalderaChain]:
        if not self.reports_dir.exists():
            return []
        chains: List[CalderaChain] = []
        for path in sorted(self.reports_dir.glob("*_report.json")):
            try:
                chains.append(self.load(path))
            except Exception as exc:  # pragma: no cover - log and continue
                LOG.warning("Failed to parse Caldera report %s: %s", path, exc)
        return chains

    def load(self, path: Path) -> CalderaChain:
        with Path(path).open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return self._parse(data)

    # ── Internals ──────────────────────────────────────────────────────
    def _parse(self, data: Dict) -> CalderaChain:
        name = str(data.get("name") or Path(data.get("filename", "Chain")).stem)
        host_groups = data.get("host_group") or []
        if not host_groups:
            raise ValueError(f"Caldera report '{name}' has no host_group")
        primary = host_groups[0]
        host = str(primary.get("host") or "unknown")
        paw = str(primary.get("paw") or "")
        attacker_ips = [str(ip) for ip in primary.get("host_ip_addrs") or [] if ip]

        links_raw = primary.get("links") or []
        links = [self._parse_link(link) for link in links_raw if link]
        links = [l for l in links if l is not None]
        links.sort(key=lambda l: l.ts)

        if links:
            started = links[0].ts
            ended = links[-1].ts
        else:
            started = _parse_dt(primary.get("created") or data.get("start") or "1970-01-01T00:00:00Z")
            ended = _parse_dt(primary.get("last_seen") or data.get("finish") or started)

        return CalderaChain(
            name=name,
            paw=paw,
            host=host,
            attacker_ips=attacker_ips,
            started_at=started,
            ended_at=ended,
            links=links,
        )

    @staticmethod
    def _parse_link(link: Dict) -> Optional[CalderaLink]:
        ability = link.get("ability") or {}
        tid = ability.get("technique_id") or link.get("technique_id") or ""
        if not tid:
            return None
        try:
            decide = _parse_dt(link.get("decide"))
        except Exception:
            return None
        finish_raw = link.get("finish")
        finish: Optional[datetime] = None
        if finish_raw:
            try:
                finish = _parse_dt(finish_raw)
            except Exception:
                finish = None
        return CalderaLink(
            decide=decide,
            finish=finish,
            technique_id=str(tid).upper().strip(),
            technique_name=str(ability.get("technique_name") or ""),
            tactic=str(ability.get("tactic") or ""),
            ability_id=str(ability.get("ability_id") or link.get("id", "")),
            plaintext_command=str(link.get("plaintext_command") or ""),
            status=int(link.get("status") or 0),
        )

    # ── Helper: bulk-import into a label store ────────────────────────
    @staticmethod
    def import_into_label_store(
        chains: Iterable[CalderaChain],
        store,
        *,
        defender_assets: Optional[Sequence[str]] = None,
        pad_seconds: int = 30,
    ) -> List[WindowLabel]:
        out: List[WindowLabel] = []
        for chain in chains:
            wl = chain.to_window_label(
                defender_assets=defender_assets, pad_seconds=pad_seconds,
            )
            store.append(wl)
            out.append(wl)
        return out
