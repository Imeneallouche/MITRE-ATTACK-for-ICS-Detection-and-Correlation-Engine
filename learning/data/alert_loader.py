"""Load alerts (and optionally raw events) from Elasticsearch.

The loader is intentionally narrow: it only knows how to issue
search-after queries against a date range, returning normalised dicts
that the feature builder can consume.  When the elasticsearch package
is not installed (e.g. unit-test environments) it falls back to reading
JSONL fixtures from disk.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

LOG = logging.getLogger("learning.alert_loader")

try:
    from elasticsearch import Elasticsearch  # type: ignore
except Exception:  # pragma: no cover
    Elasticsearch = None  # type: ignore


def _to_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


class AlertLoader:
    """Read alerts/events from Elasticsearch with simple paging."""

    def __init__(
        self,
        hosts: Optional[List[str]] = None,
        *,
        client: Optional[Any] = None,
        timeout_seconds: int = 30,
        scroll_size: int = 1000,
    ) -> None:
        self.scroll_size = int(scroll_size)
        if client is not None:
            self.client = client
        elif hosts and Elasticsearch is not None:
            self.client = Elasticsearch(hosts=hosts, request_timeout=timeout_seconds)
        else:
            self.client = None
            LOG.warning(
                "elasticsearch package unavailable or no hosts; AlertLoader is "
                "in fixture mode (use load_jsonl).",
            )

    # ── ES queries ─────────────────────────────────────────────────────
    def fetch_alerts(
        self,
        index_pattern: str,
        *,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        max_results: int = 50_000,
    ) -> List[Dict[str, Any]]:
        return list(self._iter_index(
            index_pattern, since=since, until=until, max_results=max_results,
        ))

    def fetch_events(
        self,
        index_pattern: str,
        *,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        max_results: int = 200_000,
    ) -> List[Dict[str, Any]]:
        return list(self._iter_index(
            index_pattern, since=since, until=until, max_results=max_results,
        ))

    def _iter_index(
        self,
        index_pattern: str,
        *,
        since: Optional[datetime],
        until: Optional[datetime],
        max_results: int,
    ) -> Iterator[Dict[str, Any]]:
        if self.client is None:
            LOG.error("AlertLoader.client is None; nothing to fetch.")
            return
        rng: Dict[str, str] = {}
        if since is not None:
            rng["gte"] = since.astimezone(timezone.utc).isoformat()
        if until is not None:
            rng["lte"] = until.astimezone(timezone.utc).isoformat()
        query: Dict[str, Any] = {"match_all": {}}
        if rng:
            query = {"range": {"@timestamp": rng}}

        body: Dict[str, Any] = {
            "size": self.scroll_size,
            "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}],
            "query": query,
        }

        seen = 0
        search_after: Optional[List[Any]] = None
        while seen < max_results:
            payload = dict(body)
            if search_after is not None:
                payload["search_after"] = search_after
            try:
                resp = self.client.search(index=index_pattern, body=payload)
            except Exception as exc:  # pragma: no cover
                LOG.error("AlertLoader: search failed (%s); aborting page", exc)
                return
            hits = resp.get("hits", {}).get("hits") or []
            if not hits:
                return
            for h in hits:
                src = h.get("_source", {}) or {}
                src.setdefault("_id", h.get("_id"))
                yield src
                seen += 1
                if seen >= max_results:
                    return
            search_after = hits[-1].get("sort")
            if search_after is None:
                return

    # ── Fixture mode ───────────────────────────────────────────────────
    @staticmethod
    def load_jsonl(path: Path) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        path = Path(path)
        if not path.exists():
            return out
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
        return out

    # ── Helpers ────────────────────────────────────────────────────────
    @staticmethod
    def alert_timestamp(alert: Dict[str, Any]) -> Optional[datetime]:
        return _to_dt(alert.get("@timestamp") or alert.get("first_seen"))
