from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from elasticsearch import Elasticsearch
except Exception:  # pragma: no cover - dependency may be absent before install
    Elasticsearch = None  # type: ignore

LOG = logging.getLogger("ics-detector.es")


@dataclass
class Checkpoint:
    last_timestamp: str
    last_sort: Optional[List[Any]]


class CheckpointStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> Checkpoint:
        if not self.path.exists():
            return Checkpoint(last_timestamp="1970-01-01T00:00:00Z", last_sort=None)
        with self.path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return Checkpoint(
            last_timestamp=data.get("last_timestamp", "1970-01-01T00:00:00Z"),
            last_sort=data.get("last_sort"),
        )

    def save(self, checkpoint: Checkpoint) -> None:
        with self.path.open("w", encoding="utf-8") as f:
            json.dump(
                {"last_timestamp": checkpoint.last_timestamp, "last_sort": checkpoint.last_sort},
                f,
                indent=2,
            )


class ESClient:
    def __init__(self, hosts: List[str], timeout_seconds: int = 30) -> None:
        if Elasticsearch is None:
            raise RuntimeError(
                "Missing dependency: elasticsearch. Install requirements with `pip install -r requirements.txt`."
            )
        self.client = Elasticsearch(hosts=hosts, request_timeout=timeout_seconds)

    def ensure_index_template(self, template_name: str, body: Dict[str, Any]) -> None:
        self.client.indices.put_index_template(name=template_name, body=body)

    def open_pit(self, index_pattern: str, keep_alive: str = "1m") -> str:
        result = self.client.open_point_in_time(index=index_pattern, keep_alive=keep_alive)
        return str(result["id"])

    def close_pit(self, pit_id: str) -> None:
        try:
            self.client.close_point_in_time(body={"id": pit_id})
        except Exception as exc:
            LOG.debug("close_point_in_time ignored: %s", exc)

    def poll_events(
        self,
        index_pattern: str,
        since_ts: str,
        batch_size: int,
        pit_id: Optional[str] = None,
        search_after: Optional[List[Any]] = None,
        excluded_asset_ids: Optional[List[str]] = None,
        pit_keep_alive: str = "15m",
    ) -> Dict[str, Any]:
        bool_query: Dict[str, Any] = {
            "must": [{"range": {"@timestamp": {"gt": since_ts}}}],
        }
        if excluded_asset_ids:
            bool_query["must_not"] = [
                {"terms": {"asset_id": sorted(set(excluded_asset_ids))}}
            ]
        query: Dict[str, Any] = {
            "size": batch_size,
            "sort": [{"@timestamp": "asc"}, {"_shard_doc": "asc"}],
            "query": {"bool": bool_query},
        }

        if pit_id:
            query["pit"] = {"id": pit_id, "keep_alive": pit_keep_alive}
        else:
            query["index"] = index_pattern

        if search_after:
            query["search_after"] = search_after

        return self.client.search(body=query)

    def index_document(self, index_name: str, document: Dict[str, Any], doc_id: Optional[str] = None) -> None:
        if doc_id:
            self.client.index(index=index_name, id=doc_id, document=document)
        else:
            self.client.index(index=index_name, document=document)

    @staticmethod
    def resolve_index_name(pattern: str, when: Optional[datetime] = None) -> str:
        when = when or datetime.now(tz=timezone.utc)
        return when.strftime(pattern)
