from __future__ import annotations

import argparse
import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .alerting import AlertBuilder, alert_to_document
from .config import EngineConfig, load_config
from .correlation import CorrelationConfig, CorrelationEngine
from .dc_loader import load_assets, load_datacomponents
from .es_client import Checkpoint, CheckpointStore, ESClient
from .feature_extractor import to_normalized_event
from .matcher import DataComponentMatcher
from .templates import alert_index_template, correlation_index_template


LOG = logging.getLogger("ics-detector")


class DedupCache:
    def __init__(self, max_size: int) -> None:
        self.max_size = max_size
        self._data: Dict[str, datetime] = {}

    def seen(self, key: str) -> bool:
        return key in self._data

    def add(self, key: str, ts: datetime) -> None:
        self._data[key] = ts
        if len(self._data) > self.max_size:
            # Delete oldest entries.
            for old_key in sorted(self._data.keys(), key=lambda k: self._data[k])[: self.max_size // 10]:
                del self._data[old_key]


class DetectionRuntime:
    def __init__(self, config: EngineConfig) -> None:
        self.config = config
        self.es = ESClient(config.es_hosts, timeout_seconds=int(config.raw["elasticsearch"]["timeout_seconds"]))
        self.profiles = load_datacomponents(config.datacomponents_dir)
        self.assets_by_id, self.assets_by_ip = load_assets(config.assets_file)
        self.matcher = DataComponentMatcher(
            profiles=self.profiles,
            scoring_weights=config.scoring_weights,
            candidate_threshold=config.candidate_threshold,
            high_confidence_threshold=config.high_confidence_threshold,
        )
        corr_cfg = CorrelationConfig(
            window_seconds=int(config.correlation["window_seconds"]),
            repeat_count_escalation=int(config.correlation["repeat_count_escalation"]),
            per_event_correlation_boost=float(config.correlation["per_event_correlation_boost"]),
            max_correlation_boost=float(config.correlation["max_correlation_boost"]),
            chain_step_boost=float(config.correlation["chain_step_boost"]),
        )
        self.correlation = CorrelationEngine(cfg=corr_cfg)
        self.alert_builder = AlertBuilder(
            suppress_window_seconds=int(config.raw["engine"]["suppress_window_seconds"])
        )
        self.checkpoints = CheckpointStore(config.checkpoint_file)
        self.dedup = DedupCache(max_size=int(config.raw["engine"]["dedup_cache_size"]))

    def bootstrap_templates(self) -> None:
        self.es.ensure_index_template("ics-alerts-template", alert_index_template())
        self.es.ensure_index_template("ics-correlations-template", correlation_index_template())

    def process_hits(self, hits: List[Dict[str, Any]], threshold: Optional[float] = None) -> int:
        alert_count = 0
        threshold = self.config.alert_threshold if threshold is None else threshold
        for hit in hits:
            source = hit.get("_source", {})
            dedup_key = self._dedup_key(hit)
            event_ts = _safe_datetime(source.get("@timestamp"))
            if self.dedup.seen(dedup_key):
                continue
            self.dedup.add(dedup_key, event_ts)

            event = to_normalized_event(hit, asset_by_ip=self.assets_by_ip)
            if event.asset_id in {"kali", "caldera"}:
                continue

            matches = self.matcher.match_event(event)
            if not matches:
                continue
            top_match = matches[0]

            # Unknown asset penalty.
            penalized_score = top_match.similarity_score
            if event.asset_id.startswith("unknown"):
                penalized_score = max(0.0, penalized_score - self.config.unknown_asset_penalty)
                top_match.similarity_score = penalized_score

            if top_match.similarity_score < threshold:
                continue

            group, boosts = self.correlation.process(top_match)
            alert = self.alert_builder.build_alert(
                match=top_match,
                group=group,
                boosts=boosts,
                strategy="multi_signal_weighted+correlation",
                threshold=threshold,
                sources_used=[event.log_source_normalized, f"dc:{top_match.datacomponent_id}"],
                related_matches=matches[1:4],
            )
            if alert is None:
                continue

            alert_index = self.es.resolve_index_name(self.config.es_alert_index_pattern, event.timestamp)
            corr_index = self.es.resolve_index_name(self.config.es_correlation_index_pattern, event.timestamp)
            self.es.index_document(alert_index, alert_to_document(alert), doc_id=alert.detection_id)
            self.es.index_document(
                corr_index,
                {
                    "group_id": group.group_id,
                    "asset_id": group.asset_id,
                    "asset_name": group.asset_name,
                    "first_timestamp": group.first_timestamp.isoformat(),
                    "last_timestamp": group.last_timestamp.isoformat(),
                    "chain_ids": group.chain_ids,
                    "chain_depth": group.chain_depth,
                    "aggregate_score": round(group.aggregate_score, 4),
                    "event_count": len(group.matches),
                },
            )
            alert_count += 1
        return alert_count

    def run_stream(self) -> None:
        checkpoint = self.checkpoints.load()
        LOG.info("Starting stream mode from timestamp %s", checkpoint.last_timestamp)
        while True:
            try:
                alerts = self._poll_and_process(checkpoint)
                if alerts:
                    LOG.info("Emitted %s alerts in this cycle.", alerts)
                pruned = self.correlation.prune_expired(datetime.now(tz=timezone.utc))
                if pruned:
                    LOG.debug("Pruned %s expired correlation groups.", pruned)
            except Exception:
                LOG.exception("Error in polling cycle")
            time.sleep(self.config.polling_interval_seconds)

    def run_oneshot(self) -> int:
        checkpoint = self.checkpoints.load()
        return self._poll_and_process(checkpoint)

    def run_backtest(self, start: str, end: str) -> int:
        LOG.info("Starting backtest from %s to %s", start, end)
        pit = self.es.open_pit(self.config.es_source_index_pattern, keep_alive="2m")
        total_alerts = 0
        search_after = None
        try:
            while True:
                body = {
                    "size": self.config.batch_size,
                    "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
                    "pit": {"id": pit, "keep_alive": "2m"},
                    "query": {
                        "bool": {
                            "must": [
                                {"range": {"@timestamp": {"gte": start, "lt": end}}},
                            ],
                            "must_not": [{"terms": {"asset_id": ["kali", "caldera"]}}],
                        }
                    },
                }
                if search_after:
                    body["search_after"] = search_after
                result = self.es.client.search(body=body)
                hits = result.get("hits", {}).get("hits", [])
                if not hits:
                    break
                total_alerts += self.process_hits(hits, threshold=self.config.alert_threshold)
                search_after = hits[-1].get("sort")
        finally:
            self.es.close_pit(pit)
        return total_alerts

    def _poll_and_process(self, checkpoint: Checkpoint) -> int:
        pit = self.es.open_pit(self.config.es_source_index_pattern, keep_alive="1m")
        last_sort = checkpoint.last_sort
        total_alerts = 0
        newest_timestamp = checkpoint.last_timestamp
        try:
            while True:
                result = self.es.poll_events(
                    index_pattern=self.config.es_source_index_pattern,
                    since_ts=checkpoint.last_timestamp,
                    batch_size=self.config.batch_size,
                    pit_id=pit,
                    search_after=last_sort,
                )
                hits = result.get("hits", {}).get("hits", [])
                if not hits:
                    break
                total_alerts += self.process_hits(hits)
                last_sort = hits[-1].get("sort")
                newest_timestamp = hits[-1].get("_source", {}).get("@timestamp", newest_timestamp)
                if len(hits) < self.config.batch_size:
                    break
        finally:
            self.es.close_pit(pit)

        checkpoint.last_timestamp = newest_timestamp
        checkpoint.last_sort = last_sort
        self.checkpoints.save(checkpoint)
        return total_alerts

    def _dedup_key(self, hit: Dict[str, Any]) -> str:
        src = hit.get("_source", {})
        raw = "|".join(
            [
                str(src.get("asset_id", "")),
                str(src.get("log_source_normalized", "")),
                str(src.get("@timestamp", ""))[:19],
                str(src.get("log_message", src.get("message", ""))),
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _safe_datetime(value: Any) -> datetime:
    try:
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        pass
    return datetime.now(tz=timezone.utc)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ICS DataComponent Detection and Correlation Engine")
    parser.add_argument("--config", default="config/detection.yml", help="Path to detection config file")
    parser.add_argument(
        "--mode",
        choices=["stream", "oneshot", "backtest"],
        default="stream",
        help="Engine execution mode",
    )
    parser.add_argument("--start", help="Backtest start timestamp (ISO8601)")
    parser.add_argument("--end", help="Backtest end timestamp (ISO8601)")
    parser.add_argument("--bootstrap-templates", action="store_true", help="Install ES index templates on startup")
    return parser


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    args = build_arg_parser().parse_args()
    cfg = load_config(Path(args.config))
    runtime = DetectionRuntime(cfg)

    if args.bootstrap_templates:
        runtime.bootstrap_templates()

    if args.mode == "stream":
        runtime.run_stream()
        return 0
    if args.mode == "oneshot":
        alerts = runtime.run_oneshot()
        LOG.info("Oneshot complete; emitted %s alerts.", alerts)
        return 0
    if args.mode == "backtest":
        if not args.start or not args.end:
            raise SystemExit("--start and --end are required in backtest mode")
        alerts = runtime.run_backtest(args.start, args.end)
        LOG.info("Backtest complete; emitted %s alerts.", alerts)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
