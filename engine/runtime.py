"""Main runtime for the ICS Detection and Correlation Engine.

Supports three execution modes:
- stream:   continuous near-real-time polling of Elasticsearch
- oneshot:  single poll cycle (useful for cron or testing)
- backtest: process a historical time range with PIT pagination
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .alert_suppression import should_suppress_alert
from .alerting import AlertBuilder, alert_to_document
from .config import EngineConfig, load_config
from .correlation import CorrelationConfig, CorrelationEngine
from .dc_loader import load_assets, load_datacomponents
from .embeddings import EmbeddingEngine
from .es_client import Checkpoint, CheckpointStore, ESClient
from .feature_extractor import EventNormalizer, NormalizationRules
from .matcher import DataComponentMatcher
from .neo4j_client import Neo4jClient
from .technique_mapper import TechniqueMapper
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
            for old in sorted(self._data, key=lambda k: self._data[k])[: self.max_size // 10]:
                del self._data[old]


class DetectionRuntime:
    def __init__(self, config: EngineConfig, *, embeddings_enabled: bool = True) -> None:
        self.config = config
        self.excluded_asset_ids = set(config.excluded_asset_ids)

        self.es = ESClient(
            config.es_hosts,
            timeout_seconds=int(config.raw["elasticsearch"]["timeout_seconds"]),
        )
        self.profiles = load_datacomponents(config.datacomponents_dir)
        self.assets_by_id, self.assets_by_ip = load_assets(config.assets_file)

        self.normalizer = EventNormalizer(
            rules=NormalizationRules.from_config(config.normalization),
            asset_by_ip=self.assets_by_ip,
        )

        use_embeddings = embeddings_enabled and config.embeddings_enabled
        self.embedding_engine: Optional[EmbeddingEngine] = None
        if use_embeddings:
            self.embedding_engine = EmbeddingEngine(
                model_name=config.embedding_model,
                device=config.embedding_device,
                enabled=True,
            )
            dc_texts = {p.id: p.embedding_text for p in self.profiles if p.embedding_text}
            self.embedding_engine.precompute_dc_embeddings(dc_texts)

        self.matcher = DataComponentMatcher(
            profiles=self.profiles,
            scoring_weights=config.scoring_weights,
            candidate_threshold=config.candidate_threshold,
            high_confidence_threshold=config.high_confidence_threshold,
            embedding_engine=self.embedding_engine,
            semantic_gate_threshold=config.semantic_gate_threshold,
            log_source_families=config.log_source_families,
            evidence_policy=config.scoring_policy,
        )

        corr_cfg = CorrelationConfig.build(
            window_seconds=int(config.correlation["window_seconds"]),
            repeat_count_escalation=int(config.correlation["repeat_count_escalation"]),
            per_event_correlation_boost=float(config.correlation["per_event_correlation_boost"]),
            max_correlation_boost=float(config.correlation["max_correlation_boost"]),
            chain_step_boost=float(config.correlation["chain_step_boost"]),
            decay_half_life_seconds=float(config.correlation.get("decay_half_life_seconds", 120.0)),
            chain_rules=config.correlation_chain_rules,
            network_datacomponents=config.correlation_network_datacomponents,
            accumulator=str(config.correlation.get("accumulator", "linear")),
            require_strong_match=bool(config.correlation.get("require_strong_match", False)),
        )
        self.correlation = CorrelationEngine(cfg=corr_cfg)

        self.neo4j = Neo4jClient(
            uri=config.neo4j_uri,
            username=config.neo4j_username,
            password=config.neo4j_password,
            enabled=config.neo4j_enabled,
            cache_ttl_seconds=config.neo4j_cache_ttl,
        )

        tm_cfg = config.technique_mapper
        self.technique_mapper = TechniqueMapper(
            neo4j=self.neo4j,
            alpha_group=float(tm_cfg.get("alpha_group", 0.3)),
            alpha_asset=float(tm_cfg.get("alpha_asset", 0.5)),
            max_candidates=int(tm_cfg.get("max_candidates", 5)),
            fallback_map=config.technique_fallback,
            asset_role_map=config.technique_asset_role_map,
        )

        self.alert_builder = AlertBuilder(
            technique_mapper=self.technique_mapper,
            suppress_window_seconds=int(config.raw["engine"]["suppress_window_seconds"]),
        )

        self.checkpoints = CheckpointStore(config.checkpoint_file)
        self.dedup = DedupCache(max_size=int(config.raw["engine"]["dedup_cache_size"]))

    def bootstrap_templates(self) -> None:
        self.es.ensure_index_template("ics-alerts-template", alert_index_template())
        self.es.ensure_index_template("ics-correlations-template", correlation_index_template())

    def warm_graph_cache(self) -> None:
        self.neo4j.warm_cache()

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

            event = self.normalizer.normalize(hit)

            if event.asset_id in self.excluded_asset_ids:
                continue

            matches = self.matcher.match_event(event)
            if not matches:
                continue

            top_match = matches[0]
            if self.config.skip_ambiguous_within_margin and top_match.is_ambiguous and len(matches) > 1:
                margin = top_match.similarity_score - matches[1].similarity_score
                if margin < self.config.ambiguous_score_margin:
                    continue

            penalized = top_match.similarity_score
            if event.asset_id.startswith("unknown"):
                penalized = max(0.0, penalized - self.config.unknown_asset_penalty)
                top_match.similarity_score = penalized

            if top_match.similarity_score < threshold:
                continue

            if should_suppress_alert(
                event, top_match.datacomponent_id, self.config.alert_suppression_rules,
            ):
                continue

            group, boosts = self.correlation.process(top_match)

            alert = self.alert_builder.build_alert(
                match=top_match,
                group=group,
                boosts=boosts,
                strategy="semantic_gate+multi_signal_weighted+correlation+knowledge_graph",
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
                self.correlation.get_group_summary(group.group_id) or {},
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
                bool_query: Dict[str, Any] = {
                    "must": [{"range": {"@timestamp": {"gte": start, "lt": end}}}],
                }
                if self.excluded_asset_ids:
                    bool_query["must_not"] = [
                        {"terms": {"asset_id": sorted(self.excluded_asset_ids)}}
                    ]
                body: Dict[str, Any] = {
                    "size": self.config.batch_size,
                    "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
                    "pit": {"id": pit, "keep_alive": "2m"},
                    "query": {"bool": bool_query},
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
                    excluded_asset_ids=sorted(self.excluded_asset_ids),
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
        raw = "|".join([
            str(src.get("asset_id", "")),
            str(src.get("log_source_normalized", "")),
            str(src.get("@timestamp", ""))[:19],
            str(src.get("log_message", src.get("message", ""))),
        ])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def shutdown(self) -> None:
        self.neo4j.close()


def _safe_datetime(value: Any) -> datetime:
    try:
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        pass
    return datetime.now(tz=timezone.utc)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ICS DataComponent Detection and Correlation Engine"
    )
    parser.add_argument("--config", default="config/detection.yml", help="Config file path")
    parser.add_argument(
        "--mode", choices=["stream", "oneshot", "backtest"], default="stream",
        help="Engine execution mode",
    )
    parser.add_argument("--start", help="Backtest start timestamp (ISO8601)")
    parser.add_argument("--end", help="Backtest end timestamp (ISO8601)")
    parser.add_argument("--bootstrap-templates", action="store_true", help="Install ES index templates")
    parser.add_argument("--no-graph", action="store_true", help="Disable Neo4j integration")
    parser.add_argument("--no-embeddings", action="store_true", help="Disable semantic embedding model (falls back to metadata-only scoring)")
    return parser


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    args = build_arg_parser().parse_args()
    cfg = load_config(Path(args.config))

    if args.no_graph:
        cfg.raw.setdefault("neo4j", {})["enabled"] = False

    embeddings_enabled = not args.no_embeddings

    runtime = DetectionRuntime(cfg, embeddings_enabled=embeddings_enabled)

    if args.bootstrap_templates:
        runtime.bootstrap_templates()

    runtime.warm_graph_cache()

    try:
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
    finally:
        runtime.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
