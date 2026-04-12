"""Elasticsearch index templates for alerts and correlations."""
from __future__ import annotations


def alert_index_template() -> dict:
    return {
        "index_patterns": ["ics-alerts-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "dynamic": True,
                "properties": {
                    "detection_id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "datacomponent": {"type": "keyword"},
                    "datacomponent_id": {"type": "keyword"},
                    "asset_id": {"type": "keyword"},
                    "asset_name": {"type": "keyword"},
                    "asset_ip": {"type": "ip", "ignore_malformed": True},
                    "zone": {"type": "keyword"},
                    "is_ics_asset": {"type": "boolean"},
                    "es_index": {"type": "keyword"},
                    "document_id": {"type": "keyword"},
                    "log_message": {"type": "text", "fields": {"raw": {"type": "keyword", "ignore_above": 1024}}},
                    "evidence_snippet": {"type": "text"},
                    "similarity_score": {"type": "float"},
                    "confidence_tier": {"type": "keyword"},
                    "signal_scores": {"type": "object", "dynamic": True},
                    "matched_fields": {"type": "object", "dynamic": True},
                    "matched_keywords": {"type": "keyword"},
                    "matched_categories": {"type": "keyword"},
                    "matched_log_source": {"type": "keyword"},
                    "matched_channel": {"type": "text"},
                    "technique": {
                        "type": "object",
                        "properties": {
                            "technique_id": {"type": "keyword"},
                            "technique_name": {"type": "keyword"},
                            "probability": {"type": "float"},
                            "tactics": {"type": "keyword"},
                            "detection_strategy": {"type": "keyword"},
                            "analytics_used": {"type": "keyword"},
                            "graph_path": {"type": "text"},
                            "reasoning": {"type": "text"},
                            "mitigations": {"type": "object", "dynamic": True},
                            "groups": {"type": "keyword"},
                            "software": {"type": "keyword"},
                            "targeted_assets": {"type": "keyword"},
                        },
                    },
                    "alternative_techniques": {
                        "type": "nested",
                        "properties": {
                            "technique_id": {"type": "keyword"},
                            "technique_name": {"type": "keyword"},
                            "probability": {"type": "float"},
                            "tactics": {"type": "keyword"},
                            "reasoning": {"type": "text"},
                        },
                    },
                    "correlation_group_id": {"type": "keyword"},
                    "chain_ids": {"type": "keyword"},
                    "chain_depth": {"type": "integer"},
                    "correlation_boost": {"type": "float"},
                    "chain_boost": {"type": "float"},
                    "event_count_in_group": {"type": "integer"},
                    "technique_sequence": {"type": "keyword"},
                    "detection_metadata": {"type": "object", "dynamic": True},
                },
            },
        },
        "priority": 501,
    }


def correlation_index_template() -> dict:
    return {
        "index_patterns": ["ics-correlations-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "dynamic": True,
                "properties": {
                    "group_id": {"type": "keyword"},
                    "asset_id": {"type": "keyword"},
                    "asset_name": {"type": "keyword"},
                    "first_timestamp": {"type": "date"},
                    "last_timestamp": {"type": "date"},
                    "chain_ids": {"type": "keyword"},
                    "chain_depth": {"type": "integer"},
                    "aggregate_score": {"type": "float"},
                    "event_count": {"type": "integer"},
                    "technique_sequence": {"type": "keyword"},
                },
            },
        },
        "priority": 501,
    }
