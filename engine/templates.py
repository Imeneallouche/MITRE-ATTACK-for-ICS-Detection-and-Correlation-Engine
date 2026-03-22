from __future__ import annotations


def alert_index_template() -> dict:
    return {
        "index_patterns": ["ics-alerts-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "dynamic": True,
                "properties": {
                    "datacomponent": {"type": "keyword"},
                    "datacomponent_id": {"type": "keyword"},
                    "asset_id": {"type": "keyword"},
                    "asset_name": {"type": "keyword"},
                    "es_index": {"type": "keyword"},
                    "document_id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "similarity_score": {"type": "float"},
                    "evidence_snippet": {"type": "text"},
                    "log_message": {"type": "text"},
                    "rule_or_pattern": {"type": "keyword"},
                    "detection_id": {"type": "keyword"},
                    "detection_metadata": {"type": "object", "dynamic": True},
                    "matched_fields": {"type": "object", "dynamic": True},
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
                },
            },
        },
        "priority": 501,
    }
