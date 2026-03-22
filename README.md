# ICS DataComponent Detection and Correlation Engine

This repository now includes a full implementation scaffold for a near-real-time ICS/OT detection system that:

- ingests logs with Filebeat and Logstash,
- normalizes and enriches events in Elasticsearch,
- matches events to MITRE ATT&CK for ICS DataComponents from `datacomponents/*.json`,
- computes explainable similarity scores,
- correlates events into multi-step detections,
- emits structured alerts back into Elasticsearch.

## Directory Layout

- `filebeat/filebeat.yml`: Per-asset log collection config aligned to the provided `docker-compose.yml`.
- `logstash/pipeline/*.conf`: Input, parse, enrich, and output routing pipeline stages.
- `logstash/mitre_mapping/log_source_to_dc.yml`: Log source to DataComponent mapping.
- `logstash/mitre_mapping/dc_keywords.json`: Keywords per DataComponent.
- `logstash/mitre_mapping/keyword_tagger.rb`: Keyword-based enrichment for Logstash events.
- `config/detection.yml`: Runtime tuning and thresholds for detection engine.
- `assets.json`: Asset inventory including ICS assets and simulation-only assets (`kali`, `caldera`).
- `engine/`: Python implementation (models, loader, matcher, scorer, correlation, ES integration).
- `scripts/generate_mitre_mapping.py`: Generates mapping files from `datacomponents/*.json`.
- `elasticsearch/templates/*.json`: Index templates for alerts and correlations.

## Engine Features Implemented

- **Streaming mode** (`--mode stream`): PIT + `search_after` polling.
- **Oneshot mode** (`--mode oneshot`): Single polling cycle.
- **Backtest mode** (`--mode backtest --start ... --end ...`): Historical replay.
- **Weighted scoring (0..1)**:
  - log source match,
  - keyword match,
  - field overlap,
  - category alignment,
  - channel matching.
- **Correlation**:
  - per-asset temporal grouping,
  - chain rule boosts,
  - repeated event aggregation.
- **Alert emission**:
  - full structured JSON output,
  - evidence and signal score transparency,
  - suppression window to reduce duplicates.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Generate MITRE Mapping Artifacts

```bash
python3 scripts/generate_mitre_mapping.py
```

## Run Detection Engine

### Stream Mode (default)

```bash
python3 -m engine --config config/detection.yml --mode stream --bootstrap-templates
```

### Oneshot

```bash
python3 -m engine --config config/detection.yml --mode oneshot --bootstrap-templates
```

### Backtest

```bash
python3 -m engine --config config/detection.yml --mode backtest \
  --start 2026-03-22T00:00:00Z \
  --end 2026-03-23T00:00:00Z \
  --bootstrap-templates
```

## Notes

- Events from `kali` and `caldera` are excluded from ICS alerting by design.
- Thresholds and scoring weights are configurable in `config/detection.yml`.
- Checkpoint state is persisted in `state/engine_checkpoint.json`.
