# MITRE ATT&CK for ICS — Detection and Correlation Engine

Near-real-time detection pipeline for **GRFICS**-style ICS/OT labs: logs flow through **Filebeat → Logstash → Elasticsearch**; the Python engine polls `ics-*` indices, matches events to **MITRE ATT&CK for ICS DataComponents**, optionally maps to **techniques** via a **Neo4j** knowledge graph (v18 schema), **correlates** multi-stage activity, and writes **explainable alerts** to Elasticsearch.

---

## What the engine does

| Stage | Behavior |
|--------|----------|
| **Ingest (upstream)** | Filebeat ships logs; Logstash sets `log_source_normalized`, `mitre_dc_candidates`, `mitre_keyword_hits`. |
| **Normalize** | Each ES hit becomes a `NormalizedEvent` (asset, IP, categories, enrichment fields). |
| **Match** | **Weighted similarity** across five signals: log source, keywords, fields, categories, channel (see [Scoring model](#scoring-model)). |
| **Technique inference** | **Neo4j** path `DataComponent ← Analytic ← DetectionStrategy → Technique`, or **offline fallback** DC→technique map if the graph is disabled or unreachable. |
| **Correlate** | Temporal groups per asset (with cross-asset rules for network DCs), **chain-step boosts** for known DC transitions, repeat escalation. |
| **Alert** | Documents in `ics-alerts-*`; correlation summaries in `ics-correlations-*`. |

**Excluded by design:** events whose `asset_id` is `kali` or `caldera` (attacker/C2 simulation).

For a full design reference (formulas, graph queries, module list), see [`docs/ics_detection_engine_design.md`](docs/ics_detection_engine_design.md).

---

## Repository layout

| Path | Role |
|------|------|
| `engine/` | Python package: runtime, config, models, feature extraction, DC loader, **scorer** (Jaccard / Aho-Corasick / optional IDF), **matcher**, **correlation**, **alerting**, **Neo4j client**, **technique mapper**, ES client, index templates. |
| `engine/__main__.py` | Entry: `python3 -m engine ...` |
| `config/detection.yml` | Thresholds, weights, correlation, Elasticsearch, **Neo4j**, technique-mapper knobs, paths, checkpoint. |
| `datacomponents/*.json` | Normalized MITRE ATT&CK for ICS DataComponent profiles (36 files). |
| `assets.json` | Asset inventory (IPs, zones, `is_ics_asset`, roles) for attribution and penalties. |
| `filebeat/filebeat.yml` | Per-asset log collection: all GRFICS `shared_logs` exports (Linux auth/syslog/audit/kern/cron/pacct, simulation process alarms + supervisor + nginx, PLC app + OpenPLC debug, HMI Tomcat + supervisor, router Suricata EVE/fast/engine/app + ulogd + netfilter JSON + Flask + supervisor, EWS desktop/VNC logs). |
| `logstash/pipeline/*.conf` | Parse, normalize, route; `20-enrich-mitre.conf` applies MITRE mapping. |
| `logstash/mitre_mapping/log_source_to_dc.yml` | Maps `log_source_normalized` → DC ID list. |
| `logstash/mitre_mapping/dc_keywords.json` | Keywords per DC (Ruby keyword tagger). |
| `logstash/mitre_mapping/keyword_tagger.rb` | Populates `mitre_keyword_hits`. |
| `docker-compose.yml` | GRFICS stack + Elasticsearch, Logstash, Kibana, Filebeat, etc. |
| `scripts/generate_mitre_mapping.py` | Regenerates mapping artifacts from `datacomponents/`. |
| `docs/ics_detection_engine_design.md` | Architecture, scoring, correlation, Neo4j, alert schema. |
| `docs/GRFICS ICS OT attack chain design with Caldera*.md` | Caldera adversary chains for the lab. |

---

## Scoring model

Composite similarity for an event vs. a DataComponent profile:

\[
S = w_{ls} S_{ls} + w_{kw} S_{kw} + w_{fld} S_{fld} + w_{cat} S_{cat} + w_{ch} S_{ch}
\]

| Signal | Default weight | Meaning |
|--------|----------------|---------|
| \(S_{ls}\) | **0.40** | Log source: strongest when `profile.id ∈ mitre_dc_candidates` (Logstash mapping). |
| \(S_{kw}\) | **0.20** | Keyword overlap; **Aho-Corasick** multi-pattern scan when `pyahocorasick` is installed. |
| \(S_{fld}\) | **0.10** | **Jaccard**-style overlap on field keys; **ICS_FIELD_MAP** adds OT-specific keys per DC. |
| \(S_{cat}\) | **0.20** | **Jaccard** overlap between inferred categories and the DC profile’s categories. |
| \(S_{ch}\) | **0.10** | Fuzzy match of DC log-source *channel* text against the event body. |

Values are clamped to \([0,1]\). Thresholds in `config/detection.yml`: `candidate_threshold` (minimum match), `alert_threshold` (emit alert), `high_confidence_threshold`, `unknown_asset_penalty`.

---

## Knowledge graph and techniques

- **With Neo4j** (`neo4j.enabled: true` and valid `uri` / credentials): at startup the engine **warms a cache** of DC→technique paths from the v18 graph (via `DetectionStrategy` / `Analytic` / `USES` / `DETECTS`).
- **Without Neo4j** (default `enabled: false`) or on connection failure: **fallback** DC→technique suggestions are used so alerts still include probable ICS techniques.

Technique ranking uses configurable weights `technique_mapper.alpha_group` and `alpha_asset` (see `config/detection.yml` and `docs/ics_detection_engine_design.md`).

---

## Correlation

- **Window:** `correlation.window_seconds` (default 300s) for grouping matches on the same asset.
- **Chain rules:** Dozens of allowed DC→DC transitions (e.g. network recon → content → process alarm); **chain_step_boost** increases the aggregate score when a transition matches.
- **Cross-asset:** Network-related DCs (e.g. DC0078, DC0082, DC0085) can correlate across assets.
- **Repeat escalation:** Same DC firing often within a group adds **correlation_boost** (capped by `max_correlation_boost`).

---

## Prerequisites

- **Python 3.10+** recommended.
- **Elasticsearch 8.x** reachable from the machine running the engine (same host as `docker-compose` → typically `http://localhost:9200`).
- **Indices:** populated `ics-*` events (run Filebeat + Logstash + GRFICS stack or your own pipeline that produces the same enriched fields).
- **Optional:** **Neo4j** 5.x with the MITRE ATT&CK for ICS v18 graph loaded (see the separate `MITRE-ATTACK-for-ICS-Knowledge-Graph` project).

---

## Step-by-step: run the engine

### 1. Clone and enter the repository

```bash
cd /path/to/MITRE-ATTACK-for-ICS-Detection-and-Correlation-Engine
```

### 2. (Optional) Bring up the full lab stack

If you use the bundled `docker-compose.yml` (GRFICS + Elastic + Logstash + Filebeat):

```bash
chmod +x init_shared_logs.sh 2>/dev/null || true
./init_shared_logs.sh   # if present; creates shared log dirs
docker compose up -d elasticsearch logstash kibana filebeat
# ... plus GRFICS services as needed for logs
```

Wait until Elasticsearch is healthy (`curl -s http://localhost:9200/_cluster/health`).

### 3. Python virtual environment and dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

This installs `elasticsearch`, `PyYAML`, `python-dateutil`, `pyahocorasick`, `neo4j`, etc.

### 4. Configure the engine

Edit **`config/detection.yml`**:

- **`elasticsearch.hosts`:** e.g. `http://localhost:9200` or `http://elasticsearch:9200` if the engine runs inside the same Docker network.
- **`elasticsearch.source_index_pattern`:** default `ics-*` (must match your enriched indices).
- **`paths.datacomponents_dir`** and **`paths.assets_file`:** defaults `./datacomponents` and `./assets.json` (paths are relative to the **current working directory** when you launch the engine).
- **`engine.checkpoint_file`:** default `./state/engine_checkpoint.json` — ensure the directory exists (see step 5).
- **Optional Neo4j:** set `neo4j.enabled: true`, `neo4j.uri` (e.g. `bolt://localhost:7687`), `username`, `password`.

### 5. Create state directory (first run)

```bash
mkdir -p state
```

The engine stores the Elasticsearch polling checkpoint in `state/engine_checkpoint.json` (path from `config/detection.yml`).

### 6. (Optional) Regenerate Logstash MITRE mapping files

If you change `datacomponents/*.json`:

```bash
python3 scripts/generate_mitre_mapping.py
```

Restart Logstash after updating `logstash/mitre_mapping/*`.

### 7. Install Elasticsearch index templates (recommended once)

Registers mappings for `ics-alerts-*` and `ics-correlations-*`:

```bash
source .venv/bin/activate
python3 -m engine --config config/detection.yml --bootstrap-templates
```

Run this anytime the alert/correlation template definitions in `engine/templates.py` change.

### 8. Run the engine

Run from the **repository root** so relative paths in `config/detection.yml` resolve.

| Mode | Command | Use case |
|------|---------|----------|
| **Stream** (default) | `python3 -m engine --config config/detection.yml --mode stream` | Continuous near-real-time polling (sleeps `polling_interval_seconds` between cycles). |
| **Oneshot** | `python3 -m engine --config config/detection.yml --mode oneshot` | Single poll cycle; cron or smoke test. |
| **Backtest** | `python3 -m engine --config config/detection.yml --mode backtest --start <ISO8601> --end <ISO8601>` | Replay a time range with PIT + `search_after`. |

**First-time combined run (templates + stream):**

```bash
source .venv/bin/activate
python3 -m engine --config config/detection.yml --mode stream --bootstrap-templates
```

**Backtest example:**

```bash
python3 -m engine --config config/detection.yml --mode backtest \
  --start 2026-03-22T00:00:00Z \
  --end 2026-03-23T00:00:00Z \
  --bootstrap-templates
```

**Force-disable Neo4j** (use only YAML + fallback technique mapping):

```bash
python3 -m engine --config config/detection.yml --mode stream --no-graph
```

### 9. Verify output

- **Alerts:** index pattern `ics-alerts-*` (or whatever `alert_index_pattern` expands to, e.g. daily `ics-alerts-2026.04.09`).
- **Correlations:** `ics-correlations-*`.
- **Kibana:** Discover / Dashboards on those index patterns.

Example query (Dev Tools):

```http
GET ics-alerts-*/_search
{
  "size": 5,
  "sort": [{ "timestamp": "desc" }]
}
```

### 10. Operational notes

- **Checkpoint:** Deleting `state/engine_checkpoint.json` makes the next run re-process from the checkpoint default (`1970-01-01` initial) — use carefully in production.
- **Dedup:** In-memory dedup cache limits duplicate alerts for identical asset/source/time/message keys.
- **Logs:** INFO lines on stderr from logger `ics-detector` (and `ics-detector.neo4j` if the graph is used).

---

## CLI reference

| Argument | Description |
|----------|-------------|
| `--config PATH` | Path to YAML config (default: `config/detection.yml`). |
| `--mode stream \| oneshot \| backtest` | Execution mode. |
| `--start`, `--end` | Required for `backtest` (ISO8601 timestamps). |
| `--bootstrap-templates` | Push/update ES index templates for alerts and correlations. |
| `--no-graph` | Disable Neo4j even if enabled in config. |

---

## Engine modules (quick map)

| Module | Responsibility |
|--------|----------------|
| `engine/runtime.py` | CLI, stream/oneshot/backtest loops, wiring. |
| `engine/config.py` | Loads `detection.yml` (including Neo4j and technique mapper). |
| `engine/models.py` | `NormalizedEvent`, `CandidateMatch`, `DetectionAlert`, `TechniqueAttribution`, … |
| `engine/feature_extractor.py` | ES `_source` → `NormalizedEvent`, categories, enrichment. |
| `engine/dc_loader.py` | Load DC JSON profiles and `assets.json`. |
| `engine/scorer.py` | Jaccard, keyword scoring, Aho-Corasick matcher, composite \(S\). |
| `engine/matcher.py` | Score events vs. DC profiles (`ICS_FIELD_MAP`). |
| `engine/correlation.py` | Temporal groups, chain rules, cross-asset, pruning. |
| `engine/neo4j_client.py` | Bolt driver, cache warmup, DC→technique queries. |
| `engine/technique_mapper.py` | Probable technique + mitigations / reasoning. |
| `engine/alerting.py` | Build alert documents, suppression window. |
| `engine/es_client.py` | PIT, poll, index documents. |
| `engine/templates.py` | Index templates for alerts/correlations. |

---

## Attack emulation (Caldera)

Adversary YAML and abilities live under **`Caldera Attack Chains/`**. Corrected ability snippets and chain notes are in **`docs/GRFICS ICS OT attack chain design with Caldera - CORRECTED.md`**.

---

## References

- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- GRFICS-style lab: Fortiphyd [GRFICSv3](https://github.com/Fortiphyd/GRFICSv3)
- Further reading: `docs/ics_detection_engine_design.md` (architecture diagrams, DC coverage tables, limitations).
