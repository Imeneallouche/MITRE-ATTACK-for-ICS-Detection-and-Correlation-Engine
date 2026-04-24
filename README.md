# MITRE ATT&CK for ICS — Detection and Correlation Engine

Near-real-time detection pipeline for **GRFICS**-style ICS/OT labs: logs flow through **Filebeat → Logstash → Elasticsearch**; the Python engine polls `ics-*` indices, applies a **two-tier** matcher (**log-source / enrichment / semantic gate** → **weighted composite score**), maps events to **MITRE ATT&CK for ICS DataComponents** using **sentence embeddings** (default **BAAI/bge-small-en-v1.5**), optionally maps to **techniques** via a **Neo4j** knowledge graph (v18 schema), **correlates** multi-stage activity (with **temporal decay** on boosts), and writes **explainable alerts** to Elasticsearch.

**Optional intelligent layer** — a separate `learning/` package can sit on top of the same `ics-alerts-*` stream: a **PU alert classifier** (Layer A), **causal-window Transformer** chain attributor (Layer B), **analyst-guided triage** policy (Layer C, contextual bandit with safety rails), and **Neo4j‑grounded multi-agent LLM** mitigation reports (Layer D). It reuses the engine’s `Neo4jClient` and does not replace the deterministic detection core. See [Learning-enhanced detection](#learning-enhanced-detection).

---

## What the engine does

| Stage | Behavior |
|--------|----------|
| **Ingest (upstream)** | Filebeat ships logs; Logstash sets `log_source_normalized`, `mitre_dc_candidates`, `mitre_keyword_hits`. |
| **Normalize** | Each ES hit becomes a `NormalizedEvent` (asset, IP, categories, enrichment fields, **embedding text** for semantic scoring). |
| **Gate (Tier 1)** | Keep a DataComponent if Logstash enrichment matches, **or** `log_source_normalized` matches a DC log source (exact/prefix), **or** **cosine similarity** (event vs. DC embedding) ≥ `embeddings.semantic_gate_threshold`. |
| **Score (Tier 2)** | **Weighted composite** over five signals: **semantic**, log source (graduated), keywords, fields, categories (see [Scoring model](#scoring-model)). |
| **Technique inference** | **Neo4j** path `DataComponent ← Analytic ← DetectionStrategy → Technique`, or **offline fallback** DC→technique map if the graph is disabled or unreachable. |
| **Correlate** | Temporal groups per asset (with cross-asset rules for network DCs), **chain-step boosts** for known DC transitions, **exponential decay** on correlation boosts, repeat escalation. |
| **Alert** | Documents in `ics-alerts-*` (includes `semantic_score`, `gate_reason`, `signal_scores`); correlation summaries in `ics-correlations-*`. |

**Excluded by design:** events whose `asset_id` is `kali` or `caldera` (attacker/C2 simulation).

For architecture, formulas, graph queries, and module details, see [`docs/ICS Detection Engine Design.md`](docs/ICS%20Detection%20Engine%20Design.md).

---

## Repository layout

| Path | Role |
|------|------|
| `engine/` | Python package: runtime, config, models, feature extraction, DC loader, **embeddings** (`sentence-transformers`), **scorer**, **matcher** (Tier-1 gate + Tier-2 scoring), **correlation**, **alerting**, **Neo4j client**, **technique mapper**, ES client, index templates. |
| `engine/embeddings.py` | DC/event embeddings, cosine similarity, precomputed DC vectors at startup. |
| `engine/Dockerfile` | Optional container image for the detection engine (Python 3.11, deps, model pre-download). |
| `engine/__main__.py` | Entry: `python3 -m engine ...` |
| `config/detection.yml` | Thresholds, **embedding** model and gate, weights, correlation (including **decay**), Elasticsearch, **Neo4j**, technique-mapper knobs, paths, checkpoint. |
| `datacomponents/*.json` | Normalized MITRE ATT&CK for ICS DataComponent profiles (36 files). |
| `assets.json` | Asset inventory (IPs, zones, `is_ics_asset`, roles) for attribution and penalties. |
| `filebeat/filebeat.yml` | Per-asset log collection: all GRFICS `shared_logs` exports (Linux auth/syslog/audit/kern/cron/pacct, simulation process alarms + supervisor + nginx, PLC app + OpenPLC debug, HMI Tomcat + supervisor, router Suricata EVE/fast/engine/app + ulogd + netfilter JSON + Flask + supervisor, EWS desktop/VNC logs). |
| `logstash/pipeline/*.conf` | Parse, normalize, route; `20-enrich-mitre.conf` applies MITRE mapping. |
| `logstash/mitre_mapping/log_source_to_dc.yml` | Maps `log_source_normalized` → DC ID list. |
| `logstash/mitre_mapping/dc_keywords.json` | Keywords per DC (Ruby keyword tagger). |
| `logstash/mitre_mapping/keyword_tagger.rb` | Populates `mitre_keyword_hits`. |
| `docker-compose.yml` | GRFICS stack + Elasticsearch, Logstash, Kibana, Filebeat, optional **`detection-engine`** service. |
| `scripts/generate_mitre_mapping.py` | Regenerates mapping artifacts from `datacomponents/`. |
| `docs/ICS Detection Engine Design.md` | Architecture, two-tier scoring, correlation, Neo4j, alert schema. |
| `docs/GRFICS ICS OT attack chain design with Caldera.md` | Caldera adversary chains for the lab. |
| `docs/Learning-Component-Design-and-Implementation.md` | **Learning package:** design, data flow, modules, API, training workflows, safety. |
| `docs/Learning-Enhanced ICS Detection and Mitigation Recommendation.md` | Feasibility study: paradigms (PU, bandit, RAG) and research rationale. |
| `learning/` | **Optional** intelligent layer: Layer A (PU alert classifier), B (causal-window Transformer for chains/techniques), C (triage: LinUCB / optional DQN + AVAR), D (KG-grounded 4-agent LLM mitigations), `orchestrator`, `api` (FastAPI), `eval`. |
| `config/learning.yml` | Paths, layer toggles, training hyperparameters, API host/port, Layer D safety and LLM settings. |
| `state/learning/` (default) | Window labels (`labels.jsonl`), trained artefacts (`layer_a/`, `layer_b/`, `layer_c/`), AVAR cache, evaluation metrics. |
| `scripts/learning/` | `smoke_pipeline.py` (end-to-end smoke test), `train_all.py`, `import_caldera.py`, `label_window.py` (CLI wrappers). |

---

## Learning-enhanced detection

**Optional.** The **`learning/`** package augments engine alerts with **adaptive scoring**, **chain + technique attribution**, **advisory triage** (with deterministic safety rails), and **mitigation reports** retrieved from the same MITRE ATT&CK for ICS **Neo4j** graph the engine already uses. The detection engine’s polling, matching, and alerting code paths are unchanged; the learning service consumes `ics-alerts-*` and optional time-window labels.

| Layer | Role |
|-------|------|
| **A** | Positive–unlabeled (PU) alert classifier: improves true/false-positive separation using weak window labels. |
| **B** | Per-asset sequence model (causal-window Transformer) for attack-chain and technique/tactic prediction. |
| **C** | Triage policy (contextual bandit; optional DQN) with **AVAR** (analyst-validated alert cache) and hard-coded accept / defer / ambiguity **safety rails**. |
| **D** | Planner → Generator → Analyst → Reflector **multi-agent** pipeline; mitigations are **grounded in KG retrieval**, not free-generated. |

**Documentation**

| Document | Content |
|----------|---------|
| [`docs/Learning-Component-Design-and-Implementation.md`](docs/Learning-Component-Design-and-Implementation.md) | Full **design and implementation** reference: integration with the engine, data flow, modules, configuration, API, evaluation, limitations. |
| [`docs/Learning-Enhanced ICS Detection and Mitigation Recommendation.md`](docs/Learning-Enhanced%20ICS%20Detection%20and%20Mitigation%20Recommendation.md) | Earlier **feasibility study** (why PU / bandit / RAG, literature alignment). |

**Configuration:** `config/learning.yml` (override path with `LEARNING_CONFIG_PATH`). **State and labels:** under `state/learning/` by default.

**Quick start**

```bash
# From repo root, after: pip install -r requirements.txt
mkdir -p state/learning

# Import a Caldera report as an under-attack time window (see Caldera Reports/)
python3 -m learning.cli import-caldera --defender-asset plc --defender-asset hmi --pad-seconds 60

# Add a benign baseline window (operator labels)
python3 -m learning.cli add-label --start 2026-04-24T00:00:00Z --end 2026-04-24T12:00:00Z --label benign

# Train (requires alerts in ics-alerts-* and matching labels; or use --fixture)
python3 -m learning.cli train-layer-a  --es-hosts http://localhost:9200
python3 -m learning.cli train-layer-b  --es-hosts http://localhost:9200 --engine-config config/detection.yml
python3 -m learning.cli train-layer-c  --es-hosts http://localhost:9200

# HTTP API (default host/port from config/learning.yml: 0.0.0.0:8090)
python3 -m learning.cli serve --es-hosts http://localhost:9200
```

**Smoke test (no ES / Neo4j / LLM required for wiring check):**

```bash
python3 scripts/learning/smoke_pipeline.py
```

**API (when `serve` is running):** `GET /health`, `POST /alerts/score`, `POST /alerts/batch`, `POST /alerts/feedback` (analyst verdicts → AVAR + policy), `GET`/`POST /labels`, `POST /poll/tick` — see `learning/api.py` and the design doc.

**CLI:** `python3 -m learning.cli --help` (subcommands: `import-caldera`, `add-label`, `list-labels`, `train-layer-a|b|c`, `score`, `evaluate`, `serve`).

---

## Scoring model

**Tier 1 — candidate gate:** a DataComponent is scored only if enrichment matches, log-source name/prefix matches, or **semantic** cosine similarity ≥ `semantic_gate_threshold` (default **0.25**).

**Tier 2 — composite similarity** for an event vs. a DataComponent profile:

\[
S = w_{sem} S_{sem} + w_{ls} S_{ls} + w_{kw} S_{kw} + w_{fld} S_{fld} + w_{cat} S_{cat}
\]

| Signal | Default weight | Meaning |
|--------|----------------|---------|
| \(S_{sem}\) | **0.40** | Cosine similarity between embeddings of **event text** vs. **DC text** (description + non-trivial `log_sources` channel strings). |
| \(S_{ls}\) | **0.25** | Graduated log source: enrichment or exact name → 1.0; prefix before `:` → 0.8; same **family** (e.g. Suricata variants) → 0.5. |
| \(S_{kw}\) | **0.15** | Keyword overlap vs. DC keywords; optional IDF-style scaling; Logstash `mitre_keyword_hits` when present. |
| \(S_{fld}\) | **0.10** | **Jaccard**-style overlap on field keys; **ICS_FIELD_MAP** adds OT-specific keys per DC. |
| \(S_{cat}\) | **0.10** | **Jaccard** overlap between inferred categories and the DC profile’s categories. |

Values are clamped to \([0,1]\). The legacy **channel token-ratio** signal is replaced by **\(S_{sem}\)**.

Thresholds in `config/detection.yml` (defaults): `candidate_threshold` (**0.30**), `alert_threshold` (**0.55**), `high_confidence_threshold` (**0.80**), `unknown_asset_penalty`, `embeddings.semantic_gate_threshold` (**0.25**).

---

## Knowledge graph and techniques

- **With Neo4j** (`neo4j.enabled: true` and valid `uri` / credentials): at startup the engine **warms a cache** of DC→technique paths from the v18 graph (via `DetectionStrategy` / `Analytic` / `USES` / `DETECTS`).
- **Without Neo4j** (default `enabled: false`) or on connection failure: **fallback** DC→technique suggestions are used so alerts still include probable ICS techniques.

Technique ranking uses configurable weights `technique_mapper.alpha_group` and `alpha_asset` (see `config/detection.yml` and `docs/ics_detection_engine_design.md`).

---

## Correlation

- **Window:** `correlation.window_seconds` (default 300s) for grouping matches on the same asset.
- **Chain rules:** 70+ allowed DC→DC transitions (including SSH/lateral-style pairs aligned with documented Caldera chains); **chain_step_boost** increases the aggregate score when a transition matches.
- **Temporal decay:** correlation/repeat boosts are scaled by `exp(-0.693 × Δt / decay_half_life_seconds)` (default half-life **120s**).
- **Cross-asset:** Network-related DCs (e.g. DC0078, DC0082, DC0085) can correlate across assets.
- **Repeat escalation:** Same DC firing often within a group adds **correlation_boost** (capped by `max_correlation_boost`).

---

## Prerequisites

- **Python 3.10+** recommended (3.11 used in `engine/Dockerfile`).
- **Elasticsearch 8.x** reachable from the machine running the engine (same host as `docker-compose` → typically `http://localhost:9200`).
- **Indices:** populated `ics-*` events (run Filebeat + Logstash + GRFICS stack or your own pipeline that produces the same enriched fields).
- **Python deps:** `sentence-transformers`, `torch`, `numpy` (see `requirements.txt`) for **semantic** scoring. Use `--no-embeddings` to run without loading the model (gate and scoring rely on enrichment/log-source signals; \(S_{sem}=0\)).
- **Optional (learning package):** `scikit-learn`, `xgboost` (or sklearn fallback), `fastapi`, `uvicorn`, `openai` / compatible LLM API for Layer D. Heavy pieces (`torch` for Layer B) are only needed if you train or run those layers; `python3 scripts/learning/smoke_pipeline.py` exercises the wiring with minimal services.
- **Optional:** **Neo4j** 5.x with the MITRE ATT&CK for ICS v18 graph loaded (see the separate `MITRE-ATTACK-for-ICS-Knowledge-Graph` project). The learning Layer D retriever reuses the same graph as the engine.

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

Optional: run the **detection engine** as a container (same compose file):

```bash
docker compose up -d detection-engine
```

The compose file sets **`ELASTICSEARCH_HOSTS=http://elasticsearch:9200`** for that service so the engine does not use `localhost:9200` (which would point at the engine container itself). It also passes **`--bootstrap-templates`** on startup so alert/correlation index templates are registered in Elasticsearch.

**Note:** The concrete index **`ics-alerts-YYYY.MM.DD`** is created when the **first alert document** is indexed. If the lab has little or no matching `ics-*` traffic yet, you may see templates but no daily alert index until an event scores above the alert threshold.

Wait until Elasticsearch is healthy (`curl -s http://localhost:9200/_cluster/health`).

### 3. Python virtual environment and dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

This installs `elasticsearch`, `PyYAML`, `python-dateutil`, `neo4j`, `numpy`, `sentence-transformers`, `torch`, and — for the **learning** service — `scikit-learn`, `xgboost`, `fastapi`, `uvicorn`, `openai` (LLM; optional at runtime if using the mock agent), etc. First run may download the embedding model (~hundreds of MB) unless already cached.

### 4. Configure the engine

Edit **`config/detection.yml`**:

- **`elasticsearch.hosts`:** e.g. `http://localhost:9200` or `http://elasticsearch:9200` if the engine runs inside the same Docker network.
- **`elasticsearch.source_index_pattern`:** default `ics-*` (must match your enriched indices).
- **`paths.datacomponents_dir`** and **`paths.assets_file`:** defaults `./datacomponents` and `./assets.json` (paths are relative to the **current working directory** when you launch the engine).
- **`engine.checkpoint_file`:** default `./state/engine_checkpoint.json` — ensure the directory exists (see step 5).
- **`embeddings`:** `model` (default `BAAI/bge-small-en-v1.5`), `device` (`cpu` or `cuda`), `semantic_gate_threshold`, `enabled`.
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

**Skip semantic embeddings** (no `sentence-transformers` load; faster CI / debugging):

```bash
python3 -m engine --config config/detection.yml --mode stream --no-embeddings
```

### 9. Verify output

- **Alerts:** index pattern `ics-alerts-*` (or whatever `alert_index_pattern` expands to, e.g. daily `ics-alerts-2026.04.09`). Fields include **`semantic_score`**, **`gate_reason`**, and per-signal **`signal_scores`** (`semantic_match`, `log_source_match`, …).
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
- **Embeddings:** First startup downloads/caches the Hugging Face model unless pre-baked (e.g. `engine/Dockerfile` build step).
- **Learning service:** use `state/learning/` (or paths in `config/learning.yml`) for labels and models; the learning HTTP API is separate from the engine process unless you colocate them.

---

## CLI reference

| Argument | Description |
|----------|-------------|
| `--config PATH` | Path to YAML config (default: `config/detection.yml`). |
| `--mode stream \| oneshot \| backtest` | Execution mode. |
| `--start`, `--end` | Required for `backtest` (ISO8601 timestamps). |
| `--bootstrap-templates` | Push/update ES index templates for alerts and correlations. |
| `--no-graph` | Disable Neo4j even if enabled in config. |
| `--no-embeddings` | Do not load the embedding model; semantic scores are zero; gating uses enrichment/log-source rules only. |

---

## Engine modules (quick map)

| Module | Responsibility |
|--------|----------------|
| `engine/runtime.py` | CLI, stream/oneshot/backtest loops, wiring, `EmbeddingEngine`, `--no-embeddings`. |
| `engine/config.py` | Loads `detection.yml` (Elasticsearch, Neo4j, embeddings, technique mapper). |
| `engine/models.py` | `NormalizedEvent`, `CandidateMatch`, `DetectionAlert`, `TechniqueAttribution`, … |
| `engine/embeddings.py` | `sentence-transformers` wrapper; DC cache; cosine similarity. |
| `engine/feature_extractor.py` | ES `_source` → `NormalizedEvent`; **embedding text**; categories; enrichment. |
| `engine/dc_loader.py` | Load DC JSON; **build_dc_embedding_text** (description + channels). |
| `engine/scorer.py` | Graduated log-source, keyword, field, category; composite \(S\). |
| `engine/matcher.py` | Tier-1 gate + Tier-2 scoring vs. DC profiles (**ICS_FIELD_MAP**). |
| `engine/correlation.py` | Temporal groups, chain rules, decay, cross-asset, pruning. |
| `engine/neo4j_client.py` | Bolt driver, cache warmup, DC→technique queries. |
| `engine/technique_mapper.py` | Probable technique + mitigations / reasoning. |
| `engine/alerting.py` | Build alert documents, suppression window, `semantic_score` / `gate_reason`. |
| `engine/es_client.py` | PIT, poll, index documents. |
| `engine/templates.py` | Index templates for alerts/correlations. |

**Learning package** (separate from `python3 -m engine`): `learning/orchestrator.py` (A→B→C→D), `learning/api.py` (FastAPI), `learning/cli.py`. Full module map: *Appendix B* in [`docs/Learning-Component-Design-and-Implementation.md`](docs/Learning-Component-Design-and-Implementation.md).

---

## Attack emulation (Caldera)

Adversary YAML and abilities live under **`Caldera Attack Chains/`**. Detailed chain steps, abilities, and telemetry are in **`docs/GRFICS ICS OT attack chain design with Caldera.md`**.

---

## References

- MITRE ATT&CK for ICS: https://attack.mitre.org/matrices/ics/
- GRFICS-style lab: Fortiphyd [GRFICSv3](https://github.com/Fortiphyd/GRFICSv3)
- Further reading: [`docs/ICS Detection Engine Design.md`](docs/ICS%20Detection%20Engine%20Design.md) (architecture diagrams, DC coverage tables, limitations).
- Learning component: [`docs/Learning-Component-Design-and-Implementation.md`](docs/Learning-Component-Design-and-Implementation.md) (design + implementation), [`docs/Learning-Enhanced ICS Detection and Mitigation Recommendation.md`](docs/Learning-Enhanced%20ICS%20Detection%20and%20Mitigation%20Recommendation.md) (feasibility / research rationale).
