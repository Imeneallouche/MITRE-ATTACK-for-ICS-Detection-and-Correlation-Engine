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



# ICS Detection and Correlation Engine Design

## 1. Architecture Overview

The detection engine processes ICS/OT log events from Elasticsearch, matches them against MITRE ATT&CK for ICS data components, correlates related events into attack chains, and generates alerts.

```
Filebeat -> Logstash (parse + enrich) -> Elasticsearch -> Detection Engine -> Alerts
                                                                           -> Correlations
```

### Data Flow

1. **Filebeat** collects logs from all GRFICS containers via volume mounts
2. **Logstash** parses, normalizes, and enriches each event with:
   - `log_source_normalized`: canonical log source name (e.g., `ics:modbus_io`)
   - `mitre_dc_candidates`: list of MITRE ATT&CK data component IDs from `log_source_to_dc.yml`
   - `mitre_keyword_hits`: dict of `{DC_ID: [matched_keywords]}` from keyword tagger
3. **Elasticsearch** stores enriched events in `ics-*` indices
4. **Detection Engine** (Python):
   a. Polls new events from Elasticsearch via Point-in-Time API
   b. Normalizes each event into a `NormalizedEvent` struct
   c. Scores the event against MITRE ATT&CK data component profiles
   d. Correlates matches into groups by asset and time window
   e. Applies chain-step boosting for known attack patterns
   f. Emits alerts and correlation records to dedicated ES indices

## 2. Scoring Model

The engine uses a multi-signal weighted scoring model. Each event is scored against each data component profile using five signals:

| Signal | Weight | Description |
|--------|--------|-------------|
| `log_source_match` | 0.40 | Whether the Logstash pipeline mapped this event's log source to this data component via `mitre_dc_candidates` |
| `keyword_match` | 0.20 | Ratio of DC-specific keywords found in the event (from `mitre_keyword_hits` or text search) |
| `category_match` | 0.20 | Overlap between inferred event categories and the DC profile's categories |
| `field_match` | 0.10 | Presence of DC-relevant fields (ICS-aware field mapping for OT data components) |
| `channel_match` | 0.10 | Fuzzy match of log channel descriptors against event content |

### Scoring Formula

```
similarity = Σ(signal_i × weight_i), clamped to [0, 1]
```

### Thresholds

| Threshold | Value | Purpose |
|-----------|-------|---------|
| `candidate_threshold` | 0.35 | Minimum score to consider a DC match |
| `alert_threshold` | 0.45 | Minimum score to generate an alert |
| `high_confidence_threshold` | 0.70 | Score for "high confidence" classification |
| `unknown_asset_penalty` | 0.05 | Score reduction when the source asset is not in `assets.json` |

### Why `log_source_match` is Weighted Highest

The Logstash pipeline performs deterministic mapping from normalized log sources to data components using the curated `log_source_to_dc.yml` dictionary. This mapping is authoritative -- if Logstash says a `linux:auth` event maps to DC0002 and DC0067, that mapping is correct by definition.

The engine trusts this mapping and gives it the highest weight (0.40). The remaining signals provide confidence calibration and help disambiguate when an event maps to multiple DCs.

This design follows the principle established by Mavroeidis and Bromander (2017) in "Cyber Threat Intelligence Model: An Evaluation of Taxonomies" -- structured, curated mappings outperform heuristic text matching for threat classification.

## 3. Correlation Model

### Temporal Grouping

Events from the same asset within a configurable time window (default: 300 seconds) are grouped into `CorrelationGroup` objects. Groups track:

- The sequence of distinct data components observed (`chain_ids`)
- The depth of the attack chain (`chain_depth`)
- An aggregate score that increases with correlation and chain evidence

### Chain-Step Boosting

The engine maintains a set of known attack-chain transitions (DC pairs that commonly occur in sequence during ICS attacks). When an event's DC follows a known predecessor DC in the same group, the aggregate score receives a chain-step boost (default: +0.12).

Example ICS chain rules:
- DC0078 (Network Traffic Flow) → DC0085 (Network Traffic Content): reconnaissance escalation
- DC0067 (Logon Session) → DC0038 (Application Log): credential-based access
- DC0085 (Network Traffic Content) → DC0109 (Process/Event Alarm): Modbus write → process impact
- DC0033 (Process Termination) → DC0109 (Process/Event Alarm): service disruption → process impact

This approach is informed by MITRE ATT&CK for ICS's kill-chain model and the concept of "attack graphs" described by Sheyner et al. (2002).

### Cross-Asset Correlation

Network-related data components (DC0078, DC0082, DC0085) are eligible for cross-asset correlation, reflecting the reality that network events naturally span multiple endpoints.

### Repeat Escalation

When the same data component fires repeatedly for the same asset (≥3 times within the window), an additional correlation boost is applied. This captures the pattern of sustained Modbus write attacks where the same technique is applied repeatedly.

## 4. ICS-Specific Design Decisions

### ICS Field Mapping

The DC JSON profile files define fields using Windows/enterprise terminology (e.g., `EventID`, `ProcessName`, `ParentProcessId`). The GRFICS environment produces Linux and ICS-specific fields. The engine maintains an `ICS_FIELD_MAP` dictionary that maps data component IDs to the actual fields present in GRFICS events:

- DC0109 (Process/Event Alarm): `ics.alarm_type`, `ics.severity`, `modbus.function_code`
- DC0078 (Network Traffic Flow): `src_ip`, `dst_ip`, `src_port`, `dest_port`, `protocol`
- DC0085 (Network Traffic Content): `event_type`, `alert.signature`, `ics.protocol`

### Category Alignment

The `infer_categories` function maps GRFICS event content to the category taxonomies used in DC profiles. For ICS events, this includes:
- `operational_technology`, `process_control`, `safety`, `availability` (for DC0109, DC0108)
- `network_traffic`, `traffic_analysis`, `deep_packet_inspection` (for DC0078, DC0082, DC0085)
- `authentication`, `user_session`, `remote_access` (for DC0067, DC0002)

### Asset Mapping

The `assets.json` file maps all GRFICS assets including all six simulation Modbus devices (.10-.15), ensuring Modbus traffic to any device is attributed to a known ICS asset rather than penalized as "unknown."

## 5. Data Component Coverage

The engine covers all 36 MITRE ATT&CK for ICS data components defined in the `datacomponents/` directory. The Logstash `log_source_to_dc.yml` mapping covers the following ICS-specific log sources:

| Log Source | Data Components | GRFICS Origin |
|-----------|----------------|---------------|
| `ics:process_alarm` | DC0109, DC0108 | Simulation process alarms |
| `ics:modbus_io` | DC0109, DC0078, DC0085, DC0107 | Simulation Modbus I/O logs |
| `ics:plc_app` | DC0109, DC0038, DC0108 | OpenPLC application logs |
| `ics:sim_process` | DC0107, DC0109, DC0038 | TE simulation process logs |
| `ics:sim_error` | DC0108, DC0109 | Simulation error logs |
| `ics:netfilter` | DC0078, DC0082 | Router ulogd/netfilter JSON |
| `ics:fw_app` | DC0038, DC0061 | Router Flask UI logs |
| `hmi:catalina` | DC0038, DC0109 | SCADA-LTS Tomcat logs |
| `hmi:supervisor` | DC0038, DC0060, DC0033 | HMI supervisor logs |
| `NSM:Flow` | DC0002, ..., DC0085, DC0102 | Suricata network flows |
| `linux:auth` | DC0002, DC0067 | SSH/PAM authentication |
| `auditd:*` | DC0032, DC0033, DC0064, ... | Linux audit framework |

## 6. References

- MITRE ATT&CK for ICS, v18.0 (2025). https://attack.mitre.org/techniques/ics/
- Mavroeidis, V. and Bromander, S. (2017). "Cyber Threat Intelligence Model: An Evaluation of Taxonomies, Sharing Standards, and Ontologies within Cyber Threat Intelligence." European Intelligence and Security Informatics Conference.
- Sheyner, O. et al. (2002). "Automated Generation and Analysis of Attack Graphs." IEEE Symposium on Security and Privacy.
- Conti, M. et al. (2018). "A Survey on Industrial Control System Testbeds and Datasets for Security Research." IEEE Communications Surveys & Tutorials.
- Formby, D., Durbha, S., and Beyah, R. (2017). "Out of Control: Ransomware for Industrial Control Systems." RSA Conference.
- Fortiphyd Logic (2021). "GRFICSv3: Graphical Realism Framework for Industrial Control Simulations." https://github.com/Fortiphyd/GRFICSv3
