# Collected logs — GRFICS lab pipeline

This document describes **which log files are shipped** from the ICS/OT simulation into Elasticsearch, how they are **classified** for MITRE ATT&CK for ICS detection, and how that relates to **DataComponents** (DCs). It complements `GRFICS envrionment detailed exploration.md` (topology and services).

## Design goals

- **High signal**: Prefer authentication, audit, ICS process/alarms, IDS eve JSON, and firewall JSON over generic desktop or container stdout noise.
- **Traceability**: Every stream has a Filebeat `log_type`, a Logstash-derived `log_source_normalized`, and optional `mitre_dc_candidates` from `logstash/mitre_mapping/log_source_to_dc.yml` plus keyword tagging (`keyword_tagger.rb`).
- **Extensibility**: Adding a source = new Filebeat input + Logstash normalization (`logstash/pipeline/14-parse-suricata-and-ics.conf` or syslog/auth/audit chains) + dictionary row in `log_source_to_dc.yml`. No Python detection-engine code changes are required for mapping.

## End-to-end flow

1. **Host paths** under `./shared_logs/...` are bind-mounted from ICS containers (`docker-compose.yml`).
2. **Filebeat** reads files, adds `asset_id`, `asset_ip`, `log_type`, and ships to Logstash `:5044`.
3. **Logstash** parses (grok/JSON), sets `log_source_normalized`, enriches with MITRE DC candidates and keywords, routes to daily indices (`logstash/pipeline/30-output.conf`).
4. **Detection engine** consumes `ics-*` indices and matches events to DC profiles under `datacomponents/`.

## DataComponent coverage model

Each JSON file in `datacomponents/` lists many **MITRE canonical log source names** (e.g. `WinEventLog:Security`, `linux:auth`, `NSM:Flow`) under `log_sources[].Name`. The full ATT&CK ICS corpus spans **hundreds** of vendor-specific names; the GRFICS lab implements a **focused subset** that maps to Linux syslog/auth/audit, Suricata, netfilter, and ICS app logs.

The table below maps **this deployment’s** `log_source_normalized` values (after Logstash) to **representative DC families**—not every DC in the repo, but those most directly fed by this stack:

| log_source_normalized | Primary DC themes | Role |
|----------------------|-------------------|------|
| `linux:auth` | DC0067, DC0002, DC0088 | SSH/PAM sessions |
| `auditd:*` | DC0032–DC0034, DC0039–DC0040, DC0061, DC0064 | Syscall/exec/file |
| `linux:syslog`, `linux:daemon`, `linux:kern`, `linux:cron` | DC0033, DC0060, DC0016, DC0001/DC0005 | Processes, services, modules, jobs |
| `NSM:Flow`, `NSM:Connections` | DC0078, DC0082, DC0085 | Suricata eve / fast |
| `ics:netfilter`, `ics:ulogd` | DC0078, DC0082, DC0085 | Firewall permit/deny |
| `ics:plc_app`, `ics:modbus_io`, `ics:sim_process`, `ics:process_alarm` | DC0107, DC0109 | Process / tag / alarm |
| `hmi:catalina`, `hmi:supervisor` | DC0038, DC0060, DC0109 | SCADA/Tomcat + service lifecycle |
| `apache:access_log`, `linux:nginx_error` | DC0085, DC0038 | Web UI access/errors |
| `ics:fw_app` | DC0038, DC0061 | Router Flask UI |

Lab-specific keys (e.g. `hmi:catalina`, `ics:plc_app`) are listed in `logstash/mitre_mapping/log_source_to_dc.yml` so Logstash enrichment aligns with the same DC IDs used in `datacomponents/`.

## Monitored assets and file paths

Paths are **inside the Filebeat container** as `/shared_logs/...` (host: `./shared_logs/...`). Container paths are the path inside the **ICS image** before bind-mount.

### Simulation (`simulation`, 192.168.95.10)

| Host / shared_logs path | Container path | Filebeat `log_type` | Normalized source (typical) | DC relevance |
|-------------------------|----------------|---------------------|-------------------------------|--------------|
| `simulation/syslog` | `/var/log/syslog` | `syslog` | `linux:syslog` | Broad host events |
| `simulation/auth.log` | `/var/log/auth.log` | `auth` | `linux:auth` | DC0067 |
| `simulation/kern.log` | `/var/log/kern.log` | `kern` | `linux:kern` | DC0016 |
| `simulation/process_alarms/*` | `/var/log/grfics/alarms` | `process_alarm` | `ics:process_alarm` | DC0109 |
| `simulation/supervisor/*.log` | `/var/log/supervisor` | `modbus_io`, `sim_process`, `sim_error`, `sim_supervisord` | `ics:*`, `linux:sim_supervisord` | DC0107, DC0109 |
| `simulation/nginx/access.log`, `error.log` | `/var/log/nginx` | `nginx_access`, `nginx_error` | `apache:access_log`, `linux:nginx_error` | DC0085 |

### PLC (`plc`, 192.168.95.2)

| Host path | Container path | `log_type` | Normalized source | DC relevance |
|-----------|----------------|------------|-------------------|--------------|
| `plc/auth.log` | `/var/log/auth.log` | `auth` | `linux:auth` | DC0067 |
| `plc/syslog`, `daemon.log` | `/var/log/syslog`, `daemon.log` | `syslog`, `daemon` | `linux:syslog`, `linux:daemon` | DC0033, DC0060 |
| `plc/audit/*` | `/var/log/audit` | `audit` | `auditd:*` | DC0032–DC0034 |
| `plc/plc_app/*` | `/var/log/plc` | `plc_app` | `ics:plc_app` | DC0109 |
| `plc/openplc_debug.log` | `/tmp/openplc_debug.log` | `openplc_debug` | `ics:openplc_debug` | DC0038 |
| `plc/kern.log` | `/var/log/kern.log` | `kern` | `linux:kern` | DC0016 |

### EWS (`ews`, 192.168.95.5)

| Host path | Container path | `log_type` | Normalized source | DC relevance |
|-----------|----------------|------------|-------------------|--------------|
| `ews/auth.log` | `/var/log/auth.log` | `auth` | `linux:auth` | DC0067 |
| `ews/syslog`, `daemon.log` | … | `syslog`, `daemon` | `linux:syslog`, `linux:daemon` | DC0033, DC0060 |
| `ews/audit/*` | `/var/log/audit` | `audit` | `auditd:*` | File/process/exec DCs |
| `ews/kern.log` | `/var/log/kern.log` | `kern` | `linux:kern` | DC0016 |
| `ews/cron.log` | `/var/log/cron.log` | `cron` | `linux:cron` | DC0001 |
| `ews/pacct` | `/var/log/pacct` | `pacct` | `linux:pacct` | DC0107 |
| `ews/supervisord.log` | `/var/log/supervisord.log` | `ews_supervisord` | `linux:ews_supervisord` | DC0060 |

**Not exported** (reduces noise): VNC/noVNC/X11 desktop traces under `/var/log/xvfb*`, `xfce*`, `x11vnc*`, `novnc*`—they rarely contribute ICS-relevant detections compared to auth/audit/syslog.

### HMI (`hmi`, 192.168.90.107)

| Host path | Container path | `log_type` | Normalized source | DC relevance |
|-----------|----------------|------------|-------------------|--------------|
| `hmi/catalina/*.log` | `/usr/local/tomcat/logs` | `hmi_catalina` | `hmi:catalina` | DC0109, DC0038 |
| `hmi/auth.log`, `syslog`, `daemon.log`, `kern.log` | `/var/log/...` | `auth`, `syslog`, … | `linux:*` | Same as other Linux hosts |
| `hmi/audit/*` | `/var/log/audit` | `audit` | `auditd:*` | Process/file DCs |
| `hmi/supervisor/*` | `/var/log/supervisor` | `hmi_supervisor` | `hmi:supervisor` | DC0060 |

### Router (`router`, 192.168.95.200 / DMZ)

| Host path | Container path | `log_type` | Normalized source | DC relevance |
|-----------|----------------|------------|-------------------|--------------|
| `router/eve.json` | `/var/log/suricata/eve.json` | `suricata` (NDJSON) | `NSM:Flow` / `NSM:Connections` | DC0078, DC0082, DC0085 |
| `router/fast.log` | Suricata fast alert | `suricata_fast` | `NSM:Flow` | Alert summaries |
| `router/suricata.log` | Engine log | `suricata_engine` | `NSM:SuricataEngine` | Health/engine (sparse) |
| `router/syslog` | Host syslog | `syslog` | `linux:syslog` | Router OS events |
| `router/netfilter/netfilter_log.json` | ulog JSON | `netfilter` | `ics:netfilter` | DC0078 |
| `router/netfilter/ulogd.log` | Text ulog | `ulogd` | `ics:ulogd` | DC0078 |
| `router/flask/*.log` | Flask UI | `fw_app` | `ics:fw_app` | DC0038, DC0061 |
| `router/supervisor/supervisord.log` | Supervisor | `router_supervisord` | `linux:router_supervisord` | DC0060 |

**Not collected** (redundant with `eve.json`): Suricata `http.log`, `tls.log`, `stats.log`, `*-stdio.log` — structured protocol data is already in **eve** JSON, so separate file tails added volume and FP risk without new fields.

## Intentionally excluded streams

| Stream | Reason |
|--------|--------|
| **Docker container JSON logs** (`/var/lib/docker/containers/...`) | Very high volume; normalized as `docker:runtime` and overlaps DC0033/DC0038 with low ICS specificity. Use `docker logs` for troubleshooting. |
| **EWS GUI / VNC / noVNC file logs** | Mostly display/session noise; auth remains in `auth.log` / `audit`. |
| **Suricata auxiliary text logs** (app-protocol files, stats, stdio) | Redundant with `eve.json` + `fast.log`. |

## Operational notes

- Run `./init_shared_logs.sh` once so bind-mounted **files** exist before `docker compose up`.
- After changing Filebeat inputs, restart Filebeat: `docker compose restart filebeat`.
- To add a new technology (e.g. Zeek), add a volume + Filebeat input + Logstash branch setting `log_source_normalized` + one dictionary line in `log_source_to_dc.yml`.

## Reference files

| File | Purpose |
|------|---------|
| `filebeat/filebeat.yml` | Inputs and `log_type` per path |
| `logstash/pipeline/11-parse-auth.conf` | `linux:auth` |
| `logstash/pipeline/12-parse-syslog.conf` | `linux:syslog`, `linux:daemon`, `linux:kern`, `linux:cron` |
| `logstash/pipeline/13-parse-audit.conf` | `auditd:*` |
| `logstash/pipeline/14-parse-suricata-and-ics.conf` | ICS + Suricata + nginx + router |
| `logstash/pipeline/20-enrich-mitre.conf` | DC candidates + keywords |
| `logstash/mitre_mapping/log_source_to_dc.yml` | `log_source_normalized` → DC list |
| `datacomponents/*.json` | Full MITRE DC definitions and canonical `log_sources` |
