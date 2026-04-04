### 1. Summary of All Newly Collected Logs

| # | New Log Source | GRFICS Container | Container Path | Shared Path | Log Type |
|---|---|---|---|---|---|
| 1 | **Modbus I/O supervisor log** | `simulation` | `/var/log/supervisor/modbus.log` | `shared_logs/simulation/supervisor/` | `modbus_io` |
| 2 | **TE simulation supervisor log** | `simulation` | `/var/log/supervisor/simulation.log` | `shared_logs/simulation/supervisor/` | `sim_process` |
| 3 | **Simulation error logs** | `simulation` | `/var/log/supervisor/*.err` | `shared_logs/simulation/supervisor/` | `sim_error` |
| 4 | **HMI daemon.log** | `hmi` | `/var/log/daemon.log` | `shared_logs/hmi/daemon.log` | `daemon` |
| 5 | **HMI kern.log** | `hmi` | `/var/log/kern.log` | `shared_logs/hmi/kern.log` | `kern` |
| 6 | **HMI supervisor logs** (MariaDB/Tomcat lifecycle) | `hmi` | `/var/log/supervisor/` | `shared_logs/hmi/supervisor/` | `hmi_supervisor` |
| 7 | **Router netfilter/ulogd JSON** (iptables firewall) | `router` | `/var/log/ulog/netfilter_log.json` | `shared_logs/router/netfilter/` | `netfilter` |
| 8 | **Router Flask firewall-UI logs** | `router` | `/var/log/flask/` | `shared_logs/router/flask/` | `fw_app` |
| 9 | **Docker container stdout/stderr** (all containers) | all | `/var/lib/docker/containers/` | (Docker API) | `docker` |

### 2. GRFICS Log Sources to MITRE ATT&CK Data Components Mapping

| GRFICS Log Source | Normalized Label | Data Components | Rationale |
|---|---|---|---|
| **simulation/syslog** | `linux:syslog` | DC0001, DC0002, DC0016, DC0021, DC0029, DC0032, DC0033, DC0034, DC0038, DC0041, DC0042, DC0046, DC0055, DC0059, DC0060, DC0061, DC0064, DC0067, DC0078, DC0082, DC0085, DC0088 | General system events from ICS process host |
| **simulation/auth.log** | `linux:auth` | DC0002, DC0067 | Authentication events on the Modbus remote-I/O host |
| **simulation/kern.log** | `linux:kern` | DC0004, DC0016, DC0042 | Kernel module loads, firmware, drive events |
| **simulation/process_alarms** | `ics:process_alarm` | DC0109, DC0108 | TE process sensor alarms (pressure, temp, valve deviations) |
| **simulation/supervisor/modbus.log** | `ics:modbus_io` | DC0109, DC0078, DC0085, DC0107 | Modbus register read/write activity between PLC and field devices |
| **simulation/supervisor/simulation.log** | `ics:sim_process` | DC0107, DC0109, DC0038 | TE process state and historian-like data |
| **simulation/supervisor/*.err** | `ics:sim_error` | DC0108, DC0109 | Errors in Modbus or simulation (device faults) |
| **plc/auth.log** | `linux:auth` | DC0002, DC0067 | PLC controller authentication events |
| **plc/syslog** | `linux:syslog` | (full syslog DC set) | PLC system events |
| **plc/daemon.log** | `linux:daemon` | DC0033, DC0060, DC0041 | OpenPLC service lifecycle events |
| **plc/kern.log** | `linux:kern` | DC0004, DC0016, DC0042 | PLC kernel events |
| **plc/audit/** | `auditd:<TYPE>` | DC0002, DC0004, DC0016, DC0021, DC0032, DC0033, DC0034, DC0039, DC0040, DC0042, DC0055, DC0059, DC0061, DC0064, DC0067, DC0078, DC0082, DC0085, DC0088 | Full auditd coverage on the PLC |
| **plc/plc_app/** | `ics:plc_app` | DC0109, DC0038, DC0108 | OpenPLC application logs (program uploads, runtime state) |
| **ews/auth.log** | `linux:auth` | DC0002, DC0067 | Engineering workstation authentication |
| **ews/syslog** | `linux:syslog` | (full syslog DC set) | EWS system events |
| **ews/daemon.log** | `linux:daemon` | DC0033, DC0060, DC0041 | EWS daemon events |
| **ews/kern.log** | `linux:kern` | DC0004, DC0016, DC0042 | EWS kernel events |
| **ews/audit/** | `auditd:<TYPE>` | (full auditd DC set) | EWS audit trail (file access, exec, syscalls) |
| **ews/cron.log** | `linux:cron` | DC0001, DC0005 | Cron job scheduling on EWS (persistence detection) |
| **ews/pacct** | `linux:pacct` | DC0107, DC0032 | Process accounting / execution history |
| **hmi/catalina/** | `hmi:catalina` | DC0038, DC0109 | SCADA-LTS/Tomcat application logs (HMI interaction) |
| **hmi/auth.log** | `linux:auth` | DC0002, DC0067 | HMI authentication events |
| **hmi/syslog** | `linux:syslog` | (full syslog DC set) | HMI system events |
| **hmi/daemon.log** | `linux:daemon` | DC0033, DC0060, DC0041 | MariaDB/Tomcat service lifecycle |
| **hmi/kern.log** | `linux:kern` | DC0004, DC0016, DC0042 | HMI kernel events |
| **hmi/audit/** | `auditd:<TYPE>` | (full auditd DC set) | HMI audit trail |
| **hmi/supervisor/** | `hmi:supervisor` | DC0038, DC0060, DC0033 | MariaDB/Tomcat process start/stop/restart events |
| **router/eve.json** | `NSM:Flow` / `NSM:Connections` | DC0078, DC0082, DC0085, DC0002, DC0021, DC0059, DC0102 | Suricata IDS events (alerts, flows, DNS, HTTP, TLS, Modbus protocol) |
| **router/syslog** | `linux:syslog` | (full syslog DC set) | Router system events |
| **router/netfilter/netfilter_log.json** | `ics:netfilter` | DC0078, DC0082 | iptables/ulogd firewall decisions (ACCEPT/DROP per rule) |
| **router/flask/** | `ics:fw_app` | DC0038, DC0061 | Firewall configuration UI access and changes |
| **Docker container logs** | `docker:runtime` | DC0032, DC0033, DC0038, DC0064 | stdout/stderr from all containers (including kali, caldera) |

### 3. List of All Files Changed

| File | Change Type | Description |
|---|---|---|
| `docker-compose.yml` | **Modified** | Added 6 new volume mounts (simulation/supervisor, hmi/daemon.log, hmi/kern.log, hmi/supervisor, router/netfilter, router/flask); added `es-init` service for automatic index template loading; mounted ES templates volume |
| `filebeat/filebeat.yml` | **Modified** | Added 8 new filestream inputs (simulation-supervisor-modbus, simulation-supervisor-sim, simulation-supervisor-err, hmi-daemon, hmi-kern, hmi-supervisor, router-netfilter, router-flask); added Docker container log input |
| `logstash/pipeline/11-parse-auth.conf` | **Modified** | **Bug fix**: changed `log_source_normalized` from `linux:syslog` to `linux:auth` so auth events correctly map to DC0002/DC0067 |
| `logstash/pipeline/12-parse-syslog.conf` | **Modified** | Added separate `linux:kern` and `linux:daemon` normalized sources (previously all fell into `linux:syslog`) for more granular DC mapping |
| `logstash/pipeline/14-parse-suricata-and-ics.conf` | **Modified** | Added parsing for 7 new log types (`modbus_io`, `sim_process`, `sim_error`, `netfilter`, `fw_app`, `hmi_supervisor`, `docker`); added Suricata Modbus/DNP3/EtherNet-IP protocol detection; added ICS-specific fields extraction |
| `logstash/pipeline/30-output.conf` | **Modified** | Added `ics-netfilter-*` and `ics-docker-*` index routing; expanded `ics-process-*` to include `modbus_io`, `sim_process`, `sim_error`; expanded `ics-hmi-*` to include `hmi_supervisor` |
| `logstash/mitre_mapping/log_source_to_dc.yml` | **Modified** | Added 12 new normalized source mappings: `hmi:catalina`, `hmi:supervisor`, `ics:fw_app`, `ics:modbus_io`, `ics:netfilter`, `ics:plc_app`, `ics:process_alarm`, `ics:sim_error`, `ics:sim_process`, `linux:daemon`, `linux:kern`, `linux:pacct`; expanded `docker:runtime` DC coverage |
| `logstash/mitre_mapping/dc_keywords.json` | **Modified** | Added 60+ new ICS/OT-specific keywords across 15 Data Components (Modbus, pressure, temperature, valve, coil, register, supervisor, tomcat, OpenPLC, netfilter, iptables, etc.) |
| `elasticsearch/templates/ics-logs-template.json` | **Created** | New ES index template for all `ics-*` raw log indices with typed mappings for ICS fields (modbus.*, netfilter.*, ics.*, container.*) |
| `init_shared_logs.sh` | **Created** | Bootstrap script that creates all required shared_logs directories and files before first `docker compose up` |
| `engine/feature_extractor.py` | **Modified** | Added `netfilter.*` and `modbus.*` field aliases; enhanced `infer_categories()` with 7 new category families (ics_protocol, application, kernel, firewall, scheduled_task, service, operational_technology); added nested field extraction for netfilter and modbus objects |

### 4. How Detection Coverage Improved

**Before (8 critical gaps):**

1. **Auth events mis-tagged** -- `11-parse-auth.conf` set `log_source_normalized` to `linux:syslog` instead of `linux:auth`, meaning auth events from all 5 ICS assets never matched DC0002 (User Account Authentication) or DC0067 (Logon Session Creation) through the translate filter. This is a **critical detection failure** for techniques like T0859 (Valid Accounts) and T0866 (Exploitation of Remote Services).

2. **ICS-specific sources unmapped** -- `ics:process_alarm`, `ics:plc_app`, `hmi:catalina`, and `linux:pacct` were set as normalized sources by Logstash but had **no entries** in `log_source_to_dc.yml`, so they always fell back to `"unknown"`. The most ICS-relevant Data Components (DC0109, DC0108, DC0107) received zero log-source-match score.

3. **No Modbus I/O logging** -- The Modbus bridge supervisor logs (`modbus.log`) that capture all Modbus TCP register reads/writes between the PLC and simulation devices were not collected. These logs are the primary evidence for detecting T0836 (Modify Parameter), T0855 (Unauthorized Command Message), and T0831 (Manipulation of Control).

4. **No firewall logging** -- The router's ulogd netfilter JSON logs (iptables ACCEPT/DROP decisions) were generated but never collected. This left a blind spot for DC0078 (Network Traffic Flow) and DC0082 (Network Connection Creation) at the perimeter.

5. **No firewall UI logging** -- The Flask firewall management interface logs were not collected, missing DC0061 (File Modification) evidence when an attacker changes iptables rules.

6. **No Docker container logs** -- Despite mounting Docker socket and containers directory, Filebeat had no `container` input configured, meaning stdout/stderr from kali and caldera was invisible. While these are attacker nodes (filtered by the engine), their logs provide valuable context for post-incident analysis.

7. **Kernel and daemon logs undifferentiated** -- All kern.log, daemon.log, and syslog entries were normalized to `linux:syslog`, losing the granularity needed to distinguish DC0004 (Firmware Modification) and DC0016 (Module Load) kernel events from general syslog.

8. **ES templates never loaded** -- The JSON templates in `elasticsearch/templates/` were never mounted into ES or loaded at startup. Without typed mappings, fields like `asset_ip` were stored as text instead of `ip`, degrading search and aggregation performance.

**After (improvements):**

- **+9 new log sources** collected from GRFICS containers
- **+12 new normalized source mappings** in the MITRE translate dictionary
- **+60 new ICS/OT keywords** for keyword-based matching
- **+7 new event categories** recognized by the Python engine
- **Auth events now correctly route** to DC0002/DC0067 (fixed bug)
- **Kern/daemon/cron events** now have distinct normalized labels with specific DC mappings
- **All ICS-specific sources** (`process_alarm`, `plc_app`, `modbus_io`, etc.) now have explicit DC mappings
- **Netfilter firewall logs** provide network traffic flow and connection visibility at the router
- **Suricata events** are now enhanced with ICS protocol fields (Modbus function codes, DNP3, EtherNet/IP)
- **ES index templates** are automatically loaded on first startup via the `es-init` container
- **Proper typed mappings** for all ICS fields (modbus.*, netfilter.*, ics.*)

**Net Data Component coverage improvement:**

| Data Component | Before | After | Key improvement |
|---|---|---|---|
| DC0002 (User Account Auth) | Broken (auth mislabeled as syslog) | Full coverage | Auth log normalization fixed |
| DC0004 (Firmware Modification) | Weak (kern mixed with syslog) | Strong | Dedicated `linux:kern` source |
| DC0016 (Module Load) | Weak | Strong | Kern events now separated |
| DC0033 (Process Termination) | Partial | Full | Daemon + supervisor logs added |
| DC0038 (Application Log Content) | Partial | Full | Catalina, supervisor, Flask, Modbus all mapped |
| DC0060 (Service Creation) | Weak | Strong | Daemon + supervisor logs mapped |
| DC0067 (Logon Session Creation) | Broken | Full | Auth normalization fixed |
| DC0078 (Network Traffic Flow) | Suricata only | Suricata + netfilter | Firewall logs added |
| DC0082 (Network Connection Creation) | Suricata only | Suricata + netfilter | Firewall logs added |
| DC0085 (Network Traffic Content) | Suricata only | Suricata + Modbus I/O | ICS protocol content visibility |
| DC0107 (Process History/Live Data) | pacct only (unmapped) | pacct + sim_process + modbus_io | Full OT process history |
| DC0108 (Device Alarm) | None | plc_app + process_alarm + sim_error | PLC fault and device alarm coverage |
| DC0109 (Process/Event Alarm) | Existed but unmapped | Full pipeline | Process alarms, Modbus, PLC logs all mapped |

**Limitation:** Intra-ICS-network Modbus traffic (PLC ↔ Simulation on 192.168.95.0/24) cannot be passively sniffed by a separate container due to Docker bridge networking isolation. Detection of this traffic relies on the application-level Modbus I/O supervisor logs rather than network-level packet capture. Cross-zone traffic (HMI ↔ PLC through the router) IS monitored by Suricata on the DMZ interface.