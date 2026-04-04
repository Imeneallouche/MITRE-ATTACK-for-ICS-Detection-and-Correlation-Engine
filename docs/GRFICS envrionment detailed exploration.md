# GRFICS v3 Environment — Complete Technical Deep-Dive

## 1. docker-compose.yml — Full Service Inventory

**Version**: 3.9

### Services

| Service | Image | Container | IP(s) | Ports | Networks | Key Volumes |
|---------|-------|-----------|-------|-------|----------|-------------|
| **simulation** | `fortiphyd/grfics-simulation` | `simulation` | `192.168.95.10` (b-ics-net) | `80:80` | a-grfics-admin, b-ics-net | `shared_logs/simulation/syslog`, `auth.log`, `kern.log`, `process_alarms` |
| **plc** | `fortiphyd/grfics-plc` | `plc` | `192.168.95.2` (b-ics-net) | `8080:8080` | a-grfics-admin, b-ics-net | `plc_volume:/docker_persistent`, `shared_logs/plc/{auth.log,syslog,daemon.log,audit,plc_app,kern.log}` |
| **ews** | `fortiphyd/grfics-workstation` | `ews` | `192.168.95.5` (b-ics-net) | `6080:6080` | a-grfics-admin, b-ics-net | `shared_logs/ews/{auth.log,syslog,daemon.log,audit,kern.log,wtmp,pacct,cron.log}` |
| **hmi** | `fortiphyd/grfics-scadalts` | `hmi` | `192.168.90.107` (c-dmz-net) | `6081:8080` | a-grfics-admin, c-dmz-net | `scadalts_db:/var/lib/mysql`, `shared_logs/hmi/{catalina,auth.log,syslog,audit}` |
| **kali** | `fortiphyd/grfics-attacker` | `kali` | `192.168.90.6` (c-dmz-net) | `6088:6080` | a-grfics-admin, c-dmz-net | None |
| **router** | `fortiphyd/grfics-router` | `router` | `192.168.95.200` (b-ics-net), `192.168.90.200` (c-dmz-net) | None (internal 5000) | a-grfics-admin, b-ics-net, c-dmz-net | `router_config:/etc/firewall`, `shared_logs/router` (Suricata logs) |
| **caldera** | `fortiphyd/grfics-caldera` | `caldera` | `192.168.90.250` (c-dmz-net) | `8888:8888` | a-grfics-admin, c-dmz-net | None |
| **elasticsearch** | `docker.elastic.co/.../elasticsearch:8.13.0` | `elasticsearch` | Docker bridge only | `9200:9200` | a-grfics-admin | `elasticsearch_data` volume |
| **logstash** | `docker.elastic.co/.../logstash:8.13.0` | `logstash` | Docker bridge only | `5044,5000/udp,5001,9600` | a-grfics-admin | `./logstash/pipeline`, `./logstash/config`, `./logstash/mitre_mapping` |
| **kibana** | `docker.elastic.co/.../kibana:8.13.0` | `kibana` | Docker bridge only | `5601:5601` | a-grfics-admin | None |
| **filebeat** | `docker.elastic.co/.../filebeat:8.13.0` | `filebeat` | Docker bridge only | None | a-grfics-admin | `./filebeat/filebeat.yml`, `./shared_logs`, Docker socket, `./assets.json` |

### Networks

| Network | Driver | Subnet | Gateway |
|---------|--------|--------|---------|
| `a-grfics-admin` | bridge | Docker default (auto) | auto |
| `b-ics-net` | bridge | `192.168.95.0/24` | `192.168.95.1` |
| `c-dmz-net` | bridge | `192.168.90.0/24` | `192.168.90.1` |

### Volumes
`scadalts_db`, `plc_volume`, `router_config`, `elasticsearch_data`

### Key Environment Variables
- **router**: `FWUI_SECRET_KEY: "some-long-secret-you-generate"`
- **kali**: `net.ipv4.conf.default.arp_announce: 2`, `net.ipv4.conf.all.arp_announce: 2`
- **router**: `net.ipv4.ip_forward: "1"`
- **elasticsearch**: `discovery.type=single-node`, `xpack.security.enabled=false`, `ES_JAVA_OPTS=-Xms1g -Xmx1g`
- **hmi**: `SCADA_LTS_VERSION=2.7.8.1`, `MYSQL_ROOT_PASSWORD=root`, `TOMCAT_USER=tcuser`

---

## 2. Simulation Component

### Dockerfile (multi-stage)
- **Stage 1** (`python:3.11-slim`): Compiles `TE_process.cc` and `main.cc` with `libjsoncpp-dev`, `liblapacke-dev`
- **Stage 2** (`python:3.11-slim`): Runtime with `nginx`, `php`, `php-fpm`, `tcpdump`, `ncat`, `supervisor`. Installs `pymodbus==3.9.2`. Copies web visualization (Unity WebGL app) to `/var/www/html/`. Checks for Git LFS pointer files.

### TE Process Simulation (`main.cc`, `TE_process.h`)
The simulation is a **Tennessee Eastman** chemical process model compiled from C++. It:
- Listens on **TCP port 55555** (all interfaces) for JSON-based requests
- Supports up to 30 concurrent client connections
- Accepts two types of JSON requests:
  - `{"request":"read"}` — returns full process state as JSON
  - `{"request":"write","data":{"inputs":{...}}}` — updates process inputs
- Runs the TE model using LAPACK for numerical computations
- Protected by a pthread mutex for thread safety

**State Variables** (from `TE_process.h`):
- Molar quantities: `molar_A`, `molar_B`, `molar_C`, `molar_D` (kmol)
- Valve positions: `f1_valve_pos`, `f2_valve_pos`, `purge_valve_pos`, `product_valve_pos` (%)
- `e_stop` (bool)

**Outputs**:
- `f1_flow`, `f2_flow`, `purge_flow`, `product_flow` (kmol/h)
- `pressure` (kPa, range 0–3200)
- `liquid_level` (%)
- `A_in_purge`, `B_in_purge`, `C_in_purge` (mol fractions)
- `cost` (production cost)

### Modbus Remote I/O Devices

Six Python scripts act as Modbus TCP servers on port 502, each on a separate IP alias. They bridge between the TE simulation (TCP 55555) and Modbus TCP.

**Common Pattern** (`modbusdevice.py`):
- Each device connects to `127.0.0.1:55555` (the TE simulation)
- Creates a `ModbusSlaveContext` with registers initialized
- Runs `StartAsyncTcpServer` on its assigned IP
- Periodically reads data from simulation, writes current values to Modbus **Input Registers** (function code 4)
- Reads commands from Modbus **Holding Registers** (function code 16/HR addr 1), converts back and writes to simulation

| Script | Device | IP | Modbus HR (write) | Modbus IR (read) |
|--------|--------|-----|-------------------|------------------|
| `feed1.py` | Feed 1 | `192.168.95.10` | HR[1] = `f1_valve_sp` | IR[1] = valve_pos, IR[2] = flow |
| `feed2.py` | Feed 2 | `192.168.95.11` | HR[1] = `f2_valve_sp` | IR[1] = valve_pos, IR[2] = flow |
| `purge.py` | Purge | `192.168.95.12` | HR[1] = `purge_valve_sp` | IR[1] = valve_pos, IR[2] = flow |
| `product.py` | Product | `192.168.95.13` | HR[1] = `product_valve_sp` | IR[1] = valve_pos, IR[2] = flow |
| `tank.py` | Reactor/Tank | `192.168.95.14` | None (read-only) | IR[1] = pressure, IR[2] = level |
| `analyzer.py` | Analyzer | `192.168.95.15` | None (read-only) | IR[1] = A_in_purge, IR[2] = B_in_purge, IR[3] = C_in_purge |

**Value scaling**: All values are scaled to 0–65535 UINT range. For example, pressure is `(pressure/3200.0)*65535`, valve positions are `(pos/100.0)*65535`, flows are `(flow/500.0)*65535`.

### `entrypoint.sh`
Adds 5 IP aliases (`192.168.95.11–15`) to the ICS network interface, adds a route to the DMZ (`192.168.90.0/24` via gateway `192.168.95.200`), starts `php-fpm` and `nginx`, then execs the CMD.

### `supervisord.conf`
Runs two programs:
1. `/app/simulation/simulation` — the compiled TE process binary
2. `/app/modbus/run_all.sh` — launches all 6 Modbus device scripts in parallel

### Web Visualization
- **nginx** on port 80 serves a Unity WebGL 3D chemical plant visualization
- **PHP endpoint** at `/data/index.php`:
  - `GET` → connects to `127.0.0.1:55555`, sends `{"request":"read"}`, returns JSON with all process variables
  - `POST` → accepts `e_stop` commands (0 or 1) and forwards to simulation
- The Unity app polls this PHP endpoint and renders real-time process state in 3D

---

## 3. PLC Component (OpenPLC)

### Dockerfile
- **Base**: `debian:bullseye-20240722`
- Installs: Python3, SQLite3, build-essential, git, dos2unix, autoconf/automake
- Runs `install.sh docker` which:
  - Compiles **MatIEC** (IEC 61131-3 to C compiler)
  - Compiles **ST Optimizer** and **Glue Generator**
  - Builds and installs **OpenDNP3**
  - Builds and installs **libmodbus**
  - Builds and installs **libsnap7** (S7 protocol)
  - Creates a Python venv with `flask==2.3.3`, `werkzeug==2.3.7`, `flask-login==0.6.2`, `pymodbus==2.5.3`
- Sets up persistent volume at `/docker_persistent` with symlinks for `mbconfig.cfg`, `openplc.db`, `dnp3.cfg`, `st_files/`, `active_program`
- **Entrypoint**: `start_openplc.sh` which copies default configs to the persistent volume, adds route to DMZ, and starts `webserver.py`

### `mbconfig.cfg` — Modbus Master Configuration
6 slave devices, polling every 100ms, 1000ms timeout, all using TCP protocol, all with slave_id=247:

| Device | IP | Input Regs (Start, Size) | Holding Regs (Start, Size) |
|--------|----|--------------------------|----------------------------|
| Feed 1 | 192.168.95.10 | IR(1, 2) | HR(1, 1) |
| Feed 2 | 192.168.95.11 | IR(1, 2) | HR(1, 1) |
| Purge | 192.168.95.12 | IR(1, 2) | HR(1, 1) |
| Product | 192.168.95.13 | IR(1, 2) | HR(1, 1) |
| Tank | 192.168.95.14 | IR(1, 2) | HR(1, 1) |
| Analyzer | 192.168.95.15 | IR(1, 3) | HR(1, 1) |

### Active Program: `326339.st`
The PLC runs ST file `326339.st` by default. This is the complete control logic.

### Structured Text Programs

**`326339.st`** (default active — simplified proportional control):
- **Functions**: `scale_to_real`, `scale_to_uint`, `control`, `pressure_override`
- **Program `main1`** at 20ms cycle interval
- **Input variables** (from Modbus IR via mbconfig, mapped to `%IW100–%IW112`):
  - `f1_valve_pos`, `f1_flow`, `f2_valve_pos`, `f2_flow`, `purge_valve_pos`, `purge_flow`, `product_valve_pos`, `product_flow`, `pressure`, `level`, `a_in_purge`, `b_in_purge`, `c_in_purge`
- **Output variables** (to Modbus HR, mapped to `%QW100–%QW103`):
  - `f1_valve_sp`, `f2_valve_sp`, `purge_valve_sp`, `product_valve_sp`
- **Setpoints** (held in `%MW0–%MW4`):
  - `product_flow_setpoint` = 13107, `a_setpoint` = 30801, `pressure_sp` = 55295, `override_sp` = 31675, `level_sp` = 28835
- **HMI registers** (`%MW20–%MW29`): Copies of process values for SCADA display
- **Control logic**:
  - `f1_valve_sp` = proportional control on product_flow vs setpoint (k=20.0, range 0–500)
  - `purge_valve_sp` = proportional control on pressure vs pressure_sp (k=-20.0, range 0–3200)
  - `f2_valve_sp` = proportional control on a_in_purge vs a_setpoint (k=1.0, range 0–100)
  - `product_valve_sp` = proportional control on level vs level_sp (k=-10.0, range 0–100)
  - `pressure_override`: When pressure > 2900 kPa, reduces product_flow_setpoint to increase outflow
- **run_bit** (`%QX5.0`): When FALSE → feeds close (0), purge/product open (65535) = **safe shutdown state**
- Hardcoded: `product_flow_setpoint := 30000` at end of each scan

**`690525.st`** (same logic but no `run_bit` / safe shutdown, identical control equations)

**`655326.st`** (alternate version — slightly different `control` function with inverted subtraction logic and different variable names)

**`blank_program.st`**: Minimal passthrough program (copies `var_in` to `var_out`)

### DNP3 Configuration (`dnp3.cfg`)
- Local address: 10, Remote/master address: 1
- Unsolicited reporting enabled
- Event buffer: 10, Database size: 8
- All offsets (DI, DO, AI, AO) = 0

### `webserver.py` (partial — 2600+ lines)
Full OpenPLC web interface built with Flask:
- Authentication via SQLite database (`openplc.db`)
- Manages Modbus, DNP3, EtherNet/IP, S7 protocol, and persistent storage
- Generates `mbconfig.cfg` from the `Slave_dev` SQLite table
- Endpoints for program upload, compilation, start/stop PLC, monitoring, user management
- Protocols configured in the `Settings` table: `Modbus_port`, `Dnp3_port`, `Enip_port`, `snap7`, `Pstorage_polling`

---

## 4. SCADA-LTS (HMI) Component

### Dockerfile
- **Base**: `eclipse-temurin:11` (Java 11)
- Installs: MariaDB server, Tomcat 9.0.109, wget, unzip, supervisor
- Downloads **SCADA-LTS v2.7.8.1** WAR file from GitHub releases
- Adds MySQL JDBC driver (Connector/J 8.3.0)
- Configures JNDI DataSource: `jdbc/scadalts` → `mysql://localhost:3306/scadalts` with user `scada:scada`
- Copies `1.png` (HMI background image) and `seed_project_data.sql`
- Exposes ports 8080 (Tomcat) and 3306 (MySQL)

### `init.sh`
1. Waits for MariaDB to start
2. Creates database `scadalts` and user `scada`/`scada`
3. Imports base schema from SCADA-LTS WAR's `createTables-mysql.sql`
4. Creates default admin user (`admin` / password hash `0DPiKuNIrrVmD8IUCuw1hQxNqZc=` → `admin`)
5. Seeds project data from `seed_project_data.sql` if no views exist
6. Adds route: `ip route add 192.168.95.0/24 via 192.168.90.200`

### `seed_project_data.sql`
Binary MariaDB dump containing a pre-configured SCADA-LTS view named `TenEastView1` with:
- A graphical view using `1.png` as background
- ScriptComponent data points that display process values (JavaScript formatters like `return(value.toFixed(1) + "%")`)
- Pre-configured Modbus data sources connecting to PLC at `192.168.95.2:502`

### `supervisord.conf`
Runs: MariaDB (priority 5), init.sh (priority 7, one-shot), Tomcat (priority 10, with 10s delay)

### How HMI connects to PLC
SCADA-LTS polls the PLC's Modbus slave interface at `192.168.95.2:502`. It reads the HMI registers (`%MW20–%MW29`) which contain scaled process values (pressure, level, valve positions, flows). Traffic routes through the router at `192.168.90.200` since HMI is on the DMZ and PLC is on the ICS network.

---

## 5. Router Component

### Dockerfile
- **Base**: `debian:12-slim`
- Installs: `iproute2`, `iptables`, `python3-flask`, `ulogd2`, `ulogd2-json`, `suricata`, `supervisor`, `tcpdump`, `curl`
- Enables IP forwarding
- Copies: `entrypoint.sh`, Flask app (`app.py`), HTML templates, `router.conf`, `suricata.yaml`, `ulogd.conf`

### `entrypoint.sh`
Sets `iptables -P FORWARD ACCEPT` (accept all forwarded traffic by default), shows interface info, execs CMD.

### `app.py` — Flask Firewall Management UI (port 5000)
Full-featured web application:
- **Authentication**: Default `admin:password` (stored in config.json)
- **Firewall management**: Add/delete/reorder iptables FORWARD rules, apply via `iptables-restore`
- **IDS management**: View Suricata alerts from `eve.json`, edit custom rules in `/etc/suricata/rules/local.rules`, reload Suricata with `pkill -USR2`
- **Firewall logging**: Parses NFLOG JSON from ulogd2
- Rules support: source/dest IP, protocol, dport, interface in/out, ACCEPT/DROP/REJECT actions
- DROP/REJECT rules are wrapped in LOGDROP/LOGREJECT chains that log via NFLOG before dropping

### `router.conf` (supervisord)
Runs three programs:
1. **flask** — `python3 /opt/fwui/app.py` (firewall web UI on port 5000)
2. **suricata** — `suricata -i eth2 -c /etc/suricata/suricata.yaml` (monitors WAN/DMZ interface)
3. **ulogd2** — NFLOG to JSON logging

### `ulogd.conf`
Captures NFLOG group 1 packets, processes through BASE→IFINDEX→IP2STR→HWHDR→JSON pipeline, writes to `/var/log/ulog/netfilter_log.json`.

### `suricata.yaml` — Key Settings
- **HOME_NET**: `192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12`
- **MODBUS_PORTS**: 502, **DNP3_PORTS**: 20000
- EVE JSON logging enabled to `/var/log/suricata/eve.json`
- Fast alerts enabled
- **Modbus protocol parser enabled** with `stream-depth: 0` and detection on port 502
- **DNP3 protocol parser enabled** on port 20000
- Rules loaded from `/etc/suricata/rules/*.rules`
- AF_PACKET capture on `eth0`

---

## 6. Caldera Component (C2 Framework)

### Dockerfile
- **Stage 1**: Node.js 23 — builds Magma (VueJS) front-end
- **Stage 2**: `debian:bookworm-slim` — full Caldera build
  - Installs: Python3, pip, Go, gcc, mingw-w64
  - Clones atomic-red-team and adversary-emulation-plans
  - Builds Sandcat agent (Go-based)
  - **OT Plugin**: Clones `caldera-ot` repo, extracts `modbus/` plugin
  - Custom files overlaid:
    - `local.yml` → `conf/local.yml`
    - `spec.py` → Modbus actions (read/write coils, registers, device info, fuzzing)
    - `modbus_cli.py` → CLI tool for Modbus operations
    - Rebuilds `modbus_cli` binary with PyInstaller + `pymodbus==3.11.3`
    - Custom ability YAML and adversary YAML files

### `local.yml` — Caldera Configuration
- **HTTP server**: `0.0.0.0:8888`
- **API keys**: Blue = `zygmxs5yX3F7_E7LnUZb6hEuG9-MFMOewq_PdEY6U2A`, Red = `VEvMp339du5M5efw5TpfUfiChPfbcN2Spc11jJ1y78Y`
- **Users**: `red:fortiphyd-red`, `blue:fortiphyd-blue`
- **Plugins enabled**: access, atomic, compass, debrief, fieldmanual, manx, **modbus**, response, sandcat, stockpile, training
- **Default planner**: atomic (sequential)
- Various contact channels: HTTP (:8888), TCP (:7010), UDP (:7011), Websocket (:7012), DNS (:8853), SSH (:8022), FTP (:2222)

### `spec.py` — Modbus Plugin Actions
Implements all core Modbus functions as `@ModbusClient.action` decorators:
- `read_device_info` (FC 0x2B/0x0E)
- `read_coils` (FC 0x01)
- `read_discrete_inputs` (FC 0x02)
- `read_holding_registers` (FC 0x03)
- `read_input_registers` (FC 0x04)
- `write_coil` (FC 0x05)
- `write_register` (FC 0x06)
- `write_coils` (FC 0x0F)
- `write_registers` (FC 0x10)
- `mask_write_register` (FC 0x16)

### `modbus_cli.py` — CLI Interface
Full-featured Modbus command-line tool with subcommands:
- `read_c`, `read_di`, `read_hr`, `read_ir` — read operations
- `write_c`, `write_r`, `write_multi_c`, `write_multi_r`, `mask_write_r` — write operations
- `fuzz_c`, `fuzz_r` — fuzzing (random writes with configurable range, count, wait)
- `read_device_info` — device identification

### Custom Ability YAMLs

**`9360ba0d-...yml`** — "Modbus - Read Device Information":
- Tactic: discovery, Technique: T0888
- Runs `./modbus_cli #{modbus.server.ip} --port #{modbus.server.port} read_device_info --level #{modbus.read_device_info.level}`
- Cross-platform (Linux, Windows, macOS)

**`0033b644-...yml`** — "Modbus Sample Facts" (fact source):
- Pre-loaded facts: `modbus.server.ip` = `192.168.95.10`, `modbus.server.port` = `502`
- Read parameters: `modbus.read_discrete.start` = 10000, count = 1
- Write parameters: `modbus.write_register.start` = 10000, value = 123
- Coil parameters: `modbus.write_coil.start` = 0, values = ON/OFF
- Device info level = 3

**`ff2effd0-...yml`** — "Modbus Adversary" profile:
- Contains only one ability: `9360ba0d-...` (Read Device Info)
- Serves as the default adversary template

---

## 7. Workstation (EWS) Component

### Dockerfile
- **Base**: `ubuntu:22.04`
- Sets up a full **XFCE4 desktop** with VNC access via **noVNC**
- Environment: `DISPLAY=:1`, `VNC_PORT=5900`, `NOVNC_PORT=6080`, `RESOLUTION=1280x720`
- **User**: `engineer` with password `plc123`
- Installs: xfce4, x11vnc, xvfb, noVNC, websockify, Firefox
- Installs **OpenPLC Editor** from GitHub (with wxPython)
- Creates desktop shortcut for OpenPLC Editor
- Copies `chemical/` project directory and `chemical.st` to engineer's Desktop
- Pre-configures Firefox bookmarks via `places.sqlite`
- Exposes 6080 (noVNC) and 5900 (VNC)

### `start.sh`
Sets up VNC password from `VNC_PASSWORD` env var, adds route to DMZ via `192.168.95.200`.

### `supervisord.conf`
Runs: Xvfb (virtual framebuffer), XFCE4 desktop (as `engineer`), x11vnc, noVNC proxy

### Attack Files

**`attack.st`** — Malicious PLC program (same structure as `326339.st`) with `run_bit AT %QX5.0 : BOOL := TRUE`. Identical control logic to the legitimate program — this serves as a template for an attacker to modify.

**`attack.xml`** — OpenPLC Editor project file (XML format, >200KB). Contains the full FBD/LD graphical representation of the chemical plant control program with function blocks, variables, and connections.

**`simplified_te.st`** and **`chemical.st`** — Versions of the TE process control program using FUNCTION_BLOCK style (composition_control, pressure_control, flow_control, level_control, pressure_override, scale_to_signed). The `chemical.st` uses 50ms cycle time.

---

## 8. Attack Chain Design Document

The document at `/home/imene/Desktop/Github/GRFICSv3/GRFICS ICS OT attack chain design with Caldera.md` contains **4 complete attack chains**, all fully designed for Caldera automation:

### Chain 1: Direct Modbus Write (Stealthy Process Manipulation)
Foothold on Kali → nmap ICS subnet → Modbus device enumeration → Read baseline process state → Close purge valve (HR[1]=0 on .12) → Open feed valve fully (HR[1]=65535 on .10) → Sustained writes to override PLC corrections → **Reactor overpressure**

### Chain 2: PLC Logic Replacement
Access HMI → Enumerate PLC → Default creds `openplc:openplc` on PLC web → Download current ST program → Upload malicious ST (forces all feeds max, purge/product closed, disables pressure_override) → Compile and start → **Full process loss of control**

### Chain 3: HMI Compromise + Operator Deception
Login to SCADA-LTS with `admin:admin` → Enumerate data sources → Read all process I/O → Simultaneously: close purge + open feeds + **spoof Tank pressure** (write false normal value to IR on .14) → **Pressure excursion while operators see normal values**

### Chain 4: Safety System Defeat
Enumerate PLC's own Modbus slave registers (MW0-MW30, coils) → Write dangerous setpoints (MW0=65535, MW2=0, MW4=65535) → Manipulate run_bit coil → **Defeat built-in safe-state mechanism**

Each chain includes full Caldera ability YAMLs, adversary profiles, REST API curl commands, MITRE ATT&CK for ICS technique mappings, expected telemetry/log sources, and detection engineering recommendations.

---

## 9. Network Topology Summary

```
┌─────────────────────────────────────────────────────────────┐
│                    a-grfics-admin (Docker bridge)           │
│    All containers connected for management                  │
│    + ELK Stack (Elasticsearch, Logstash, Kibana, Filebeat)  │
└─────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│              b-ics-net  (192.168.95.0/24)                  │
│                                                            │
│  ┌──────────┐  ┌──────────────────────────────────────┐    │
│  │   PLC    │  │         SIMULATION                   │    │
│  │  .2:8080 │  │  .10 Feed1    .11 Feed2              │    │
│  │  .2:502  │  │  .12 Purge    .13 Product            │    │
│  │ (Modbus  │  │  .14 Tank     .15 Analyzer           │    │
│  │  master) │  │  (All on port 502)                   │    │
│  └──────────┘  │  .10:80 (Web visualization)          │    │
│                └──────────────────────────────────────┘    │
│  ┌──────────┐                                              │
│  │   EWS    │  ┌────────────────┐                          │
│  │  .5:6080 │  │    ROUTER      │                          │
│  │ (noVNC)  │  │  .200 (ICS)    │                          │
│  └──────────┘  │  Flask :5000   │                          │
│                │  Suricata IDS  │                          │
│                └────────┬───────┘                          │
└─────────────────────────┼──────────────────────────────────┘
                          │
┌─────────────────────────┼──────────────────────────────────┐
│              c-dmz-net  │ (192.168.90.0/24)                │
│                         │                                  │
│                ┌────────┴───────┐                          │
│                │    ROUTER      │                          │
│                │  .200 (DMZ)    │                          │
│                └────────────────┘                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │   HMI    │  │   KALI   │  │ CALDERA  │                  │
│  │ .107:8080│  │  .6:6080 │  │ .250:8888│                  │
│  │SCADA-LTS │  │(attacker)│  │  (C2)    │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
└────────────────────────────────────────────────────────────┘
```

### Routing
- **simulation** → DMZ via `route add -net 192.168.90.0/24 gw 192.168.95.200`
- **plc** → DMZ via `route add -net 192.168.90.0/24 gw 192.168.95.200`
- **ews** → DMZ via `route add -net 192.168.90.0/24 gw 192.168.95.200`
- **hmi** → ICS net via `ip route add 192.168.95.0/24 via 192.168.90.200`
- **router** → IP forwarding enabled (`net.ipv4.ip_forward=1`), `iptables -P FORWARD ACCEPT` by default

### Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| PLC (OpenPLC web) | `openplc` | `openplc` |
| HMI (SCADA-LTS) | `admin` | `admin` |
| Router (Firewall UI) | `admin` | `password` |
| Caldera (Red team) | `red` | `fortiphyd-red` |
| Caldera (Blue team) | `blue` | `fortiphyd-blue` |
| EWS (Linux user) | `engineer` | `plc123` |

### Host-Exposed Ports

| Host Port | Container | Internal Port | Service |
|-----------|-----------|---------------|---------|
| 80 | simulation | 80 | 3D Web Visualization (nginx) |
| 8080 | plc | 8080 | OpenPLC Web Interface |
| 6080 | ews | 6080 | Engineering Workstation (noVNC) |
| 6081 | hmi | 8080 | SCADA-LTS HMI |
| 6088 | kali | 6080 | Kali Attacker (noVNC) |
| 8888 | caldera | 8888 | Caldera C2 Framework |
| 9200 | elasticsearch | 9200 | Elasticsearch API |
| 5601 | kibana | 5601 | Kibana Dashboard |
| 5044 | logstash | 5044 | Beats input |
| 5000/udp | logstash | 5000 | Syslog UDP |
| 9600 | logstash | 9600 | Logstash monitoring |