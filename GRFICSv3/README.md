# GRFICSv3 —  Open Source OT Security Lab

> **GRFICSv3** is a fully containerized OT / ICS cyber-physical security lab that simulates a industrial chemical plant.
> It brings together realistic process dynamics, industrial protocols, engineering tools, and attacker infrastructure all inside Docker.
>
> Use it to explore **ICS / OT security**, practice **incident response**, or develop and test **defensive and offensive tools** in a safe, hands-on environment.

<p align="center">
  <img src="/images/dashboard.png" alt="OT security lab dashboard" width="700">
</p>


---

## 🎯 Who is GRFICS for?

GRFICSv3 is designed for anyone learning or teaching **OT and ICS security**, including:

- OT / ICS security practitioners and engineers
- Blue teams and incident responders training on industrial environments
- Red teams exploring ICS-specific attack paths
- Educators building hands-on industrial cybersecurity labs
- Researchers developing or testing OT security tools

If you’ve ever wanted a realistic **OT security lab** without racks of hardware,
this is for you.

<p align="center">
  <img src="/images/diagram.png" alt="Network diagram of OT security lab" width="700">
</p>

---

## 🚀 Key Features

* **End-to-end OT / ICS security lab** — PLCs, HMIs, engineering workstations, routers, and attacker tools
* **3D process visualization** — watch tank levels and valves respond in real time
* **Virtual Walkthroughs** — explore the warehouse in first person, observing physical layouts and security lapses 
* **Built-in attack & defense tools** — Kali Linux, MITRE Caldera, and a custom firewall and Suricata IDS interface
* **Modular, containerized design** — launch everything with a single `docker compose up`
* **Realistic networking** — segmented process and enterprise zones with controllable traffic flow

---

## Physical Vulnerabilities & Cyber Hygiene

One of the most powerful aspects of GRFICSv3 as an **OT security lab** is the ability to
virtually walk the entire plant and warehouse.

This allows learners to understand what a real industrial environment looks like and
identify common **physical security and cyber hygiene failures**, such as:

- Passwords written on sticky notes
- Propped-open security doors
- Unlocked cabinets and control panels
- Poor separation between IT and OT spaces

As vulnerabilities are discovered, the **Vulnerabilities Found** tracker in the top-left
corner keeps score — making this ideal for self-paced learning and classroom exercises.

<p align="center">
  <img src="/images/vulns.png" alt="Track physical vulnerabilities and cyber hygiene" width="700">
</p>

---

# 🤌 Installation

## 1. Prerequisites

* **Recommended OS:** Linux (native, VM, or WSL2)
  GRFICS uses Docker and Docker Compose. Linux provides the lightest and most reliable experience, but following Docker's instructions for Windows should work fine too.
* **Required packages:**
  * For prebuilt images - Docker and Docker Compose
  * For building from source - Docker, Docker Compose, Git, and Git LFS

You can find an example walkthrough installation video here:
https://youtu.be/X7YYCLJxMmo?si=qHRXlzfovdr3HsSZ

Otherwise, you can follow the instructions below.

Example install on Debian/Ubuntu:

```bash
# Remove packages that conflict with Docker
sudo apt remove $(dpkg --get-selections docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc | cut -f1)

# Add Docker's official GPG key:
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update

# Install latest version of Docker
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Install git
sudo apt install -y git git-lfs

# (Optional) allow non-root docker use
sudo usermod -aG docker $USER
```

Log out and back in if you added yourself to the Docker group.

---

## 2. Install GRFICS

You can either **pull the prebuilt images from Docker Hub** (quick and easy)  
or **build everything locally** if you want to modify or customize.

---

### 🐋 Option A: Pull prebuilt images (recommended)

The fastest way to get started — no building required!

```bash
# Download the latest docker-compose.yml
curl -O https://raw.githubusercontent.com/Fortiphyd/GRFICSv3/main/docker-compose.yml

# Start GRFICS using prebuilt images from Docker Hub
docker compose pull
docker compose up -d
```

### 🏗️ Option B: Clone and build

```bash
sudo apt install -y git git-lfs
git clone https://github.com/Fortiphyd/GRFICSv3.git
cd GRFICSv3
docker compose build
```

Start the environment:

```bash
docker compose up -d
```

Watch logs (optional):

```bash
docker compose logs -f
```

Then open your browser and visit **[http://localhost](http://localhost)** —
you should see the 3D chemical plant simulation come to life.

---

# 🗞 Using GRFICS

## Starting & Stopping

* To stop all running containers:

  ```bash
  docker compose down
  ```
* To stop but keep containers/images:

  ```bash
  docker compose stop
  ```
* To restart later:

  ```bash
  docker compose start
  ```

---

## Core Containers & Access Points

| Container                   | How to Access                                                           | Credentials           | Description                               |
| --------------------------- | ----------------------------------------------------------------------- | --------------------- | ----------------------------------------- |
| **Simulation**              | [http://localhost](http://localhost)                                    | —                     | 3D chemical plant visualization           |
| **Engineering Workstation** | [http://localhost:6080](http://localhost:6080)        | —                     | HMI and PLC configuration                 |
| **Kali**                    | [http://localhost:6088](http://localhost:6088)        | `kali : kali`         | Attacker VM for exploitation and scanning |
| **Caldera**                 | [http://localhost:8888](http://localhost:8888)                          | `red : fortiphyd-red` | MITRE Caldera with OT plugin              |
| **PLC (OpenPLC)**           | [http://localhost:8080](http://localhost:8080) or `192.168.95.2:8080`   | `openplc : openplc`   | Programmable logic controller             |
| **HMI**                     | [http://localhost:6081](http://localhost:6081) or `192.168.90.107:8080` | `admin : admin`       | Operator interface                        |
| **Router / Firewall UI**    | `192.168.90.200:5000` or `192.168.95.200:5000`                          | `admin : password`    | View or modify firewall rules             |


---

## Screenshots

Simulation

![Simulation screenshot](/images/sim.png)

Kali

![Kali screenshot](/images/kali.png)

Caldera

![Caldera screenshot](/images/caldera.png)

Engineering Workstation

![EW screenshot](/images/ew.png)

Router / Firewall

![Router screenshot](/images/firewall.png)

PLC

![PLC screenshot](/images/plc.png)

HMI

![HMI screenshot](/images/hmi.png)

---

# 🛠 Troubleshooting

### Network interface errors

If build or startup fails with a message about creating a network interface,
edit `docker-compose.yml` (around lines 140 and 149) to match your actual network interface name (e.g., `eth0`, `enp0s3`, or your WSL adapter).

### Permission errors

If you see `permission denied` errors running Docker commands, prefix with `sudo` or ensure your user is added to the `docker` group.

### Container won’t start

Run:

```bash
docker compose logs <service-name>
```

to view detailed logs, or `docker compose ps` to check the status of all containers.

### Resetting everything

To rebuild from scratch:

```bash
docker compose down --volumes
docker compose up -d --build
```

---

# ⚙️ Development Tips

* To rebuild a single service:

  ```bash
  docker compose build <service-name>
  docker compose up -d <service-name>
  ```
* To monitor logs interactively:

  ```bash
  docker compose logs -f
  ```
* To check which containers are running:

  ```bash
  docker compose ps
  ```

---

# 🌐 About GRFICS

GRFICS was created by **Fortiphyd Logic** to make industrial cybersecurity **accessible, hands-on, and realistic**.
Version 3 takes everything from earlier GRFICS releases and brings it into a modern, containerized architecture
ready for use in classrooms, cyber ranges, and research environments.

Learn more at [https://fortiphyd.com](https://fortiphyd.com)

---

# 💡 More from Fortiphyd Logic

If you enjoy GRFICSv3, you may be interested in our commercial offerings that expand on GRFICS with:

- A growing catalog of **sector-specific simulations** — power grid, water, manufacturing, and maritime
- **Hosted cyber ranges** for teams and classrooms, no installation required

Visit [https://fortiphyd.com](https://fortiphyd.com) to learn more, or [follow us on LinkedIn](https://www.linkedin.com/company/fortiphyd-logic) for updates, new labs, and release announcements.

💛 If you use GRFICSv3 in your research, teaching, or demos and want to help sustain its development, consider **sponsoring the project**. Even small contributions help us keep improving the open version!

---

> **Build. Break. Defend. Learn.**  
> GRFICSv3 brings industrial cybersecurity to life, no hardware required.

