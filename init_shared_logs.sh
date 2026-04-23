#!/usr/bin/env bash
set -euo pipefail

# Create all shared_logs directories that docker-compose bind-mounts expect.
# Run once before first `docker compose up`.

BASE="./shared_logs"

dirs=(
  # simulation
  "$BASE/simulation"
  "$BASE/simulation/process_alarms"
  "$BASE/simulation/supervisor"
  "$BASE/simulation/nginx"

  # plc
  "$BASE/plc"
  "$BASE/plc/audit"
  "$BASE/plc/plc_app"

  # ews
  "$BASE/ews"
  "$BASE/ews/audit"

  # hmi
  "$BASE/hmi"
  "$BASE/hmi/catalina"
  "$BASE/hmi/audit"
  "$BASE/hmi/supervisor"

  # router
  "$BASE/router"
  "$BASE/router/netfilter"
  "$BASE/router/flask"
  "$BASE/router/supervisor"
)

for d in "${dirs[@]}"; do
  mkdir -p "$d"
done

# Optional: touch Suricata eve.json so the path exists before the IDS starts
# (empty file; Suricata overwrites with NDJSON when running).
if [[ ! -f "$BASE/router/eve.json" ]]; then
  touch "$BASE/router/eve.json"
fi

# Create empty log files for file-level bind mounts (Docker needs the host
# path to exist before it will bind-mount a file rather than a directory).
files=(
  "$BASE/simulation/syslog"
  "$BASE/simulation/auth.log"
  "$BASE/simulation/kern.log"

  "$BASE/plc/auth.log"
  "$BASE/plc/syslog"
  "$BASE/plc/daemon.log"
  "$BASE/plc/kern.log"
  "$BASE/plc/openplc_debug.log"

  "$BASE/ews/auth.log"
  "$BASE/ews/syslog"
  "$BASE/ews/daemon.log"
  "$BASE/ews/kern.log"
  "$BASE/ews/wtmp"
  "$BASE/ews/pacct"
  "$BASE/ews/cron.log"
  "$BASE/ews/cron_fim.log"
  "$BASE/ews/supervisord.log"

  "$BASE/hmi/auth.log"
  "$BASE/hmi/syslog"
  "$BASE/hmi/daemon.log"
  "$BASE/hmi/kern.log"

  "$BASE/router/syslog"
  "$BASE/simulation/nginx/access.log"
  "$BASE/simulation/nginx/error.log"
  "$BASE/simulation/supervisor/supervisord.log"
  "$BASE/simulation/supervisor/modbus.log"
  "$BASE/simulation/supervisor/modbus.err"
  "$BASE/simulation/supervisor/simulation.log"
  "$BASE/simulation/supervisor/simulation.err"
  "$BASE/router/netfilter/ulogd.log"
  "$BASE/router/supervisor/supervisord.log"
)

for f in "${files[@]}"; do
  # Docker bind-mounts a missing host path as a directory; `touch` on a directory
  # does not replace it with a file — rsyslog then sees /var/log/syslog as a dir and fails.
  if [[ -d "$f" ]]; then
    rm -rf "$f"
  fi
  touch "$f"
done

echo "shared_logs structure initialised."
