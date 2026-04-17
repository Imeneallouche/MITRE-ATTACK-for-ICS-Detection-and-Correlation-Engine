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
  "$BASE/ews/supervisord.log"

  "$BASE/hmi/auth.log"
  "$BASE/hmi/syslog"
  "$BASE/hmi/daemon.log"
  "$BASE/hmi/kern.log"

  "$BASE/router/syslog"
  "$BASE/simulation/nginx/access.log"
  "$BASE/simulation/nginx/error.log"
  "$BASE/simulation/supervisor/supervisord.log"
  "$BASE/router/netfilter/ulogd.log"
  "$BASE/router/supervisor/supervisord.log"
)

for f in "${files[@]}"; do
  touch "$f"
done

echo "shared_logs structure initialised."
