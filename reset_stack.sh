#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VOLUME_NAME="mitre-attack-for-ics-detection-and-correlation-engine_elasticsearch_data"
SHARED_LOGS_DIR="$SCRIPT_DIR/shared_logs"
INIT_SCRIPT="$SCRIPT_DIR/init_shared_logs.sh"
SSH_SETUP_SCRIPT="$SCRIPT_DIR/setup_ssh_rsyslog.sh"

log() {
  echo "=== $1 ==="
}

run_script() {
  local script_path="$1"

  if [[ -x "$script_path" ]]; then
    "$script_path"
  elif [[ -f "$script_path" ]]; then
    bash "$script_path"
  else
    log "Skipping missing script: $(basename "$script_path")"
  fi
}

trap 'echo "Error on line $LINENO. Reset aborted." >&2' ERR

log "Stopping all containers"
if [[ -f "$SCRIPT_DIR/docker-compose.yml" || -f "$SCRIPT_DIR/compose.yml" || -f "$SCRIPT_DIR/compose.yaml" ]]; then
  docker compose down --remove-orphans || true
else
  log "No compose file found, skipping docker compose down"
fi

log "Removing Elasticsearch volume if it exists"
if docker volume inspect "$VOLUME_NAME" >/dev/null 2>&1; then
  docker volume rm "$VOLUME_NAME"
else
  log "Volume not found, skipping: $VOLUME_NAME"
fi

log "Deleting shared logs if the directory exists"
if [[ -d "$SHARED_LOGS_DIR" ]]; then
  rm -rf "$SHARED_LOGS_DIR"
else
  log "Directory not found, skipping: shared_logs"
fi

log "Re-initializing shared logs"
run_script "$INIT_SCRIPT"

log "Restarting full stack"
if [[ -f "$SCRIPT_DIR/docker-compose.yml" || -f "$SCRIPT_DIR/compose.yml" || -f "$SCRIPT_DIR/compose.yaml" ]]; then
  docker compose up -d
else
  log "No compose file found, skipping docker compose up"
fi

log "Setting up SSH and rsyslog"
run_script "$SSH_SETUP_SCRIPT"

log "Reset complete ✅"
