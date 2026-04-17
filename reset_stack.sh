#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VOLUME_NAME="mitre-attack-for-ics-detection-and-correlation-engine_elasticsearch_data"
SHARED_LOGS_DIR="$SCRIPT_DIR/shared_logs"
INIT_SCRIPT="$SCRIPT_DIR/init_shared_logs.sh"
SSH_SETUP_SCRIPT="$SCRIPT_DIR/setup_ssh_rsyslog.sh"
ENGINE_CHECKPOINT_FILE="$SCRIPT_DIR/state/engine_checkpoint.json"

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

log "Resetting engine checkpoint"
mkdir -p "$(dirname "$ENGINE_CHECKPOINT_FILE")"
printf '{}\n' > "$ENGINE_CHECKPOINT_FILE"

log "Re-initializing shared logs"
run_script "$INIT_SCRIPT"

log "Starting all services except detection-engine"
if [[ -f "$SCRIPT_DIR/docker-compose.yml" || -f "$SCRIPT_DIR/compose.yml" || -f "$SCRIPT_DIR/compose.yaml" ]]; then
  mapfile -t COMPOSE_SERVICES < <(docker compose config --services 2>/dev/null | grep -v '^detection-engine$' || true)

  if ((${#COMPOSE_SERVICES[@]} > 0)); then
    docker compose up -d "${COMPOSE_SERVICES[@]}"
  else
    log "No compose services found, skipping initial bring-up"
  fi
else
  log "No compose file found, skipping docker compose up"
fi

log "Setting up SSH and rsyslog"
run_script "$SSH_SETUP_SCRIPT"

log "Waiting 60 seconds before starting detection-engine"
sleep 60

log "Starting detection-engine"
if [[ -f "$SCRIPT_DIR/docker-compose.yml" || -f "$SCRIPT_DIR/compose.yml" || -f "$SCRIPT_DIR/compose.yaml" ]]; then
  docker compose up -d detection-engine
else
  log "No compose file found, skipping detection-engine start"
fi

log "Reset complete ✅"