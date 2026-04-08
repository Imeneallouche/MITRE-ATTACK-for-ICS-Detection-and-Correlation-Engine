#!/bin/bash

set -e

echo "=== Stopping all containers ==="
docker compose down

echo "=== Removing Elasticsearch volume ==="
docker volume rm mitre-attack-for-ics-detection-and-correlation-engine_elasticsearch_data

echo "=== Deleting shared logs ==="
rm -rf shared_logs

echo "=== Re-initializing shared logs ==="
./init_shared_logs.sh


echo "=== Restarting full stack ==="
docker compose up -d


echo "=== Reset complete ✅ ==="

./setup_ssh_rsyslog.sh
