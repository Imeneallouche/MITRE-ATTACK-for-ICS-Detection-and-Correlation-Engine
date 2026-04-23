#!/usr/bin/env bash
# Quick health check: Elasticsearch has expected ics-* indices with non-zero docs
# for core log types. Requires curl and a reachable Elasticsearch (e.g. localhost:9200).
set -euo pipefail
ES="${ELASTICSEARCH_URL:-http://localhost:9200}"

echo "Checking Elasticsearch at $ES ..."
curl -sS "$ES/_cluster/health?pretty" | head -8

echo ""
echo "ics-* indices (doc counts):"
curl -sS "$ES/_cat/indices/ics-*?v&s=index" || true

echo ""
echo "Sample log_type coverage (ics-process-*):"
curl -sS "$ES/ics-process-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d '{"aggs":{"lt":{"terms":{"field":"log_type","size":25}}}}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d.get('aggregations',{}).get('lt',{}).get('buckets',[]), indent=2))" 2>/dev/null || echo "(no ics-process index or python3 missing)"

echo ""
echo "process_alarm documents (should be >0 after simulation bootstrap + pressure events):"
curl -sS "$ES/ics-process-*/_count?q=log_type:process_alarm" | python3 -m json.tool 2>/dev/null || true

echo "Done."
