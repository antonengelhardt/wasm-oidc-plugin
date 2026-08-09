#!/usr/bin/env bash
set -euo pipefail

# Performance testing script for wasm-oidc-plugin
# Usage: ./scripts/performance.sh <endpoint> [num_requests]

ENDPOINT="${1:-http://localhost:10000}"
NUM_REQUESTS="${2:-1000}"

echo "Running performance test against $ENDPOINT with $NUM_REQUESTS requests..."

START_TIME=$(date +%s%N)
for i in $(seq 1 "$NUM_REQUESTS"); do
  curl -s -o /dev/null "$ENDPOINT" || true
done
END_TIME=$(date +%s%N)

ELAPSED=$(( (END_TIME - START_TIME) / 1000000 ))
echo "Completed $NUM_REQUESTS requests in ${ELAPSED}ms"
THROUGHPUT=$(awk "BEGIN {printf \"%.2f\", $NUM_REQUESTS / ($ELAPSED / 1000)}")
echo "Throughput: $THROUGHPUT req/s"
