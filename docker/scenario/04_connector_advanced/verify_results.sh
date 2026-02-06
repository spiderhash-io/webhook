#!/bin/bash
# Verify that webhooks were received by a local processor
#
# Usage: ./verify_results.sh [expected_count] [log_path] [max_wait]
#   expected_count: Expected number of webhooks (default: 5)
#   log_path:       Path to log file (default: ./logs/local-a/webhooks.log)
#   max_wait:       Max seconds to wait (default: 60)

set -e

EXPECTED_COUNT="${1:-5}"
LOG_PATH="${2:-./logs/local-a/webhooks.log}"
MAX_WAIT="${3:-60}"
WAIT_INTERVAL=2

count_webhooks() {
    if [ -d "$1" ]; then
        find "$1" -type f \( -name "*.txt" -o -name "*.json" \) 2>/dev/null | wc -l | tr -d ' '
    elif [ -f "$1" ]; then
        wc -l < "$1" | tr -d ' '
    else
        echo "0"
    fi
}

echo "Verifying: expecting $EXPECTED_COUNT webhooks in $LOG_PATH"

waited=0
while [ ! -e "$LOG_PATH" ] && [ $waited -lt $MAX_WAIT ]; do
    sleep $WAIT_INTERVAL
    waited=$((waited + WAIT_INTERVAL))
done

if [ ! -e "$LOG_PATH" ]; then
    echo "  FAIL: Log path not found after ${MAX_WAIT}s"
    exit 1
fi

ACTUAL_COUNT=$(count_webhooks "$LOG_PATH")

while [ "$ACTUAL_COUNT" -lt "$EXPECTED_COUNT" ] && [ $waited -lt $MAX_WAIT ]; do
    sleep $WAIT_INTERVAL
    waited=$((waited + WAIT_INTERVAL))
    ACTUAL_COUNT=$(count_webhooks "$LOG_PATH")
done

ACTUAL_COUNT=$(count_webhooks "$LOG_PATH")

if [ "$ACTUAL_COUNT" -ge "$EXPECTED_COUNT" ]; then
    echo "  PASS: $ACTUAL_COUNT/$EXPECTED_COUNT webhooks received"
    exit 0
else
    echo "  FAIL: Only $ACTUAL_COUNT/$EXPECTED_COUNT webhooks received"
    exit 1
fi
