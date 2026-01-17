#!/bin/bash
# Verify that webhooks were received by local processor
#
# Usage: ./verify_results.sh [expected_count]
#   expected_count: Expected number of webhooks (default: 10)

set -e

EXPECTED_COUNT="${1:-10}"
LOG_PATH="./logs/local/webhooks.log"
MAX_WAIT=60
WAIT_INTERVAL=2

echo "=================================================="
echo "Verifying webhook delivery"
echo "Expected count: $EXPECTED_COUNT"
echo "Log path: $LOG_PATH"
echo "=================================================="

# Wait for log file/directory to exist
echo ""
echo "Waiting for webhooks to be delivered..."
waited=0
while [ ! -e "$LOG_PATH" ] && [ $waited -lt $MAX_WAIT ]; do
    sleep $WAIT_INTERVAL
    waited=$((waited + WAIT_INTERVAL))
    echo "  Waiting... ($waited seconds)"
done

if [ ! -e "$LOG_PATH" ]; then
    echo ""
    echo "ERROR: Log path not found after ${MAX_WAIT}s"
    echo "Check if local-processor and connector are running"
    exit 1
fi

# Count delivered webhooks (handle both file and directory)
count_webhooks() {
    if [ -d "$LOG_PATH" ]; then
        # Directory with individual files
        find "$LOG_PATH" -type f -name "*.txt" -o -name "*.json" 2>/dev/null | wc -l | tr -d ' '
    elif [ -f "$LOG_PATH" ]; then
        # Single file with one webhook per line
        wc -l < "$LOG_PATH" | tr -d ' '
    else
        echo "0"
    fi
}

ACTUAL_COUNT=$(count_webhooks)

echo ""
echo "Results:"
echo "  Expected: $EXPECTED_COUNT webhooks"
echo "  Received: $ACTUAL_COUNT webhooks"

# Wait for more webhooks if needed
while [ "$ACTUAL_COUNT" -lt "$EXPECTED_COUNT" ] && [ $waited -lt $MAX_WAIT ]; do
    sleep $WAIT_INTERVAL
    waited=$((waited + WAIT_INTERVAL))
    ACTUAL_COUNT=$(count_webhooks)
    echo "  Waiting for more webhooks... (received $ACTUAL_COUNT, waited $waited seconds)"
done

ACTUAL_COUNT=$(count_webhooks)

echo ""
echo "=================================================="
if [ "$ACTUAL_COUNT" -ge "$EXPECTED_COUNT" ]; then
    echo "SUCCESS: All webhooks delivered!"
    echo "  Expected: $EXPECTED_COUNT"
    echo "  Received: $ACTUAL_COUNT"

    # Show sample of received webhooks
    echo ""
    echo "Sample of received webhooks (first 3):"
    if [ -d "$LOG_PATH" ]; then
        # Directory with individual files
        find "$LOG_PATH" -type f \( -name "*.txt" -o -name "*.json" \) 2>/dev/null | head -3 | while read file; do
            echo "  $(cat "$file" | head -c 200)..."
        done
    elif [ -f "$LOG_PATH" ]; then
        # Single file
        head -3 "$LOG_PATH" | while read line; do
            echo "  $line" | head -c 200
            echo "..."
        done
    fi

    # Verify sequence numbers
    echo ""
    echo "Sequence number verification:"
    if [ -d "$LOG_PATH" ]; then
        SEQUENCES=$(cat "$LOG_PATH"/*.txt "$LOG_PATH"/*.json 2>/dev/null | grep -o '"sequence":[0-9]*\|'"'"'sequence'"'"':[[:space:]]*[0-9]*' | grep -o '[0-9]*' | sort -n | uniq)
    else
        SEQUENCES=$(cat "$LOG_PATH" | grep -o '"sequence":[0-9]*' | cut -d: -f2 | sort -n | uniq)
    fi
    FIRST_SEQ=$(echo "$SEQUENCES" | head -1)
    LAST_SEQ=$(echo "$SEQUENCES" | tail -1)
    SEQ_COUNT=$(echo "$SEQUENCES" | wc -l | tr -d ' ')
    echo "  First sequence: $FIRST_SEQ"
    echo "  Last sequence: $LAST_SEQ"
    echo "  Unique sequences: $SEQ_COUNT"
else
    echo "FAILURE: Not all webhooks delivered"
    echo "  Expected: $EXPECTED_COUNT"
    echo "  Received: $ACTUAL_COUNT"
    echo "  Missing: $((EXPECTED_COUNT - ACTUAL_COUNT))"
    exit 1
fi
echo "=================================================="
