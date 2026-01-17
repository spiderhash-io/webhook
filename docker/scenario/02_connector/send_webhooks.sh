#!/bin/bash
# Send test webhooks to cloud receiver
#
# Usage: ./send_webhooks.sh [count] [delay_ms]
#   count: Number of webhooks to send (default: 10)
#   delay_ms: Delay between webhooks in milliseconds (default: 100)

set -e

CLOUD_URL="${CLOUD_URL:-http://localhost:8010}"
COUNT="${1:-10}"
DELAY_MS="${2:-100}"
DELAY_SEC=$(echo "scale=3; $DELAY_MS / 1000" | bc)

echo "=================================================="
echo "Sending $COUNT webhooks to cloud receiver"
echo "URL: $CLOUD_URL/webhook/cloud-webhook"
echo "Delay between requests: ${DELAY_MS}ms"
echo "=================================================="

for i in $(seq 1 $COUNT); do
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")

    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$CLOUD_URL/webhook/cloud-webhook" \
        -H "Content-Type: application/json" \
        -d "{
            \"event\": \"test_event\",
            \"sequence\": $i,
            \"timestamp\": \"$TIMESTAMP\",
            \"data\": {
                \"message\": \"Test webhook $i of $COUNT\",
                \"value\": $((RANDOM % 1000))
            }
        }")

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    # Get all lines except the last (portable approach for macOS and Linux)
    BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" -eq 200 ] || [ "$HTTP_CODE" -eq 202 ]; then
        echo "[$i/$COUNT] Sent successfully (HTTP $HTTP_CODE)"
    else
        echo "[$i/$COUNT] Failed (HTTP $HTTP_CODE): $BODY"
    fi

    if [ "$i" -lt "$COUNT" ]; then
        sleep $DELAY_SEC
    fi
done

echo ""
echo "=================================================="
echo "Sent $COUNT webhooks to cloud receiver"
echo "=================================================="
