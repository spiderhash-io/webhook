#!/bin/bash
# Send test webhooks to cloud receiver
#
# Usage: ./send_webhooks.sh [count] [delay_ms] [endpoint] [cloud_url]
#   count:     Number of webhooks to send (default: 5)
#   delay_ms:  Delay between webhooks in milliseconds (default: 100)
#   endpoint:  Webhook endpoint name (default: cloud-webhook-alpha)
#   cloud_url: Cloud receiver URL (default: http://localhost:8010)

set -e

COUNT="${1:-5}"
DELAY_MS="${2:-100}"
ENDPOINT="${3:-cloud-webhook-alpha}"
CLOUD_URL="${4:-http://localhost:8010}"
DELAY_SEC=$(echo "scale=3; $DELAY_MS / 1000" | bc)

echo "Sending $COUNT webhooks to $CLOUD_URL/webhook/$ENDPOINT"

SUCCESS_COUNT=0
FAIL_COUNT=0

for i in $(seq 1 $COUNT); do
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")

    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$CLOUD_URL/webhook/$ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "{
            \"event\": \"test_event\",
            \"sequence\": $i,
            \"timestamp\": \"$TIMESTAMP\",
            \"channel_endpoint\": \"$ENDPOINT\",
            \"data\": {
                \"message\": \"Test webhook $i of $COUNT\",
                \"value\": $((RANDOM % 1000))
            }
        }" 2>/dev/null)

    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" -eq 200 ] || [ "$HTTP_CODE" -eq 202 ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "  [$i/$COUNT] FAILED (HTTP $HTTP_CODE): $BODY"
    fi

    if [ "$i" -lt "$COUNT" ]; then
        sleep "$DELAY_SEC"
    fi
done

echo "  Sent: $SUCCESS_COUNT success, $FAIL_COUNT failed"

# Return exit code based on results
if [ "$FAIL_COUNT" -gt 0 ] && [ "$SUCCESS_COUNT" -eq 0 ]; then
    exit 1
fi
exit 0
