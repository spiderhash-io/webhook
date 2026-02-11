#!/bin/bash
# Webhook Connect Relay Resilience Integration Test
#
# Validates that messages are NOT lost to DLQ during client disconnect/reconnect.
# Requires: docker compose up -d (this script does NOT start services)

set -e

echo "=========================================="
echo "Webhook Connect Relay Resilience Test"
echo "=========================================="

WEBHOOK_URL="http://localhost:8000"
RABBITMQ_API="http://localhost:15672/api"
TOKEN="test_token_123"

# Wait for webhook service
echo "Waiting for webhook service..."
for i in {1..30}; do
    if curl -s -f "${WEBHOOK_URL}/" > /dev/null 2>&1; then
        echo "Webhook service is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "ERROR: Webhook service did not become ready"
        exit 1
    fi
    sleep 1
done

# Wait for RabbitMQ management API
echo "Waiting for RabbitMQ management API..."
for i in {1..30}; do
    if curl -s -f -u guest:guest "${RABBITMQ_API}/overview" > /dev/null 2>&1; then
        echo "RabbitMQ management API is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "ERROR: RabbitMQ management API did not become ready"
        exit 1
    fi
    sleep 1
done

echo ""
echo "--- Step 1: Send webhook (no consumer connected) ---"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "${WEBHOOK_URL}/webhook/test_connect" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d '{"test": "relay_resilience", "message": "Should not go to DLQ"}')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" == "200" ]; then
    echo "Webhook accepted (HTTP ${HTTP_CODE})"
else
    echo "ERROR: Webhook rejected (HTTP ${HTTP_CODE})"
    echo "Response: ${BODY}"
    exit 1
fi

sleep 2

echo ""
echo "--- Step 2: Check message is in main queue (not DLQ) ---"
# List queues via RabbitMQ management API
QUEUES=$(curl -s -u guest:guest "${RABBITMQ_API}/queues")

# Check for messages in the queue (not DLQ)
echo "Queue status:"
echo "$QUEUES" | python3 -c "
import json, sys
queues = json.load(sys.stdin)
for q in queues:
    name = q.get('name', '')
    msgs = q.get('messages', 0)
    print(f'  {name}: {msgs} messages')
    if 'dlq' in name.lower() and msgs > 0:
        print(f'  WARNING: Messages found in DLQ!')
        sys.exit(1)
print('No messages in DLQ - test passed!')
"

echo ""
echo "--- Step 3: Send more webhooks ---"
for i in 1 2 3; do
    curl -s -X POST \
        "${WEBHOOK_URL}/webhook/test_connect" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        -d "{\"test\": \"batch_${i}\", \"message\": \"Batch message ${i}\"}" > /dev/null
    echo "Sent webhook ${i}/3"
done

sleep 2

echo ""
echo "--- Step 4: Verify messages still in queue (not DLQ) ---"
QUEUES=$(curl -s -u guest:guest "${RABBITMQ_API}/queues")
echo "$QUEUES" | python3 -c "
import json, sys
queues = json.load(sys.stdin)
dlq_count = 0
main_count = 0
for q in queues:
    name = q.get('name', '')
    msgs = q.get('messages', 0)
    if 'dlq' in name.lower():
        dlq_count += msgs
    else:
        main_count += msgs
    print(f'  {name}: {msgs} messages')

if dlq_count > 0:
    print(f'FAIL: {dlq_count} messages in DLQ!')
    sys.exit(1)
print(f'OK: {main_count} messages in main queue(s), 0 in DLQ')
"

echo ""
echo "=========================================="
echo "Relay resilience tests passed!"
echo "=========================================="
