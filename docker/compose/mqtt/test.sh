#!/bin/bash
# Mqtt Module Integration Test
# Uses Python requests from inside container for reliable HTTP requests

set -e

echo "=========================================="
echo "Mqtt Module Integration Test"
echo "=========================================="

WEBHOOK_URL="http://localhost:8000"
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

# Run tests from inside the container for reliable HTTP requests
# Change to script directory to ensure docker compose works correctly
cd "$(dirname "$0")" || exit 1
docker compose exec -T webhook python3 << EOF
import requests
import sys

webhook_url = "http://localhost:8000"
token = "${TOKEN}"

# Test Mqtt webhook
print("")
print("Testing Mqtt webhook...")
try:
    response = requests.post(
        f"{webhook_url}/webhook/test_mqtt",
        json={"test": "data", "message": "Hello Mqtt"},
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        },
        timeout=10
    )
    if response.status_code == 200:
        print(f"✓ Mqtt webhook test passed (HTTP {response.status_code})")
        print(f"Response: {response.json()}")
    else:
        print(f"✗ Mqtt webhook test failed (HTTP {response.status_code})")
        print(f"Response: {response.text}")
        sys.exit(1)
except Exception as e:
    print(f"✗ Mqtt webhook test failed with error: {e}")
    sys.exit(1)

print("")
print("==========================================")
print("Mqtt module tests passed! ✓")
print("==========================================")
EOF
