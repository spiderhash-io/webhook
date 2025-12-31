#!/bin/bash
# Redis Module Integration Test
# Uses Python requests from inside container for reliable HTTP requests

set -e

echo "=========================================="
echo "Redis Module Integration Test"
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

# Test Redis Rq webhook
print("")
print("Testing Redis Rq webhook...")
try:
    response = requests.post(
        f"{webhook_url}/webhook/test_redis_rq",
        json={"test": "data", "message": "Hello Redis Rq"},
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        },
        timeout=10
    )
    if response.status_code == 200:
        print(f"✓ Redis Rq webhook test passed (HTTP {response.status_code})")
        print(f"Response: {response.json()}")
    else:
        print(f"✗ Redis Rq webhook test failed (HTTP {response.status_code})")
        print(f"Response: {response.text}")
        sys.exit(1)
except Exception as e:
    print(f"✗ Redis Rq webhook test failed with error: {e}")
    sys.exit(1)

# Test Redis Publish webhook
print("")
print("Testing Redis Publish webhook...")
try:
    response = requests.post(
        f"{webhook_url}/webhook/test_redis_publish",
        json={"test": "data", "message": "Hello Redis Publish"},
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        },
        timeout=10
    )
    if response.status_code == 200:
        print(f"✓ Redis Publish webhook test passed (HTTP {response.status_code})")
        print(f"Response: {response.json()}")
    else:
        print(f"✗ Redis Publish webhook test failed (HTTP {response.status_code})")
        print(f"Response: {response.text}")
        sys.exit(1)
except Exception as e:
    print(f"✗ Redis Publish webhook test failed with error: {e}")
    sys.exit(1)

print("")
print("==========================================")
print("Redis module tests passed! ✓")
print("==========================================")
EOF
