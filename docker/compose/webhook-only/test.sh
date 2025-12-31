#!/bin/bash
# Webhook Only Module Integration Test
# Uses Python requests from inside container for reliable HTTP requests

set -e

echo "=========================================="
echo "Webhook Only Module Integration Test"
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
# Note: For webhook-only, we run from host but use docker exec to access the container
cd "$(dirname "$0")" || exit 1
docker compose exec -T webhook python3 << EOF
import requests
import sys

webhook_url = "http://localhost:8000"
token = "${TOKEN}"

# Test Log webhook
print("")
print("Testing Log webhook...")
try:
    response = requests.post(
        f"{webhook_url}/webhook/test_log",
        json={"test": "data", "message": "Hello Log"},
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        },
        timeout=10
    )
    if response.status_code == 200:
        print(f"✓ Log webhook test passed (HTTP {response.status_code})")
        print(f"Response: {response.json()}")
    else:
        print(f"✗ Log webhook test failed (HTTP {response.status_code})")
        print(f"Response: {response.text}")
        sys.exit(1)
except Exception as e:
    print(f"✗ Log webhook test failed with error: {e}")
    sys.exit(1)

# Test Save To Disk webhook
print("")
print("Testing Save To Disk webhook...")
try:
    response = requests.post(
        f"{webhook_url}/webhook/test_save_to_disk",
        json={"test": "data", "message": "Hello Save To Disk"},
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        },
        timeout=10
    )
    if response.status_code == 200:
        print(f"✓ Save To Disk webhook test passed (HTTP {response.status_code})")
        print(f"Response: {response.json()}")
    else:
        print(f"✗ Save To Disk webhook test failed (HTTP {response.status_code})")
        print(f"Response: {response.text}")
        sys.exit(1)
except Exception as e:
    print(f"✗ Save To Disk webhook test failed with error: {e}")
    sys.exit(1)

print("")
print("==========================================")
print("Webhook Only module tests passed! ✓")
print("==========================================")
EOF
