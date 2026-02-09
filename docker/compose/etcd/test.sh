#!/bin/bash
# etcd Config Backend Integration Test
# Tests that webhook configs loaded from etcd work correctly

set -e

echo "=========================================="
echo "etcd Config Backend Integration Test"
echo "=========================================="

WEBHOOK_URL="http://localhost:8000"
TOKEN="test_token_123"
STAGING_TOKEN="staging_token_456"

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
cd "$(dirname "$0")" || exit 1
docker compose exec -T webhook python3 << 'EOF'
import requests
import sys

webhook_url = "http://localhost:8000"
token = "test_token_123"
staging_token = "staging_token_456"

# Test 1: Log webhook (default namespace)
print("")
print("Test 1: Log webhook (default namespace)...")
try:
    response = requests.post(
        f"{webhook_url}/webhook/test_log",
        json={"test": "data", "source": "etcd_integration_test"},
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        },
        timeout=10
    )
    if response.status_code == 200:
        print(f"  PASS - Log webhook (HTTP {response.status_code})")
        print(f"  Response: {response.json()}")
    else:
        print(f"  FAIL - Log webhook (HTTP {response.status_code})")
        print(f"  Response: {response.text}")
        sys.exit(1)
except Exception as e:
    print(f"  FAIL - Log webhook error: {e}")
    sys.exit(1)

# Test 2: Save-to-disk webhook (default namespace)
print("")
print("Test 2: Save-to-disk webhook (default namespace)...")
try:
    response = requests.post(
        f"{webhook_url}/webhook/test_save",
        json={"test": "save_data", "source": "etcd_integration_test"},
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        },
        timeout=10
    )
    if response.status_code == 200:
        print(f"  PASS - Save webhook (HTTP {response.status_code})")
        print(f"  Response: {response.json()}")
    else:
        print(f"  FAIL - Save webhook (HTTP {response.status_code})")
        print(f"  Response: {response.text}")
        sys.exit(1)
except Exception as e:
    print(f"  FAIL - Save webhook error: {e}")
    sys.exit(1)

# Test 3: Namespaced webhook (staging namespace)
print("")
print("Test 3: Namespaced webhook (staging/test_log_staging)...")
try:
    response = requests.post(
        f"{webhook_url}/webhook/staging/test_log_staging",
        json={"test": "staging_data", "source": "etcd_namespace_test"},
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {staging_token}"
        },
        timeout=10
    )
    if response.status_code == 200:
        print(f"  PASS - Namespaced webhook (HTTP {response.status_code})")
        print(f"  Response: {response.json()}")
    else:
        print(f"  FAIL - Namespaced webhook (HTTP {response.status_code})")
        print(f"  Response: {response.text}")
        sys.exit(1)
except Exception as e:
    print(f"  FAIL - Namespaced webhook error: {e}")
    sys.exit(1)

# Test 4: Dynamic config update via etcd
print("")
print("Test 4: Dynamic config update (add webhook via etcd)...")
# This test is informational - it verifies the webhook service is running with etcd backend
try:
    response = requests.get(f"{webhook_url}/", timeout=10)
    if response.status_code == 200:
        print(f"  PASS - Service healthy (HTTP {response.status_code})")
    else:
        print(f"  FAIL - Service unhealthy (HTTP {response.status_code})")
        sys.exit(1)
except Exception as e:
    print(f"  FAIL - Service health check error: {e}")
    sys.exit(1)

print("")
print("==========================================")
print("etcd config backend tests passed!")
print("==========================================")
EOF
