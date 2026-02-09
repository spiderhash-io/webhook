#!/bin/bash
# Vault Secret Provider Integration Test
# Tests that webhook configs with Vault secret references resolve correctly

set -e

echo "=========================================="
echo "Vault Secret Provider Integration Test"
echo "=========================================="

WEBHOOK_URL="http://localhost:8000"
VAULT_TOKEN="vault_secret_token_789"
FALLBACK_TOKEN="fallback_token_999"

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
vault_token = "vault_secret_token_789"
fallback_token = "fallback_token_999"

# Test 1: Vault-resolved auth token (log module)
print("")
print("Test 1: Log webhook with Vault-resolved auth token...")
try:
    response = requests.post(
        f"{webhook_url}/webhook/test_vault_log",
        json={"test": "data", "source": "vault_integration_test"},
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {vault_token}"
        },
        timeout=10
    )
    if response.status_code == 200:
        print(f"  PASS - Vault auth resolved (HTTP {response.status_code})")
        print(f"  Response: {response.json()}")
    else:
        print(f"  FAIL - Vault auth failed (HTTP {response.status_code})")
        print(f"  Response: {response.text}")
        sys.exit(1)
except Exception as e:
    print(f"  FAIL - Vault log test error: {e}")
    sys.exit(1)

# Test 2: Vault-resolved auth token (save_to_disk module)
print("")
print("Test 2: Save-to-disk webhook with Vault-resolved auth token...")
try:
    response = requests.post(
        f"{webhook_url}/webhook/test_vault_save",
        json={"test": "save_data", "source": "vault_integration_test"},
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {vault_token}"
        },
        timeout=10
    )
    if response.status_code == 200:
        print(f"  PASS - Vault save webhook (HTTP {response.status_code})")
        print(f"  Response: {response.json()}")
    else:
        print(f"  FAIL - Vault save webhook (HTTP {response.status_code})")
        print(f"  Response: {response.text}")
        sys.exit(1)
except Exception as e:
    print(f"  FAIL - Vault save test error: {e}")
    sys.exit(1)

# Test 3: Vault fallback token (nonexistent secret path)
print("")
print("Test 3: Vault fallback token (nonexistent secret uses default)...")
try:
    response = requests.post(
        f"{webhook_url}/webhook/test_vault_fallback",
        json={"test": "fallback_data", "source": "vault_fallback_test"},
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {fallback_token}"
        },
        timeout=10
    )
    if response.status_code == 200:
        print(f"  PASS - Vault fallback resolved (HTTP {response.status_code})")
        print(f"  Response: {response.json()}")
    else:
        print(f"  FAIL - Vault fallback failed (HTTP {response.status_code})")
        print(f"  Response: {response.text}")
        sys.exit(1)
except Exception as e:
    print(f"  FAIL - Vault fallback test error: {e}")
    sys.exit(1)

# Test 4: Wrong token should be rejected
print("")
print("Test 4: Wrong token should be rejected...")
try:
    response = requests.post(
        f"{webhook_url}/webhook/test_vault_log",
        json={"test": "should_fail"},
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer wrong_token"
        },
        timeout=10
    )
    if response.status_code in (401, 403):
        print(f"  PASS - Wrong token rejected (HTTP {response.status_code})")
    elif response.status_code == 200:
        print(f"  FAIL - Wrong token was accepted (HTTP {response.status_code})")
        sys.exit(1)
    else:
        print(f"  INFO - Unexpected status (HTTP {response.status_code})")
except Exception as e:
    print(f"  FAIL - Rejection test error: {e}")
    sys.exit(1)

print("")
print("==========================================")
print("Vault secret provider tests passed!")
print("==========================================")
EOF
