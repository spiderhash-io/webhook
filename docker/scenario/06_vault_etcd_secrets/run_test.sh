#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BASE_URL="http://localhost:18000"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

assert_status() {
  local description="$1"
  local expected="$2"
  local actual="$3"

  if [ "$expected" = "$actual" ]; then
    echo -e "${GREEN}[PASS]${NC} ${description} (HTTP ${actual})"
    PASS=$((PASS + 1))
  else
    echo -e "${RED}[FAIL]${NC} ${description} (expected ${expected}, got ${actual})"
    FAIL=$((FAIL + 1))
  fi
}

cleanup() {
  docker compose down -v >/dev/null 2>&1 || true
}

wait_for_http_200() {
  local url="$1"
  local timeout_secs="${2:-90}"

  for i in $(seq 1 "$timeout_secs"); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$url" || true)
    if [ "$code" = "200" ]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

echo "============================================================"
echo "  Vault + etcd Secrets End-to-End Scenario"
echo "============================================================"

echo "Starting services..."
docker compose --progress plain up -d --build

if ! wait_for_http_200 "${BASE_URL}/health" 120; then
  echo -e "${RED}Webhook service did not become healthy in time${NC}"
  docker compose logs webhook-receiver --tail=200 || true
  cleanup
  exit 1
fi

echo "Seeding Vault and etcd..."
bash ./seed_vault.sh "vault_auth_token_v1" "vault_hmac_secret_123" "vault_redis_password_123"
bash ./seed_etcd.sh

# Give etcd watch callbacks time to update in-memory caches
sleep 3

echo
echo "--- Step 1: Vault-backed authorization webhook ---"
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/webhook/vault_auth" \
  -H "Content-Type: application/json" \
  -d '{"event":"no_auth"}')
assert_status "vault_auth without token" "401" "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/webhook/vault_auth" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer wrong_token" \
  -d '{"event":"bad_auth"}')
assert_status "vault_auth with wrong token" "401" "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/webhook/vault_auth" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer vault_auth_token_v1" \
  -d '{"event":"good_auth"}')
assert_status "vault_auth with vault token" "200" "$code"

echo
echo "--- Step 2: Vault-backed HMAC webhook ---"
payload='{"event":"good_hmac"}'
good_sig=$(python3 - <<'PY'
import hashlib
import hmac
payload = b'{"event":"good_hmac"}'
print(hmac.new(b"vault_hmac_secret_123", payload, hashlib.sha256).hexdigest())
PY
)

code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/webhook/vault_hmac" \
  -H "Content-Type: application/json" \
  -H "X-HMAC-Signature: deadbeef" \
  -d "$payload")
assert_status "vault_hmac with wrong signature" "401" "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/webhook/vault_hmac" \
  -H "Content-Type: application/json" \
  -H "X-HMAC-Signature: ${good_sig}" \
  -d "$payload")
assert_status "vault_hmac with vault secret" "200" "$code"

echo
echo "--- Step 3: Legacy env placeholder compatibility ---"
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/webhook/legacy_env" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer legacy_env_token_789" \
  -d '{"event":"legacy_env"}')
assert_status "legacy env placeholder still works" "200" "$code"

echo
echo "--- Step 4: Secret rotation (Vault + etcd live update) ---"
# Rotate secret in Vault
bash ./seed_vault.sh "vault_auth_token_v2" "vault_hmac_secret_123" "vault_redis_password_123"
# Re-publish etcd config to trigger watch update and re-resolution
bash ./seed_etcd.sh
sleep 3

code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/webhook/vault_auth" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer vault_auth_token_v1" \
  -d '{"event":"old_token_after_rotation"}')
assert_status "old vault token rejected after rotation" "401" "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/webhook/vault_auth" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer vault_auth_token_v2" \
  -d '{"event":"new_token_after_rotation"}')
assert_status "new vault token accepted after rotation" "200" "$code"

echo
echo "============================================================"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "============================================================"

if [ "$FAIL" -ne 0 ]; then
  echo -e "${YELLOW}Recent webhook service logs:${NC}"
  docker compose logs webhook-receiver --tail=200 || true
  cleanup
  exit 1
fi

echo "Scenario completed successfully."
cleanup
