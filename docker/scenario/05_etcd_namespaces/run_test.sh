#!/usr/bin/env bash
# Integration test for etcd-based namespaced webhook routing.
#
# This script:
#   1. Starts services and seeds etcd with two namespaces (ns_alpha, ns_beta)
#   2. Posts to namespaced webhook endpoints and verifies responses
#   3. Adds a webhook via etcdctl, verifies it's picked up (watch)
#   4. Deletes a webhook via etcdctl, verifies 404
#   5. Tests non-namespaced route fallback to default namespace
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

WEBHOOK_URL="http://localhost:8000"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0

assert_status() {
    local description="$1"
    local expected="$2"
    local actual="$3"

    if [ "$expected" == "$actual" ]; then
        echo -e "${GREEN}[PASS]${NC} ${description} (HTTP ${actual})"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}[FAIL]${NC} ${description} (expected ${expected}, got ${actual})"
        FAIL=$((FAIL + 1))
    fi
}

etcd_put() {
    docker compose exec -T etcd /usr/local/bin/etcdctl \
        --endpoints=http://127.0.0.1:2379 \
        put "$1" "$2" >/dev/null
}

etcd_del() {
    docker compose exec -T etcd /usr/local/bin/etcdctl \
        --endpoints=http://127.0.0.1:2379 \
        del "$1" >/dev/null
}

cleanup() {
    docker compose down -v >/dev/null 2>&1 || true
}

echo "============================================================"
echo "  etcd Namespace Integration Test"
echo "============================================================"

# Start services
echo ""
echo "Starting services..."
docker compose --progress plain up -d --build

# Wait for webhook receiver to be ready
echo ""
echo "--- Waiting for webhook-receiver to be ready ---"
for i in $(seq 1 60); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${WEBHOOK_URL}/health" 2>/dev/null || echo "000")
    if [ "$STATUS" == "200" ]; then
        echo "  Webhook receiver is ready."
        break
    fi
    if [ "$i" == "60" ]; then
        echo "  ERROR: Webhook receiver not ready after 60 seconds."
        docker compose logs webhook-receiver --tail=50 || true
        cleanup
        exit 1
    fi
    sleep 1
done

# Step 1: Seed etcd
echo ""
echo "--- Step 1: Seed etcd ---"
bash "${SCRIPT_DIR}/seed_etcd.sh"

# Give the watcher a moment to propagate
sleep 3

# Step 2: Test namespaced routes
echo ""
echo "--- Step 2: Test namespaced webhook routes ---"

# ns_alpha/hook1 should work
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${WEBHOOK_URL}/webhook/ns_alpha/hook1" \
    -H "Content-Type: application/json" -d '{"test":"alpha_hook1"}')
assert_status "POST /webhook/ns_alpha/hook1" "200" "$STATUS"

# ns_alpha/hook2 should work
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${WEBHOOK_URL}/webhook/ns_alpha/hook2" \
    -H "Content-Type: application/json" -d '{"test":"alpha_hook2"}')
assert_status "POST /webhook/ns_alpha/hook2" "200" "$STATUS"

# ns_beta/hook1 should work (different config)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${WEBHOOK_URL}/webhook/ns_beta/hook1" \
    -H "Content-Type: application/json" -d '{"test":"beta_hook1"}')
assert_status "POST /webhook/ns_beta/hook1" "200" "$STATUS"

# ns_beta/hook2 should NOT exist
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${WEBHOOK_URL}/webhook/ns_beta/hook2" \
    -H "Content-Type: application/json" -d '{"test":"should_fail"}')
assert_status "POST /webhook/ns_beta/hook2 (should 404)" "404" "$STATUS"

# Step 3: Live update — add a webhook via etcdctl
echo ""
echo "--- Step 3: Live update — add webhook via etcdctl ---"
etcd_put /cwm/ns_beta/webhooks/hook_new '{"data_type":"json","module":"log"}'

# Wait for watch to propagate
sleep 3

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${WEBHOOK_URL}/webhook/ns_beta/hook_new" \
    -H "Content-Type: application/json" -d '{"test":"new_hook"}')
assert_status "POST /webhook/ns_beta/hook_new (after etcdctl put)" "200" "$STATUS"

# Step 4: Live delete — remove a webhook via etcdctl
echo ""
echo "--- Step 4: Live delete — remove webhook via etcdctl ---"
etcd_del /cwm/ns_alpha/webhooks/hook2

# Wait for watch to propagate
sleep 3

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${WEBHOOK_URL}/webhook/ns_alpha/hook2" \
    -H "Content-Type: application/json" -d '{"test":"deleted_hook"}')
assert_status "POST /webhook/ns_alpha/hook2 (after etcdctl del, should 404)" "404" "$STATUS"

# Step 5: Non-namespaced route still works (uses default namespace)
echo ""
echo "--- Step 5: Non-namespaced route fallback ---"
etcd_put /cwm/default/webhooks/fallback_hook '{"data_type":"json","module":"log"}'
sleep 2

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${WEBHOOK_URL}/webhook/fallback_hook" \
    -H "Content-Type: application/json" -d '{"test":"fallback"}')
assert_status "POST /webhook/fallback_hook (non-namespaced)" "200" "$STATUS"

# Summary
echo ""
echo "============================================================"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "============================================================"

if [ "$FAIL" -gt 0 ]; then
    echo -e "${YELLOW}Recent webhook service logs:${NC}"
    docker compose logs webhook-receiver --tail=50 || true
    cleanup
    exit 1
fi

echo "Scenario completed successfully."
cleanup
