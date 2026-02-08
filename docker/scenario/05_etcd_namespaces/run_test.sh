#!/usr/bin/env bash
# Integration test for etcd-based namespaced webhook routing.
#
# Prerequisites: docker compose up -d (from this directory)
# This script:
#   1. Seeds etcd with two namespaces (ns_alpha, ns_beta)
#   2. Posts to namespaced webhook endpoints and verifies responses
#   3. Adds a webhook via etcdctl, verifies it's picked up (watch)
#   4. Deletes a webhook via etcdctl, verifies 404
set -euo pipefail

WEBHOOK_URL="http://localhost:8000"
ETCD_ENDPOINT="http://localhost:2379"

RED='\033[0;31m'
GREEN='\033[0;32m'
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

echo "============================================================"
echo "  etcd Namespace Integration Test"
echo "============================================================"

# Wait for webhook receiver to be ready
echo ""
echo "--- Waiting for webhook-receiver to be ready ---"
for i in $(seq 1 30); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${WEBHOOK_URL}/health" 2>/dev/null || echo "000")
    if [ "$STATUS" == "200" ]; then
        echo "  Webhook receiver is ready."
        break
    fi
    if [ "$i" == "30" ]; then
        echo "  ERROR: Webhook receiver not ready after 30 seconds."
        exit 1
    fi
    sleep 1
done

# Step 1: Seed etcd
echo ""
echo "--- Step 1: Seed etcd ---"
bash "$(dirname "$0")/seed_etcd.sh" "${ETCD_ENDPOINT}"

# Give the watcher a moment to propagate
sleep 2

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
etcdctl --endpoints="${ETCD_ENDPOINT}" put /cwm/ns_beta/webhooks/hook_new \
    '{"data_type":"json","module":"log"}'

# Wait for watch to propagate
sleep 3

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${WEBHOOK_URL}/webhook/ns_beta/hook_new" \
    -H "Content-Type: application/json" -d '{"test":"new_hook"}')
assert_status "POST /webhook/ns_beta/hook_new (after etcdctl put)" "200" "$STATUS"

# Step 4: Live delete — remove a webhook via etcdctl
echo ""
echo "--- Step 4: Live delete — remove webhook via etcdctl ---"
etcdctl --endpoints="${ETCD_ENDPOINT}" del /cwm/ns_alpha/webhooks/hook2

# Wait for watch to propagate
sleep 3

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${WEBHOOK_URL}/webhook/ns_alpha/hook2" \
    -H "Content-Type: application/json" -d '{"test":"deleted_hook"}')
assert_status "POST /webhook/ns_alpha/hook2 (after etcdctl del, should 404)" "404" "$STATUS"

# Step 5: Non-namespaced route still works (uses default namespace)
echo ""
echo "--- Step 5: Non-namespaced route fallback ---"
# Seed a webhook in the "default" namespace
etcdctl --endpoints="${ETCD_ENDPOINT}" put /cwm/default/webhooks/fallback_hook \
    '{"data_type":"json","module":"log"}'
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
    exit 1
fi
