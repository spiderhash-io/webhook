#!/bin/sh
# Seeds etcd with test webhook configs via HTTP API
# Uses etcd v3 REST gateway (base64-encoded keys/values)

set -e

ETCD_URL="http://etcd:2379"

put_key() {
    KEY=$(printf '%s' "$1" | base64 | tr -d '\n')
    VAL=$(printf '%s' "$2" | base64 | tr -d '\n')
    RESULT=$(curl -s -X POST "${ETCD_URL}/v3/kv/put" \
        -H "Content-Type: application/json" \
        -d "{\"key\":\"${KEY}\",\"value\":\"${VAL}\"}")
    if echo "${RESULT}" | grep -q "error"; then
        echo "  FAIL: $1 -> ${RESULT}"
        return 1
    else
        echo "  OK: $1"
    fi
}

echo "Seeding etcd with test webhook configs..."

# Webhook: log module (default namespace)
put_key '/cwm/default/webhooks/test_log' \
    '{"data_type":"json","module":"log","authorization":"Bearer test_token_123","module-config":{"pretty_print":true}}'

# Webhook: save_to_disk module (default namespace)
put_key '/cwm/default/webhooks/test_save' \
    '{"data_type":"json","module":"save_to_disk","authorization":"Bearer test_token_123","module-config":{"path":"/tmp/webhooks","filename_template":"webhook_{timestamp}.json"}}'

# Webhook: log module (staging namespace)
put_key '/cwm/staging/webhooks/test_log_staging' \
    '{"data_type":"json","module":"log","authorization":"Bearer staging_token_456","module-config":{"pretty_print":true}}'

echo ""
echo "Verifying seeded data..."
KEY=$(printf '%s' '/cwm/' | base64 | tr -d '\n')
RANGE_END=$(printf '%s' '/cwm0' | base64 | tr -d '\n')
curl -s -X POST "${ETCD_URL}/v3/kv/range" \
    -H "Content-Type: application/json" \
    -d "{\"key\":\"${KEY}\",\"range_end\":\"${RANGE_END}\",\"keys_only\":true}" | \
    python3 -c "
import sys, json, base64
try:
    data = json.load(sys.stdin)
    for kv in data.get('kvs', []):
        print('  Key:', base64.b64decode(kv['key']).decode())
except: print('  (raw verification skipped)')
" 2>/dev/null || echo "  (keys seeded)"

echo ""
echo "etcd seeding complete!"
