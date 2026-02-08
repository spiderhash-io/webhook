#!/usr/bin/env bash
# Seed etcd with test data for two namespaces.
# Usage: bash seed_etcd.sh [ETCD_ENDPOINT]
set -euo pipefail

ETCD_ENDPOINT="${1:-http://localhost:2379}"
ETCDCTL="etcdctl --endpoints=${ETCD_ENDPOINT}"

echo "=== Seeding etcd at ${ETCD_ENDPOINT} ==="

# Namespace: ns_alpha
$ETCDCTL put /cwm/ns_alpha/webhooks/hook1 '{"data_type":"json","module":"log","module-config":{"pretty_print":true}}'
$ETCDCTL put /cwm/ns_alpha/webhooks/hook2 '{"data_type":"json","module":"log"}'

# Namespace: ns_beta
$ETCDCTL put /cwm/ns_beta/webhooks/hook1 '{"data_type":"json","module":"log","module-config":{"pretty_print":false}}'

# Global connections (shared)
$ETCDCTL put /cwm/global/connections/redis_main '{"type":"redis-rq","host":"redis","port":6379}'

echo "=== Seeding complete ==="
echo "  ns_alpha: hook1, hook2"
echo "  ns_beta:  hook1"
echo "  connections: redis_main"
