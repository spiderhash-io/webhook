#!/usr/bin/env bash
# Seed etcd with test data for two namespaces.
# Uses docker compose exec to run etcdctl inside the etcd container.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

etcd_put() {
  local key="$1"
  local value="$2"
  docker compose exec -T etcd /usr/local/bin/etcdctl \
    --endpoints=http://127.0.0.1:2379 \
    put "$key" "$value" >/dev/null
}

echo "=== Seeding etcd ==="

# Namespace: ns_alpha
etcd_put /cwm/ns_alpha/webhooks/hook1 '{"data_type":"json","module":"log","module-config":{"pretty_print":true}}'
etcd_put /cwm/ns_alpha/webhooks/hook2 '{"data_type":"json","module":"log"}'

# Namespace: ns_beta
etcd_put /cwm/ns_beta/webhooks/hook1 '{"data_type":"json","module":"log","module-config":{"pretty_print":false}}'

# Global connections (shared)
etcd_put /cwm/global/connections/redis_main '{"type":"redis-rq","host":"redis","port":6379}'

echo "=== Seeding complete ==="
echo "  ns_alpha: hook1, hook2"
echo "  ns_beta:  hook1"
echo "  connections: redis_main"
