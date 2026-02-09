#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Vault-backed authorization webhook
WEBHOOK_AUTH_JSON='{"data_type":"json","module":"log","authorization":"Bearer {$vault:app/auth#webhook_token}"}'

# Vault-backed HMAC webhook
WEBHOOK_HMAC_JSON='{"data_type":"json","module":"log","hmac":{"secret":"{$vault:app/auth#hmac_secret}","header":"X-HMAC-Signature","algorithm":"sha256"}}'

# Legacy env var webhook (backward compatibility)
WEBHOOK_ENV_JSON='{"data_type":"json","module":"log","authorization":"Bearer {$LEGACY_ENV_TOKEN}"}'

# Connection showing secrets can also come from Vault with etcd backend
CONNECTION_JSON='{"type":"redis-rq","host":"redis","port":6379,"password":"{$vault:app/connections#redis_password}"}'

etcd_put() {
  local key="$1"
  local value="$2"
  docker compose exec -T etcd /usr/local/bin/etcdctl \
    --endpoints=http://127.0.0.1:2379 \
    put "$key" "$value" >/dev/null
}

etcd_put "/cwm/default/webhooks/vault_auth" "$WEBHOOK_AUTH_JSON"
etcd_put "/cwm/default/webhooks/vault_hmac" "$WEBHOOK_HMAC_JSON"
etcd_put "/cwm/default/webhooks/legacy_env" "$WEBHOOK_ENV_JSON"
etcd_put "/cwm/global/connections/redis_main" "$CONNECTION_JSON"

echo "etcd seeded with vault_auth, vault_hmac, legacy_env and redis_main"
