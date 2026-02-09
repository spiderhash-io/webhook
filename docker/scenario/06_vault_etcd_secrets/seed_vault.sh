#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

WEBHOOK_TOKEN="${1:-vault_auth_token_v1}"
HMAC_SECRET="${2:-vault_hmac_secret_123}"
REDIS_PASSWORD="${3:-vault_redis_password_123}"

docker compose exec -T vault sh -lc '
  export VAULT_ADDR=http://127.0.0.1:8200
  export VAULT_TOKEN=root
  if ! vault secrets list -format=json | grep -q "\"webhooks/\""; then
    vault secrets enable -path=webhooks kv-v2
  fi
'

docker compose exec -T vault sh -lc "
  export VAULT_ADDR=http://127.0.0.1:8200
  export VAULT_TOKEN=root
  vault kv put webhooks/app/auth webhook_token='${WEBHOOK_TOKEN}' hmac_secret='${HMAC_SECRET}'
  vault kv put webhooks/app/connections redis_password='${REDIS_PASSWORD}'
"

echo "Vault seeded: webhook_token=${WEBHOOK_TOKEN}, hmac_secret=<redacted>, redis_password=<redacted>"
