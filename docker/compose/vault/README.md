# Vault Secret Provider Scenario

Tests HashiCorp Vault integration for secret resolution. Webhook configs reference Vault secrets using `{$vault:path#field}` syntax, which are resolved at startup.

## Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| **webhook** | Built from `docker/Dockerfile.smaller` | 8000 | Webhook service with Vault-resolved secrets |
| **vault** | `hashicorp/vault:1.15` | 8200 | Vault dev server (KV v2 engine) |
| **vault-seed** | `hashicorp/vault:1.15` | — | One-shot container that seeds test secrets |

## Quick Start

```bash
cd docker/compose/vault
cp env.example .env    # (already provided)
docker compose up -d
./test.sh
docker compose down -v
```

## What Gets Seeded

The vault-seed container stores these secrets:

| Secret Path | Fields |
|-------------|--------|
| `secret/webhooks/auth` | `bearer_token`, `basic_user`, `basic_pass` |
| `secret/db/postgres` | `password`, `username` |
| `secret/integrations/api` | `api_key`, `api_secret` |

## How Vault References Work

In `config/webhooks.json`, secrets are referenced using this syntax:

```
{$vault:path/to/secret#field}
{$vault:path/to/secret#field:default_value}
```

Example from this scenario:

```json
{
  "test_vault_log": {
    "authorization": "Bearer {$vault:webhooks/auth#bearer_token}",
    ...
  },
  "test_vault_fallback": {
    "authorization": "Bearer {$vault:webhooks/nonexistent#token:fallback_token_999}",
    ...
  }
}
```

- `test_vault_log` resolves to `Bearer vault_secret_token_789` from Vault
- `test_vault_fallback` falls back to `Bearer fallback_token_999` (secret path doesn't exist)

## Test Endpoints

```bash
# Vault-resolved auth token
curl -X POST http://localhost:8000/webhook/test_vault_log \
  -H "Authorization: Bearer vault_secret_token_789" \
  -H "Content-Type: application/json" \
  -d '{"hello": "vault"}'

# Vault-resolved auth for save_to_disk
curl -X POST http://localhost:8000/webhook/test_vault_save \
  -H "Authorization: Bearer vault_secret_token_789" \
  -H "Content-Type: application/json" \
  -d '{"save": "with_vault"}'

# Fallback token (nonexistent Vault path)
curl -X POST http://localhost:8000/webhook/test_vault_fallback \
  -H "Authorization: Bearer fallback_token_999" \
  -H "Content-Type: application/json" \
  -d '{"fallback": true}'
```

## Vault UI

The Vault dev server includes a web UI:

```
http://localhost:8200/ui
Token: test-root-token
```

## Managing Secrets

```bash
# Read a secret
docker compose exec vault vault kv get secret/webhooks/auth

# Update a secret (requires webhook restart to pick up changes)
docker compose exec vault vault kv put secret/webhooks/auth \
  bearer_token="new_token" \
  basic_user="admin" \
  basic_pass="new_pass"

# List secrets
docker compose exec vault vault kv list secret/webhooks
```

## Environment Variables

| Variable | Value | Description |
|----------|-------|-------------|
| `VAULT_ADDR` | `http://vault:8200` | Vault server URL |
| `VAULT_TOKEN` | `test-root-token` | Root token (dev mode) |
| `VAULT_KV_VERSION` | `2` | KV secrets engine version |
| `VAULT_MOUNT_POINT` | `secret` | KV mount path |
| `SECRETS_BACKEND` | `vault` | Enables Vault secret resolution |
| `VAULT_CACHE_TTL_SECONDS` | `300` | Secret cache TTL |

## Troubleshooting

**Vault unhealthy**: The vault container needs `VAULT_ADDR` set for health checks. This is already configured.

**Secret not resolved**: Check webhook logs for `Vault resolution failed` messages. Verify the secret path exists with `docker compose exec vault vault kv get secret/path`.

**Wrong auth rejected**: This is expected behavior — the test verifies that wrong tokens return HTTP 401.

**Updating secrets**: Vault secrets are resolved at webhook startup. To pick up changed secrets, restart the webhook: `docker compose restart webhook`.
