# Scenario 06: Vault + etcd Secrets (End-to-End)

End-to-end test for HashiCorp Vault secret resolution combined with etcd distributed configuration. Validates that `{$vault:path#field}` references in etcd-stored webhook configs are resolved correctly, legacy `{$ENV_VAR}` placeholders still work, and secrets can be rotated live.

## What It Tests

1. **Vault-backed Bearer auth** - `{$vault:app/auth#webhook_token}` resolves to a Vault secret for token comparison
2. **Vault-backed HMAC auth** - `{$vault:app/auth#hmac_secret}` resolves for HMAC signature verification
3. **Legacy env placeholders** - `{$LEGACY_ENV_TOKEN}` still works alongside Vault references
4. **Secret rotation** - Update Vault secret + re-publish etcd config = old token rejected, new token accepted

## Services

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| etcd | `quay.io/coreos/etcd:v3.5.14` | — | Config store (webhooks + connections) |
| vault | `hashicorp/vault:1.16` | — | Secret store (dev mode, token: `root`) |
| redis | `redis:7-alpine` | — | Required by webhook-receiver |
| webhook-receiver | Built from `docker/Dockerfile.smaller` | 18000 | `CONFIG_BACKEND=etcd` + `SECRETS_BACKEND=vault` |

## Quick Start

```bash
cd docker/scenario/06_vault_etcd_secrets
chmod +x run_test.sh seed_vault.sh seed_etcd.sh
./run_test.sh
```

The script brings up the stack, seeds Vault and etcd, runs all tests, and tears everything down.

## Configuration

### Vault Secrets (seeded by `seed_vault.sh`)

| Path | Field | Initial Value |
|------|-------|---------------|
| `webhooks/app/auth` | `webhook_token` | `vault_auth_token_v1` |
| `webhooks/app/auth` | `hmac_secret` | `vault_hmac_secret_123` |
| `webhooks/app/connections` | `redis_password` | `vault_redis_password_123` |

### etcd Keys (seeded by `seed_etcd.sh`)

| Key | Auth Method | Secret Reference |
|-----|-------------|------------------|
| `/cwm/default/webhooks/vault_auth` | Bearer | `{$vault:app/auth#webhook_token}` |
| `/cwm/default/webhooks/vault_hmac` | HMAC | `{$vault:app/auth#hmac_secret}` |
| `/cwm/default/webhooks/legacy_env` | Bearer | `{$LEGACY_ENV_TOKEN}` (env var) |
| `/cwm/global/connections/redis_main` | — | `{$vault:app/connections#redis_password}` |

### Environment

| Variable | Value | Description |
|----------|-------|-------------|
| `CONFIG_BACKEND` | `etcd` | Use etcd for webhook/connection config |
| `SECRETS_BACKEND` | `vault` | Enable Vault secret resolution |
| `VAULT_ADDR` | `http://vault:8200` | Vault server |
| `VAULT_TOKEN` | `root` | Dev mode root token |
| `VAULT_MOUNT_POINT` | `webhooks` | Custom KV v2 mount |
| `VAULT_KV_VERSION` | `2` | KV engine version |
| `VAULT_CACHE_TTL_SECONDS` | `1` | Low TTL for rotation testing |
| `LEGACY_ENV_TOKEN` | `legacy_env_token_789` | Legacy env var for backward compat |

## Test Flow

```
Step 1: Vault-backed authorization
        POST /webhook/vault_auth (no token)         → 401
        POST /webhook/vault_auth (wrong token)      → 401
        POST /webhook/vault_auth (vault token)      → 200

Step 2: Vault-backed HMAC
        POST /webhook/vault_hmac (wrong signature)  → 401
        POST /webhook/vault_hmac (correct HMAC)     → 200

Step 3: Legacy env placeholder
        POST /webhook/legacy_env (env token)        → 200

Step 4: Secret rotation
        Re-seed Vault with vault_auth_token_v2
        Re-publish etcd keys (triggers watch + re-resolve)
        POST /webhook/vault_auth (old v1 token)     → 401
        POST /webhook/vault_auth (new v2 token)     → 200
```

## Files

| File | Description |
|------|-------------|
| `docker-compose.yaml` | Service definitions (etcd, vault, redis, webhook-receiver) |
| `run_test.sh` | Full test orchestrator (start, seed, test, rotate, cleanup) |
| `seed_vault.sh` | Seeds Vault KV v2 with auth tokens and connection secrets |
| `seed_etcd.sh` | Seeds etcd with webhook configs containing `{$vault:...}` references |
