# Vault Secret Management

Resolve secrets from HashiCorp Vault directly in webhook and connection configurations using the `{$vault:...}` syntax.

## Overview

Instead of storing secrets in plaintext in config files or environment variables, you can reference secrets stored in HashiCorp Vault. The Vault secret resolver fetches and caches secrets at runtime.

**Config with environment variables (existing):**
```json
{
  "my_webhook": {
    "authorization": "Bearer {$WEBHOOK_TOKEN}"
  }
}
```

**Config with Vault references (new):**
```json
{
  "my_webhook": {
    "authorization": "Bearer {$vault:webhooks/my_webhook#bearer_token}"
  }
}
```

### Benefits

- **No secrets on disk** - Config files contain references, not values
- **Centralized management** - Single source of truth for all secrets
- **Audit logging** - Vault tracks every secret access
- **Secret rotation** - Update secrets in Vault without restarting the app
- **Cache with TTL** - In-memory caching reduces Vault API calls

## Reference Syntax

Vault references use the format:

```
{$vault:path/to/secret#field}
{$vault:path/to/secret#field:default_value}
```

| Part | Description |
|------|-------------|
| `path/to/secret` | Vault KV secret path (max 512 chars, alphanumeric + `_./-`) |
| `field` | Field name within the secret (max 128 chars, alphanumeric + `_.-`) |
| `default_value` | Optional fallback if Vault is unreachable or field is missing |

### Examples

```json
{
  "github_webhook": {
    "authorization": "Bearer {$vault:webhooks/github#token}",
    "hmac": {
      "secret": "{$vault:webhooks/github#hmac_secret}",
      "header": "X-Hub-Signature-256",
      "algorithm": "sha256"
    }
  },
  "stripe_webhook": {
    "authorization": "Bearer {$vault:webhooks/stripe#bearer_token:fallback_token}",
    "module": "log"
  }
}
```

Vault references work everywhere environment variable substitution works - in `webhooks.json`, `connections.json`, and etcd-stored configs.

:::tip Mixed Usage
You can mix `{$VAR}` environment variables and `{$vault:...}` references in the same config file. They are resolved independently.
:::

## Quick Start

### 1. Start Vault (Development)

```bash
docker run -d --cap-add=IPC_LOCK \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' \
  -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
  -p 8200:8200 \
  --name vault-dev \
  vault:latest
```

### 2. Store a Secret

```bash
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN='myroot'

# Enable KV v2 engine (if not already enabled)
vault secrets enable -path=secret kv-v2

# Store webhook secrets
vault kv put secret/webhooks/github \
  token="ghp_abc123..." \
  hmac_secret="whsec_def456..."
```

### 3. Configure the Application

```bash
# Enable Vault secret resolution
export SECRETS_BACKEND=vault    # or VAULT_ENABLED=true
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=myroot       # or use VAULT_ROLE_ID + VAULT_SECRET_ID

make run
```

### 4. Use Vault References in Config

**webhooks.json:**
```json
{
  "github_events": {
    "data_type": "json",
    "module": "log",
    "authorization": "Bearer {$vault:webhooks/github#token}",
    "hmac": {
      "secret": "{$vault:webhooks/github#hmac_secret}",
      "header": "X-Hub-Signature-256",
      "algorithm": "sha256"
    }
  }
}
```

### 5. Test

```bash
curl -X POST http://localhost:8000/webhook/github_events \
  -H "Authorization: Bearer ghp_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"action":"push"}'
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRETS_BACKEND` | `env` | Set to `vault` to enable Vault resolution |
| `VAULT_ENABLED` | `false` | Alternative: set to `true` to enable |
| `VAULT_ADDR` | (required) | Vault server URL (e.g., `http://localhost:8200`) |
| `VAULT_TOKEN` | (none) | Vault token for authentication |
| `VAULT_ROLE_ID` | (none) | AppRole role ID (alternative to token) |
| `VAULT_SECRET_ID` | (none) | AppRole secret ID (alternative to token) |
| `VAULT_MOUNT_POINT` | `secret` | KV secrets engine mount point |
| `VAULT_KV_VERSION` | `2` | KV engine version (`1` or `2`) |
| `VAULT_NAMESPACE` | (none) | Vault enterprise namespace |
| `VAULT_VERIFY` | `true` | TLS verification (`true`, `false`, or CA cert path) |
| `VAULT_CACHE_TTL_SECONDS` | `300` | Secret cache TTL in seconds (0 to disable) |

## Authentication

Two authentication methods are supported:

### Token Auth (Development)

```bash
export VAULT_TOKEN=myroot
```

### AppRole Auth (Production)

```bash
export VAULT_ROLE_ID=<role-id>
export VAULT_SECRET_ID=<secret-id>
```

AppRole is recommended for production. See the [full Vault guide](../../docs/VAULT_INTEGRATION_GUIDE.md) for AppRole setup instructions.

## Caching

Resolved secrets are cached in memory with a configurable TTL (default: 5 minutes). This avoids hitting Vault on every webhook request.

- **Cache hit**: < 1ms
- **Cache miss (Vault API)**: 50-150ms
- **TTL configurable**: via `VAULT_CACHE_TTL_SECONDS`
- **Cache cleared**: on application restart

Set `VAULT_CACHE_TTL_SECONDS=0` to disable caching entirely (every request hits Vault).

## Works with etcd Backend

Vault references work with both config backends:

- **File backend**: References in `webhooks.json` / `connections.json` are resolved at load time
- **etcd backend**: References in etcd-stored JSON values are resolved at load time

```bash
# Store a webhook in etcd with Vault references
etcdctl put /cwm/production/webhooks/secure_hook \
  '{"data_type":"json","module":"log","authorization":"Bearer {$vault:webhooks/secure#token}"}'
```

## Docker Scenario

An end-to-end Docker Compose scenario is available at `docker/scenario/06_vault_etcd_secrets/`:

```bash
cd docker/scenario/06_vault_etcd_secrets
docker compose up -d
bash seed_vault.sh
bash seed_etcd.sh
bash run_test.sh
docker compose down
```

This tests Vault-backed authorization, HMAC secrets, legacy env placeholder compatibility, and secret rotation flows.

## Further Reading

- Full integration guide: `docs/VAULT_INTEGRATION_GUIDE.md`
- Source: `src/vault_secret_resolver.py`
- Variable substitution: `src/utils.py` (`load_env_vars`)
- Tests: `tests/unit/test_vault_secret_resolver.py`
