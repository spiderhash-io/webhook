# Scenario 06: Vault + etcd Secrets (End-to-End)

This scenario validates HashiCorp Vault secret resolution for webhook configs that are stored in etcd, while preserving legacy environment variable placeholders.

## What It Tests

1. Vault-backed `authorization` secret resolution from etcd config
2. Vault-backed HMAC secret resolution from etcd config
3. Legacy env placeholder compatibility (`{$LEGACY_ENV_TOKEN}`)
4. Secret rotation flow (update Vault secret + etcd live update)

## Services

- `vault` (dev mode)
- `etcd`
- `redis`
- `webhook-receiver`

## Run

```bash
cd docker/scenario/06_vault_etcd_secrets
chmod +x run_test.sh seed_vault.sh seed_etcd.sh
./run_test.sh
```

The script brings up the stack, seeds Vault and etcd, executes all checks, and tears everything down.
