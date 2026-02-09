# etcd Config Backend Scenario

Tests the etcd distributed configuration backend. Instead of reading webhook/connection configs from JSON files, the app reads them from an etcd cluster in real-time.

## Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| **webhook** | Built from `docker/Dockerfile.smaller` | 8000 | Webhook service with `CONFIG_BACKEND=etcd` |
| **etcd** | `quay.io/coreos/etcd:v3.5.9` | 2379 | etcd key-value store |
| **etcd-seed** | `curlimages/curl` | — | One-shot container that seeds test data via etcd HTTP API |

## Quick Start

```bash
cd docker/compose/etcd
cp env.example .env    # (already provided)
docker compose up -d
./test.sh
docker compose down -v
```

## What Gets Seeded

The `seed.sh` script populates etcd with three test webhooks:

| Key | Namespace | Module | Auth Token |
|-----|-----------|--------|------------|
| `/cwm/default/webhooks/test_log` | default | `log` | `test_token_123` |
| `/cwm/default/webhooks/test_save` | default | `save_to_disk` | `test_token_123` |
| `/cwm/staging/webhooks/test_log_staging` | staging | `log` | `staging_token_456` |

## Test Endpoints

After startup, these endpoints are available:

```bash
# Default namespace webhooks
curl -X POST http://localhost:8000/webhook/test_log \
  -H "Authorization: Bearer test_token_123" \
  -H "Content-Type: application/json" \
  -d '{"hello": "world"}'

curl -X POST http://localhost:8000/webhook/test_save \
  -H "Authorization: Bearer test_token_123" \
  -H "Content-Type: application/json" \
  -d '{"save": "this"}'

# Namespaced webhook (staging)
curl -X POST http://localhost:8000/webhook/staging/test_log_staging \
  -H "Authorization: Bearer staging_token_456" \
  -H "Content-Type: application/json" \
  -d '{"env": "staging"}'
```

## Adding Webhooks at Runtime

etcd configs are watched in real-time. Add a new webhook without restarting:

```bash
# Using etcd HTTP API (base64-encoded key/value)
KEY=$(echo -n '/cwm/default/webhooks/new_hook' | base64 | tr -d '\n')
VAL=$(echo -n '{"data_type":"json","module":"log","authorization":"Bearer test_token_123","module-config":{"pretty_print":true}}' | base64 | tr -d '\n')

curl -X POST http://localhost:2379/v3/kv/put \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"${KEY}\",\"value\":\"${VAL}\"}"

# The webhook is immediately available
curl -X POST http://localhost:8000/webhook/new_hook \
  -H "Authorization: Bearer test_token_123" \
  -H "Content-Type: application/json" \
  -d '{"dynamic": true}'
```

## Environment Variables

| Variable | Value | Description |
|----------|-------|-------------|
| `CONFIG_BACKEND` | `etcd` | Selects etcd as config source |
| `ETCD_HOST` | `etcd` | etcd service hostname |
| `ETCD_PORT` | `2379` | etcd client port |
| `ETCD_PREFIX` | `/cwm/` | Key prefix for all configs |
| `ETCD_NAMESPACE` | `default` | Default namespace for non-namespaced routes |

## Key Layout

```
/cwm/{namespace}/webhooks/{webhook_id}  →  webhook JSON config
/cwm/global/connections/{conn_name}     →  connection JSON config
```

## Troubleshooting

**Webhook shows 0 webhooks loaded**: Check etcd-seed logs with `docker compose logs etcd-seed`. Ensure seeding completed before webhook started.

**Cannot connect to etcd**: Verify etcd is healthy with `docker compose ps`. The etcd healthcheck uses `etcdctl endpoint health`.

**Config not updating at runtime**: The etcd watch thread reconnects automatically. Check webhook logs for watch connection status.
