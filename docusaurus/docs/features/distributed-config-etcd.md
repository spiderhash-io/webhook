# Distributed Configuration with etcd

Use etcd as a distributed configuration backend for real-time, namespace-scoped webhook management across multiple instances.

## Overview

Core Webhook Module supports two configuration backends:

| Backend | Env Var | Description |
|---------|---------|-------------|
| **file** (default) | `CONFIG_BACKEND=file` | JSON files (`webhooks.json`, `connections.json`) |
| **etcd** | `CONFIG_BACKEND=etcd` | etcd cluster with namespace-scoped configs |

The etcd backend enables:

- **Namespaces** - Organizational grouping for webhooks (teams, environments, tenants)
- **Multi-node sync** - All instances see the same config via etcd watch
- **Granular updates** - Change one webhook without reloading everything
- **Zero-downtime config changes** - Watch thread detects changes in real-time

:::info Read-Only
The application only **reads** from etcd. Users manage etcd directly with `etcdctl` or any etcd client.
:::

## Architecture

```
CONFIG_BACKEND=file (default):
  JSON files -> FileConfigProvider -> ConfigManager -> WebhookHandler

CONFIG_BACKEND=etcd:
  etcd cluster -> EtcdConfigProvider (in-memory cache + watch) -> ConfigManager -> WebhookHandler
  Users manage etcd directly (etcdctl put/delete)
  Watch thread detects changes -> updates single key in cache (O(1), sub-ms)
```

### etcd Key Layout

```
/cwm/{namespace}/webhooks/{webhook_id}     -> webhook config JSON
/cwm/global/connections/{conn_name}        -> connection config JSON (shared)
```

- Connections are **global** (shared across all namespaces)
- Each webhook is its own etcd key for granular watch events
- `{namespace}` must match `[a-zA-Z0-9_-]{1,64}`

### Routes

```
POST /webhook/{namespace}/{webhook_id}    -> namespaced route
POST /webhook/{webhook_id}                -> uses default namespace (ETCD_NAMESPACE)
```

## Quick Start

### 1. Start etcd

```bash
docker run -d --name etcd -p 2379:2379 \
  -e ALLOW_NONE_AUTHENTICATION=yes \
  bitnami/etcd:3.5
```

### 2. Seed Configuration

```bash
# Create a webhook in the "production" namespace
etcdctl put /cwm/production/webhooks/github_events \
  '{"data_type":"json","module":"log","module-config":{"pretty_print":true}}'

# Create a global connection
etcdctl put /cwm/global/connections/redis_main \
  '{"type":"redis-rq","host":"localhost","port":6379}'
```

### 3. Start the Webhook Receiver

```bash
export CONFIG_BACKEND=etcd
export ETCD_HOST=localhost
export ETCD_PORT=2379
export ETCD_NAMESPACE=production

make run
```

### 4. Send a Webhook

```bash
# Namespaced route
curl -X POST http://localhost:8000/webhook/production/github_events \
  -H "Content-Type: application/json" \
  -d '{"action":"push","repo":"myapp"}'

# Non-namespaced route (uses ETCD_NAMESPACE default)
curl -X POST http://localhost:8000/webhook/github_events \
  -H "Content-Type: application/json" \
  -d '{"action":"push","repo":"myapp"}'
```

### 5. Live Update (No Restart Needed)

```bash
# Add a new webhook - watch thread picks it up automatically
etcdctl put /cwm/production/webhooks/stripe_events \
  '{"data_type":"json","module":"log"}'

# Delete a webhook
etcdctl del /cwm/production/webhooks/old_hook
```

## Namespaces

Namespaces are a generic organizational concept. Common patterns:

- **Multi-tenant isolation**: one namespace per customer
- **Environment separation**: `production`, `staging`, `development`
- **Team grouping**: `team-backend`, `team-frontend`

### Namespace Rules

- 1-64 characters
- Allowed characters: `a-z`, `A-Z`, `0-9`, `-`, `_`
- Validated on both key parsing and route handling

### Example: Multi-Namespace Setup

```bash
# Team A's webhooks
etcdctl put /cwm/team-a/webhooks/orders    '{"module":"kafka","module-config":{"topic":"orders"}}'
etcdctl put /cwm/team-a/webhooks/payments  '{"module":"log"}'

# Team B's webhooks
etcdctl put /cwm/team-b/webhooks/analytics '{"module":"clickhouse"}'

# Both teams share the same connections
etcdctl put /cwm/global/connections/kafka_main '{"type":"kafka","bootstrap_servers":"kafka:9092"}'
```

```bash
# Each team uses their own namespace prefix
curl -X POST http://localhost:8000/webhook/team-a/orders   -d '{"order_id":"123"}'
curl -X POST http://localhost:8000/webhook/team-b/analytics -d '{"event":"pageview"}'
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_BACKEND` | `file` | Config backend: `file` or `etcd` |
| `ETCD_HOST` | `localhost` | etcd server hostname |
| `ETCD_PORT` | `2379` | etcd server port |
| `ETCD_PREFIX` | `/cwm/` | Key prefix in etcd |
| `ETCD_NAMESPACE` | `default` | Default namespace for non-namespaced routes |
| `ETCD_USERNAME` | (none) | etcd authentication username |
| `ETCD_PASSWORD` | (none) | etcd authentication password |

### Connector Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONNECTOR_ETCD_HOST` | (none) | etcd host for connector (enables etcd mode) |
| `CONNECTOR_ETCD_PORT` | `2379` | etcd port for connector |
| `CONNECTOR_ETCD_PREFIX` | `/cwm/` | Key prefix for connector |
| `CONNECTOR_NAMESPACE` | (none) | Namespace for connector webhook lookups |

## Watch Behavior

- **Startup**: Loads all keys under the configured prefix into an in-memory cache
- **Runtime**: etcd watch on the prefix. Each event updates one key in cache
- **Scale**: 5,000 namespaces x 5 webhooks = 25K keys. One change = one ~200 byte event
- **etcd down**: Cache continues serving reads. Watch auto-reconnects with exponential backoff (1s to 60s) with jitter. Full prefix reload on reconnect to catch missed events

## Health Endpoint

When using etcd backend, the `/health` endpoint includes etcd connectivity status:

```json
{
  "status": "healthy",
  "components": {
    "config_manager": "healthy",
    "etcd": "healthy"
  }
}
```

If etcd is unreachable, `etcd` shows `"disconnected"` but the service remains healthy (cache continues serving).

## Migration from File to etcd

```bash
# 1. Export current webhooks.json to etcd
python3 -c "
import json, subprocess
with open('webhooks.json') as f:
    webhooks = json.load(f)
for wh_id, config in webhooks.items():
    key = f'/cwm/default/webhooks/{wh_id}'
    subprocess.run(['etcdctl', 'put', key, json.dumps(config)])
    print(f'  Migrated: {wh_id}')
print(f'Done: {len(webhooks)} webhooks')
"

# 2. Export connections.json to etcd
python3 -c "
import json, subprocess
with open('connections.json') as f:
    conns = json.load(f)
for name, config in conns.items():
    key = f'/cwm/global/connections/{name}'
    subprocess.run(['etcdctl', 'put', key, json.dumps(config)])
    print(f'  Migrated: {name}')
print(f'Done: {len(conns)} connections')
"

# 3. Switch backend
export CONFIG_BACKEND=etcd
```

## Docker Scenario

A Docker Compose scenario is available at `docker/scenario/05_etcd_namespaces/`:

```bash
cd docker/scenario/05_etcd_namespaces
docker compose up -d
bash seed_etcd.sh
bash run_test.sh
docker compose down
```

This tests namespace-scoped webhook routing, live config addition/deletion via etcdctl, and non-namespaced route fallback.

## Further Reading

- Full technical guide: `docs/DISTRIBUTED_CONFIG_ETCD.md`
- Source: `src/etcd_config_provider.py`
- Tests: `tests/unit/test_etcd_config_provider.py`
