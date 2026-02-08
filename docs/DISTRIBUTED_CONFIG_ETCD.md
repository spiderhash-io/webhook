# Distributed Configuration with etcd

> **Built-in etcd backend for real-time, distributed webhook configuration with namespace support.**

## Overview

Core Webhook Module supports two configuration backends:

| Backend | Env Var | Description |
|---------|---------|-------------|
| **file** (default) | `CONFIG_BACKEND=file` | JSON files (`webhooks.json`, `connections.json`) |
| **etcd** | `CONFIG_BACKEND=etcd` | etcd cluster with namespace-scoped configs |

The etcd backend enables:
- **Namespaces**: organizational grouping for webhooks (teams, environments, tenants)
- **Multi-node sync**: all instances see the same config via etcd watch
- **Granular updates**: change one webhook without reloading everything
- **Zero-downtime config changes**: watch thread detects changes in real-time

Users manage etcd directly with `etcdctl` or any etcd client. The app is read-only.

---

## Architecture

```
CONFIG_BACKEND=file (default, unchanged):
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
POST /webhook/{namespace}/{webhook_id}    -> namespaced route (new)
POST /webhook/{webhook_id}                -> uses "default" namespace or flat file config
```

---

## Quick Start

### 1. Start etcd

```bash
docker run -d --name etcd -p 2379:2379 \
  -e ALLOW_NONE_AUTHENTICATION=yes \
  bitnami/etcd:3.5
```

### 2. Seed some config

```bash
# Create a webhook in the "production" namespace
etcdctl put /cwm/production/webhooks/github_events \
  '{"data_type":"json","module":"log","module-config":{"pretty_print":true}}'

# Create a global connection
etcdctl put /cwm/global/connections/redis_main \
  '{"type":"redis-rq","host":"localhost","port":6379}'
```

### 3. Start the webhook receiver

```bash
export CONFIG_BACKEND=etcd
export ETCD_HOST=localhost
export ETCD_PORT=2379
export ETCD_NAMESPACE=production

make run
```

### 4. Send a webhook

```bash
# Namespaced route
curl -X POST http://localhost:8000/webhook/production/github_events \
  -H "Content-Type: application/json" \
  -d '{"action":"push","repo":"myapp"}'

# Non-namespaced route (uses ETCD_NAMESPACE, default: "default")
curl -X POST http://localhost:8000/webhook/github_events \
  -H "Content-Type: application/json" \
  -d '{"action":"push","repo":"myapp"}'
```

### 5. Live update (no restart needed)

```bash
# Add a new webhook — watch thread picks it up automatically
etcdctl put /cwm/production/webhooks/stripe_events \
  '{"data_type":"json","module":"log"}'

# Delete a webhook
etcdctl del /cwm/production/webhooks/old_hook
```

---

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

---

## Watch Behavior

- **Startup**: `get_prefix("/cwm/")` loads all namespaces into memory cache
- **Runtime**: etcd watch on `/cwm/` prefix. Each event updates ONE key in cache
- **Scale**: 5000 namespaces x 5 webhooks = 25K keys. One change = one ~200 byte event
- **etcd down**: cache continues serving reads. Watch auto-reconnects with exponential backoff (1s->60s), full `get_prefix` reload on reconnect to catch missed events

---

## Namespaces

Namespaces are a generic organizational concept. Users can use them for:
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

---

## Docker Scenario

A Docker Compose scenario is available at `docker/scenario/05_etcd_namespaces/`:

```bash
cd docker/scenario/05_etcd_namespaces
docker compose up -d
bash seed_etcd.sh
bash run_test.sh
docker compose down
```

This tests:
1. Namespace-scoped webhook routing
2. Live config addition via etcdctl
3. Live config deletion via etcdctl
4. Non-namespaced route fallback

---

## Health Endpoint

When using etcd backend, the `/health` endpoint includes etcd connectivity status:

```json
{
  "status": "healthy",
  "components": {
    "config_manager": "healthy",
    "etcd": "healthy",
    ...
  }
}
```

If etcd is unreachable, `etcd` shows `"disconnected"` but the service remains healthy (cache continues serving).

---

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

---

## Source Files

| File | Purpose |
|------|---------|
| `src/config_provider.py` | ConfigProvider ABC (read-only interface) |
| `src/file_config_provider.py` | File-based provider (wraps JSON file loading) |
| `src/etcd_config_provider.py` | etcd provider (cache + watch + reconnect) |
| `src/config_manager.py` | ConfigManager with provider delegation + factory |
| `src/main.py` | CONFIG_BACKEND switching, namespace route |
| `src/webhook.py` | WebhookHandler with optional namespace |
| `src/connector/config.py` | Connector etcd fields |
| `src/connector/main.py` | Connector etcd delivery mode |
