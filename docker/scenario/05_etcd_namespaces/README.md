# Scenario 05: etcd Namespace Routing

End-to-end test for etcd-based distributed configuration with namespace-scoped webhook routing, live config updates via etcd watch, and non-namespaced fallback.

## What It Tests

1. **Namespace routing** - Webhooks scoped to `ns_alpha` and `ns_beta` are routed independently
2. **Namespace isolation** - A webhook in `ns_beta` that doesn't exist returns 404
3. **Live add** - Adding a webhook key via `etcdctl put` is picked up by the watch thread
4. **Live delete** - Removing a webhook key via `etcdctl del` makes the endpoint return 404
5. **Default namespace fallback** - A non-namespaced POST (`/webhook/name`) resolves from the `default` namespace

## Services

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| etcd | `quay.io/coreos/etcd:v3.5.14` | 2379 | Config store |
| redis | `redis:7-alpine` | 6379 | Required by webhook-receiver |
| webhook-receiver | Built from `docker/Dockerfile.smaller` | 8000 | `CONFIG_BACKEND=etcd` |

## Quick Start

```bash
cd docker/scenario/05_etcd_namespaces
chmod +x run_test.sh seed_etcd.sh
./run_test.sh
```

The script brings up the stack, seeds etcd, runs all tests, and tears everything down.

## etcd Key Layout

```
/cwm/ns_alpha/webhooks/hook1       →  log module (pretty_print: true)
/cwm/ns_alpha/webhooks/hook2       →  log module
/cwm/ns_beta/webhooks/hook1        →  log module (pretty_print: false)
/cwm/global/connections/redis_main →  redis-rq connection
```

## Test Flow

```
Step 1: Seed etcd (ns_alpha: hook1, hook2 | ns_beta: hook1)
Step 2: Verify namespace routing
        POST /webhook/ns_alpha/hook1  → 200
        POST /webhook/ns_alpha/hook2  → 200
        POST /webhook/ns_beta/hook1   → 200
        POST /webhook/ns_beta/hook2   → 404 (not seeded)
Step 3: Live add via etcdctl put
        PUT /cwm/ns_beta/webhooks/hook_new
        POST /webhook/ns_beta/hook_new → 200
Step 4: Live delete via etcdctl del
        DEL /cwm/ns_alpha/webhooks/hook2
        POST /webhook/ns_alpha/hook2   → 404
Step 5: Non-namespaced fallback
        PUT /cwm/default/webhooks/fallback_hook
        POST /webhook/fallback_hook    → 200
```

## Files

| File | Description |
|------|-------------|
| `docker-compose.yaml` | Service definitions (etcd, redis, webhook-receiver) |
| `run_test.sh` | Full test orchestrator (start, seed, test, cleanup) |
| `seed_etcd.sh` | Seeds etcd with namespace data via `docker compose exec` |
