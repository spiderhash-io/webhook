# Release v0.2.0 - Vault, etcd, Connector & Security Hardening

This release brings distributed configuration via etcd, HashiCorp Vault secret management, a completely refactored connector, Kubernetes support, and significant security hardening across the board.

## Highlights

- **etcd Distributed Configuration** — namespace-scoped webhooks with live watch and automatic reconnection
- **HashiCorp Vault Integration** — secure credential storage with environment variable substitution
- **Refactored Connector** — three delivery modes (HTTP, Module, etcd) with stability fixes
- **Admin Auth by Default** — admin endpoints now require `CONFIG_RELOAD_ADMIN_TOKEN` (breaking change)
- **Kubernetes Ready** — Helm chart and K8s manifest scenarios
- **3,216+ passing tests** (up from 2,493 in v0.1.0)

## New Features

### etcd Distributed Configuration
- Full etcd backend with namespace isolation (`/cwm/{namespace}/webhooks/{id}`)
- Live watch for real-time config updates (no restart needed)
- Automatic reconnection with exponential backoff and jitter
- `ConfigProvider` abstraction with `FileConfigProvider` and `EtcdConfigProvider`
- New route: `POST /webhook/{namespace}/{webhook_id}`
- Environment variables: `CONFIG_BACKEND=etcd`, `ETCD_HOST`, `ETCD_PORT`, `ETCD_PREFIX`, `ETCD_NAMESPACE`

### Vault Secret Management
- HashiCorp Vault integration for credential storage
- Secrets injected via environment variable substitution
- Docker scenario: `06_vault_etcd_secrets` for combined Vault + etcd deployment
- Standalone Vault compose at `docker/compose/vault/`

### Connector Overhaul
- Three delivery modes:
  - **HTTP mode**: Forward to local HTTP targets
  - **Module mode**: Dispatch to internal modules (kafka, save_to_disk, etc.)
  - **etcd mode**: Load webhook/connection config from etcd namespace
- Advanced connector scenario (`04_connector_advanced`)
- Fixes from code review report (roast 006)

### Kubernetes Support
- Helm chart for K8s deployment
- YAML manifest scenario (`03_kubernetes`)
- Test scenarios for K8s deployments

### CI/CD Enhancements
- GitHub Container Registry (GHCR) image publishing
- Docusaurus docs Docker build and GHCR deployment

## Breaking Changes

- **Admin endpoints require authentication** — set `CONFIG_RELOAD_ADMIN_TOKEN` env var. Without it, admin endpoints return `403 Forbidden` (previously open by default)
- **Sensitive data redaction enabled by default** — `redact_sensitive` now defaults to `True`

## Security Fixes

- Fixed information exposure in SSE error handling (CodeQL alert)
- Trusted proxy handling for `get_client_ip()`
- Lazy lock initialization in rate limiter (prevents race conditions)
- Replaced all `print()` with proper `logger` usage
- Comprehensive security scan confirmed zero hardcoded secrets

## Bug Fixes

- Queue limit now checks per-webhook depth (`channel_manager.py`)
- Concurrent `add_connection` no longer double-subscribes (`channel_manager.py`)
- WebSocket rejection properly cleans leaked send callbacks (`api.py`)
- Redis failed delivery now retries and sends to DLQ after limit (`redis_buffer.py`)
- Connector stability fixes
- Vault integration edge case fixes
- Docs nginx relative redirect fix

## Installation

### Docker (Recommended)
```bash
docker pull spiderhash/webhook:0.2.0
docker run -p 8000:8000 \
  -v $(pwd)/webhooks.json:/app/webhooks.json:ro \
  -v $(pwd)/connections.json:/app/connections.json:ro \
  spiderhash/webhook:0.2.0
```

### From Source
```bash
git clone https://github.com/spiderhash-io/webhook.git
cd webhook
git checkout v0.2.0
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn src.main:app --host 0.0.0.0 --port 8000
```

## Migration from v0.1.0

1. **Set admin token** — add `CONFIG_RELOAD_ADMIN_TOKEN=<your-secret>` to your environment
2. **Review redaction** — sensitive data is now redacted by default; check log output if you relied on seeing credentials
3. **Optional: Switch to etcd** — set `CONFIG_BACKEND=etcd` and configure etcd environment variables

## Testing

- 3,216+ passing unit tests
- 100% CI success rate
- Security audit tests for all new components

```bash
make test        # Unit tests
make test-all    # All tests
make test-cov    # With coverage
```

## Documentation

- [etcd Configuration Guide](https://github.com/spiderhash-io/webhook/blob/main/docs/DISTRIBUTED_CONFIG_ETCD.md)
- [Release Process](https://github.com/spiderhash-io/webhook/blob/main/docs/RELEASE_PROCESS.md)
- [Development Standards](https://github.com/spiderhash-io/webhook/blob/main/docs/DEVELOPMENT_STANDARDS.md)

---

**Full Changelog**: https://github.com/spiderhash-io/webhook/compare/v0.1.0...v0.2.0
