# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Critical Rules

**ALWAYS ask for user permission before:**
- Running destructive commands (rm -rf, git reset --hard, DROP TABLE, etc.)
- Accessing files or directories outside this project folder
- Installing global packages (pip install --user, npm install -g, brew install, etc.)

**After making code changes:**
- Always restart the dev server so changes can be viewed: `make run` or `pkill -f uvicorn && make run`

## Project Overview

Core Webhook Module is a FastAPI-based webhook receiver/processor that validates incoming webhooks using 11 authentication methods and routes payloads to 17+ output destinations. Key features include webhook chaining (sequential/parallel execution), live configuration reload, and distributed analytics via ClickHouse.

## Common Commands

```bash
# Install dependencies
make install              # Dev dependencies (default)
make install-prod         # Production only

# Testing
make test                 # Unit tests (excludes integration)
make test-integration     # Integration tests (requires Docker services)
make test-all             # All tests
make test-cov             # With coverage report
pytest tests/unit/test_webhooks.py -v  # Single test file

# Docker services for integration tests
make integration-up       # Start Redis, RabbitMQ, ClickHouse, etc.
make integration-down     # Stop services

# Code quality
make format               # Black formatting
make lint                 # Flake8
make type-check           # Mypy
make security-scan        # Bandit + Safety

# Run application
make run                  # Dev server with reload
make run-prod             # Production (4 workers)

# Docker
make docker-build         # Build image
make docker-up            # Start compose
```

## Architecture

```
HTTP Request → FastAPI (main.py) → WebhookHandler (webhook.py)
                                      ├─ Authorization (validators.py) - 11 methods
                                      ├─ Payload validation (input_validator.py)
                                      ├─ Rate limiting (rate_limiter.py)
                                      ↓
                                   ModuleRegistry (modules/registry.py)
                                      ↓
                                   BaseModule subclasses (modules/*)
                                      ↓
                                   ChainProcessor (chain_processor.py)
                                      ├─ Sequential/parallel execution
                                      └─ Retry handling
```

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| main.py | src/ | FastAPI app, routes, startup/shutdown |
| webhook.py | src/ | Core webhook processing, validation orchestration |
| config_manager.py | src/ | Live config reload, async-safe management |
| validators.py | src/ | 11 auth validators (JWT, HMAC, OAuth, etc.) |
| chain_processor.py | src/ | Multi-module sequential/parallel execution |
| connection_pool_registry.py | src/ | Connection lifecycle, versioned pools |
| modules/base.py | src/ | Abstract base class for output modules |
| modules/registry.py | src/ | Plugin registry with security validation |

### Output Modules (src/modules/)

log, save_to_disk, rabbitmq, redis_rq, redis_publish, http_webhook, kafka, s3, websocket, clickhouse, mqtt, postgres, mysql, zeromq, activemq, aws_sqs, gcp_pubsub, webhook_connect_module

### Webhook Connect Subsystem

Cloud-to-local webhook relay (similar to ngrok):
- **Cloud side**: `src/webhook_connect/` - WebSocket/SSE streaming, channel management
- **Local connector**: `src/connector/` - Connects to cloud, forwards to local HTTP targets

## Configuration

- **Files**: `webhooks.json`, `connections.json` (root or via env vars `WEBHOOKS_CONFIG_FILE`, `CONNECTIONS_CONFIG_FILE`)
- **Env var substitution**: `{$VAR}` or `{$VAR:default_value}`
- **Hot reload**: Changes detected automatically, or POST `/admin/reload-config`

Example webhook config:
```json
{
  "my_webhook": {
    "data_type": "json",
    "module": "log",
    "authorization": "Bearer token",
    "module-config": { "pretty_print": true }
  }
}
```

## Testing Structure

- Test markers: `integration`, `unit`, `performance`, `slow`, `longrunning`, `external_services`
- `make test` excludes: longrunning, todo, external_services
- 151 test files, 2493+ passing tests

## Adding New Features

### New Output Module
1. Create `src/modules/<name>.py` extending `BaseModule`
2. Implement `process()` method
3. Register in `src/modules/registry.py`
4. Add tests in `tests/unit/test_<name>_module.py`

### New Auth Method
1. Add validator class in `src/validators.py`
2. Integrate into validation flow in `src/webhook.py`
3. Add corresponding tests

## Security

- 11 auth methods: Bearer, Basic, JWT, HMAC, IP whitelist, reCAPTCHA, rate limiting, query param, header, OAuth2, Digest
- Type validation on all config values
- Input sanitization with size/depth limits
- Credential redaction in logs
- Constant-time HMAC comparison

## Key Documentation

- `docs/ARCHITECTURE.md` - Module system, adding new modules
- `docs/DEVELOPMENT.md` - Local development workflow
- `docs/LIVE_CONFIG_RELOAD_FEATURE.md` - Config reload, pool versioning
- `docs/WEBHOOK_CHAINING_FEATURE.md` - Multi-destination patterns
- `agent-instructions.md` - Comprehensive webhook config guide
