# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Critical Rules

**ALWAYS ask for user permission before:**
- Running destructive commands (rm -rf, git reset --hard, DROP TABLE, etc.)
- Accessing files or directories outside this project folder
- Installing global packages (pip install --user, npm install -g, brew install, etc.)

**After making code changes:**
- Always restart the dev server so changes can be viewed: `make run` or `pkill -f uvicorn && make run`

**After fixing issues from reports (`reports/roast/`):**
- Always mark the fixed item as done (`[x]`) in the corresponding report file

**After ANY change that affects documented structure, patterns, or standards:**
- Automatically update `docs/DEVELOPMENT_STANDARDS.md` to reflect the change (e.g., new module added, file renamed/moved, new pattern introduced, new auth method, config key changed, test convention changed)
- Update this `CLAUDE.md` if the change affects architecture overview, module list, command references, or key documentation paths
- This is mandatory — documentation must always match the actual codebase

## Project Overview

Core Webhook Module is a FastAPI-based webhook receiver/processor that validates incoming webhooks using 11 authentication methods and routes payloads to 17+ output destinations. Key features include webhook chaining (sequential/parallel execution), live configuration reload, and distributed analytics via ClickHouse.

## Python Environment

This project uses a local virtualenv at `venv/`. Always use the venv Python/pytest:

```bash
# Activate venv (or prefix commands with venv/bin/)
source venv/bin/activate

# Direct paths (use these if venv is not activated)
venv/bin/python           # Python interpreter
venv/bin/pytest           # Test runner
```

**Important:** System `python3` does NOT have project dependencies installed. Always use `venv/bin/pytest` or activate the venv first.

## Common Commands

```bash
# Install dependencies
make install              # Dev dependencies (default)
make install-prod         # Production only

# Testing (all use venv automatically via Makefile)
make test                 # Unit tests (excludes integration)
make test-integration     # Integration tests (requires Docker services)
make test-all             # All tests
make test-cov             # With coverage report
venv/bin/pytest tests/unit/test_webhooks.py -v  # Single test file

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

> **Full guide: `docs/DEVELOPMENT_STANDARDS.md`** - Complete templates, checklists, and examples.

### New Output Module
1. Create `src/modules/<name>.py` extending `BaseModule`
2. Register in `src/modules/registry.py` (both `MODULE_MAP` and `IMPORT_MAP`)
3. Add unit tests: `tests/unit/test_<name>_module.py`
4. Add security audit tests: `tests/unit/test_<name>_security_audit.py`
5. Add docker-compose scenario: `docker/compose/<name>/`
6. Add documentation: `docusaurus/docs/modules/<name>.md`

### New Auth Method
1. Add validator class in `src/validators.py` extending `BaseValidator`
2. Integrate into validation flow in `src/webhook.py`
3. Add unit tests and security audit tests
4. Add documentation: `docusaurus/docs/authentication/<name>.md`

## Mandatory Development Rules

> Derived from 6 code review reports (79 findings). Follow these to prevent recurring issues.

### Security (ALWAYS)
- **Type-validate ALL config** in `__init__`, not in `process()` — use `isinstance()` checks
- **SSRF-protect ALL network connections** — block localhost, private IPs (`10.x`, `172.16.x`, `192.168.x`), metadata endpoints (`169.254.169.254`)
- **Validate destination/topic/channel names** — block path traversal (`..`), control chars, excessive length
- **Use `hmac.compare_digest()`** for ALL secret/token comparison — never `==`
- **Sanitize ALL error messages** before returning to clients — use `sanitize_error_message()`
- **Redact credentials in logs** — define `SENSITIVE_KEYS` set in each module
- **Validate header names** — block newline/null byte injection with regex

### Reliability (ALWAYS)
- **Timeout ALL external operations** — use `asyncio.wait_for(coro, timeout=N)`
- **Bound ALL queues** — use `asyncio.Queue(maxsize=N)`, never unbounded
- **Initialize locks in `__init__`** — never lazy-init (causes race conditions)
- **Add jitter to reconnection backoff** — prevents thundering herd
- **Track async tasks** — never fire-and-forget; use task sets with done callbacks

### Code Quality (ALWAYS)
- **Use `logger`, NEVER `print()`** for operational output
- **Keep functions under 50 lines** — extract helpers for complex logic
- **Type hints on ALL function signatures**
- **Docstrings on ALL classes and public methods**
- **No magic numbers** — define as named constants
- **No duplicated validation** — use shared utilities from `src/utils.py`

### Testing (ALWAYS)
- **Every component needs `test_<name>_security_audit.py`** with: type confusion, SSRF, injection, disclosure, payload limits
- **Follow Arrange-Act-Assert pattern** with descriptive docstrings
- **Use `@pytest.mark.asyncio`** for all async tests
- **Mock external deps** with `AsyncMock` / `MagicMock` / `patch`

## Security

- 11 auth methods: Bearer, Basic, JWT, HMAC, IP whitelist, reCAPTCHA, rate limiting, query param, header, OAuth2, Digest
- Type validation on all config values
- Input sanitization with size/depth limits
- Credential redaction in logs
- Constant-time HMAC comparison
- SSRF prevention on all network modules
- Header injection prevention
- Error message sanitization

## Key Documentation

- **`docs/DEVELOPMENT_STANDARDS.md`** - **Complete development guide, standards, checklists** (START HERE)
- `docs/ARCHITECTURE.md` - Module system, adding new modules
- `docs/DEVELOPMENT.md` - Local development workflow
- `docs/LIVE_CONFIG_RELOAD_FEATURE.md` - Config reload, pool versioning
- `docs/WEBHOOK_CHAINING_FEATURE.md` - Multi-destination patterns
- `agent-instructions.md` - Comprehensive webhook config guide
- `reports/roast/` - Code review findings (mark `[x]` when fixing)
