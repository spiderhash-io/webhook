# Development Standards & Project Guide

> Comprehensive guide for building, extending, and maintaining core-webhook-module.
> Derived from project analysis, 6 code review (roast) reports, and pattern analysis across 50+ source files and 250+ test files.

> **KEEP THIS DOCUMENT IN SYNC:** Whenever you add, rename, move, or remove a module, validator, test file, config key, directory, or pattern described in this guide — update the relevant section here immediately. This document must always reflect the actual state of the codebase. The same applies to `CLAUDE.md`.

---

## Table of Contents

1. [Project Structure](#1-project-structure)
2. [Adding New Features](#2-adding-new-features)
3. [Code Standards](#3-code-standards)
4. [Security Standards](#4-security-standards)
5. [Testing Standards](#5-testing-standards)
6. [Configuration Standards](#6-configuration-standards)
7. [Error Handling Standards](#7-error-handling-standards)
8. [Logging Standards](#8-logging-standards)
9. [Async Programming Standards](#9-async-programming-standards)
10. [Common Pitfalls (from Roast Reports)](#10-common-pitfalls)
11. [Checklists](#11-checklists)

---

## 1. Project Structure

### Directory Layout

```
core-webhook-module/
├── src/                          # All application source code
│   ├── __init__.py
│   ├── __version__.py            # Single source of truth for version
│   ├── main.py                   # FastAPI app, routes, startup/shutdown
│   ├── webhook.py                # Core webhook processing + validation orchestration
│   ├── config.py                 # Configuration loading + env var substitution
│   ├── config_manager.py         # Live config reload, async-safe config access, provider delegation
│   ├── config_provider.py        # ConfigProvider ABC (read-only interface for config backends)
│   ├── config_watcher.py         # File watcher for config changes
│   ├── file_config_provider.py   # File-based config provider (wraps JSON loading)
│   ├── etcd_config_provider.py   # etcd config provider (cache + watch + reconnect)
│   ├── vault_secret_resolver.py  # Vault secret resolver ({$vault:path#field} references)
│   ├── validators.py             # 11 authentication validators
│   ├── input_validator.py        # Payload validation (size, depth, type)
│   ├── rate_limiter.py           # Rate limiting (sliding window)
│   ├── retry_handler.py          # Retry with exponential backoff
│   ├── chain_processor.py        # Sequential/parallel multi-module execution
│   ├── chain_validator.py        # Chain config validation
│   ├── utils.py                  # Shared utility functions
│   ├── openapi_generator.py      # Dynamic OpenAPI spec generation
│   ├── analytics_processor.py    # Analytics data processing
│   ├── clickhouse_analytics.py   # ClickHouse analytics integration
│   ├── connection_pool_registry.py  # Connection pool lifecycle management
│   │
│   ├── modules/                  # Output module plugins
│   │   ├── base.py               # BaseModule abstract class (EXTEND THIS)
│   │   ├── registry.py           # Module registry (REGISTER HERE)
│   │   ├── log.py                # Log module (simplest reference)
│   │   ├── http_webhook.py       # HTTP forwarding (complex reference)
│   │   ├── rabbitmq.py           # RabbitMQ producer
│   │   ├── redis_publish.py      # Redis Pub/Sub
│   │   ├── redis_rq.py           # Redis RQ jobs
│   │   ├── kafka.py              # Apache Kafka
│   │   ├── mqtt.py               # MQTT broker
│   │   ├── postgres.py           # PostgreSQL insertion
│   │   ├── mysql.py              # MySQL insertion
│   │   ├── s3.py                 # AWS S3 storage
│   │   ├── clickhouse.py         # ClickHouse insertion
│   │   ├── websocket.py          # WebSocket relay
│   │   ├── zeromq.py             # ZeroMQ distribution
│   │   ├── activemq.py           # ActiveMQ broker
│   │   ├── aws_sqs.py            # AWS SQS queue
│   │   ├── gcp_pubsub.py         # GCP Pub/Sub
│   │   └── webhook_connect_module.py  # Webhook Connect relay
│   │
│   ├── webhook_connect/          # Cloud-side webhook relay
│   │   ├── api.py                # Streaming endpoints (WS, SSE)
│   │   ├── admin_api.py          # Admin API (secure-by-default)
│   │   ├── models.py             # Data models
│   │   ├── channel_manager.py    # Channel lifecycle
│   │   └── buffer/               # Event buffering backends
│   │       ├── interface.py      # Buffer interface
│   │       ├── redis_buffer.py   # Redis-backed buffer
│   │       └── rabbitmq_buffer.py # RabbitMQ-backed buffer
│   │
│   └── connector/                # Local connector (connects to cloud)
│       ├── main.py               # Connector entry point
│       ├── config.py             # Connector configuration
│       ├── stream_client.py      # WebSocket/SSE/LongPoll clients
│       ├── processor.py          # Request forwarding processor
│       └── module_processor.py   # Module-based routing
│
├── tests/
│   ├── conftest.py               # Global fixtures (env vars, nonce cleanup)
│   ├── unit/                     # Unit tests (mocked, no external deps)
│   │   ├── conftest.py           # Unit test fixtures
│   │   ├── test_<component>.py   # Component-specific tests
│   │   └── test_<component>_security_audit.py  # Security-focused tests
│   └── integration/              # Integration tests (requires Docker services)
│       ├── conftest.py           # Service fixtures (Redis, RabbitMQ, etc.)
│       ├── utils.py              # Health check utilities
│       ├── api/                  # API endpoint tests
│       └── modules/              # Module integration tests
│
├── config/
│   ├── development/              # Dev environment configs
│   │   ├── webhooks.json         # Webhook definitions
│   │   └── connections.json      # Connection details
│   └── examples/                 # Example configurations
│
├── docker/
│   ├── Dockerfile                # Standard image
│   ├── Dockerfile.small          # Optimized image
│   ├── Dockerfile.smaller        # Smallest image (CI default)
│   ├── compose/                  # 16 docker-compose scenarios
│   │   ├── webhook-only/         # Minimal setup
│   │   ├── redis/                # Redis + webhook
│   │   ├── rabbitmq/             # RabbitMQ + webhook
│   │   ├── kafka/                # Kafka + webhook
│   │   ├── full-stack/           # All services
│   │   └── ...                   # One per output module
│   └── scenario/                 # Complex deployment demos
│       ├── 01_live_config/       # Live reload demo
│       ├── 02_connector/         # Connector demo
│       ├── 03_kubernetes/        # K8s deployment
│       ├── 04_connector_advanced/ # Advanced connector
│       ├── 05_etcd_namespaces/   # etcd namespace integration test
│       └── 06_vault_etcd_secrets/ # Vault + etcd secret resolution test
│
├── docs/                         # Developer documentation
├── docusaurus/                   # User-facing documentation site
├── kubernetes/                   # K8s manifests (base + optional)
├── reports/roast/                # Code review reports
├── .github/workflows/            # CI/CD (GitHub Actions)
├── .gitlab-ci.yml                # CI/CD (GitLab)
└── Makefile                      # Build automation
```

### Request Processing Flow

```
HTTP Request
    │
    ▼
FastAPI Routes (main.py)
    │
    ▼
WebhookHandler (webhook.py)
    ├── InputValidator.validate_headers()
    ├── InputValidator.validate_webhook_id()
    ├── InputValidator.validate_payload_size()
    ├── Authorization (validators.py) ─── 11 methods
    ├── InputValidator.validate_json_depth()
    ├── InputValidator.validate_string_length()
    │
    ▼
ModuleRegistry.get(module_name) (modules/registry.py)
    │
    ▼
BaseModule.process(payload, headers) (modules/<name>.py)
    │
    ├─── [Single module] ──► Direct execution
    │
    └─── [Chain mode] ──► ChainProcessor (chain_processor.py)
                              ├── Sequential: module1 → module2 → module3
                              └── Parallel: module1 ┬ module2
                                                    └ module3
```

---

## 2. Adding New Features

### 2.1 Adding a New Output Module

**Files to create/modify:**

| Step | File | Action |
|------|------|--------|
| 1 | `src/modules/<name>.py` | Create module extending `BaseModule` |
| 2 | `src/modules/registry.py` | Register module name → class mapping |
| 3 | `tests/unit/test_<name>_module.py` | Create functional tests |
| 4 | `tests/unit/test_<name>_security_audit.py` | Create security tests |
| 5 | `docker/compose/<name>/` | Create docker-compose scenario |
| 6 | `docusaurus/docs/modules/<name>.md` | Create user documentation |

**Module template (follow existing patterns from `log.py` and `http_webhook.py`):**

```python
"""
<Name> output module for Core Webhook Module.

Processes webhook payloads and sends them to <destination>.
"""

import logging
from typing import Any, Dict, Optional

from src.modules.base import BaseModule

logger = logging.getLogger(__name__)


class <Name>Module(BaseModule):
    """
    Output module that sends webhook payloads to <destination>.

    Configuration options (via module-config):
        - option_name: Description (type, default: value)
    """

    # SECURITY: sensitive config keys that must be redacted in logs
    SENSITIVE_KEYS = {"password", "secret", "token", "api_key"}

    def __init__(self, config: dict, pool_registry=None):
        """Initialize module with validated configuration."""
        # SECURITY: type validation happens in BaseModule.__init__
        super().__init__(config, pool_registry=pool_registry)

        # Validate and store config with safe defaults
        self._validated_host = self._validate_host(
            self.connection_details.get("host", "")
        )
        self._validated_port = self._validate_port(
            self.connection_details.get("port", 0)
        )

    def _validate_host(self, host: str) -> str:
        """Validate host against SSRF attacks."""
        if not isinstance(host, str) or not host.strip():
            raise ValueError("Host must be a non-empty string")
        # SECURITY: block private/internal IPs
        # Use shared SSRF validation from utils if available
        return host.strip()

    def _validate_port(self, port: Any) -> int:
        """Validate port is in valid range."""
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ValueError(f"Port must be an integer, got {type(port).__name__}")
        if not (1 <= port <= 65535):
            raise ValueError(f"Port must be 1-65535, got {port}")
        return port

    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """
        Process a webhook payload.

        Args:
            payload: The validated webhook payload (dict, str, or bytes)
            headers: The HTTP headers from the original request

        Raises:
            Exception: On processing failure (triggers retry if configured)
        """
        try:
            # Implementation here
            logger.info(
                "Payload processed successfully",
                extra={"module": "<name>", "size": len(str(payload))},
            )
        except Exception as e:
            logger.error(
                "Failed to process payload",
                extra={"module": "<name>", "error": str(e)},
            )
            raise  # Re-raise for retry handler

    async def setup(self) -> None:
        """Initialize connections/resources. Called once at startup."""
        pass

    async def teardown(self) -> None:
        """Clean up connections/resources. Called on shutdown."""
        pass
```

**Registry registration (`src/modules/registry.py`):**

```python
# Add to MODULE_MAP dict:
"<name>": "<Name>Module",

# Add to IMPORT_MAP dict:
"<Name>Module": "src.modules.<name>",
```

### 2.2 Adding a New Authentication Method

**Files to create/modify:**

| Step | File | Action |
|------|------|--------|
| 1 | `src/validators.py` | Add validator class extending `BaseValidator` |
| 2 | `src/webhook.py` | Integrate into validation flow |
| 3 | `tests/unit/test_<auth>_auth.py` | Create functional tests |
| 4 | `tests/unit/test_<auth>_security_audit.py` | Create security tests |
| 5 | `docusaurus/docs/authentication/<auth>.md` | Create user documentation |

**Validator template:**

```python
class <Name>Validator(BaseValidator):
    """
    Validates requests using <method> authentication.

    Config keys:
        - <key>: Description
    """

    def __init__(self, config: dict):
        """Initialize with validated config."""
        # SECURITY: type validation in BaseValidator.__init__
        super().__init__(config)
        self._validated_secret = self._validate_secret(
            config.get("<auth_key>", {})
        )

    async def validate(
        self, headers: Dict[str, str], body: bytes
    ) -> Tuple[bool, str]:
        """
        Validate the request.

        Returns:
            Tuple of (is_valid, message)
            - (True, "Valid <auth> authentication") on success
            - (False, "Sanitized error message") on failure
        """
        try:
            # Validation logic
            return True, "Valid <auth> authentication"
        except Exception as e:
            # SECURITY: sanitize before returning
            return False, sanitize_error_message(str(e))
```

### 2.3 Adding a New Webhook Connect Buffer Backend

**Files to create:**

| Step | File | Action |
|------|------|--------|
| 1 | `src/webhook_connect/buffer/<name>_buffer.py` | Implement `BufferInterface` |
| 2 | `tests/unit/test_webhook_connect_<name>_buffer.py` | Tests |

### 2.4 Adding a New Docker Compose Scenario

**Create directory: `docker/compose/<service>/`**

Required files:
- `docker-compose.yaml` - Service definitions with health checks
- `.env` - Environment variables
- `webhooks.json` - Webhook configuration
- `connections.json` - Connection details
- `test.sh` - Test script to verify the scenario works

---

## 3. Code Standards

### 3.1 Import Ordering

Follow this order (matches existing codebase):

```python
# 1. Standard library
import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

# 2. Third-party packages
from fastapi import HTTPException

# 3. Local application imports
from src.modules.base import BaseModule
from src.utils import sanitize_error_message
```

### 3.2 Logging Setup

Every module must use this pattern:

```python
import logging

logger = logging.getLogger(__name__)
```

**NEVER use `print()` for operational output.** Use `logger.info()`, `logger.warning()`, `logger.error()`.

### 3.3 Type Hints

All function signatures must include type hints:

```python
# Good
async def process(self, payload: Any, headers: Dict[str, str]) -> None:

# Bad
async def process(self, payload, headers):
```

### 3.4 Docstrings

All classes and public methods must have docstrings:

```python
class MyModule(BaseModule):
    """
    Brief description of module purpose.

    Configuration options (via module-config):
        - option_a: Description (type, default: value)
        - option_b: Description (type, default: value)
    """

    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """
        Process a webhook payload by doing X.

        Args:
            payload: The validated webhook payload
            headers: HTTP request headers

        Raises:
            Exception: When connection to X fails
        """
```

### 3.5 Function Size Limits

**Keep functions under 50 lines.** If a function exceeds this, extract helper methods.

This rule exists because roast reports found:
- `validate_connections()` at 390 lines
- `OAuth2Validator.validate()` at 192 lines
- `read_webhook()` endpoint at 133 lines
- `CORS configuration logic` at 80 lines

### 3.6 Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Files | `snake_case.py` | `redis_publish.py` |
| Classes | `PascalCase` | `RedisPublishModule` |
| Functions/Methods | `snake_case` | `validate_host()` |
| Constants | `UPPER_SNAKE_CASE` | `MAX_CHAIN_LENGTH` |
| Private methods | `_prefixed` | `_validate_port()` |
| Validated values | `_validated_` prefix | `self._validated_host` |
| Config keys (JSON) | `snake_case` or `kebab-case` | `module-config`, `data_type` |

---

## 4. Security Standards

### 4.1 Mandatory Security Checks

Every new module or feature MUST implement:

#### Type Validation

```python
# In __init__, validate ALL config parameters
if not isinstance(config, dict):
    raise TypeError(f"Config must be a dictionary, got {type(config).__name__}")

# Validate nested config types
host = config.get("host", "")
if not isinstance(host, str):
    raise TypeError(f"Host must be a string, got {type(host).__name__}")
```

#### SSRF Prevention (for any module that makes network connections)

```python
# Block private IPs, localhost, metadata endpoints
BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "169.254.169.254",  # AWS metadata
    "metadata.google.internal",  # GCP metadata
}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def _validate_host(self, host: str) -> str:
    if host.lower() in self.BLOCKED_HOSTS:
        raise ValueError("Host points to internal/private address")
    # Check IP ranges
    try:
        ip = ipaddress.ip_address(host)
        for network in self.PRIVATE_RANGES:
            if ip in network:
                raise ValueError("Host points to private IP range")
    except ValueError:
        pass  # Not an IP, hostname is OK
    return host
```

#### Port Validation

```python
def _validate_port(self, port: Any) -> int:
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError(f"Port must be integer, got {type(port).__name__}")
    if not (1 <= port <= 65535):
        raise ValueError(f"Port out of range: {port}")
    return port
```

#### Header Injection Prevention

```python
import re

SAFE_HEADER_PATTERN = re.compile(r"^[a-zA-Z0-9\-_]+$")

def _validate_header_name(self, name: str) -> str:
    if not self.SAFE_HEADER_PATTERN.match(name):
        raise ValueError("Invalid characters in header name")
    return name
```

#### Destination/Topic/Channel Name Validation

```python
import re

SAFE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9._\-/]+$")

def _validate_destination_name(self, name: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Destination name must be non-empty string")
    if not self.SAFE_NAME_PATTERN.match(name):
        raise ValueError("Destination name contains invalid characters")
    if ".." in name or name.startswith("/"):
        raise ValueError("Path traversal detected in destination name")
    if len(name) > 255:
        raise ValueError("Destination name too long")
    return name
```

#### Constant-Time Secret Comparison

```python
import hmac

# ALWAYS use hmac.compare_digest for secret comparison
# NEVER use == for comparing secrets, tokens, or signatures
if not hmac.compare_digest(provided_token, expected_token):
    return False, "Invalid token"
```

#### Error Message Sanitization

```python
from src.utils import sanitize_error_message

# NEVER expose internal details in error responses
try:
    result = await some_operation()
except Exception as e:
    # Internal log gets full detail
    logger.error(f"Operation failed: {e}", extra={"detail": str(e)})
    # Client gets sanitized message
    raise HTTPException(
        status_code=500,
        detail=sanitize_error_message(str(e))
    )
```

#### Credential Redaction in Logs

```python
SENSITIVE_KEYS = {"password", "secret", "token", "api_key", "credentials"}

def _redact_config(self, config: dict) -> dict:
    """Redact sensitive values before logging."""
    redacted = {}
    for key, value in config.items():
        if any(s in key.lower() for s in self.SENSITIVE_KEYS):
            redacted[key] = "***REDACTED***"
        else:
            redacted[key] = value
    return redacted
```

### 4.2 Security Anti-Patterns (NEVER do these)

| Anti-Pattern | Why | Fix |
|-------------|-----|-----|
| `if token == secret:` | Timing attack | Use `hmac.compare_digest()` |
| `raise Exception(f"DB error: {e}")` to client | Info disclosure | Use `sanitize_error_message()` |
| Accept any URL without validation | SSRF | Block private IPs/metadata |
| `setattr(obj, key, user_input)` | Attribute injection | Whitelist allowed keys |
| Log secrets/tokens | Credential leak | Redact with `SENSITIVE_KEYS` |
| `eval()` or `exec()` on user input | RCE | Never use |
| Hardcoded secrets in source | Exposure | Use env vars: `{$SECRET}` |
| `--token` in CLI args | Visible in `ps aux` | Use env var or `--token-file` |
| Unbounded queues/caches | DoS via OOM | Always set `maxsize` |
| MD5/SHA1 for new crypto | Cryptographically weak | Use SHA256+ (unless RFC requires it) |

### 4.3 Security Testing Requirements

Every new component MUST have a corresponding `test_<component>_security_audit.py` with tests for:

1. **Type confusion attacks** - Pass wrong types to all config parameters
2. **SSRF prevention** - Verify localhost, private IPs, metadata endpoints are blocked
3. **Injection attacks** - SQL injection, path traversal, header injection, null bytes
4. **Large/deep payload handling** - Verify size/depth limits work
5. **Error information disclosure** - Verify errors don't leak internals
6. **Missing/None field validation** - Verify graceful handling of missing config
7. **Concurrent processing** - Verify thread safety under parallel requests

---

## 5. Testing Standards

### 5.1 Test File Organization

```
tests/unit/
├── test_<component>.py                    # Functional tests
├── test_<component>_security_audit.py     # Security-focused tests
├── test_<component>_integration.py        # Unit-level integration tests
└── test_<component>_comprehensive_security.py  # Deep security tests (for complex components)
```

### 5.2 Test Structure (Arrange-Act-Assert)

```python
@pytest.mark.asyncio
async def test_valid_payload_processing():
    """Test that valid JSON payload is processed correctly."""
    # Arrange
    config = {
        "module": "my_module",
        "module-config": {"option": "value"},
        "connection_details": {"host": "example.com", "port": 5672},
    }
    module = MyModule(config)
    payload = {"key": "value"}
    headers = {"content-type": "application/json"}

    # Act
    await module.process(payload, headers)

    # Assert
    assert module.last_result is not None
```

### 5.3 Test Naming Convention

```python
# Pattern: test_<what>_<scenario>_<expected_result>
def test_hmac_validator_invalid_signature():
def test_redis_publish_connection_timeout():
def test_chain_processor_parallel_execution_with_failure():
def test_config_type_validation_rejects_non_dict():
```

### 5.4 Test Class Organization

Group related tests in classes:

```python
class TestMyModuleConfiguration:
    """Test configuration validation."""

    async def test_valid_config(self):
        ...

    async def test_invalid_host_type(self):
        ...


class TestMyModuleProcessing:
    """Test payload processing."""

    async def test_json_payload(self):
        ...

    async def test_empty_payload(self):
        ...


class TestMyModuleSSRFPrevention:
    """Test SSRF attack prevention."""

    async def test_localhost_blocked(self):
        ...

    async def test_private_ip_blocked(self):
        ...
```

### 5.5 Mocking Conventions

```python
from unittest.mock import AsyncMock, MagicMock, patch

# Mock async functions with AsyncMock
mock_client = AsyncMock()
mock_client.publish.return_value = True

# Mock sync functions with MagicMock
mock_config = MagicMock()
mock_config.get.return_value = "value"

# Patch imports at the point of use
with patch("src.modules.my_module.SomeClient") as mock_cls:
    mock_cls.return_value = mock_client
    module = MyModule(config)
    await module.process(payload, headers)
    mock_client.publish.assert_called_once()
```

### 5.6 Test Markers

```python
@pytest.mark.asyncio          # All async tests (required even with auto mode for clarity)
@pytest.mark.unit             # Unit tests (default, runs in CI)
@pytest.mark.integration      # Requires Docker services
@pytest.mark.slow             # Takes > 5 seconds
@pytest.mark.longrunning      # Takes > 30 seconds
@pytest.mark.external_services # Requires external services
@pytest.mark.todo             # Known broken, needs fix
```

### 5.7 Security Test Template

Every module needs this test file (`test_<module>_security_audit.py`):

```python
"""Security audit tests for <Module>."""

import pytest
from src.modules.<name> import <Name>Module


class TestConfigTypeValidation:
    """Test type confusion attacks on configuration."""

    def test_config_must_be_dict(self):
        with pytest.raises(TypeError):
            <Name>Module("not a dict")

    def test_config_must_be_dict_list(self):
        with pytest.raises(TypeError):
            <Name>Module([1, 2, 3])

    def test_host_type_validation(self):
        config = {"connection_details": {"host": 12345}}
        with pytest.raises((TypeError, ValueError)):
            <Name>Module(config)


class TestSSRFPrevention:
    """Test SSRF attack prevention."""

    @pytest.mark.asyncio
    async def test_localhost_blocked(self):
        config = {"connection_details": {"host": "127.0.0.1", "port": 5672}}
        with pytest.raises(ValueError, match="private|internal|blocked"):
            <Name>Module(config)

    @pytest.mark.asyncio
    async def test_metadata_service_blocked(self):
        config = {"connection_details": {"host": "169.254.169.254", "port": 80}}
        with pytest.raises(ValueError, match="private|internal|blocked"):
            <Name>Module(config)


class TestInjectionPrevention:
    """Test injection attack prevention."""

    @pytest.mark.asyncio
    async def test_destination_path_traversal(self):
        config = {
            "connection_details": {"host": "example.com"},
            "module-config": {"destination": "../../../etc/passwd"},
        }
        with pytest.raises(ValueError, match="invalid|traversal"):
            <Name>Module(config)

    @pytest.mark.asyncio
    async def test_header_injection(self):
        config = {"connection_details": {"host": "example.com"}}
        module = <Name>Module(config)
        headers = {"X-Evil\r\nInjected": "value"}
        with pytest.raises((ValueError, Exception)):
            await module.process({"data": "test"}, headers)


class TestErrorInformationDisclosure:
    """Test that errors don't leak internal details."""

    @pytest.mark.asyncio
    async def test_connection_error_sanitized(self):
        # Verify error messages don't contain internal IPs, paths, or stack traces
        ...


class TestPayloadSecurity:
    """Test payload handling edge cases."""

    @pytest.mark.asyncio
    async def test_large_payload(self):
        ...

    @pytest.mark.asyncio
    async def test_deeply_nested_payload(self):
        ...
```

### 5.8 Running Tests

```bash
# Unit tests (default, runs in CI)
make test
venv/bin/pytest tests/unit/ -x -v

# Single file
venv/bin/pytest tests/unit/test_my_module.py -v

# Single test
venv/bin/pytest tests/unit/test_my_module.py::TestClass::test_method -v

# With coverage
make test-cov

# Integration (requires Docker services)
make integration-up
make test-integration
make integration-down
```

---

## 6. Configuration Standards

### 6.1 Config Key Naming

- **JSON config files**: Use `snake_case` for all new keys
- **Legacy**: `module-config` uses hyphen (keep for backward compatibility)
- **Env vars**: `UPPER_SNAKE_CASE` prefix with `WEBHOOK_`

### 6.2 Config Validation Pattern

Validate ALL configuration in `__init__`, not in `process()`:

```python
def __init__(self, config: dict, pool_registry=None):
    super().__init__(config, pool_registry=pool_registry)

    # Validate during init, not at runtime
    self._validated_host = self._validate_host(
        self.connection_details.get("host", "")
    )
    self._validated_port = self._validate_port(
        self.connection_details.get("port", 0)
    )
    self._validated_topic = self._validate_destination_name(
        self.module_config.get("topic", "")
    )
```

### 6.3 Config Access Pattern

```python
# Use .get() with safe defaults
host = self.connection_details.get("host", "localhost")
port = self.connection_details.get("port", 5672)
timeout = self.module_config.get("timeout", 30)

# Validate types explicitly
if not isinstance(timeout, (int, float)):
    raise TypeError(f"timeout must be numeric, got {type(timeout).__name__}")
if timeout <= 0 or timeout > 300:
    raise ValueError(f"timeout must be 1-300, got {timeout}")
```

### 6.4 Environment Variable Substitution

Config files support `{$VAR}` and `{$VAR:default}` syntax:

```json
{
  "my_webhook": {
    "authorization": "Bearer {$WEBHOOK_TOKEN}",
    "connection_details": {
      "host": "{$REDIS_HOST:localhost}",
      "port": "{$REDIS_PORT:6379}"
    }
  }
}
```

### 6.5 Config Backend Architecture

The configuration system uses a provider pattern with two backends:

```
CONFIG_BACKEND=file (default):
  JSON files → FileConfigProvider → ConfigManager → WebhookHandler

CONFIG_BACKEND=etcd:
  etcd cluster → EtcdConfigProvider (in-memory cache + watch) → ConfigManager → WebhookHandler
```

**Key interfaces:**

| File | Purpose |
|------|---------|
| `src/config_provider.py` | `ConfigProvider` ABC — read-only interface all backends implement |
| `src/file_config_provider.py` | File-based provider (wraps JSON file loading) |
| `src/etcd_config_provider.py` | etcd provider (in-memory cache + background watch thread) |
| `src/config_manager.py` | `ConfigManager.create(backend=...)` factory, delegates reads to provider |

**Adding a new config backend:**

1. Create `src/<name>_config_provider.py` implementing `ConfigProvider` ABC
2. Add backend option to `ConfigManager.create()` factory in `src/config_manager.py`
3. Add startup/shutdown handling in `src/main.py`
4. Create tests: `tests/unit/test_<name>_config_provider.py`

**etcd-specific details:** See `docs/DISTRIBUTED_CONFIG_ETCD.md` for key layout, namespace rules, watch behavior, env vars, and migration guide.

**Vault secret resolution:** Config values can reference Vault secrets using `{$vault:path#field}` syntax. The `VaultSecretResolver` in `src/vault_secret_resolver.py` is invoked during env var substitution in `src/utils.py:load_env_vars()`. See `docs/VAULT_INTEGRATION_GUIDE.md` for full setup.

---

## 7. Error Handling Standards

### 7.1 Error Return Patterns

| Component | Return Pattern | Example |
|-----------|---------------|---------|
| Validators | `Tuple[bool, str]` | `return (False, "Invalid token")` |
| Modules | Raise `Exception` | `raise Exception("Connection failed")` |
| API endpoints | Raise `HTTPException` | `raise HTTPException(status_code=401)` |

### 7.2 Exception Hierarchy

```python
# In validators: return tuple, NEVER raise
async def validate(self, headers, body) -> Tuple[bool, str]:
    try:
        # validation logic
        return True, "Valid"
    except Exception as e:
        return False, sanitize_error_message(str(e))

# In modules: raise for retry handler to catch
async def process(self, payload, headers) -> None:
    try:
        await self._send(payload)
    except ConnectionError as e:
        logger.error(f"Connection failed: {e}")
        raise  # Retry handler will catch this

# In API routes: raise HTTPException
@app.post("/webhook/{webhook_id}")
async def receive_webhook(webhook_id: str):
    try:
        await handler.process(webhook_id, request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=sanitize_error_message(str(e)))
```

### 7.3 Resource Cleanup

Always use `try/finally` for resource cleanup:

```python
async def process(self, payload, headers):
    connection = None
    try:
        connection = await self._get_connection()
        await connection.send(payload)
    except Exception:
        raise
    finally:
        if connection:
            await connection.close()
```

---

## 8. Logging Standards

### 8.1 Required Pattern

```python
import logging

logger = logging.getLogger(__name__)
```

### 8.2 Log Levels

| Level | When to Use | Example |
|-------|-------------|---------|
| `ERROR` | Operation failed, needs attention | Connection failure, auth failure |
| `WARNING` | Unexpected but handled | Config fallback used, deprecated feature |
| `INFO` | Normal operations | Webhook processed, config reloaded |
| `DEBUG` | Diagnostic detail | Payload contents, connection details |

### 8.3 Structured Logging with `extra`

```python
# Include context in extra dict
logger.info(
    "Webhook processed successfully",
    extra={
        "webhook_id": webhook_id,
        "module": module_name,
        "duration_ms": duration,
    },
)

logger.error(
    "Failed to process webhook",
    extra={
        "webhook_id": webhook_id,
        "module": module_name,
        "error": sanitize_error_message(str(e)),
    },
)
```

### 8.4 NEVER Log These

- Passwords, tokens, API keys, secrets
- Full request bodies in production
- Stack traces in client-facing responses
- Internal IP addresses or file paths in responses

---

## 9. Async Programming Standards

### 9.1 Lock Initialization

Initialize locks in `__init__`, not lazily:

```python
# GOOD: Initialize in __init__
class MyProcessor:
    def __init__(self):
        self._lock = asyncio.Lock()

# BAD: Lazy initialization (race condition)
class MyProcessor:
    def __init__(self):
        self._lock = None

    async def process(self):
        if self._lock is None:  # Race condition!
            self._lock = asyncio.Lock()
```

This was identified as a recurring bug in roast reports (webhook.py, config_manager.py).

### 9.2 Timeouts on All External Operations

```python
# ALWAYS use asyncio.wait_for() for external calls
try:
    result = await asyncio.wait_for(
        self._client.send(payload),
        timeout=self._timeout,
    )
except asyncio.TimeoutError:
    logger.error("Operation timed out", extra={"timeout": self._timeout})
    raise
```

### 9.3 Bounded Queues

```python
# ALWAYS set maxsize on queues
self._queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

# Handle backpressure
try:
    self._queue.put_nowait(item)
except asyncio.QueueFull:
    logger.warning("Queue full, dropping item")
```

### 9.4 Task Management

```python
# Track created tasks for cleanup
self._tasks: set = set()

async def _create_tracked_task(self, coro):
    task = asyncio.create_task(coro)
    self._tasks.add(task)
    task.add_done_callback(self._tasks.discard)
    return task

async def _cleanup_tasks(self):
    for task in self._tasks:
        task.cancel()
    await asyncio.gather(*self._tasks, return_exceptions=True)
```

### 9.5 Reconnection with Jitter

```python
import random

async def _reconnect(self):
    delay = self._initial_delay
    while True:
        try:
            await self._connect()
            self._reconnect_delay = self._initial_delay
            return
        except Exception:
            # Add jitter to prevent thundering herd
            jitter = random.uniform(0, delay * 0.3)
            await asyncio.sleep(delay + jitter)
            delay = min(delay * self._backoff_multiplier, self._max_delay)
```

### 9.6 Relay Resilience (Webhook Connect)

When a relay-client (WebSocket/SSE/long-poll) disconnects and reconnects, messages
must be preserved for redelivery, not permanently lost to the DLQ.

**Requeue on callback failure (not DLQ):**

```python
# BAD: Immediate DLQ on any callback failure
except Exception as e:
    await amqp_message.reject(requeue=False)  # Lost forever

# GOOD: Requeue with retry limit
except Exception as e:
    self._requeue_counts[msg_id] = self._requeue_counts.get(msg_id, 0) + 1
    if self._requeue_counts[msg_id] >= self.max_redelivery_attempts:
        self._requeue_counts.pop(msg_id, None)
        await amqp_message.reject(requeue=False)  # DLQ only after N attempts
    else:
        await asyncio.sleep(self.requeue_delay_seconds)  # Prevent tight loop
        await amqp_message.reject(requeue=True)  # Requeue for redelivery
```

**Stale connection eviction:**

Dead connections consume consumer slots and count against `max_connections`.
Use protocol-aware heartbeat monitoring to detect and evict stale connections:

- **WebSocket**: Stale if `last_heartbeat_at` older than `heartbeat_interval * 3`
- **SSE**: Stale if no activity for 24 hours
- **Long-poll**: Stale if no activity for 5 minutes

The eviction loop runs in `ChannelManager._eviction_loop()` on a 30-second interval.

**Always set initial heartbeat timestamp:**

```python
connection.last_heartbeat_at = datetime.now(timezone.utc)  # Baseline for eviction
```

### 9.7 Per-Webhook Queues & Deferred Consumption (Webhook Connect)

Messages are routed to per-webhook queues for independent visibility, backpressure,
and admin stats. Consumption only starts when a relay-client connects.

**Queue naming and routing (RabbitMQ):**

- Exchange: topic exchange `webhook_connect`
- Per-webhook queue: `wc.{channel}.{webhook_id}` bound with routing key `{channel}.{webhook_id}`
- Collector queue (subscribe): transient auto-delete queue bound with wildcard `{channel}.*`
- DLQ: `wc.{channel}.{webhook_id}.dlq`

```python
# Push routes to per-webhook queue via routing key
routing_key = f"{channel}.{webhook_id}"
await exchange.publish(message, routing_key=routing_key)

# Subscribe creates a collector that receives from ALL per-webhook queues
collector = await channel.declare_queue(exclusive=True, auto_delete=True)
await collector.bind(exchange, routing_key=f"{channel}.*")
```

**Redis Streams equivalent:**

- Per-webhook stream key: `{prefix}:stream:{channel}:{webhook_id}`
- Subscribe uses SCAN to discover all streams, reads via XREADGROUP
- Stream discovery runs every `STREAM_DISCOVERY_INTERVAL` seconds to pick up new webhooks

**Deferred consumption pattern:**

Buffer consumers only start when the first client connects and stop when the last
client disconnects. This prevents messages piling up in transient collector queues
when no clients are connected — messages stay safely in per-webhook queues.

```python
# In add_connection(): start consumer on first client
if channel not in self._consumer_tags:
    callback = self._make_delivery_callback(channel)
    consumer_tag = await self.buffer.subscribe(channel, callback)
    self._consumer_tags[channel] = consumer_tag

# In _cleanup_connection(): stop consumer when last client leaves
if not remaining_connections:
    consumer_tag = self._consumer_tags.pop(channel, None)
    if consumer_tag:
        await self.buffer.unsubscribe(consumer_tag)
```

**Per-connection send functions:**

Each transport (WebSocket/SSE/long-poll) registers a send function. The delivery
callback tries all connected clients for the channel, falling back to nack+requeue.

```python
channel_manager.register_send_fn(connection.connection_id, ws_send)
```

---

## 10. Common Pitfalls

> Derived from analysis of 79 issues found across 6 roast reports. These are the recurring patterns that cause bugs.

### 10.1 Global Mutable State (Found 8+ times)

**Problem:** Globals created at module import without atomic updates cause race conditions.

```python
# BAD: Global mutable state
config_manager = None  # Set during startup, read everywhere

# GOOD: Use app.state or dependency injection
app.state.config_manager = ConfigManager()
```

### 10.2 Unbounded Growth (Found 6 times)

**Problem:** Queues, caches, and trackers without size limits cause OOM.

```python
# BAD: Unbounded
self._nonce_cache = {}  # Grows forever
self._queue = asyncio.Queue()  # No limit

# GOOD: Bounded
self._nonce_cache = {}  # with TTL-based cleanup
self._queue = asyncio.Queue(maxsize=1000)
```

### 10.3 Fire-and-Forget Tasks (Found 4 times)

**Problem:** Tasks created without result tracking silently lose data.

```python
# BAD: Fire-and-forget
asyncio.create_task(self._process(payload))
return {"status": "accepted"}  # Success returned before processing

# GOOD: Track task results
task = asyncio.create_task(self._process(payload))
self._pending_tasks.add(task)
task.add_done_callback(self._handle_result)
```

### 10.4 Deep Copy Performance (Found 5 times)

**Problem:** `copy.deepcopy()` on every request is expensive.

```python
# BAD: Deep copy per request
config = copy.deepcopy(self._config)

# GOOD: Shallow copy or immutable view
config = dict(self._config)  # If nested mutation isn't needed
# Or use frozen dataclasses / namedtuples for config
```

### 10.5 Missing Timeouts (Found 3 times)

**Problem:** Operations hang forever without timeouts.

```python
# BAD: No timeout
response = await client.get(url)

# GOOD: Always timeout
response = await asyncio.wait_for(client.get(url), timeout=30)
```

### 10.6 Duplicated Validation Logic (Found 3 times)

**Problem:** Same validation implemented differently in multiple places.

```python
# BAD: SSRF validation in each module separately
# redis_publish.py has its own version
# http_webhook.py has its own version
# kafka.py has its own version

# GOOD: Shared utility
from src.utils import validate_host_ssrf
validated_host = validate_host_ssrf(host)
```

### 10.7 print() Instead of Logging (Found 4+ times)

**Problem:** `print()` bypasses structured logging, can't be filtered or formatted.

```python
# BAD
print(f"Processing webhook {webhook_id}")

# GOOD
logger.info("Processing webhook", extra={"webhook_id": webhook_id})
```

### 10.8 Blocking I/O in Async Context (Found 2 times)

**Problem:** Synchronous operations block the event loop.

```python
# BAD: Blocking the event loop
data = json.loads(large_body)  # Blocks for large payloads

# GOOD: Offload to thread
data = await asyncio.to_thread(json.loads, large_body)
```

### 10.9 Hardcoded Magic Numbers (Found 3+ times)

**Problem:** Magic numbers scattered across code without constants.

```python
# BAD
await asyncio.sleep(3600)  # What is 3600?
if len(chain) > 20:  # Why 20?

# GOOD
CLEANUP_INTERVAL_SECONDS = 3600
MAX_CHAIN_LENGTH = 20  # Defined as constant with comment
```

### 10.10 Config Env Override Bugs (Found 2 times)

**Problem:** Comparing env var value against class default instead of checking existence.

```python
# BAD: Compares value against default
if os.environ.get("MY_VAR", default) != default:
    config.my_var = os.environ["MY_VAR"]
# This fails when env var value happens to equal the class default

# GOOD: Check existence
env_value = os.environ.get("MY_VAR")
if env_value is not None:
    config.my_var = env_value
```

---

## 11. Checklists

### 11.1 New Module Checklist

- [ ] Extends `BaseModule` from `src/modules/base.py`
- [ ] Registered in `src/modules/registry.py` (both `MODULE_MAP` and `IMPORT_MAP`)
- [ ] Type validation in `__init__` for all config parameters
- [ ] SSRF validation for any host/URL parameters
- [ ] Port validation (1-65535 range)
- [ ] Destination/topic/channel name validation (no path traversal)
- [ ] Header name validation (no injection)
- [ ] Credential redaction in logs (`SENSITIVE_KEYS`)
- [ ] Error messages sanitized before client exposure
- [ ] Constant-time comparison for any secrets
- [ ] `async def process()` with proper error handling
- [ ] `async def setup()` and `async def teardown()` if resources need lifecycle
- [ ] `pool_registry` parameter accepted if using connection pools
- [ ] Unit tests in `tests/unit/test_<name>_module.py`
- [ ] Security audit tests in `tests/unit/test_<name>_security_audit.py`
- [ ] Docker compose scenario in `docker/compose/<name>/`
- [ ] Documentation in `docusaurus/docs/modules/<name>.md`
- [ ] All tests pass: `venv/bin/pytest tests/unit/test_<name>*.py -v`

### 11.2 New Validator Checklist

- [ ] Extends `BaseValidator` from `src/validators.py`
- [ ] Returns `Tuple[bool, str]` from `validate()`
- [ ] Config type validation in `__init__`
- [ ] Constant-time comparison for secrets (`hmac.compare_digest`)
- [ ] Error messages don't disclose internal details
- [ ] No timing side-channels in validation logic
- [ ] Unit tests covering valid/invalid cases
- [ ] Security audit tests (type confusion, injection, disclosure)
- [ ] Documentation in `docusaurus/docs/authentication/<name>.md`

### 11.3 Pre-Commit Checklist

- [ ] All tests pass: `make test`
- [ ] Code formatted: `make format`
- [ ] Linting passes: `make lint`
- [ ] Type checking passes: `make type-check`
- [ ] Security scan passes: `make security-scan`
- [ ] No `print()` statements (use `logger`)
- [ ] No hardcoded secrets
- [ ] No unbounded queues/caches
- [ ] All external operations have timeouts
- [ ] Error messages are sanitized
- [ ] If fixing a roast report issue: marked `[x]` in report file

### 11.4 PR Review Checklist

- [ ] Functions under 50 lines
- [ ] Type hints on all function signatures
- [ ] Docstrings on classes and public methods
- [ ] No global mutable state without locks
- [ ] SSRF protection on new network connections
- [ ] Input validation on all user-facing parameters
- [ ] Security audit tests for new attack surfaces
- [ ] No `print()` statements
- [ ] Constant-time comparison for secrets
- [ ] Error messages sanitized for client exposure
- [ ] Timeouts on all external operations
- [ ] Queues have `maxsize`
- [ ] Reconnection logic has jitter
- [ ] Docker compose scenario (if new module)
- [ ] Docusaurus documentation (if user-facing)

---

## Appendix A: Roast Report Summary

79 total issues found across 6 reports. 31 fixed (39%), 48 unfixed (61%).

| Category | Total | Fixed | Unfixed | Top Recurring Patterns |
|----------|-------|-------|---------|----------------------|
| Security | 17 | 8 | 9 | SSRF, timing attacks, info disclosure |
| Reliability | 23 | 9 | 14 | Race conditions, unbounded growth, no timeouts |
| Performance | 15 | 7 | 8 | Deep copy overhead, blocking I/O |
| Maintainability | 25 | 8 | 17 | Large functions, code duplication |

**Top 5 recurring patterns across all reports:**
1. **Global mutable state & concurrency issues** (8+ occurrences)
2. **Unbounded resource growth** (6 occurrences)
3. **Fire-and-forget task patterns** (4 occurrences)
4. **Deep copy performance** (5 occurrences)
5. **Missing timeouts/heartbeats** (3 occurrences)

See individual reports in `reports/roast/` for detailed findings.

---

## Appendix B: Key File Reference

| Purpose | File | Notes |
|---------|------|-------|
| App entry point | `src/main.py` | FastAPI app, routes, lifecycle |
| Webhook processing | `src/webhook.py` | Core handler, TaskManager |
| Authentication | `src/validators.py` | 11 validator classes |
| Module base class | `src/modules/base.py` | Extend this for new modules |
| Module registry | `src/modules/registry.py` | Register modules here |
| Simple module example | `src/modules/log.py` | Reference implementation |
| Complex module example | `src/modules/http_webhook.py` | Full SSRF, validation |
| Chain processing | `src/chain_processor.py` | Sequential/parallel execution |
| Config management | `src/config_manager.py` | Live reload, async safety, provider delegation |
| Config provider ABC | `src/config_provider.py` | Read-only interface for config backends |
| File config provider | `src/file_config_provider.py` | File-based provider (wraps JSON loading) |
| etcd config provider | `src/etcd_config_provider.py` | etcd provider (cache + watch + reconnect) |
| Vault secret resolver | `src/vault_secret_resolver.py` | Vault `{$vault:path#field}` config references |
| Input validation | `src/input_validator.py` | Size, depth, type limits |
| Utilities | `src/utils.py` | Shared helpers |
| Global test fixtures | `conftest.py` | Env vars, nonce cleanup |
| Unit test fixtures | `tests/unit/conftest.py` | Performance test exclusion |
| Integration fixtures | `tests/integration/conftest.py` | Docker service health |
| CI pipeline | `.gitlab-ci.yml` | Test + build stages |
| CI pipeline | `.github/workflows/ci.yml` | GitHub Actions |
| Build automation | `Makefile` | All dev commands |
| Dev config | `config/development/` | Dev webhook + connection configs |
