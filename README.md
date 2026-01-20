# Core Webhook Module

[![CI](https://github.com/spiderhash-io/webhook/actions/workflows/ci.yml/badge.svg)](https://github.com/spiderhash-io/webhook/actions/workflows/ci.yml)
[![Docker Build](https://github.com/spiderhash-io/webhook/actions/workflows/docker-build.yml/badge.svg)](https://github.com/spiderhash-io/webhook/actions/workflows/docker-build.yml)
[![Security Scan](https://github.com/spiderhash-io/webhook/actions/workflows/security-scan.yml/badge.svg)](https://github.com/spiderhash-io/webhook/actions/workflows/security-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](https://github.com/spiderhash-io/webhook/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/spiderhash/webhook)](https://hub.docker.com/r/spiderhash/webhook)

A webhook receiver and processor built with FastAPI. Receives HTTP webhook requests, validates them using authentication and validation rules, and forwards payloads to destinations including RabbitMQ, Redis, MQTT, databases, object storage, message queues, and local filesystem.

**Status**: 2,493 passing tests. Supports 11 authentication methods, 17 output modules, and cloud-to-local webhook relay.

## Recent Updates (2025-01)

### Webhook Connect - Cloud-to-Local Relay
- **NEW**: Cloud-to-local webhook relay system for receiving webhooks behind firewalls
- WebSocket and SSE streaming protocols
- Channel-based isolation with HMAC authentication
- Message acknowledgments, retries, and dead-letter queue
- Multi-target forwarding support

### Performance & Reliability Improvements
- **Webhook Chaining**: Added timeout protection for parallel execution (configurable, default 30s)
- **Webhook Chaining**: Automatic task cancellation on partial failure
- **Performance**: Credential cleanup deferred to background tasks (no request latency impact)
- **Observability**: Replaced all `print()` statements with structured logging
- **Metrics**: Added in-memory metrics for chain execution tracking
- **Memory**: Module config pre-building optimization (reduced allocations)
- **Reliability**: Fail-fast on circular references (no unsafe shallow copy fallback)
- **TaskManager**: Enhanced with semaphore-based backpressure and timeout protection

## Features

### Core Functionality
- **Output Modules**: Send webhook data to RabbitMQ, Redis (RQ), local disk, HTTP endpoints, ClickHouse, MQTT, WebSocket, PostgreSQL, MySQL/MariaDB, S3, Kafka, ActiveMQ, AWS SQS, GCP Pub/Sub, ZeroMQ, or stdout.
- **Webhook Chaining**: Send webhook payloads to multiple destinations in sequence or parallel with timeout protection, task cancellation, and retry support (e.g., save to S3 then Redis, save to DB and RabbitMQ simultaneously).
- **Webhook Connect**: Cloud-to-local webhook relay system for receiving webhooks at a cloud endpoint and streaming them to local networks via WebSocket/SSE (similar to ngrok for webhooks).
- **Plugin Architecture**: Extensible module system. New output modules can be added without modifying core code.
- **Configuration-Driven**: Configuration via JSON files (`webhooks.json`, `connections.json`) located in `config/development/` (or root directory) and environment variables.
- **Live Config Reload**: Hot-reload webhook and connection configurations without restarting the application (via ConfigManager and ConfigFileWatcher).
- **Connection Pool Management**: Centralized connection pool registry with automatic pool lifecycle management and versioning.
- **Statistics**: Tracks webhook usage statistics (requests per minute, hour, day, etc.) via `/stats`.
- **ClickHouse Analytics**: Automatic logging of all webhook events to ClickHouse for analytics and monitoring.
- **Distributed Architecture**: Support for multiple webhook instances with centralized analytics processing.
- **Observability**: Structured logging with correlation IDs, in-memory metrics for chain execution, and task manager monitoring.

### Security Features
- **Authorization**: Authorization header validation (Bearer tokens).
- **Basic Authentication**: HTTP Basic Auth with credential validation.
- **JWT Authentication**: JWT token validation with issuer, audience, and expiration checks.
- **HMAC Verification**: Webhook signature validation using HMAC-SHA256/SHA1/SHA512.
- **IP Whitelisting**: Restrict webhooks to specific IP addresses.
- **Google reCAPTCHA**: Backend validation for Google reCAPTCHA v2 and v3 tokens with score threshold support.
- **Rate Limiting**: Per-webhook rate limiting with configurable time windows.
- **Multi-Layer Validation**: Combine multiple validators (Authorization + HMAC + IP whitelist + reCAPTCHA).
- **Payload Validation**: JSON payload validation with size, depth, and string length checks.
- **JSON Schema Validation**: Validate incoming payloads against JSON schemas.
- **Credential Cleanup**: Masks or removes credentials from payloads and headers before logging or storing (deferred to background tasks for optimal performance).
- **Task Manager**: Concurrent task management with semaphore-based limiting, timeout protection, and backpressure handling.

## Project Structure
- `src/main.py`: Entry point, FastAPI app, and route definitions.
- `src/webhook.py`: Core logic for handling and processing webhooks.
- `src/config.py`: Configuration loading and injection.
- `src/config_manager.py`: Live configuration management with hot-reload support.
- `src/config_watcher.py`: File system watcher for automatic config reload on file changes.
- `src/connection_pool_registry.py`: Centralized connection pool management with versioning and lifecycle control.
- `src/chain_processor.py`: Chain processor for executing multiple modules sequentially or in parallel.
- `src/chain_validator.py`: Chain configuration validation and security checks.
- `src/modules/`: Output modules (RabbitMQ, Redis, ClickHouse, etc.).
  - `base.py`: Abstract base class for all modules
  - `registry.py`: Module registry for plugin management
  - `log.py`, `save_to_disk.py`, `rabbitmq_module.py`, `redis_rq.py`, `clickhouse.py`, `mqtt.py`, `postgres.py`, `mysql.py`, `s3.py`, `kafka.py`, `websocket.py`, `activemq.py`, `aws_sqs.py`, `gcp_pubsub.py`, `zeromq.py`: Individual modules
- `src/utils.py`: Utility functions and in-memory statistics.
- `src/clickhouse_analytics.py`: ClickHouse analytics service for saving logs and statistics.
- `src/analytics_processor.py`: Separate analytics processor that reads from ClickHouse and calculates aggregated statistics.
- `src/openapi_generator.py`: Dynamic OpenAPI schema generation from webhook configurations.
- `src/rate_limiter.py`: Sliding window rate limiting implementation.
- `src/input_validator.py`: Input validation and sanitization utilities.
- `src/webhook_connect/`: Webhook Connect cloud-to-local relay system
  - `api.py`: WebSocket/SSE streaming endpoints
  - `channel_manager.py`: Channel management and message queuing
  - `models.py`: Data models for channels, connections, and messages
  - `admin_api.py`: Admin endpoints for channel management
- `src/connector/`: Local connector for receiving cloud webhooks
  - `main.py`: Main connector service
  - `stream_client.py`: WebSocket/SSE client implementations
  - `processor.py`: Message processing and forwarding
  - `config.py`: Connector configuration models
- `ARCHITECTURE.md`: Detailed architecture documentation
- `PERFORMANCE_TEST.md`: Performance testing documentation

**See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture documentation and how to add new modules.**

**See [DEVELOPMENT.md](docs/DEVELOPMENT.md) for development setup and workflow guide.**

## Quick Start

### Docker (Recommended)

The easiest way to get started:

```bash
# Pull the image
docker pull spiderhash/webhook:0.1.0

# Run with default configuration
docker run -p 8000:8000 spiderhash/webhook:0.1.0

# Or run with your own configuration
docker run -p 8000:8000 \
  -v $(pwd)/config:/app/config \
  spiderhash/webhook:0.1.0
```

**Docker Hub:** https://hub.docker.com/r/spiderhash/webhook

**Supported Architectures:** `linux/amd64`, `linux/arm64`

### Using Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  webhook:
    image: spiderhash/webhook:0.1.0
    ports:
      - "8000:8000"
    volumes:
      - ./config:/app/config
    environment:
      - WEBHOOKS_CONFIG_FILE=/app/config/webhooks.json
      - CONNECTIONS_CONFIG_FILE=/app/config/connections.json
    restart: unless-stopped
```

Then run:
```bash
docker-compose up -d
```

### Python Installation (For Development)

If you want to contribute or run from source, see [DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed setup instructions.

### Docker (Single Instance)

Use the optimized smaller image from Docker Hub to run a single FastAPI instance in Docker:

```bash
# Pull image from Docker Hub
docker pull spiderhash/webhook:latest

# Run container (mount configs from host)
# Config files are automatically found in config/development/ if they exist
docker run --rm \
  -p 8000:8000 \
  -v "$(pwd)/config/development:/app/config/development:ro" \
  --env-file .env \
  spiderhash/webhook:latest

# Or mount specific config files (if not using config/development/)
docker run --rm \
  -p 8000:8000 \
  -v "$(pwd)/config/development/webhooks.json:/app/config/development/webhooks.json:ro" \
  -v "$(pwd)/config/development/connections.json:/app/config/development/connections.json:ro" \
  --env-file .env \
  spiderhash/webhook:latest
```

**Using Docker Hub:**
```bash
# Pull from Docker Hub
docker pull spiderhash/webhook:latest

# Run container
# Config files are automatically found in config/development/ if they exist
docker run --rm \
  -p 8000:8000 \
  -v "$(pwd)/config/development:/app/config/development:ro" \
  spiderhash/webhook:latest
```

**Docker Compose Example:**
```yaml
services:
  webhook:
    image: spiderhash/webhook:latest
    container_name: webhook-service
    ports:
      - "8000:8000"
    volumes:
      # Mount config directory (application auto-detects config/development/)
      - ./config/development:/app/config/development:ro
      # Or use environment variables to specify custom paths
      # - WEBHOOKS_CONFIG_FILE=/app/config/development/webhooks.json
      # - CONNECTIONS_CONFIG_FILE=/app/config/development/connections.json
    environment:
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
```

Then open `http://localhost:8000/docs` for the interactive API docs (Swagger UI) or `http://localhost:8000/redoc` for ReDoc.

**Note:** OpenAPI documentation is automatically generated from `webhooks.json` configuration. See the [Dynamic OpenAPI Docs](#dynamic-openapi-documentation) section for details.

### Docker (Multi-Instance with Redis & ClickHouse)

For performance testing and a full deployment with multiple webhook instances:

```bash
# Start all services (5 webhook instances + ClickHouse + Redis + RabbitMQ + Analytics)
cd docker/compose
docker compose up -d

# Run performance tests
./scripts/run_performance_test.sh
# Or manually:
python3 tests/unit/performance_test_multi_instance.py
```

See `docs/PERFORMANCE_TEST.md` and `DEVELOPMENT.md` for detailed multi-instance and performance testing documentation.

### Live Configuration Reload

The application supports hot-reloading of configuration files without restart:

**Enable File Watching:**
```bash
export CONFIG_FILE_WATCHING_ENABLED=true
export CONFIG_RELOAD_DEBOUNCE_SECONDS=3.0
```

**Manual Reload via API:**
```bash
# Reload webhook configurations
curl -X POST http://localhost:8000/admin/reload-config \
  -H "Authorization: Bearer admin_token"

# Reload connection configurations
curl -X POST http://localhost:8000/admin/reload-connections \
  -H "Authorization: Bearer admin_token"
```

**Features:**
- Automatic file watching with debouncing (default: 3 seconds)
- Thread-safe configuration updates
- Connection pool lifecycle management
- Validation before applying changes
- Rollback on errors
- Zero-downtime updates

See `docs/LIVE_CONFIG_RELOAD_FEATURE.md` for detailed documentation.

## Configuration

### Configuration File Locations

Configuration files are automatically located in the following order:
1. **`config/development/webhooks.json`** and **`config/development/connections.json`** (default if they exist)
2. **`webhooks.json`** and **`connections.json`** in the root directory (fallback)

You can override these defaults using environment variables:
- `WEBHOOKS_CONFIG_FILE` - Path to webhooks configuration file
- `CONNECTIONS_CONFIG_FILE` - Path to connections configuration file

**Example:**
```bash
export WEBHOOKS_CONFIG_FILE=/app/config/production/webhooks.json
export CONNECTIONS_CONFIG_FILE=/app/config/production/connections.json
```

### Environment Variables

The configuration files (`webhooks.json` and `connections.json`) support environment variable substitution using the `{$VAR}` syntax. This allows you to keep sensitive data out of configuration files and use environment-specific values.

#### Supported Patterns

1. **Simple replacement**: `{$VAR}` - Replace entire value with environment variable
2. **With default**: `{$VAR:default}` - Use environment variable or default value if not set
3. **Embedded in strings**: Variables can be embedded within strings: `"http://{$HOST}:{$PORT}/api"`

#### Examples

**In `connections.json`:**
```json
{
    "redis_prod": {
        "type": "redis-rq",
        "host": "{$REDIS_HOST}",
        "port": "{$REDIS_PORT:6379}",
        "db": "{$REDIS_DB:0}"
    },
    "rabbitmq_prod": {
        "type": "rabbitmq",
        "host": "{$RABBITMQ_HOST}",
        "port": "{$RABBITMQ_PORT:5672}",
        "user": "{$RABBITMQ_USER}",
        "pass": "{$RABBITMQ_PASS}"
    }
}
```

**In `webhooks.json`:**
```json
{
    "secure_webhook": {
        "data_type": "json",
        "module": "http_webhook",
        "module-config": {
            "url": "http://{$API_HOST:localhost}:{$API_PORT:8080}/webhooks",
            "headers": {
                "Authorization": "Bearer {$API_TOKEN}"
            }
        },
        "authorization": "Bearer {$WEBHOOK_SECRET}",
        "jwt": {
            "secret": "{$JWT_SECRET}",
            "algorithm": "{$JWT_ALGORITHM:HS256}"
        }
    }
}
```

**Notes:**
- Environment variables are loaded from the system environment and `.env` files (via `python-dotenv`)
- Default values are used when environment variables are not set
- Empty string defaults are supported: `{$VAR:}` 
- Variables work in nested dictionaries and lists
- Missing variables without defaults will show a warning and use a placeholder value

### `webhooks.json`
Defines the webhooks to listen for.
```json
{
    "webhook_id": {
        "data_type": "json",
        "module": "log",
        "authorization": "secret_token"
    }
}
```

### `connections.json`
Defines connection details for modules (e.g., RabbitMQ, Redis).
```json
{
    "rabbitmq_conn": {
        "type": "rabbitmq",
        "host": "localhost",
        "port": 5672,
        "user": "guest",
        "pass": "guest"
    }
}
```

### Security Configuration

#### Basic Authentication
```json
{
    "basic_auth_webhook": {
        "data_type": "json",
        "module": "log",
        "basic_auth": {
            "username": "admin",
            "password": "secret_password_123"
        }
    }
}
```

#### JWT Authentication
```json
{
    "jwt_auth_webhook": {
        "data_type": "json",
        "module": "log",
        "jwt": {
            "secret": "my_jwt_secret_key",
            "algorithm": "HS256",
            "issuer": "my-app",
            "audience": "webhook-api",
            "verify_exp": true
        }
    }
}
```

#### CORS Support
The application includes CORS middleware enabled by default, allowing webhooks to be called from browser-based applications (e.g., frontend JavaScript).
- Allowed Origins: `*` (All)
- Allowed Methods: `*` (All)
- Allowed Headers: `*` (All)

#### Bearer Token Authorization
```json
{
    "secure_webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer my_secret_token"
    }
}
```

#### HMAC Signature Validation
```json
{
    "github_webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer token",
        "hmac": {
            "secret": "your_hmac_secret",
            "header": "X-Hub-Signature-256",
            "algorithm": "sha256"
        }
    }
}
```

#### IP Whitelisting
```json
{
    "secure_webhook": {
        "data_type": "json",
        "module": "save_to_disk",
        "module-config": {
            "path": "webhooks/secure"
        },
        "ip_whitelist": [
            "192.168.1.100",
            "10.0.0.50"
        ]
    }
}
```

#### Combined Security (Authorization + HMAC + IP Whitelist)
```json
{
    "fully_secured": {
        "data_type": "json",
        "module": "rabbitmq",
        "connection": "rabbitmq_local",
        "module-config": {
            "queue_name": "secure_queue"
        },
        "authorization": "Bearer super_secret",
        "hmac": {
            "secret": "hmac_secret_key",
            "header": "X-HMAC-Signature",
            "algorithm": "sha256"
        },
        "ip_whitelist": [
            "203.0.113.0"
        ]
    }
}
```

#### Rate Limiting
```json
{
    "rate_limited_webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer token",
        "rate_limit": {
            "max_requests": 100,
            "window_seconds": 60
        }
    }
}
```

#### Credential Cleanup
Automatically clean credentials from webhook payloads and headers before logging or storing to prevent credential exposure. This feature is enabled by default (opt-out) and supports both masking and removal modes.

```json
{
    "secure_webhook": {
        "data_type": "json",
        "module": "postgresql",
        "connection": "postgres_local",
        "module-config": {
            "table": "webhook_events"
        },
        "credential_cleanup": {
            "enabled": true,
            "mode": "mask",
            "fields": ["password", "api_key", "custom_secret"]
        }
    }
}
```

**Configuration Options:**
- `enabled`: Enable credential cleanup (default: `true` - opt-out behavior)
- `mode`: Cleanup mode - `"mask"` replaces with `***REDACTED***` or `"remove"` deletes the field (default: `"mask"`)
- `fields`: Optional list of additional custom field names to treat as credentials (default fields are always included)

**Default Credential Fields:**
The following field names are automatically detected as credentials (case-insensitive):
- `password`, `passwd`, `pwd`
- `secret`, `api_secret`, `client_secret`
- `token`, `api_key`, `apikey`, `access_token`, `refresh_token`
- `authorization`, `auth`, `credential`, `credentials`
- `private_key`, `privatekey`
- `bearer`, `x-api-key`, `x-auth-token`, `x-access-token`
- `session_id`, `sessionid`, `session_token`
- `csrf_token`, `csrf`
- `oauth_token`, `oauth_secret`, `consumer_secret`, `token_secret`

**Usage:**
- Credentials are automatically cleaned from payloads and headers before data is passed to modules
- Credentials are also cleaned from ClickHouse analytics logs (always enabled for logging)
- Original data is preserved for validation; only cleaned copies are stored/logged
- Supports nested JSON structures and arrays
- Pattern matching detects credential-like field names even if not in the default list

**Security Features:**
- Prevents credential exposure in logs, databases, and storage modules
- Deep cleaning of nested JSON structures
- Case-insensitive field name matching
- Pattern-based detection for credential-like fields
- Automatic cleanup in ClickHouse analytics (always enabled)

**Example:**
```json
// Input payload:
{
    "username": "user123",
    "password": "secret123",
    "api_key": "key456",
    "user": {
        "email": "user@example.com",
        "token": "token789"
    }
}

// Output (mask mode):
{
    "username": "user123",
    "password": "***REDACTED***",
    "api_key": "***REDACTED***",
    "user": {
        "email": "user@example.com",
        "token": "***REDACTED***"
    }
}

// Output (remove mode):
{
    "username": "user123",
    "user": {
        "email": "user@example.com"
    }
}
```

#### JSON Schema Validation
Validate incoming webhook payloads against a JSON schema to ensure data structure compliance:
```json
{
    "validated_webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer token",
        "json_schema": {
            "type": "object",
            "properties": {
                "event": {"type": "string"},
                "data": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"}
                    },
                    "required": ["id", "name"]
                }
            },
            "required": ["event", "data"]
        }
    }
}
```

#### Dynamic OpenAPI Documentation
Automatically generate OpenAPI 3.0 documentation from `webhooks.json` configuration. The documentation includes detailed information about each webhook endpoint, authentication requirements, payload schemas, rate limits, and security features.

**Access Documentation:**
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- OpenAPI JSON: `http://localhost:8000/openapi.json`

**Features:**
- Automatically generates API documentation for all configured webhooks
- Includes authentication schemes (Bearer, Basic, OAuth2, HMAC, etc.)
- Extracts request body schemas from `json_schema` if available
- Documents security features (rate limits, IP whitelist, HMAC, reCAPTCHA, etc.)
- Includes standard error responses (400, 401, 403, 413, 415, 500)
- Updates automatically when `webhooks.json` changes (on server restart)

**Disable OpenAPI Docs:**
Set the `DISABLE_OPENAPI_DOCS` environment variable to `true`:
```bash
export DISABLE_OPENAPI_DOCS=true
# or in docker-compose.yaml:
environment:
  - DISABLE_OPENAPI_DOCS=true
```

When disabled, the `/docs`, `/redoc`, and `/openapi.json` endpoints are not available.

**Example Generated Documentation:**
The OpenAPI schema automatically includes:
- Path parameters (webhook_id)
- Request body schemas (from json_schema or generic schema)
- Security requirements (authentication methods)
- Response schemas (success and error responses)
- Security features descriptions (rate limits, IP whitelist, etc.)

**Configuration:**
No additional configuration needed. The OpenAPI documentation is generated automatically from your `webhooks.json` file. Each webhook configuration is analyzed to extract:
- Authentication methods
- Request body schemas (if `json_schema` is provided)
- Security features (rate limits, IP whitelist, HMAC, reCAPTCHA, credential cleanup)
- Data type (JSON or blob)

#### Header-based Authentication
Authenticate webhooks using API keys passed in custom headers (e.g., `X-API-Key`, `X-Auth-Token`).

```json
{
    "header_auth_webhook": {
        "data_type": "json",
        "module": "log",
        "header_auth": {
            "header_name": "X-API-Key",
            "api_key": "{$HEADER_AUTH_KEY:secret_api_key_123}",
            "case_sensitive": false
        }
    }
}
```

**Configuration Options:**
- `header_name`: Header name to look for (default: `"X-API-Key"`)
- `api_key`: Expected API key value (required)
- `case_sensitive`: Whether key comparison is case-sensitive (default: `false`)

**Usage:**
- Send requests with API key in custom header: `X-API-Key: secret_api_key_123`
- Header name lookup is case-insensitive (e.g., `x-api-key`, `X-API-Key`, `X-Api-Key` all work)
- Supports common header names: `X-API-Key`, `X-Auth-Token`, `X-Access-Token`, `API-Key`, etc.
- Uses constant-time comparison to resist timing attacks

**Security Features:**
- Constant-time key comparison (timing attack resistant)
- Case-insensitive header name lookup
- Case-insensitive key comparison by default (configurable)
- Validates empty keys and missing headers
- Handles special characters, Unicode, and injection attempts

#### HTTP Digest Authentication
Authenticate webhooks using HTTP Digest Authentication (RFC 7616), a challenge-response authentication method that doesn't transmit passwords in plain text.

```json
{
    "digest_auth_webhook": {
        "data_type": "json",
        "module": "log",
        "digest_auth": {
            "username": "{$DIGEST_USERNAME:webhook_user}",
            "password": "{$DIGEST_PASSWORD}",
            "realm": "{$DIGEST_REALM:Webhook API}",
            "algorithm": "MD5",
            "qop": "auth"
        }
    }
}
```

**Configuration Options:**
- `username`: Expected username
- `password`: Expected password
- `realm`: Authentication realm (default: `"Webhook API"`)
- `algorithm`: Hash algorithm (default: `"MD5"`)
- `qop`: Quality of protection (default: `"auth"`, can be empty for no qop)

**Usage:**
- Send requests with Digest Authorization header: `Authorization: Digest username="...", realm="...", nonce="...", uri="...", response="...", ...`
- Supports MD5 algorithm
- Supports qop="auth" and no-qop modes
- Validates username, realm, and response hash
- Constant-time comparison for security

**Security Features:**
- No password transmission (uses MD5 hash)
- Nonce-based challenge-response
- Constant-time response comparison (timing attack resistant)
- Realm validation
- URI and method validation

#### OAuth 1.0 Authentication
Authenticate webhooks using OAuth 1.0 signatures (RFC 5849), commonly used by legacy APIs like Twitter.

```json
{
    "oauth1_webhook": {
        "data_type": "json",
        "module": "log",
        "oauth1": {
            "consumer_key": "{$OAUTH1_CONSUMER_KEY}",
            "consumer_secret": "{$OAUTH1_CONSUMER_SECRET}",
            "token_secret": "{$OAUTH1_TOKEN_SECRET:}",
            "signature_method": "HMAC-SHA1",
            "verify_timestamp": true,
            "timestamp_window": 300
        }
    }
}
```

**Configuration Options:**
- `consumer_key`: OAuth 1.0 consumer key
- `consumer_secret`: OAuth 1.0 consumer secret
- `token_secret`: Optional token secret (for three-legged OAuth)
- `signature_method`: Signature method - `HMAC-SHA1` (default) or `PLAINTEXT`
- `verify_timestamp`: Whether to validate timestamp (default: `true`)
- `timestamp_window`: Maximum allowed timestamp difference in seconds (default: `300`)

**Usage:**
- Send requests with OAuth Authorization header: `Authorization: OAuth oauth_consumer_key="...", oauth_signature="...", ...`
- Supports HMAC-SHA1 and PLAINTEXT signature methods
- Validates signature, consumer key, and timestamp
- Constant-time signature comparison (timing attack resistant)

**Security Features:**
- Signature validation using HMAC-SHA1 or PLAINTEXT
- Timestamp validation (prevents replay attacks)
- Consumer key validation
- Constant-time signature comparison
- Nonce support (can be extended for nonce tracking)

#### OAuth 2.0 Authentication
Authenticate webhooks using OAuth 2.0 access tokens with token introspection or JWT validation.

**Token Introspection (Recommended):**
```json
{
    "oauth2_webhook": {
        "data_type": "json",
        "module": "log",
        "oauth2": {
            "token_type": "Bearer",
            "introspection_endpoint": "{$OAUTH2_INTROSPECTION_URL:https://auth.example.com/introspect}",
            "client_id": "{$OAUTH2_CLIENT_ID}",
            "client_secret": "{$OAUTH2_CLIENT_SECRET}",
            "required_scope": ["webhook:write", "webhook:read"],
            "validate_token": true
        }
    }
}
```

**JWT Token Validation:**
```json
{
    "oauth2_jwt_webhook": {
        "data_type": "json",
        "module": "log",
        "oauth2": {
            "token_type": "Bearer",
            "jwt_secret": "{$OAUTH2_JWT_SECRET}",
            "jwt_algorithms": ["HS256", "RS256"],
            "audience": "webhook-api",
            "issuer": "https://auth.example.com",
            "required_scope": ["read", "write"],
            "verify_exp": true
        }
    }
}
```

**Configuration Options:**
- `token_type`: Token type in Authorization header (default: `"Bearer"`)
- `introspection_endpoint`: OAuth 2.0 token introspection endpoint URL
- `client_id` / `client_secret`: Client credentials for introspection endpoint
- `jwt_secret`: Secret key for JWT validation (alternative to introspection)
- `jwt_algorithms`: Allowed JWT algorithms (default: `["HS256", "RS256"]`)
- `audience`: Required token audience (for JWT)
- `issuer`: Required token issuer (for JWT)
- `required_scope`: List of required OAuth scopes
- `validate_token`: Whether to validate token (default: `true`)

**Usage:**
- Send requests with Bearer token: `Authorization: Bearer <access_token>`
- Supports token introspection endpoint (RFC 7662)
- Supports JWT access tokens with signature validation
- Validates token scope, audience, and issuer
- Handles expired tokens and invalid signatures

**Security Features:**
- Token introspection with active/inactive status
- JWT signature validation
- Scope validation
- Audience and issuer validation
- Expiration checking
- Network error handling

#### Query Parameter Authentication
Authenticate webhooks using API keys passed as query parameters (e.g., `?api_key=xxx`).

```json
{
    "query_auth_webhook": {
        "data_type": "json",
        "module": "log",
        "query_auth": {
            "parameter_name": "api_key",
            "api_key": "{$QUERY_AUTH_KEY:secret_api_key_123}",
            "case_sensitive": false
        }
    }
}
```

**Configuration Options:**
- `parameter_name`: Query parameter name (default: `"api_key"`)
- `api_key`: Expected API key value (required)
- `case_sensitive`: Whether key comparison is case-sensitive (default: `false`)

**Usage:**
- Send requests with API key in query string: `POST /webhook/query_auth_webhook?api_key=secret_api_key_123`
- Supports common parameter names: `api_key`, `token`, `key`, `apikey`, `access_token`, `auth_token`
- Uses constant-time comparison to resist timing attacks

**Security Features:**
- Constant-time key comparison (timing attack resistant)
- Case-insensitive by default (configurable)
- Validates empty keys and missing parameters
- Handles special characters and Unicode

#### Google reCAPTCHA Validation
Validate webhook requests using Google reCAPTCHA v2 or v3 to prevent bot submissions.

**reCAPTCHA v3 (Recommended):**
```json
{
    "recaptcha_v3_webhook": {
        "data_type": "json",
        "module": "log",
        "recaptcha": {
            "secret_key": "your_recaptcha_v3_secret_key",
            "version": "v3",
            "token_source": "header",
            "token_field": "X-Recaptcha-Token",
            "min_score": 0.5
        }
    }
}
```

**reCAPTCHA v2:**
```json
{
    "recaptcha_v2_webhook": {
        "data_type": "json",
        "module": "log",
        "recaptcha": {
            "secret_key": "your_recaptcha_v2_secret_key",
            "version": "v2",
            "token_source": "body",
            "token_field": "g-recaptcha-response"
        }
    }
}
```

**Configuration Options:**
- `secret_key` (required): Your reCAPTCHA secret key from Google
- `version`: `"v2"` or `"v3"` (default: `"v3"`)
- `token_source`: `"header"` or `"body"` (default: `"header"`)
- `token_field`: Field name to look for token (default: `"X-Recaptcha-Token"`)
- `min_score`: Minimum score for v3 validation (default: `0.5`, range: 0.0-1.0)

**Usage:**
- For header-based tokens: Send token in `X-Recaptcha-Token` header
- For body-based tokens: Include token in JSON body as `recaptcha_token`, `recaptcha`, or `g-recaptcha-response`

**Combined with other validators:**
```json
{
    "secure_webhook_with_recaptcha": {
        "data_type": "json",
        "module": "save_to_disk",
        "module-config": {
            "path": "webhooks/secure"
        },
        "authorization": "Bearer token_123",
        "recaptcha": {
            "secret_key": "your_recaptcha_secret_key",
            "version": "v3",
            "token_source": "header",
            "min_score": 0.7
        }
    }
}
```


#### Kafka Integration
```json
{
    "kafka_events": {
        "data_type": "json",
        "module": "kafka",
        "connection": "kafka_local",
        "module-config": {
            "topic": "webhook_events",
            "key": "event_key",
            "forward_headers": true
        },
        "authorization": "Bearer kafka_secret"
    }
}
```

#### S3 Storage
```json
{
    "s3_archival": {
        "data_type": "json",
        "module": "s3",
        "connection": "s3_storage",
        "module-config": {
            "bucket": "my-webhook-bucket",
            "prefix": "webhooks/archive",
            "filename_pattern": "webhook_{timestamp}_{uuid}.json",
            "include_headers": true
        },
        "authorization": "Bearer s3_secret"
    }
}
```

#### MQTT Publishing
```json
{
    "mqtt_events": {
        "data_type": "json",
        "module": "mqtt",
        "connection": "mqtt_local",
        "module-config": {
            "topic": "webhook/events",
            "qos": 1,
            "retained": false,
            "format": "json",
            "topic_prefix": "webhook"
        },
        "authorization": "Bearer mqtt_secret"
    }
}
```

**MQTT Module Features:**
- Support for MQTT 3.1.1 and 5.0 protocols
- TLS/SSL encryption (MQTTS) support
- QoS levels: 0, 1, 2
- Retained messages
- Topic prefix configuration
- **Shelly Device Compatibility**: Gen1 (multi-topic) and Gen2/Gen3 (JSON format) support
- **Sonoff/Tasmota Compatibility**: Command (cmnd), status (stat), and telemetry (tele) topic formats

**Shelly Gen2 Format Example:**
```json
{
    "shelly_webhook": {
        "data_type": "json",
        "module": "mqtt",
        "connection": "mqtt_shelly",
        "module-config": {
            "topic": "shellies/device123/status",
            "shelly_gen2_format": true,
            "device_id": "device123",
            "qos": 1
        }
    }
}
```

**Sonoff/Tasmota Format Example:**
```json
{
    "tasmota_webhook": {
        "data_type": "json",
        "module": "mqtt",
        "connection": "mqtt_sonoff",
        "module-config": {
            "topic": "cmnd/device_name/POWER",
            "tasmota_format": true,
            "tasmota_type": "cmnd",
            "device_name": "device_name",
            "command": "POWER",
            "qos": 1
        }
    }
}
```

#### WebSocket Real-time Forwarding
```json
{
    "websocket_realtime": {
        "data_type": "json",
        "module": "websocket",
        "module-config": {
            "url": "ws://localhost:8080/webhooks",
            "format": "json",
            "include_headers": true,
            "wait_for_response": false,
            "timeout": 10,
            "max_retries": 3
        },
        "authorization": "Bearer ws_secret"
    }
}
```

#### ClickHouse Analytics & Logging
Save webhook logs and statistics to ClickHouse database for analytics and monitoring.

```json
{
    "clickhouse_webhook": {
        "data_type": "json",
        "module": "clickhouse",
        "connection": "clickhouse_local",
        "module-config": {
            "table": "webhook_logs",
            "include_headers": true,
            "include_timestamp": true
        },
        "authorization": "Bearer clickhouse_secret"
    }
}
```

#### PostgreSQL Database Storage
Store webhook payloads in PostgreSQL with JSONB, relational, or hybrid storage modes.

```json
{
    "postgres_webhook": {
        "data_type": "json",
        "module": "postgresql",
        "connection": "postgres_local",
        "module-config": {
            "table": "webhook_events",
            "storage_mode": "json",
            "upsert": true,
            "upsert_key": "event_id",
            "include_headers": true
        },
        "authorization": "Bearer db_secret"
    }
}
```

**Storage Modes:**
- `json`: Store entire payload in JSONB column (default)
- `relational`: Map payload fields to table columns with schema validation
- `hybrid`: Store mapped fields in columns + full payload in JSONB

#### MySQL/MariaDB Database Storage
Store webhook payloads in MySQL/MariaDB with JSON, relational, or hybrid storage modes.

```json
{
    "mysql_webhook": {
        "data_type": "json",
        "module": "mysql",
        "connection": "mysql_local",
        "module-config": {
            "table": "webhook_events",
            "storage_mode": "json",
            "upsert": true,
            "upsert_key": "event_id",
            "include_headers": true
        },
        "authorization": "Bearer db_secret"
    }
}
```

**Storage Modes:**
- `json`: Store entire payload in JSON column (default)
- `relational`: Map payload fields to table columns with schema validation
- `hybrid`: Store mapped fields in columns + full payload in JSON

#### Redis RQ (Task Queue)
```json
{
    "redis_rq_webhook": {
        "data_type": "json",
        "module": "redis_rq",
        "connection": "redis_local",
        "module-config": {
            "queue_name": "webhook_tasks",
            "function": "process_webhook"
        },
        "authorization": "Bearer redis_secret"
    }
}
```

#### Redis Publish (Pub/Sub)
```json
{
    "redis_publish_webhook": {
        "data_type": "json",
        "module": "redis_publish",
        "redis": {
            "host": "redis",
            "port": 6379,
            "channel": "webhook_events"
        },
        "authorization": "Bearer redis_secret"
    }
}
```

**Note**: `redis_publish` module uses a legacy configuration format with top-level `redis` object instead of `connection` + `module-config`. This is for backward compatibility.

#### ActiveMQ
```json
{
    "activemq_webhook": {
        "data_type": "json",
        "module": "activemq",
        "connection": "activemq_local",
        "module-config": {
            "destination": "webhook.events",
            "destination_type": "queue"
        },
        "authorization": "Bearer activemq_secret"
    }
}
```

**Destination Types:**
- `queue`: Publish to ActiveMQ queue
- `topic`: Publish to ActiveMQ topic

#### AWS SQS
```json
{
    "aws_sqs_webhook": {
        "data_type": "json",
        "module": "aws_sqs",
        "connection": "aws_sqs_local",
        "module-config": {
            "queue_name": "webhook-queue"
        },
        "authorization": "Bearer aws_secret"
    }
}
```

**Note**: Queue is automatically created if it doesn't exist (useful for LocalStack development).

#### GCP Pub/Sub
```json
{
    "gcp_pubsub_webhook": {
        "data_type": "json",
        "module": "gcp_pubsub",
        "connection": "gcp_pubsub_local",
        "module-config": {
            "topic": "webhook-events"
        },
        "authorization": "Bearer gcp_secret"
    }
}
```

**Note**: Topic is automatically created if it doesn't exist (useful for Pub/Sub Emulator development).

#### Webhook Connect (Cloud-to-Local Relay)
**NEW FEATURE** - Receive webhooks at a cloud endpoint and stream them to local networks behind firewalls or NAT (similar to ngrok for webhooks).

**Architecture:**
- **Cloud Receiver**: Runs in the cloud with public IP, receives webhooks via HTTP
- **Local Connector**: Runs on local network, connects to cloud via WebSocket/SSE
- **Channel-based**: Multiple channels with unique channel IDs and secrets for isolation
- **Reliable Delivery**: Message queuing, acknowledgments, retries, and dead-letter handling

**Use Cases:**
- Receive webhooks from external services (GitHub, Stripe, etc.) without exposing local services
- Development and testing webhooks on local machines
- Enterprise environments with strict firewall rules
- Multi-site deployments with centralized webhook receiver

**Configuration:**

1. **Cloud Side** - Enable Webhook Connect in cloud deployment:
```bash
export WEBHOOK_CONNECT_ENABLED=true
export WEBHOOK_CONNECT_ADMIN_TOKEN=your_admin_secret
```

2. **Local Side** - Run connector with configuration:
```json
{
    "channel_id": "my-channel-123",
    "channel_secret": "secret_key_456",
    "cloud_url": "https://webhook-cloud.example.com",
    "protocol": "websocket",
    "targets": [
        {
            "name": "local_api",
            "url": "http://localhost:8080/webhooks",
            "enabled": true
        }
    ],
    "retry": {
        "enabled": true,
        "max_attempts": 3,
        "backoff": "exponential"
    }
}
```

```bash
# Run local connector
python -m src.connector.main --config connector.json
```

**Features:**
- WebSocket and SSE (Server-Sent Events) protocols
- HMAC signature authentication
- Message acknowledgments and retries
- Dead-letter queue for failed messages
- Multi-target support (forward to multiple local endpoints)
- Channel-based isolation and security
- Admin API for channel management

**Cloud Endpoints:**
- `/webhook-connect/ws/{channel_id}` - WebSocket streaming
- `/webhook-connect/sse/{channel_id}` - SSE streaming
- `/webhook-connect/channels` - Channel management (admin)

**See `src/webhook_connect/` and `src/connector/` for implementation details.**

---

#### Webhook Chaining (Multiple Destinations)
Send webhook payloads to multiple destinations in sequence or parallel. This feature allows you to create complex workflows where a single webhook triggers multiple actions.

**Recent Improvements:**
- ✅ Parallel execution timeout protection (configurable, default 30s)
- ✅ Automatic task cancellation on partial failure when `continue_on_error=false`
- ✅ Background credential cleanup for improved performance
- ✅ Structured logging with correlation IDs
- ✅ In-memory metrics tracking (chain execution success/failure/partial rates)
- ✅ Optimized module config pre-building (reduced memory pressure)

**Simple Array Format (requires connections in `connections.json`):**
```json
{
    "chained_webhook": {
        "data_type": "json",
        "chain": ["s3", "redis_rq"],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": true
        },
        "authorization": "Bearer token"
    }
}
```

**Note**: The simple array format requires connections to be defined in `connections.json` with names matching the module names (e.g., `"s3"` and `"redis_rq"`). For clarity and explicit configuration, use the detailed format below.

**Detailed Format with Per-Module Config:**
```json
{
    "chained_webhook": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_storage",
                "module-config": {
                    "bucket": "webhook-archive",
                    "prefix": "events"
                },
                "retry": {
                    "enabled": true,
                    "max_attempts": 3
                }
            },
            {
                "module": "redis_rq",
                "connection": "redis_local",
                "module-config": {
                    "queue_name": "process_events",
                    "function": "process_webhook"
                }
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": true
        },
        "authorization": "Bearer secret"
    }
}
```

**Configuration Options:**
- `chain`: Array of module names (strings) or detailed module configurations (objects)
- `chain-config.execution`: `"sequential"` (one after another) or `"parallel"` (all at once)
- `chain-config.continue_on_error`: `true` to continue chain execution even if a module fails, `false` to stop on first error (with automatic task cancellation for parallel mode)
- `chain-config.timeout`: Maximum timeout in seconds for parallel execution (default: 30s, configurable)
- `retry`: Per-module retry configuration (optional)

**Performance & Reliability:**
- Credential cleanup runs in background tasks (no latency impact on HTTP response)
- Parallel tasks have configurable timeouts to prevent indefinite hangs
- Failed tasks are automatically cancelled in parallel mode when `continue_on_error=false`
- Structured logging with webhook_id, module names, and error details for debugging
- In-memory metrics track execution success, failures, and partial successes
- Module configurations are pre-built once at initialization (reduced memory allocations)

**Execution Modes:**
- **Sequential**: Modules execute one after another in order. Useful when one module depends on another (e.g., save to DB then publish to Kafka).
- **Parallel**: All modules execute simultaneously. Useful for independent operations (e.g., save to DB and send to RabbitMQ at the same time).

**Examples:**

**Example 1: Save to S3 then Redis (Sequential)**
```json
{
    "s3_then_redis": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_storage",
                "module-config": {
                    "bucket": "webhook-archive",
                    "prefix": "events"
                }
            },
            {
                "module": "redis_rq",
                "connection": "redis_local",
                "module-config": {
                    "queue_name": "process_events",
                    "function": "process_webhook"
                }
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": true
        },
        "authorization": "Bearer secret"
    }
}
```

**Example 2: Save to DB and RabbitMQ (Parallel)**
```json
{
    "db_and_rmq": {
        "data_type": "json",
        "chain": [
            {
                "module": "postgresql",
                "connection": "postgres_local",
                "module-config": {
                    "table": "webhook_events"
                }
            },
            {
                "module": "rabbitmq",
                "connection": "rabbitmq_local",
                "module-config": {
                    "queue_name": "event_queue"
                }
            }
        ],
        "chain-config": {
            "execution": "parallel",
            "continue_on_error": true
        },
        "authorization": "Bearer secret"
    }
}
```

**Backward Compatibility:**
- Existing single-module configurations (using `module` field) continue to work unchanged
- If both `module` and `chain` are present, `chain` takes precedence
- No breaking changes to existing webhook configurations

**Security Features:**
- Maximum chain length limit (20 modules) to prevent DoS attacks
- Module name validation to prevent injection attacks
- Type validation for all configuration fields
- Resource management with concurrency limits (TaskManager with semaphore-based backpressure)
- Error sanitization to prevent information disclosure
- Task timeout protection to prevent resource exhaustion
- Fail-fast on circular references in configuration (no unsafe shallow copy fallback)

**Observability:**
- Structured logging with `logger.info()`, `logger.warning()`, `logger.error()`
- Log correlation via webhook_id in all log entries
- In-memory metrics dictionary:
  - `chain_execution_total`: Total chain executions
  - `chain_execution_failed_total`: Fully failed chains
  - `chain_execution_partial_success_total`: Partially successful chains
  - `chain_tasks_dropped_total`: Chains dropped due to task manager overflow
  - `module_execution_dropped_total`: Individual modules dropped due to task manager overflow
- Individual module failure logging with error details

See `docs/WEBHOOK_CHAINING_FEATURE.md` for detailed documentation.

## TODO List

### Core Features
- [x] Plugin Architecture (BaseModule and ModuleRegistry)
- [x] Rate Limiting per webhook ID
- [x] Retry Mechanism for failed module executions
- [x] Persistent Statistics (Redis-based)
- [x] ClickHouse Analytics integration
- [x] JSON Schema Validation
- [x] Payload size, depth, and string length validation
- [x] Dynamic OpenAPI Docs (generate from webhooks.json)
- [x] Webhook chaining (multiple destinations per webhook)

### Authentication Methods (11/11 Complete ✅)
- [x] Basic Authentication
- [x] Bearer Token Authorization
- [x] JWT Authentication
- [x] HMAC Signature Validation
- [x] IP Whitelisting
- [x] Header-based Authentication (X-API-Key, etc.)
- [x] Query Parameter Authentication
- [x] HTTP Digest Authentication
- [x] OAuth 1.0 Authentication
- [x] OAuth 2.0 Authentication (Token Introspection & JWT)
- [x] Google reCAPTCHA Validation (v2 & v3)

### Output Modules (17/17 Complete ✅)
- [x] Log Module (stdout)
- [x] Save to Disk Module
- [x] RabbitMQ Module
- [x] Redis RQ Module
- [x] Redis Publish Module
- [x] HTTP Webhook Module
- [x] Kafka Module
- [x] MQTT Module
- [x] WebSocket Module
- [x] ClickHouse Module
- [x] PostgreSQL Module
- [x] MySQL/MariaDB Module
- [x] ActiveMQ Module
- [x] S3 Module
- [x] AWS SQS Module
- [x] GCP Pub/Sub Module
- [x] ZeroMQ Module

### Configuration Management
- [x] Live Config Reload (ConfigManager)
- [x] File System Watcher (ConfigFileWatcher)
- [x] Connection Pool Registry
- [x] Environment Variable Substitution
- [x] Configuration Validation

### Cloud-to-Local Relay
- [x] Webhook Connect (Cloud Receiver)
- [x] Local Connector (WebSocket/SSE clients)
- [x] Channel Management
- [x] Message Queue with Acknowledgments
- [x] Dead-Letter Queue Support
- [x] Multi-Target Forwarding

### Performance & Reliability (Recent Improvements)
- [x] Parallel execution timeout protection (chain processor)
- [x] Task cancellation on partial failure
- [x] Background credential cleanup (deferred from request path)
- [x] Structured logging with correlation IDs
- [x] In-memory metrics tracking
- [x] Module config pre-building optimization
- [x] TaskManager with semaphore-based backpressure
- [x] Fail-fast on circular references

### Future Enhancements
- [ ] Prometheus/Grafana metrics integration (replace in-memory metrics)
- [ ] Distributed tracing with OpenTelemetry
- [ ] Payload Transformation (pre-processing step)
- [ ] Cloudflare Turnstile Validation
- [ ] Batch insert support for database modules
- [ ] Circuit breakers for consistently failing modules
- [ ] Performance test documentation expansion

## Test Status

**Current Test Coverage: 2,493 tests passing** ✅ (109 longrunning tests deselected by default)

Test suites include:
- Authentication tests (all 11 methods)
- Validation tests (HMAC, IP Whitelist, reCAPTCHA, JSON Schema)
- Security audit tests (SQL injection, SSRF, XSS, injection attacks)
- Module tests (all 17 output modules)
- Database module tests (PostgreSQL, MySQL)
- Webhook flow tests
- Webhook chaining tests (sequential and parallel execution, timeout, cancellation)
- Webhook Connect tests (channel management, streaming, connector)
- Rate limiting tests
- Redis statistics tests
- Input validation tests
- CORS tests
- Integration tests
- Config manager and watcher tests
- Connection pool registry tests
- Analytics processor tests
- Chain processor and validator tests
- Credential cleanup tests
- Task manager tests

**Test Coverage:** 90%+ code coverage

Run tests with:
```bash
make test-all    # Run all tests (excludes longrunning)
pytest -v        # Run all tests with verbose output
pytest -m "not longrunning"  # Exclude long-running tests
```

**CI/CD:**
- GitLab CI runs unit tests on every push
- Docker images are automatically built and pushed to GitLab Container Registry
- Tests run with coverage reporting
