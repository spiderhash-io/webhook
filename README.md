# Core Webhook Module

A flexible and configurable webhook receiver and processor built with FastAPI. It receives webhooks, validates them, and forwards the payloads to various destinations such as RabbitMQ, Redis, disk, or stdout.

**Status**: Production-ready with comprehensive security features, 274 passing tests, and support for multiple output destinations. All 11 authentication methods implemented!

## Features

### Core Functionality
- **Flexible Destinations**: Send webhook data to RabbitMQ, Redis (RQ), local disk, HTTP endpoints, ClickHouse, or stdout.
- **Plugin Architecture**: Easy to extend with new modules without modifying core code.
- **Configuration-Driven**: Easy configuration via JSON files (`webhooks.json`, `connections.json`) and environment variables.
- **Statistics**: Tracks webhook usage statistics (requests per minute, hour, day, etc.) via `/stats`.
- **ClickHouse Analytics**: Automatic logging of all webhook events to ClickHouse for analytics and monitoring.
- **Distributed Architecture**: Support for multiple webhook instances with centralized analytics processing.

### Security Features
- **Authorization**: Supports Authorization header validation (including Bearer tokens).
- **Basic Authentication**: HTTP Basic Auth support with secure credential validation.
- **JWT Authentication**: Full JWT token validation with issuer, audience, and expiration checks.
- **HMAC Verification**: Validates webhook signatures using HMAC-SHA256/SHA1/SHA512.
- **IP Whitelisting**: Restrict webhooks to specific IP addresses.
- **Google reCAPTCHA**: Backend validation for Google reCAPTCHA v2 and v3 tokens with score threshold support.
- **Rate Limiting**: Per-webhook rate limiting with configurable windows.
- **Multi-Layer Validation**: Combine multiple validators (Authorization + HMAC + IP whitelist + reCAPTCHA).
- **Payload Validation**: Validates JSON payloads with size, depth, and string length checks.
- **JSON Schema Validation**: Validate incoming payloads against defined JSON schemas.

## Project Structure

- `src/main.py`: Entry point, FastAPI app, and route definitions.
- `src/webhook.py`: Core logic for handling and processing webhooks.
- `src/config.py`: Configuration loading and injection.
- `src/modules/`: Output modules (RabbitMQ, Redis, ClickHouse, etc.).
  - `base.py`: Abstract base class for all modules
  - `registry.py`: Module registry for plugin management
  - `log.py`, `save_to_disk.py`, `rabbitmq_module.py`, `redis_rq.py`, `clickhouse.py`: Individual modules
- `src/utils.py`: Utility functions and in-memory statistics.
- `src/clickhouse_analytics.py`: ClickHouse analytics service for saving logs and statistics.
- `src/analytics_processor.py`: Separate analytics processor that reads from ClickHouse and calculates aggregated statistics.
- `ARCHITECTURE.md`: Detailed architecture documentation
- `PERFORMANCE_TEST.md`: Performance testing documentation

**See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed architecture documentation and how to add new modules.**

**See [DEVELOPMENT.md](DEVELOPMENT.md) for development setup and workflow guide.**

## Installation & Running

### Local Development (venv)

1. Create a virtual environment (recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install development dependencies (includes production deps + testing tools):
   ```bash
   pip install -r requirements-dev.txt
   ```

3. Run the server:
   ```bash
   uvicorn src.main:app --reload
   ```

4. Run the tests:

```bash
make test        # or: pytest -v
```

See `DEVELOPMENT.md` for a more detailed development workflow.

### Production Installation

For production deployments, install only production dependencies:
```bash
pip install -r requirements.txt
```

### Development Tools

The development requirements include:
- **pytest** - Testing framework
- **pytest-asyncio** - Async test support
- **fakeredis** - Redis mock for testing
- **black** - Code formatter (optional)
- **flake8** - Linter (optional)
- **mypy** - Type checker (optional)
- **pytest-cov** - Coverage reporting (optional)

To run tests:
```bash
pytest
```

To format code (if black is installed):
```bash
black src/
```

### Docker (Single Instance)

Use the optimized small image to run a single FastAPI instance in Docker:

```bash
# Build image
docker build -f Dockerfile.small -t core-webhook-module:small .

# Run container (mount configs from host)
docker run --rm \
  -p 8000:8000 \
  -v "$(pwd)/webhooks.json:/app/webhooks.json:ro" \
  -v "$(pwd)/connections.json:/app/connections.json:ro" \
  --env-file .env \
  core-webhook-module:small
```

Then open `http://localhost:8000/docs` for the interactive API docs.

### Docker (Multi-Instance with Redis & ClickHouse)

For performance testing and a full deployment with multiple webhook instances:

```bash
# Start all services (5 webhook instances + ClickHouse + Redis + RabbitMQ + Analytics)
docker-compose up -d

# Run performance tests
./src/tests/run_performance_test.sh
# Or manually:
python3 src/tests/performance_test_multi_instance.py
```

See `docs/PERFORMANCE_TEST.md` and `DEVELOPMENT.md` for detailed multi-instance and performance testing documentation.

## Configuration

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
        "queue_name": "secure_queue",
        "connection": "rabbitmq_local",
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
        "topic": "webhook_events",
        "connection": "kafka_local",
        "module-config": {
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

**Webhook Logs Module:**
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

**Automatic Statistics Saving:**
To enable automatic statistics saving to ClickHouse, add a `clickhouse_analytics` connection in `connections.json`:
```json
{
    "clickhouse_analytics": {
        "type": "clickhouse",
        "host": "localhost",
        "port": 9000,
        "database": "webhook_analytics",
        "user": "default",
        "password": ""
    }
}
```

The system will automatically:
- Create `webhook_stats` table for statistics
- Create `webhook_logs` table for general logging
- Save statistics every 5 minutes
- Store metrics: total, minute, 5_minutes, 15_minutes, 30_minutes, hour, day, week, month

**Architecture Note:**
- **Webhook Instances**: Only send raw webhook events to ClickHouse (no aggregation)
- **Analytics Service**: Separate service (`src/analytics_processor.py`) reads from ClickHouse and calculates aggregated statistics
- **Multiple Instances**: All webhook instances write to the same ClickHouse database, allowing centralized analytics

## TODO List

This list is ordered from easiest/highest impact to more complex features.

### 1. Immediate Fixes & Quick Wins ✅ **COMPLETE (5/5)**
- [x] **Connect `save_to_disk` module**: The logic exists in `src/utils.py` but is not connected in `src/webhook.py`.
- [x] **Connect `redis_rq` module**: The module exists in `src/modules/pythonrq.py` but is not connected in `src/webhook.py`.
- [x] **Refactor to Plugin Architecture**: Implemented a modular, extensible architecture using BaseModule and ModuleRegistry.
- [x] **Enable HMAC Verification**: Implemented validator system with HMAC, Authorization, and IP whitelist support.
- [x] **Populate `connections.json`**: Added example configurations for RabbitMQ and Redis.

### 2. Core Feature Implementation ✅ **COMPLETE (4/4)**
- [x] **Implement Kafka Module**: `src/modules/kafka.py` exists but needs implementation.
- [x] **Rate Limiting**: Implement rate limiting per webhook ID.
- [x] **Implement S3 Module**: Add ability to save payloads to AWS S3.
- [x] **Implement Websockets Module**: Forward webhooks to a websocket connection.

### 3. Advanced Improvements
- [x] **Persistent Statistics**: Move stats from in-memory (`src/utils.py`) to Redis or a database to survive restarts. ✅
- [x] **Analytics**: Create option to save statistics and logs to clickhouse db, there will be another UI project that will access it ✅
- [x] **JSON Schema Validation**: Validate incoming webhook payloads against a defined JSON schema. ✅
- [x] **Google reCAPTCHA Validation**: Implement backend validation for Google reCAPTCHA tokens (v2 and v3 support). ✅
- [x] **Retry Mechanism**: Implement retries for failed module executions (e.g., if RabbitMQ is down). ✅
- [ ] **Dynamic OpenAPI Docs**: Generate OpenAPI documentation automatically based on `webhooks.json` config.
- [ ] **Payload Transformation**: Add a step to transform payload structure before sending to destination.
- [ ] **Cloudflare Turnstile Validation**: Implement backend validation for Cloudflare Turnstile tokens.

### 4. Authentication Methods Enhancement
**Current Status**: 11/11 authentication methods implemented (100% coverage) ✅

**Implemented** ✅:
- [x] **Basic Auth**: HTTP Basic Authentication with constant-time comparison
- [x] **Bearer Auth**: Simple Bearer token authentication
- [x] **Custom Auth**: Custom authorization header formats
- [x] **JWT**: JSON Web Token validation with issuer/audience/expiration
- [x] **HMAC**: HMAC signature validation (SHA1, SHA256, SHA512)
- [x] **Header Auth (HMAC)**: Custom header with HMAC signature

**Missing** ❌:
- [ ] **Digest Auth**: HTTP Digest Authentication (RFC 7616) - Challenge-response auth, more secure than Basic
- [ ] **OAuth 1.0**: OAuth 1.0 signature validation - For Twitter and legacy OAuth providers
- [ ] **OAuth 2.0**: OAuth 2.0 access token validation - Modern standard, token introspection
- [x] **Query Parameter Auth**: API key authentication via query parameters (?api_key=xxx) ✅
- [x] **Generic Header Auth**: Custom header-based API key auth (X-API-Key, X-Auth-Token, etc.) ✅
- [x] **OAuth 2.0**: OAuth 2.0 access token validation - Token introspection and JWT validation ✅
- [x] **Digest Auth**: HTTP Digest Authentication (RFC 7616) - Challenge-response auth without password transmission ✅
- [x] **OAuth 1.0**: OAuth 1.0 signature validation (RFC 5849) - HMAC-SHA1 and PLAINTEXT signatures ✅

**Status**: ✅ All authentication methods implemented!

See [docs/AUTH_METHODS_ANALYSIS.md](docs/AUTH_METHODS_ANALYSIS.md) for detailed analysis.

### 5. Testing & Documentation
- [x] **Unit Tests**: Comprehensive test suite with 274 tests covering validators, modules, and core functionality. ✅
- [x] **Integration Tests**: Tests for full webhook flow, authentication, validation, and module processing. ✅
- [ ] **Performance Tests**: Expand performance testing documentation and benchmarks.

### 6. Database Webhook Storage Modules
- [ ] **PostgreSQL Module**: Store webhook payloads in PostgreSQL database
  - Support JSONB storage for flexible schema-less storage
  - Support relational mapping with explicit field definitions
  - Auto table creation with schema validation
  - Connection pooling for performance
  - Transaction support for atomic operations
  - Upsert support (INSERT ... ON CONFLICT) for idempotency
  - Batch insert support for high-throughput scenarios
  - Error handling with retry mechanism integration
  - Support for PostgreSQL-specific features (JSONB queries, full-text search)

- [ ] **MariaDB/MySQL Module**: Store webhook payloads in MariaDB/MySQL database
  - Support JSON column type for flexible storage
  - Support relational mapping with explicit field definitions
  - Auto table creation with schema validation
  - Connection pooling for performance
  - Transaction support for atomic operations
  - INSERT ... ON DUPLICATE KEY UPDATE for upsert operations
  - Batch insert support for high-throughput scenarios
  - Error handling with retry mechanism integration
  - Support for MySQL/MariaDB JSON functions

**Storage Format Options**:
1. **JSON Storage** (Default):
   - PostgreSQL: Store entire payload in JSONB column
   - MySQL/MariaDB: Store entire payload in JSON column
   - Flexible, no schema changes needed
   - Supports nested structures
   - Enables JSON querying (PostgreSQL JSONB operators, MySQL JSON functions)

2. **Relational Mapping**:
   - Map payload fields to table columns
   - Requires explicit schema definition in webhook config
   - Better for structured data and SQL queries
   - Type validation and constraints
   - Index support for performance

3. **Hybrid Approach**:
   - Store mapped fields in columns + full payload in JSON column
   - Best of both worlds: queryable columns + full payload preservation

**Validation Requirements**:
- **Optional**: Allow unvalidated storage (JSON only, no schema)
- **Schema Required**: Require explicit field mapping definition
  - Field name mapping (payload field → column name)
  - Data type definitions (string, integer, float, boolean, datetime, JSON)
  - Optional constraints (NOT NULL, UNIQUE, DEFAULT values)
  - Index definitions for performance

**Configuration Example**:
```json
{
  "webhook_to_db": {
    "data_type": "json",
    "module": "postgresql",  // or "mysql", "mariadb"
    "connection": "postgres_local",
    "module-config": {
      "table": "webhook_events",
      "storage_mode": "json",  // or "relational", "hybrid"
      "schema": {
        "fields": {
          "event_id": {"type": "string", "column": "event_id", "constraints": ["NOT NULL", "UNIQUE"]},
          "user_id": {"type": "integer", "column": "user_id", "index": true},
          "timestamp": {"type": "datetime", "column": "created_at", "default": "CURRENT_TIMESTAMP"},
          "metadata": {"type": "json", "column": "metadata"}
        }
      },
      "upsert": true,
      "upsert_key": "event_id",
      "batch_size": 100,
      "include_headers": true,
      "include_timestamp": true
    },
    "authorization": "Bearer db_secret"
  }
}
```

**Required Features** (Industry Standard):
- Connection pooling (asyncpg for PostgreSQL, aiomysql for MySQL/MariaDB)
- Auto table creation with schema validation
- Upsert/conflict resolution (ON CONFLICT for PostgreSQL, ON DUPLICATE KEY UPDATE for MySQL)
- Batch insert support for performance
- Transaction support (optional, configurable)
- Error handling with retry integration (use existing retry_handler)
- Connection health checks
- SSRF prevention (validate database hostnames)
- SQL injection prevention (parameterized queries only)
- Connection timeout and retry configuration
- Support for SSL/TLS connections
- Support for connection string and individual parameters

**Compatibility Considerations**:
- PostgreSQL 12+ (for JSONB support and modern features)
- MySQL 5.7+ / MariaDB 10.2+ (for JSON column type support)
- Use async database drivers (asyncpg, aiomysql) for non-blocking I/O
- Support both connection string format and individual parameters
- Handle database-specific SQL syntax differences
- Support for read replicas (optional, future enhancement)

## Test Status

**Current Test Coverage: 274 tests passing** ✅

Test suites include:
- Authentication tests (Basic Auth, JWT, Authorization)
- Validation tests (HMAC, IP Whitelist, reCAPTCHA, JSON Schema)
- Security edge cases (injection attacks, large payloads, malformed data)
- Webhook flow tests
- Rate limiting tests
- Redis statistics tests
- Input validation tests
- CORS tests

Run tests with:
```bash
pytest -v
```
