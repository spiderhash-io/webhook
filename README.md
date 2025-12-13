# Core Webhook Module

A flexible and configurable webhook receiver and processor built with FastAPI. It receives webhooks, validates them, and forwards the payloads to various destinations such as RabbitMQ, Redis, MQTT, disk, or stdout.

**Status**: Production-ready with comprehensive security features, 2,493 passing tests, and support for multiple output destinations. All 11 authentication methods implemented!

## Features

### Core Functionality
- **Flexible Destinations**: Send webhook data to RabbitMQ, Redis (RQ), local disk, HTTP endpoints, ClickHouse, MQTT, WebSocket, PostgreSQL, MySQL/MariaDB, S3, Kafka, ActiveMQ, AWS SQS, GCP Pub/Sub, ZeroMQ, or stdout.
- **Plugin Architecture**: Easy to extend with new modules without modifying core code.
- **Configuration-Driven**: Easy configuration via JSON files (`webhooks.json`, `connections.json`) and environment variables.
- **Live Config Reload**: Hot-reload webhook and connection configurations without restarting the application (via ConfigManager and ConfigFileWatcher).
- **Connection Pool Management**: Centralized connection pool registry with automatic pool lifecycle management and versioning.
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
- **Credential Cleanup**: Automatically masks or removes credentials from payloads and headers before logging or storing to prevent credential exposure.

## Project Structure
- `src/main.py`: Entry point, FastAPI app, and route definitions.
- `src/webhook.py`: Core logic for handling and processing webhooks.
- `src/config.py`: Configuration loading and injection.
- `src/config_manager.py`: Live configuration management with hot-reload support.
- `src/config_watcher.py`: File system watcher for automatic config reload on file changes.
- `src/connection_pool_registry.py`: Centralized connection pool management with versioning and lifecycle control.
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

Use the optimized smaller image (multi-stage build for minimal size) to run a single FastAPI instance in Docker:

```bash
# Build image using smallest Dockerfile
docker build -f Dockerfile.smaller -t core-webhook-module:latest .

# Run container (mount configs from host)
docker run --rm \
  -p 8000:8000 \
  -v "$(pwd)/webhooks.json:/app/webhooks.json:ro" \
  -v "$(pwd)/connections.json:/app/connections.json:ro" \
  --env-file .env \
  core-webhook-module:latest
```

**Using GitLab Container Registry:**
```bash
# Pull from registry
docker pull registry.gitlab.com/saas-core-platform/core-webhook-module:latest

# Run container
docker run --rm \
  -p 8000:8000 \
  -v "$(pwd)/webhooks.json:/app/webhooks.json:ro" \
  -v "$(pwd)/connections.json:/app/connections.json:ro" \
  registry.gitlab.com/saas-core-platform/core-webhook-module:latest
```

**Docker Compose Example:**
```yaml
services:
  webhook:
    image: registry.gitlab.com/saas-core-platform/core-webhook-module:latest
    container_name: webhook-service
    ports:
      - "8000:8000"
    volumes:
      - ./webhooks.json:/app/webhooks.json:ro
      - ./connections.json:/app/connections.json:ro
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
docker compose up -d

# Run performance tests
./src/tests/run_performance_test.sh
# Or manually:
python3 src/tests/performance_test_multi_instance.py
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

#### Credential Cleanup
Automatically clean credentials from webhook payloads and headers before logging or storing to prevent credential exposure. This feature is enabled by default (opt-out) and supports both masking and removal modes.

```json
{
    "secure_webhook": {
        "data_type": "json",
        "module": "postgresql",
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

#### MQTT Publishing
```json
{
    "mqtt_events": {
        "data_type": "json",
        "module": "mqtt",
        "topic": "webhook/events",
        "connection": "mqtt_local",
        "module-config": {
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
        "topic": "shellies/device123/status",
        "connection": "mqtt_shelly",
        "module-config": {
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
        "topic": "cmnd/device_name/POWER",
        "connection": "mqtt_sonoff",
        "module-config": {
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

### Future Enhancements
- [ ] Payload Transformation (pre-processing step)
- [ ] Cloudflare Turnstile Validation
- [ ] Batch insert support for database modules
- [ ] Webhook chaining (multiple destinations per webhook)
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
- Rate limiting tests
- Redis statistics tests
- Input validation tests
- CORS tests
- Integration tests
- Config manager and watcher tests
- Connection pool registry tests
- Analytics processor tests

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
