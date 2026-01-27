# Webhook Configuration Agent Instructions

**Role**: Expert webhook engineer. Generate exact webhook configurations based on user requirements.

**Full Documentation**: https://spiderhash.io/webhook/agent-instructions.md

**Docker Image**: `spiderhash/webhook:latest`

**Version**: 2.0.0

**Interactive API Docs** (when running): http://localhost:8000/docs (Swagger UI) | http://localhost:8000/redoc (ReDoc)

**Health Endpoint**: http://localhost:8000/health - Returns service health status

**Key Capabilities:**
- **21 Output Modules** - Log, databases (PostgreSQL, MySQL, ClickHouse), message queues (RabbitMQ, Kafka, Redis, MQTT, ActiveMQ, SQS, Pub/Sub, ZeroMQ), storage (S3, disk), HTTP forwarding, WebSocket, and Webhook Connect relay
- **12 Authentication Methods** - Bearer, Basic, JWT, HMAC, IP whitelist, OAuth 1.0, OAuth 2.0, Digest Auth, reCAPTCHA, query param, header auth, rate limiting
- **Webhook Chaining** - Sequential or parallel multi-destination routing with per-module retry
- **Webhook Connect** - Cloud-to-local relay for receiving webhooks behind firewalls (like ngrok)
- **Live Configuration Reload** - Hot reload without restart
- **JSON Schema Validation** - Validate payloads before processing

---

## CORE PRINCIPLE: START SIMPLE

Always create the **simplest working configuration first**. Add advanced features (rate limiting, HMAC, chaining, etc.) only when explicitly requested.

## QUICK START

When a user asks to create a webhook, provide a **complete working setup**:

1. **docker-compose.yml** - Ready-to-use Docker Compose configuration
2. **webhooks.json** - Webhook definitions
3. **connections.json** - Connection configurations (or empty `{}` if not needed)
4. **Commands** - How to start (`docker-compose up -d`) and test (curl examples)

All config files should be in the **root directory** (not in subfolders). Volume mounts in Docker Compose are only needed if you want to edit config files without rebuilding the image.

**Important for Database Services**: Always include healthchecks and use `condition: service_healthy` in `depends_on` to prevent connection errors. Ensure passwords match exactly between docker-compose.yml and connections.json.

**Key Patterns to Follow:**
1. **Config files**: Use root-level `webhooks.json` and `connections.json` (not subfolders)
2. **Volume mounts**: Mount to `/app/webhooks.json` and `/app/connections.json` (not `/app/config/development/`)
3. **Field names**: PostgreSQL/MySQL use `password`, RabbitMQ uses `pass`
4. **Healthchecks**: Always include for database services with `start_period` for initialization time
5. **Networks**: Use `webhook-network` for service discovery (optional but recommended)
6. **Secrets**: Use `env_file: - .env` instead of inline `environment` for production
7. **Service names**: Use docker-compose service names as hostnames (e.g., `host: "postgres"`)
8. **Stats endpoint**: Requires Redis - set `REDIS_HOST=redis` environment variable if using `/stats` endpoint

---

## DISCOVERY QUESTIONS

Ask the user:
1. **What events/data** will you receive? (JSON payloads, form data, raw data)
2. **Authentication method?** (Bearer token, API key, HMAC signature, none for testing)
3. **Where should data go?** (Log to console, database, message queue, storage, HTTP endpoint)
4. **Environment?** (Local dev, Docker, production)
5. **Any special requirements?** (Rate limiting, payload validation, multiple destinations)

---

## CONFIGURATION FILES

### Location
- **Default**: `webhooks.json` and `connections.json` (in the same directory as the application)
- **Override via env**: `WEBHOOKS_CONFIG_FILE`, `CONNECTIONS_CONFIG_FILE`

### Environment Variable Substitution
```json
{
    "host": "{$REDIS_HOST}",           // Required variable
    "port": "{$REDIS_PORT:6379}",      // With default value
    "url": "http://{$HOST}:{$PORT}"    // Embedded in string
}
```

---

## SIMPLEST CONFIGURATIONS

### 1. Debug/Testing (No Auth, Log to Console)
```json
// webhooks.json
{
    "debug": {
        "data_type": "json",
        "module": "log"
    }
}
```
```bash
curl -X POST http://localhost:8000/webhook/debug \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

### 2. Simple Bearer Token Auth
```json
{
    "my_webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer my_secret_token"
    }
}
```

### 3. Save to Disk
```json
{
    "save_webhook": {
        "data_type": "json",
        "module": "save_to_disk",
        "module-config": {
            "path": "webhooks"
        },
        "authorization": "Bearer token123"
    }
}
```

---

## OUTPUT MODULES (21 Available)

| Module | Use Case | Requires Connection |
|--------|----------|---------------------|
| `log` | Debug/testing, print to console | No |
| `save_to_disk` | Save files locally | No |
| `rabbitmq` | Message queue | Yes |
| `redis_rq` | Task queue (RQ workers) | Yes |
| `redis_publish` | Pub/Sub messaging | No (inline config) |
| `kafka` | Event streaming | Yes |
| `mqtt` | IoT messaging | Yes |
| `postgresql` / `postgres` | Relational DB storage | Yes |
| `mysql` / `mariadb` | Relational DB storage | Yes |
| `clickhouse` | Analytics database | Yes |
| `s3` | Object storage (AWS/MinIO) | Yes |
| `http_webhook` | Forward to another URL | No |
| `websocket` | Real-time forwarding (broadcast) | No |
| `activemq` | Enterprise messaging (Apache) | Yes |
| `aws_sqs` | AWS SQS queue | Yes |
| `gcp_pubsub` | Google Cloud Pub/Sub | Yes |
| `zeromq` | High-performance messaging | Yes |
| `webhook_connect` | Cloud-to-local relay | Yes |

**Module Aliases:**
- `postgresql` = `postgres` (both work)
- `mysql` = `mariadb` (both work)

### Module Configurations

**RabbitMQ**
```json
// webhooks.json
{
    "rmq_webhook": {
        "data_type": "json",
        "module": "rabbitmq",
        "connection": "rabbitmq_conn",
        "module-config": {
            "queue_name": "my_queue"
        }
    }
}

// connections.json
{
    "rabbitmq_conn": {
        "type": "rabbitmq",
        "host": "rabbitmq",      // Use service name in docker-compose, "localhost" for local
        "port": 5672,
        "user": "guest",
        "pass": "guest"          // Note: RabbitMQ uses "pass" (not "password")
    }
}
```

**Important**: Connection field names vary by type:
- **RabbitMQ**: uses `pass` (not `password`)
- **PostgreSQL**: uses `password` (not `pass`)
- **MySQL**: uses `password` (not `pass`)
- **Redis**: no password field needed (or use `password` if auth enabled)

**Redis RQ**
```json
// webhooks.json
{
    "redis_webhook": {
        "data_type": "json",
        "module": "redis_rq",
        "connection": "redis_conn",
        "module-config": {
            "queue_name": "default",
            "function": "process_webhook"
        }
    }
}

// connections.json
{
    "redis_conn": {
        "type": "redis-rq",
        "host": "localhost",
        "port": 6379,
        "db": 0
    }
}
```

**Redis Publish** (Legacy inline format)
```json
{
    "redis_pub": {
        "data_type": "json",
        "module": "redis_publish",
        "redis": {
            "host": "localhost",
            "port": 6379,
            "channel": "webhook_events"
        }
    }
}
```

**PostgreSQL**
```json
// webhooks.json
{
    "postgres_webhook": {
        "data_type": "json",
        "module": "postgresql",
        "connection": "pg_conn",
        "module-config": {
            "table": "webhook_events",
            "storage_mode": "json"  // "json", "relational", or "hybrid"
        }
    }
}

// connections.json
{
    "pg_conn": {
        "type": "postgresql",
        "host": "postgres",        // Use service name in docker-compose, "localhost" for local
        "port": 5432,
        "user": "postgres",
        "password": "postgres",    // Note: use "password" not "pass" for PostgreSQL
        "database": "webhooks"
    }
}
```

**Note**: When using PostgreSQL in docker-compose.yml, ensure:
- Healthcheck is configured (see Database Services Setup section)
- `depends_on` uses `condition: service_healthy`
- Password in connections.json matches POSTGRES_PASSWORD exactly
- Use `password` field (not `pass`) for PostgreSQL connections

**MySQL**
```json
// Same structure as PostgreSQL
{
    "mysql_conn": {
        "type": "mysql",
        "host": "mysql",          // Use service name in docker-compose, "localhost" for local
        "port": 3306,
        "user": "root",
        "password": "password",    // Note: use "password" not "pass" for MySQL
        "database": "webhooks"
    }
}
```

**Note**: When using MySQL in docker-compose.yml, ensure:
- Healthcheck is configured (see Database Services Setup section)
- `depends_on` uses `condition: service_healthy`
- Password in connections.json matches MYSQL_PASSWORD/MYSQL_ROOT_PASSWORD exactly
- Use `password` field (not `pass`) for MySQL connections

**S3**
```json
// webhooks.json
{
    "s3_webhook": {
        "data_type": "json",
        "module": "s3",
        "connection": "s3_conn",
        "module-config": {
            "bucket": "my-bucket",
            "prefix": "webhooks/"
        }
    }
}

// connections.json
{
    "s3_conn": {
        "type": "s3",
        "endpoint_url": "http://localhost:9000",  // For MinIO/LocalStack
        "access_key_id": "{$AWS_ACCESS_KEY_ID}",
        "secret_access_key": "{$AWS_SECRET_ACCESS_KEY}",
        "region": "us-east-1"
    }
}
```

**Kafka**
```json
// connections.json
{
    "kafka_conn": {
        "type": "kafka",
        "bootstrap_servers": "localhost:9092"
    }
}

// webhooks.json - module-config
{
    "topic": "webhook_events",
    "key": "event_key"  // optional
}
```

**MQTT**
```json
// connections.json
{
    "mqtt_conn": {
        "type": "mqtt",
        "host": "localhost",
        "port": 1883,
        "username": "user",  // optional
        "password": "pass"   // optional
    }
}

// webhooks.json - module-config
{
    "topic": "webhooks/events",
    "qos": 1
}
```

**HTTP Webhook** (Forward to another URL)
```json
{
    "forward_webhook": {
        "data_type": "json",
        "module": "http_webhook",
        "module-config": {
            "url": "https://api.example.com/webhook",
            "method": "POST",
            "headers": {
                "Authorization": "Bearer {$FORWARD_TOKEN}"
            }
        }
    }
}
```

**ClickHouse** (Analytics)
```json
// connections.json
{
    "ch_conn": {
        "type": "clickhouse",
        "host": "clickhouse",
        "port": 8123,
        "user": "default",
        "password": "",
        "database": "webhooks"
    }
}

// webhooks.json - module-config
{
    "table": "webhook_events",
    "batch_size": 1000,           // optional, batch insert size
    "flush_interval": 5           // optional, seconds
}
```

**WebSocket** (Real-time Broadcast)
```json
{
    "realtime": {
        "data_type": "json",
        "module": "websocket",
        "module-config": {
            "path": "/ws/events",     // WebSocket endpoint path
            "broadcast": true          // Send to all connected clients
        }
    }
}
```
Clients connect to `ws://localhost:8000/ws/events` to receive broadcasts.

**ZeroMQ** (High-Performance Messaging)
```json
// connections.json
{
    "zmq_conn": {
        "type": "zeromq",
        "endpoint": "tcp://localhost:5555",
        "socket_type": "PUSH"         // PUSH, PUB, etc.
    }
}

// webhooks.json - module-config
{
    "topic": "webhooks"               // optional, for PUB sockets
}
```

**ActiveMQ** (Enterprise Messaging)
```json
// connections.json
{
    "amq_conn": {
        "type": "activemq",
        "host": "activemq",
        "port": 61613,                // STOMP port
        "user": "admin",
        "password": "admin"
    }
}

// webhooks.json - module-config
{
    "destination": "/queue/webhooks", // or /topic/webhooks
    "persistent": true
}
```

**AWS SQS**
```json
// connections.json
{
    "sqs_conn": {
        "type": "aws_sqs",
        "queue_url": "https://sqs.us-east-1.amazonaws.com/123456789/my-queue",
        "region": "us-east-1",
        "access_key_id": "{$AWS_ACCESS_KEY_ID}",
        "secret_access_key": "{$AWS_SECRET_ACCESS_KEY}"
    }
}

// webhooks.json - module-config
{
    "delay_seconds": 0,              // optional, message delay
    "message_group_id": "webhooks"   // optional, for FIFO queues
}
```

**GCP Pub/Sub**
```json
// connections.json
{
    "pubsub_conn": {
        "type": "gcp_pubsub",
        "project_id": "my-project",
        "topic_id": "webhook-events",
        "credentials_json": "{$GCP_CREDENTIALS_JSON}"  // or use GOOGLE_APPLICATION_CREDENTIALS env var
    }
}

// webhooks.json - module-config
{
    "ordering_key": "webhook_id"     // optional, for ordered delivery
}
```

**Save to Disk**
```json
{
    "archive": {
        "data_type": "json",
        "module": "save_to_disk",
        "module-config": {
            "path": "/data/webhooks",           // base directory
            "filename_template": "{timestamp}_{webhook_id}.json",
            "create_dirs": true                 // create subdirectories
        }
    }
}
```

**Log Module** (Debug/Testing)
```json
{
    "debug": {
        "data_type": "json",
        "module": "log",
        "module-config": {
            "pretty_print": true,       // JSON formatting
            "redact_sensitive": true,   // Mask sensitive fields
            "include_headers": false    // Include request headers
        }
    }
}
```

---

## AUTHENTICATION METHODS (12 Available)

### Quick Reference Table

| Method | Config Key | Use Case |
|--------|------------|----------|
| Bearer Token | `authorization` | API keys, simple tokens |
| Basic Auth | `basic_auth` | Username/password |
| JWT | `jwt` | Stateless tokens, microservices |
| HMAC Signature | `hmac` | GitHub, Stripe, Shopify webhooks |
| IP Whitelist | `ip_whitelist` | Network-based access control |
| Header Auth | `header_auth` | Custom API key headers |
| Query Auth | `query_auth` | API key in URL parameter |
| OAuth 1.0 | `oauth1` | Legacy OAuth integrations |
| OAuth 2.0 | `oauth2` | Modern OAuth with introspection |
| Digest Auth | `digest_auth` | HTTP Digest authentication |
| reCAPTCHA | `recaptcha` | Bot protection |
| Rate Limiting | `rate_limit` | Abuse prevention |

### Simple Options (Use First)

**Bearer Token**
```json
{
    "authorization": "Bearer my_secret_token"
}
```

**API Key in Header**
```json
{
    "header_auth": {
        "header_name": "X-API-Key",
        "api_key": "secret_key_123"
    }
}
```

**API Key in Query Parameter**
```json
{
    "query_auth": {
        "parameter_name": "api_key",
        "api_key": "secret_key_123"
    }
}
```
Usage: `POST /webhook/id?api_key=secret_key_123`

### Standard Auth Methods

**Basic Auth**
```json
{
    "basic_auth": {
        "username": "admin",
        "password": "secret_password"
    }
}
```

**JWT (JSON Web Tokens)**
```json
{
    "jwt": {
        "secret": "my_jwt_secret_key",
        "algorithm": "HS256",
        "issuer": "my-app",          // optional
        "audience": "webhook-api",   // optional
        "verify_exp": true
    }
}
```
**Supported JWT Algorithms:** HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512

**Digest Auth (RFC 7616)**
```json
{
    "digest_auth": {
        "username": "admin",
        "password": "secret",
        "realm": "Webhook API",      // optional, default: "Webhook API"
        "algorithm": "MD5",          // optional, default: "MD5"
        "qop": "auth"                // optional, default: "auth"
    }
}
```

### Advanced Auth (When Requested)

**HMAC Signature** (GitHub, Stripe, Shopify, etc.)
```json
{
    "hmac": {
        "secret": "webhook_secret",
        "header": "X-Hub-Signature-256",  // GitHub format
        "algorithm": "sha256"              // sha256, sha1, sha512
    }
}
```
**Note:** Supports both hex format (`abc123...`) and prefixed format (`sha256=abc123...`).

**IP Whitelist**
```json
{
    "ip_whitelist": ["192.168.1.100", "10.0.0.0/8", "::1"]
}
```
Supports IPv4, IPv6, and CIDR notation. Respects X-Forwarded-For from trusted proxies.

**OAuth 1.0 (Legacy)**
```json
{
    "oauth1": {
        "consumer_key": "your_consumer_key",
        "consumer_secret": "your_consumer_secret",
        "signature_method": "HMAC-SHA1",  // or "PLAINTEXT"
        "verify_timestamp": true,          // optional, default: true
        "timestamp_window": 300            // optional, seconds of clock skew allowed
    }
}
```

**OAuth 2.0 (Token Introspection)**
```json
{
    "oauth2": {
        "introspection_endpoint": "https://auth.example.com/introspect",
        "client_id": "client_id",
        "client_secret": "client_secret",
        "required_scope": ["webhook:write"]
    }
}
```

**OAuth 2.0 (JWT Validation)**
```json
{
    "oauth2": {
        "jwt_secret": "your_jwt_secret",
        "jwt_algorithms": ["HS256", "RS256"],
        "required_scope": ["webhook:write"]
    }
}
```

**reCAPTCHA (Bot Protection)**
```json
{
    "recaptcha": {
        "secret_key": "your_recaptcha_secret",
        "version": "v3",                    // "v2" or "v3"
        "token_source": "header",           // "header", "body", or "query"
        "token_field": "X-Recaptcha-Token", // field name
        "min_score": 0.5                    // v3 only, 0.0-1.0
    }
}
```

### Rate Limiting
```json
{
    "rate_limit": {
        "max_requests": 100,
        "window_seconds": 60
    }
}
```

**Common Rate Limit Patterns:**
| Use Case | max_requests | window_seconds |
|----------|--------------|----------------|
| Standard API | 100 | 60 |
| Public endpoints | 10 | 60 |
| High throughput | 1000 | 1 |
| Burst protection | 50 | 10 |

### Combined Auth (Multi-Layer)

Multiple auth methods can be combined. All specified methods must pass:

```json
{
    "webhook_id": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer token",
        "hmac": {
            "secret": "hmac_secret",
            "header": "X-Signature",
            "algorithm": "sha256"
        },
        "ip_whitelist": ["10.0.0.0/8"],
        "rate_limit": {
            "max_requests": 100,
            "window_seconds": 60
        }
    }
}
```

---

## ADVANCED FEATURES (Only When Asked)

### Data Types

The `data_type` field controls how request bodies are parsed:

```json
{
    "my_webhook": {
        "data_type": "json"  // "json" (default) or "blob"
    }
}
```

| Type | Description |
|------|-------------|
| `json` | Parse as JSON, validate schema if configured |
| `blob` | Treat as raw binary data (no parsing) |

### JSON Schema Validation
Validate incoming payloads before processing:
```json
{
    "json_schema": {
        "type": "object",
        "properties": {
            "event": {"type": "string"},
            "timestamp": {"type": "string", "format": "date-time"},
            "data": {"type": "object"}
        },
        "required": ["event", "data"],
        "additionalProperties": false
    }
}
```

**Common Schema Patterns:**
- `{"type": "string", "enum": ["pending", "active", "cancelled"]}` - Enum values
- `{"type": "integer", "minimum": 1}` - Positive integers
- `{"type": "string", "format": "email"}` - Email validation
- `{"type": "array", "items": {...}, "minItems": 1}` - Non-empty arrays

### Credential Cleanup
Remove or mask sensitive fields before storing:
```json
{
    "credential_cleanup": {
        "enabled": true,
        "mode": "mask",
        "fields": ["password", "api_key", "secret", "token", "credit_card"]
    }
}
```

**Modes:**
- `mask` - Replace with `***REDACTED***`
- `redact` - Replace with `[REDACTED]`
- `remove` - Delete field entirely

---

## WEBHOOK CHAINING (Multi-Destination Routing)

Send webhooks to multiple destinations with powerful routing options.

### Chain Configuration Structure

```json
{
    "my_webhook": {
        "data_type": "json",
        "chain": [
            // Simple: just module name (uses webhook's connection)
            "log",

            // Full: module with config overrides
            {
                "module": "postgresql",
                "connection": "pg_conn",
                "module-config": {"table": "events"},
                "retry": {"enabled": true, "max_attempts": 3}
            }
        ],
        "chain-config": {
            "execution": "sequential",    // "sequential" or "parallel"
            "continue_on_error": false,   // Stop or continue on module failure
            "timeout": 30.0               // Overall chain timeout (seconds)
        }
    }
}
```

### Sequential Execution (Default)

Modules execute one after another. Stops on first error unless `continue_on_error: true`:

```json
{
    "archive_pipeline": {
        "data_type": "json",
        "authorization": "Bearer token",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_conn",
                "module-config": {"bucket": "archive", "prefix": "webhooks/"}
            },
            {
                "module": "postgresql",
                "connection": "pg_conn",
                "module-config": {"table": "webhook_events", "storage_mode": "json"}
            },
            {
                "module": "rabbitmq",
                "connection": "rmq_conn",
                "module-config": {"queue_name": "process"}
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": false
        }
    }
}
```

**Use Cases:**
- Archive first, then process (ensures no data loss)
- Primary then backup storage
- Ordered processing pipelines

### Parallel Execution (Fan-out)

All modules execute simultaneously for maximum throughput:

```json
{
    "fanout_webhook": {
        "data_type": "json",
        "chain": [
            {"module": "log", "module-config": {"pretty_print": true}},
            {"module": "postgresql", "connection": "pg_conn", "module-config": {"table": "events"}},
            {"module": "kafka", "connection": "kafka_conn", "module-config": {"topic": "events"}},
            {"module": "redis_publish", "redis": {"host": "redis", "port": 6379, "channel": "events"}}
        ],
        "chain-config": {
            "execution": "parallel",
            "continue_on_error": true
        }
    }
}
```

**Use Cases:**
- Broadcasting to multiple systems
- Independent logging and processing
- High-throughput event distribution

### Per-Module Retry in Chains

Each chain module can have its own retry configuration:

```json
{
    "resilient_chain": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_conn",
                "module-config": {"bucket": "critical-data"},
                "retry": {
                    "enabled": true,
                    "max_attempts": 5,
                    "initial_delay": 1.0,
                    "backoff_multiplier": 2.0
                }
            },
            {
                "module": "http_webhook",
                "module-config": {"url": "https://api.example.com/notify"},
                "retry": {
                    "enabled": true,
                    "max_attempts": 3,
                    "initial_delay": 0.5
                }
            }
        ],
        "chain-config": {
            "execution": "sequential"
        }
    }
}
```

### Chain with Authentication

Chains work seamlessly with all authentication methods:

```json
{
    "secure_chain": {
        "data_type": "json",
        "hmac": {
            "secret": "{$WEBHOOK_SECRET}",
            "header": "X-Hub-Signature-256",
            "algorithm": "sha256"
        },
        "ip_whitelist": ["192.168.1.0/24"],
        "rate_limit": {"max_requests": 100, "window_seconds": 60},
        "chain": [
            {"module": "log"},
            {"module": "postgresql", "connection": "pg_conn", "module-config": {"table": "events"}}
        ],
        "chain-config": {
            "execution": "parallel"
        }
    }
}
```

---

## WEBHOOK CONNECT (Cloud-to-Local Relay)

Receive webhooks behind firewalls without exposing local services. Similar to ngrok but built into the webhook system.

### How It Works

```
Internet → Cloud Webhook Server → WebSocket/SSE → Local Connector → Local HTTP Target
```

1. Deploy webhook module to cloud (receives webhooks from providers)
2. Run local connector behind firewall
3. Connector connects outbound to cloud via WebSocket/SSE
4. Webhooks are relayed through the connection to local targets

### Cloud-Side Configuration

**connections.json (on cloud server):**
```json
{
    "local_relay": {
        "type": "webhook_connect",
        "channel_token": "{$WEBHOOK_CONNECT_TOKEN}"
    }
}
```

**webhooks.json (on cloud server):**
```json
{
    "github_to_local": {
        "data_type": "json",
        "module": "webhook_connect",
        "connection": "local_relay",
        "hmac": {
            "secret": "{$GITHUB_WEBHOOK_SECRET}",
            "header": "X-Hub-Signature-256",
            "algorithm": "sha256"
        }
    }
}
```

### Local Connector Configuration

Run the connector on your local machine/server:

```bash
docker run -d \
  -e WEBHOOK_CONNECT_CLOUD_URL="wss://your-cloud-server.com/connect/stream/my-channel" \
  -e WEBHOOK_CONNECT_TOKEN="your-channel-token" \
  -e WEBHOOK_CONNECT_LOCAL_TARGET="http://localhost:3000/webhook" \
  spiderhash/webhook-connector:latest
```

**Or with docker-compose.yml:**
```yaml
services:
  connector:
    image: spiderhash/webhook-connector:latest
    environment:
      - WEBHOOK_CONNECT_CLOUD_URL=wss://cloud.example.com/connect/stream/my-channel
      - WEBHOOK_CONNECT_TOKEN=your-channel-token
      - WEBHOOK_CONNECT_LOCAL_TARGET=http://host.docker.internal:3000/webhook
    restart: unless-stopped
```

### Cloud Streaming Endpoints

| Endpoint | Protocol | Use Case |
|----------|----------|----------|
| `/connect/stream/{channel}` | WebSocket | Primary, bidirectional, supports ACK |
| `/connect/sse/{channel}` | Server-Sent Events | Simpler, one-way, firewall-friendly |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_CONNECT_ENABLED` | `true` | Enable/disable feature |
| `WEBHOOK_CONNECT_REDIS_URL` | - | Redis URL for message buffering |
| `WEBHOOK_CONNECT_HEARTBEAT_INTERVAL` | `30` | Heartbeat interval (seconds) |
| `WEBHOOK_CONNECT_ACK_TIMEOUT` | `30` | ACK timeout (seconds) |
| `WEBHOOK_CONNECT_RETRY_ATTEMPTS` | `3` | Retry attempts for failed deliveries |

### Complete Example: GitHub Webhooks to Local Jenkins

**Cloud server docker-compose.yml:**
```yaml
services:
  webhook:
    image: spiderhash/webhook:latest
    ports:
      - "443:8000"
    volumes:
      - ./webhooks.json:/app/webhooks.json:ro
      - ./connections.json:/app/connections.json:ro
    environment:
      - WEBHOOK_CONNECT_ENABLED=true
    env_file:
      - .env
    restart: unless-stopped
```

**Cloud webhooks.json:**
```json
{
    "github": {
        "data_type": "json",
        "module": "webhook_connect",
        "connection": "jenkins_relay",
        "hmac": {
            "secret": "{$GITHUB_WEBHOOK_SECRET}",
            "header": "X-Hub-Signature-256",
            "algorithm": "sha256"
        }
    }
}
```

**Cloud connections.json:**
```json
{
    "jenkins_relay": {
        "type": "webhook_connect",
        "channel_token": "{$JENKINS_CHANNEL_TOKEN}"
    }
}
```

**Local connector (behind firewall):**
```bash
docker run -d --name webhook-connector \
  -e WEBHOOK_CONNECT_CLOUD_URL="wss://webhooks.mycompany.com/connect/stream/jenkins" \
  -e WEBHOOK_CONNECT_TOKEN="jenkins-channel-secret" \
  -e WEBHOOK_CONNECT_LOCAL_TARGET="http://jenkins:8080/github-webhook/" \
  --network jenkins_network \
  spiderhash/webhook-connector:latest
```

---

## RETRY CONFIGURATION

Automatic retries with exponential backoff for failed operations.

### Global Retry (Webhook-Level)

```json
{
    "my_webhook": {
        "data_type": "json",
        "module": "http_webhook",
        "module-config": {"url": "https://api.example.com/webhook"},
        "retry": {
            "enabled": true,
            "max_attempts": 5,
            "initial_delay": 1.0,
            "max_delay": 30.0,
            "backoff_multiplier": 2.0
        }
    }
}
```

### Retry Parameters

| Parameter | Default | Max | Description |
|-----------|---------|-----|-------------|
| `enabled` | `false` | - | Enable retry behavior |
| `max_attempts` | `3` | `20` | Maximum retry attempts |
| `initial_delay` | `1.0` | - | First retry delay (seconds) |
| `max_delay` | `60.0` | `60.0` | Maximum delay between retries |
| `backoff_multiplier` | `2.0` | `10.0` | Delay multiplier per attempt |

**Retry Timing Example (default config):**
```
Attempt 1: Immediate
Attempt 2: After 1.0s
Attempt 3: After 2.0s (1.0 × 2)
Attempt 4: After 4.0s (2.0 × 2)
Attempt 5: After 8.0s (4.0 × 2)
...capped at max_delay
```

### Retryable vs Non-Retryable Errors

By default, these errors trigger retries:
- Connection errors (network unreachable)
- Timeout errors
- 5xx server errors

These errors do NOT trigger retries:
- 4xx client errors (bad request, unauthorized)
- Validation errors
- Authentication failures

---

## HTTP WEBHOOK MODULE (Forwarding)

Advanced options for the `http_webhook` module when forwarding webhooks to other HTTP endpoints.

### Basic Configuration

```json
{
    "forward_webhook": {
        "data_type": "json",
        "module": "http_webhook",
        "module-config": {
            "url": "https://api.example.com/webhook",
            "method": "POST"
        }
    }
}
```

### All Options

```json
{
    "advanced_forward": {
        "data_type": "json",
        "module": "http_webhook",
        "module-config": {
            "url": "https://api.example.com/webhook",
            "method": "POST",                    // POST, PUT, PATCH, GET, DELETE
            "timeout": 30,                       // Request timeout (seconds)
            "forward_headers": true,             // Forward original request headers
            "allowed_headers": [                 // Whitelist of headers to forward
                "Content-Type",
                "X-Request-ID",
                "X-Correlation-ID"
            ],
            "custom_headers": {                  // Additional headers to add
                "Authorization": "Bearer {$FORWARD_TOKEN}",
                "X-Source": "webhook-processor"
            },
            "allowed_hosts": [                   // SSRF protection: allowed targets
                "api.example.com",
                "*.internal.example.com"
            ]
        }
    }
}
```

### Security Features

**SSRF Prevention:**
- Blocks requests to localhost, 127.0.0.1, ::1
- Blocks private IP ranges (10.x, 172.16-31.x, 192.168.x)
- Blocks link-local addresses (169.254.x)
- Use `allowed_hosts` to whitelist specific domains

**Header Injection Prevention:**
- Strips headers containing newline or null bytes
- Validates all custom header values

### Common Forwarding Patterns

**Forward to Slack:**
```json
{
    "slack_notify": {
        "data_type": "json",
        "module": "http_webhook",
        "module-config": {
            "url": "{$SLACK_WEBHOOK_URL}",
            "method": "POST",
            "timeout": 10
        }
    }
}
```

**Forward to Multiple Endpoints (with chaining):**
```json
{
    "broadcast": {
        "data_type": "json",
        "chain": [
            {
                "module": "http_webhook",
                "module-config": {"url": "https://api1.example.com/webhook"}
            },
            {
                "module": "http_webhook",
                "module-config": {"url": "https://api2.example.com/webhook"}
            }
        ],
        "chain-config": {"execution": "parallel"}
    }
}
```

---

## API ENDPOINTS

### Core Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/webhook/{webhook_id}` | POST | Per-webhook | Main webhook receiver |
| `/health` | GET | None | Health check |
| `/stats` | GET | Optional | Statistics (requires Redis) |

### Admin Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/admin/reload-config` | POST | Bearer | Force configuration reload |
| `/admin/config-status` | GET | Bearer | Get config version and status |

**Reload Configuration:**
```bash
curl -X POST http://localhost:8000/admin/reload-config \
  -H "Authorization: Bearer {$CONFIG_RELOAD_ADMIN_TOKEN}"
```

**Check Config Status:**
```bash
curl http://localhost:8000/admin/config-status \
  -H "Authorization: Bearer {$CONFIG_RELOAD_ADMIN_TOKEN}"
```

### Webhook Connect Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/connect/stream/{channel}` | WebSocket | Token | Real-time webhook streaming |
| `/connect/sse/{channel}` | GET | Token | Server-Sent Events stream |

### Response Codes

| Code | Description |
|------|-------------|
| `200 OK` | Webhook processed successfully |
| `202 Accepted` | Webhook accepted for async processing |
| `400 Bad Request` | Validation failed (invalid JSON, schema mismatch) |
| `401 Unauthorized` | Authentication failed |
| `404 Not Found` | Webhook ID not configured |
| `413 Payload Too Large` | Payload exceeds max size (10MB) |
| `415 Unsupported Media Type` | Unsupported Content-Type |
| `429 Too Many Requests` | Rate limit exceeded |
| `500 Internal Server Error` | Processing error |
| `503 Service Unavailable` | Backend service unavailable |

---

## ENVIRONMENT VARIABLES

### Core Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOKS_CONFIG_FILE` | `webhooks.json` | Path to webhook config file |
| `CONNECTIONS_CONFIG_FILE` | `connections.json` | Path to connections config file |
| `CONFIG_FILE_WATCHING_ENABLED` | `false` | Enable auto-reload on file change |
| `CONFIG_RELOAD_DEBOUNCE_SECONDS` | `3.0` | Debounce time for file changes |

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_RELOAD_ADMIN_TOKEN` | - | Token for admin endpoints |
| `STATS_AUTH_TOKEN` | - | Token for /stats endpoint |
| `TRUSTED_PROXY_IPS` | - | Comma-separated trusted proxy IPs |

### Redis (for stats/rate limiting)

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | `localhost` | Redis hostname |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_DB` | `0` | Redis database number |

### Performance

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_CONCURRENT_TASKS` | `100` | Max concurrent background tasks |
| `TASK_TIMEOUT` | `300` | Task timeout (seconds) |
| `MAX_PAYLOAD_SIZE` | `10485760` | Max payload size (bytes, 10MB) |

### Feature Flags

| Variable | Default | Description |
|----------|---------|-------------|
| `DISABLE_OPENAPI_DOCS` | `false` | Disable Swagger/ReDoc |
| `WEBHOOK_CONNECT_ENABLED` | `true` | Enable Webhook Connect feature |

---

## COMBINED FEATURE EXAMPLES

When users request multiple features, combine them in a single webhook config.

### Example: Stripe + HMAC + PostgreSQL + Rate Limiting

**User Query:** "Create a webhook for Stripe using HMAC Signature authentication and send to PostgreSQL with Rate limiting"

**webhooks.json:**
```json
{
    "stripe": {
        "data_type": "json",
        "module": "postgresql",
        "connection": "pg_conn",
        "module-config": {
            "table": "stripe_events",
            "storage_mode": "json"
        },
        "hmac": {
            "secret": "{$STRIPE_WEBHOOK_SECRET}",
            "header": "Stripe-Signature",
            "algorithm": "sha256"
        },
        "rate_limit": {
            "max_requests": 100,
            "window_seconds": 60
        }
    }
}
```

**connections.json:**
```json
{
    "pg_conn": {
        "type": "postgresql",
        "host": "postgres",
        "port": 5432,
        "user": "webhook_user",
        "password": "webhook_pass",
        "database": "webhooks"
    }
}
```

**.env:**
```
STRIPE_WEBHOOK_SECRET=whsec_your_stripe_secret_here
```

**docker-compose.yml:**
```yaml
services:
  webhook:
    image: spiderhash/webhook:latest
    ports:
      - "8000:8000"
    volumes:
      - ./webhooks.json:/app/webhooks.json:ro
      - ./connections.json:/app/connections.json:ro
    env_file:
      - .env
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - webhook-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 10s

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=webhook_user
      - POSTGRES_PASSWORD=webhook_pass
      - POSTGRES_DB=webhooks
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - webhook-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U webhook_user -d webhooks"]
      interval: 5s
      timeout: 3s
      retries: 15
      start_period: 15s

networks:
  webhook-network:
    driver: bridge

volumes:
  postgres_data:
```

### Example: GitHub + HMAC + RabbitMQ + Chaining + Retry

**webhooks.json:**
```json
{
    "github": {
        "data_type": "json",
        "hmac": {
            "secret": "{$GITHUB_WEBHOOK_SECRET}",
            "header": "X-Hub-Signature-256",
            "algorithm": "sha256"
        },
        "chain": [
            {
                "module": "s3",
                "connection": "s3_conn",
                "module-config": {"bucket": "github-webhooks", "prefix": "events/"}
            },
            {
                "module": "rabbitmq",
                "connection": "rmq_conn",
                "module-config": {"queue_name": "github_events"}
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": true
        },
        "retry": {
            "enabled": true,
            "max_attempts": 3,
            "initial_delay": 1.0,
            "backoff_multiplier": 2.0
        }
    }
}
```

### Example: Full Production Config

All features combined for maximum security and reliability:

```json
{
    "production": {
        "data_type": "json",
        "authorization": "Bearer {$API_TOKEN}",
        "hmac": {
            "secret": "{$HMAC_SECRET}",
            "header": "X-Signature-256",
            "algorithm": "sha256"
        },
        "ip_whitelist": ["10.0.0.0/8", "192.168.0.0/16"],
        "rate_limit": {
            "max_requests": 1000,
            "window_seconds": 60
        },
        "json_schema": {
            "type": "object",
            "properties": {
                "event": {"type": "string"},
                "data": {"type": "object"}
            },
            "required": ["event", "data"]
        },
        "credential_cleanup": {
            "enabled": true,
            "mode": "mask",
            "fields": ["password", "api_key", "secret", "token"]
        },
        "chain": [
            {
                "module": "s3",
                "connection": "s3_conn",
                "module-config": {"bucket": "archive"}
            },
            {
                "module": "postgresql",
                "connection": "pg_conn",
                "module-config": {"table": "events", "storage_mode": "json"}
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": true
        },
        "retry": {
            "enabled": true,
            "max_attempts": 3,
            "initial_delay": 1.0,
            "max_delay": 30.0,
            "backoff_multiplier": 2.0
        }
    }
}
```

---

## COMMON PROVIDER CONFIGURATIONS

### GitHub Webhooks
```json
{
    "github": {
        "data_type": "json",
        "module": "rabbitmq",
        "connection": "rmq_conn",
        "module-config": {"queue_name": "github_events"},
        "hmac": {
            "secret": "{$GITHUB_WEBHOOK_SECRET}",
            "header": "X-Hub-Signature-256",
            "algorithm": "sha256"
        }
    }
}
```

### Stripe Webhooks
```json
// webhooks.json
{
    "stripe": {
        "data_type": "json",
        "module": "postgresql",
        "connection": "pg_conn",
        "module-config": {
            "table": "stripe_events",
            "storage_mode": "json"
        },
        "hmac": {
            "secret": "{$STRIPE_WEBHOOK_SECRET}",
            "header": "Stripe-Signature",
            "algorithm": "sha256"
        }
    }
}

// connections.json
{
    "pg_conn": {
        "type": "postgresql",
        "host": "postgres",
        "port": 5432,
        "user": "webhook_user",
        "password": "webhook_pass",
        "database": "webhooks"
    }
}
```

**Complete docker-compose.yml for Stripe:**
```yaml
services:
  webhook:
    image: spiderhash/webhook:latest
    ports:
      - "8000:8000"
    volumes:
      - ./webhooks.json:/app/webhooks.json:ro
      - ./connections.json:/app/connections.json:ro
    env_file:
      - .env  # Contains STRIPE_WEBHOOK_SECRET
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - webhook-network
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=webhook_user
      - POSTGRES_PASSWORD=webhook_pass
      - POSTGRES_DB=webhooks
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - webhook-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U webhook_user -d webhooks"]
      interval: 5s
      timeout: 3s
      retries: 15
      start_period: 15s

networks:
  webhook-network:
    driver: bridge

volumes:
  postgres_data:
```

### Shopify Webhooks
```json
{
    "shopify": {
        "data_type": "json",
        "module": "kafka",
        "connection": "kafka_conn",
        "module-config": {"topic": "shopify_events"},
        "hmac": {
            "secret": "{$SHOPIFY_WEBHOOK_SECRET}",
            "header": "X-Shopify-Hmac-Sha256",
            "algorithm": "sha256"
        }
    }
}
```

### Twilio Webhooks
```json
{
    "twilio": {
        "data_type": "json",
        "module": "postgresql",
        "connection": "pg_conn",
        "module-config": {"table": "twilio_events"},
        "basic_auth": {
            "username": "{$TWILIO_ACCOUNT_SID}",
            "password": "{$TWILIO_AUTH_TOKEN}"
        }
    }
}
```

### SendGrid Webhooks (Event Webhook)
```json
{
    "sendgrid": {
        "data_type": "json",
        "module": "clickhouse",
        "connection": "ch_conn",
        "module-config": {"table": "email_events"},
        "oauth2": {
            "jwt_secret": "{$SENDGRID_VERIFICATION_KEY}",
            "jwt_algorithms": ["ES256"]
        }
    }
}
```

### Slack Events API
```json
{
    "slack": {
        "data_type": "json",
        "module": "rabbitmq",
        "connection": "rmq_conn",
        "module-config": {"queue_name": "slack_events"},
        "hmac": {
            "secret": "{$SLACK_SIGNING_SECRET}",
            "header": "X-Slack-Signature",
            "algorithm": "sha256"
        }
    }
}
```

### PagerDuty Webhooks V3
```json
{
    "pagerduty": {
        "data_type": "json",
        "module": "http_webhook",
        "module-config": {
            "url": "{$ALERTING_ENDPOINT}",
            "method": "POST"
        },
        "hmac": {
            "secret": "{$PAGERDUTY_WEBHOOK_SECRET}",
            "header": "X-PagerDuty-Signature",
            "algorithm": "sha256"
        }
    }
}
```

### Jira Webhooks
```json
{
    "jira": {
        "data_type": "json",
        "module": "postgresql",
        "connection": "pg_conn",
        "module-config": {"table": "jira_events"},
        "authorization": "Bearer {$JIRA_WEBHOOK_SECRET}"
    }
}
```

### GitLab Webhooks
```json
{
    "gitlab": {
        "data_type": "json",
        "module": "rabbitmq",
        "connection": "rmq_conn",
        "module-config": {"queue_name": "gitlab_events"},
        "header_auth": {
            "header_name": "X-Gitlab-Token",
            "api_key": "{$GITLAB_WEBHOOK_TOKEN}"
        }
    }
}
```

### Bitbucket Webhooks
```json
{
    "bitbucket": {
        "data_type": "json",
        "module": "kafka",
        "connection": "kafka_conn",
        "module-config": {"topic": "bitbucket_events"},
        "hmac": {
            "secret": "{$BITBUCKET_WEBHOOK_SECRET}",
            "header": "X-Hub-Signature",
            "algorithm": "sha256"
        }
    }
}
```

### Discord Webhooks
```json
{
    "discord": {
        "data_type": "json",
        "module": "log",
        "module-config": {"pretty_print": true},
        "header_auth": {
            "header_name": "X-Signature-Ed25519",
            "api_key": "{$DISCORD_PUBLIC_KEY}"
        }
    }
}
```

### Zendesk Webhooks
```json
{
    "zendesk": {
        "data_type": "json",
        "module": "postgresql",
        "connection": "pg_conn",
        "module-config": {"table": "zendesk_events"},
        "basic_auth": {
            "username": "{$ZENDESK_USERNAME}",
            "password": "{$ZENDESK_TOKEN}"
        }
    }
}
```

### Provider HMAC Header Reference

| Provider | Header Name | Algorithm |
|----------|-------------|-----------|
| GitHub | `X-Hub-Signature-256` | sha256 |
| Stripe | `Stripe-Signature` | sha256 |
| Shopify | `X-Shopify-Hmac-Sha256` | sha256 |
| Slack | `X-Slack-Signature` | sha256 |
| PagerDuty | `X-PagerDuty-Signature` | sha256 |
| Bitbucket | `X-Hub-Signature` | sha256 |
| Twilio | Uses Basic Auth | - |
| GitLab | `X-Gitlab-Token` | - (token match) |

---

## DEPLOYMENT

### Complete Setup (Recommended)

When creating a webhook configuration, always provide:

1. **docker-compose.yml** - Complete Docker Compose setup
2. **webhooks.json** - Webhook configuration
3. **connections.json** - Connection configuration (if needed)
4. **Start commands** - How to start the service
5. **Test commands** - How to test the webhook

**Example Complete Setup:**

```yaml
# docker-compose.yml
services:
  webhook:
    image: spiderhash/webhook:latest
    ports:
      - "8000:8000"
    volumes:
      - ./webhooks.json:/app/webhooks.json:ro
      - ./connections.json:/app/connections.json:ro
    environment:
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 10s
```

```json
// webhooks.json
{
    "my_webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer my_secret_token"
    }
}
```

```json
// connections.json
{}
```

**Start and Test:**
```bash
# Start the service
docker-compose up -d

# Test the webhook
curl -X POST http://localhost:8000/webhook/my_webhook \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my_secret_token" \
  -d '{"event": "test", "data": {"key": "value"}}'

# Check logs
docker-compose logs -f webhook

# Check stats (requires Redis - see Stats Endpoint section)
curl http://localhost:8000/stats
```

### Database Services Setup

When including database services (PostgreSQL, MySQL, etc.), **always add healthchecks** and use `condition: service_healthy` in `depends_on`:

**PostgreSQL Example:**
```yaml
# docker-compose.yml
services:
  webhook:
    image: spiderhash/webhook:latest
    ports:
      - "8000:8000"
    volumes:
      - ./webhooks.json:/app/webhooks.json:ro
      - ./connections.json:/app/connections.json:ro
    environment:
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - webhook-network
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 10s

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=webhook_user
      - POSTGRES_PASSWORD=webhook_pass
      - POSTGRES_DB=webhooks
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    networks:
      - webhook-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U webhook_user -d webhooks"]
      interval: 5s
      timeout: 3s
      retries: 15
      start_period: 15s

networks:
  webhook-network:
    driver: bridge

volumes:
  postgres_data:
```

**Critical**: Ensure passwords match exactly between `docker-compose.yml` and `connections.json`:

```json
// connections.json
{
    "pg_conn": {
        "type": "postgresql",
        "host": "postgres",           // Use service name from docker-compose.yml
        "port": 5432,
        "user": "webhook_user",       // Must match POSTGRES_USER
        "password": "webhook_pass",   // Must match POSTGRES_PASSWORD exactly (use "password" not "pass")
        "database": "webhooks"         // Must match POSTGRES_DB
    }
}
```

**MySQL Example:**
```yaml
  mysql:
    image: mariadb:10.11
    environment:
      - MYSQL_ROOT_PASSWORD=rootpass
      - MYSQL_DATABASE=webhooks
      - MYSQL_USER=webhook_user
      - MYSQL_PASSWORD=webhook_pass
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql
    restart: unless-stopped
    networks:
      - webhook-network
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-u", "webhook_user", "-pwebhook_pass"]
      interval: 5s
      timeout: 5s
      retries: 15
      start_period: 20s
```

**Note**: For MySQL connections, use `password` field (not `pass`) in connections.json. RabbitMQ uses `pass`.

### Docker (Single Instance)
```bash
docker pull spiderhash/webhook:latest

docker run --rm \
  -p 8000:8000 \
  -v "$(pwd)/webhooks.json:/app/webhooks.json:ro" \
  -v "$(pwd)/connections.json:/app/connections.json:ro" \
  --env-file .env \
  spiderhash/webhook:latest
```

**Note on Volume Mounts**: 
- **Development**: Use volume mounts to edit config files without rebuilding
- **Production**: Either copy config files into the image during build, or use environment variables via `WEBHOOKS_CONFIG_FILE` and `CONNECTIONS_CONFIG_FILE`
- **No volume mount needed**: If configs are baked into the image or you're using environment variables only

**Using Environment Variables for Secrets:**
For production, use `env_file` instead of inline `environment` for secrets:

```yaml
services:
  webhook:
    image: spiderhash/webhook:latest
    env_file:
      - .env  # Contains STRIPE_WEBHOOK_SECRET, database passwords, etc.
    volumes:
      - ./webhooks.json:/app/webhooks.json:ro
      - ./connections.json:/app/connections.json:ro
```

Then reference them in config files using `{$VAR_NAME}` syntax.

### Live Config Reload
```bash
export CONFIG_FILE_WATCHING_ENABLED=true
export CONFIG_RELOAD_DEBOUNCE_SECONDS=3.0
```

Or via API:
```bash
curl -X POST http://localhost:8000/admin/reload-config \
  -H "Authorization: Bearer admin_token"
```

---

## TESTING WEBHOOK

```bash
# Simple test
curl -X POST http://localhost:8000/webhook/WEBHOOK_ID \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"event": "test", "data": {"key": "value"}}'

# Check stats (requires Redis - see Stats Endpoint section below)
curl http://localhost:8000/stats
```

## STATS ENDPOINT

The `/stats` endpoint provides webhook usage statistics but **requires Redis** to be running.

**Important**: 
- If you don't need statistics, you can skip Redis setup
- If you want to use `/stats`, you must include Redis in docker-compose.yml and configure `REDIS_HOST` environment variable

**Complete Setup with Stats:**

```yaml
# docker-compose.yml
services:
  webhook:
    image: spiderhash/webhook:latest
    ports:
      - "8000:8000"
    volumes:
      - ./webhooks.json:/app/webhooks.json:ro
      - ./connections.json:/app/connections.json:ro
    environment:
      - PYTHONUNBUFFERED=1
      - REDIS_HOST=redis        # Required for /stats endpoint
      - REDIS_PORT=6379         # Optional, defaults to 6379
    restart: unless-stopped
    depends_on:
      redis:
        condition: service_healthy
    networks:
      - webhook-network
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 10s

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    networks:
      - webhook-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 5s
    volumes:
      - redis_data:/data

networks:
  webhook-network:
    driver: bridge

volumes:
  redis_data:
```

**Note**: The `REDIS_HOST` environment variable must match the Redis service name in docker-compose.yml (e.g., `redis`). If Redis is running on the host machine, use `localhost` or the actual hostname.

---

## RESPONSE FORMAT

When generating configs, always provide:

1. **docker-compose.yml** - Complete Docker Compose setup with:
   - Volume mounts for config files
   - **Healthchecks for all database services** (PostgreSQL, MySQL, etc.)
   - `depends_on` with `condition: service_healthy` for webhook service
   - Matching credentials between docker-compose.yml and connections.json
2. **webhooks.json** - Complete webhook configuration
3. **connections.json** - Connection configuration (use `{}` if no external services needed)
   - **Critical**: Passwords must match exactly with docker-compose.yml environment variables
4. **Start commands** - `docker-compose up -d` and how to check logs
5. **Test commands** - Complete curl examples to test the webhook
6. **Environment variables** - Any secrets to set (if needed)
7. **Comments** - Explain non-obvious settings, especially password matching requirements

---

## DEFAULT WEBHOOK (No Config File)

If `webhooks.json` doesn't exist, the system automatically creates a default logging endpoint:

```json
{
    "default": {
        "data_type": "json",
        "module": "log",
        "module-config": {
            "pretty_print": true,
            "redact_sensitive": false
        }
    }
}
```

This allows ANY webhook_id to work for debugging:
```bash
curl -X POST http://localhost:8000/webhook/anything \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

---

## TROUBLESHOOTING

### Common Errors and Solutions

**401 Unauthorized**
```
{"detail": "Invalid authorization header"}
```
- Check if `Authorization` header matches the `authorization` field in webhooks.json
- For Bearer tokens: include the full "Bearer " prefix
- For HMAC: verify secret matches and signature is calculated correctly

**404 Not Found**
```
{"detail": "Webhook 'xyz' not found"}
```
- Verify webhook_id in URL matches key in webhooks.json
- Check file path: ensure `WEBHOOKS_CONFIG_FILE` points to correct file
- Verify webhooks.json is mounted correctly in Docker

**Connection Refused to Database**
```
Connection refused to postgres:5432
```
- Ensure database service is healthy before webhook starts
- Add `depends_on` with `condition: service_healthy`
- Check that hostnames match (use Docker service names, not localhost)
- Verify passwords match between docker-compose.yml and connections.json

**Connection Field Name Errors**
```
KeyError: 'password'
```
- **PostgreSQL/MySQL**: use `password` field
- **RabbitMQ**: use `pass` field
- Check exact field names in the Module Configurations section

**Rate Limit Exceeded**
```
{"detail": "Rate limit exceeded. Try again in X seconds"}
```
- Increase `max_requests` or `window_seconds` in `rate_limit` config
- For testing, temporarily remove rate_limit configuration

**JSON Schema Validation Failed**
```
{"detail": "Schema validation failed: ..."}
```
- Check payload matches the defined schema
- Test with a simpler schema first
- Verify all `required` fields are present

**HMAC Signature Mismatch**
```
{"detail": "Invalid HMAC signature"}
```
- Verify secret matches exactly (no extra whitespace)
- Check if provider uses hex encoding vs base64
- Confirm algorithm matches (sha256 vs sha1)
- Use env vars `{$SECRET}` to avoid JSON escaping issues

### Debugging Tips

**Enable Debug Logging:**
```yaml
environment:
  - LOG_LEVEL=DEBUG
  - PYTHONUNBUFFERED=1
```

**Test Webhook Locally:**
```bash
# Simple test without auth
curl -X POST http://localhost:8000/webhook/test \
  -H "Content-Type: application/json" \
  -d '{"test": true}'

# With Bearer auth
curl -X POST http://localhost:8000/webhook/test \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your_token" \
  -d '{"test": true}'

# Check health
curl http://localhost:8000/health

# Check if webhook exists
curl http://localhost:8000/docs  # Opens Swagger UI
```

**View Container Logs:**
```bash
# Follow logs
docker-compose logs -f webhook

# Last 100 lines
docker-compose logs --tail=100 webhook

# All services
docker-compose logs -f
```

**Verify Configuration:**
```bash
# Check if config file is mounted
docker-compose exec webhook cat /app/webhooks.json

# Check environment variables
docker-compose exec webhook env | grep -E "(WEBHOOK|REDIS|CONFIG)"
```

**Test Database Connectivity:**
```bash
# PostgreSQL
docker-compose exec postgres pg_isready -U webhook_user -d webhooks

# MySQL
docker-compose exec mysql mysqladmin ping -u webhook_user -pwebhook_pass

# Redis
docker-compose exec redis redis-cli ping
```

### Performance Issues

**High Memory Usage:**
- Reduce `MAX_CONCURRENT_TASKS`
- Enable rate limiting
- Check for payload size limits

**Slow Response Times:**
- Enable parallel chain execution
- Add retry timeouts
- Check backend service health

**Connection Pool Exhaustion:**
- Increase pool size in connection config
- Add connection timeouts
- Check for connection leaks in logs

---

## QUICK REFERENCE

### Webhook Config Structure
```json
{
    "webhook_id": {
        "data_type": "json",           // Required: "json" or "blob"
        "module": "log",               // Required if no chain
        "connection": "conn_name",     // Optional: connection reference
        "module-config": {},           // Optional: module settings
        "authorization": "Bearer x",   // Optional: auth method
        "hmac": {},                     // Optional: HMAC signature
        "ip_whitelist": [],            // Optional: allowed IPs
        "rate_limit": {},              // Optional: rate limiting
        "json_schema": {},             // Optional: payload validation
        "credential_cleanup": {},      // Optional: redact fields
        "chain": [],                   // Optional: multi-destination
        "chain-config": {},            // Optional: chain settings
        "retry": {}                    // Optional: retry config
    }
}
```

### Connection Config Structure
```json
{
    "conn_name": {
        "type": "postgresql",          // Required: service type
        "host": "hostname",            // Required: service host
        "port": 5432,                  // Required: service port
        "user": "username",            // Service-specific fields
        "password": "password",        // (or "pass" for RabbitMQ)
        "database": "dbname"           // Additional fields vary
    }
}
```

### Environment Variable Substitution
```json
{
    "field": "{$VAR_NAME}",            // Required variable
    "field": "{$VAR_NAME:default}",    // With default value
    "field": "prefix_{$VAR}_suffix"    // Embedded in string
}
```