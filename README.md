<div align="center">

# Core Webhook Module

### Receive. Validate. Route. Chain.

The self-hosted webhook gateway with 12 auth methods, 18 destinations, and zero vendor lock-in.

[![CI](https://github.com/spiderhash-io/webhook/actions/workflows/ci.yml/badge.svg)](https://github.com/spiderhash-io/webhook/actions/workflows/ci.yml)
[![Docker Build](https://github.com/spiderhash-io/webhook/actions/workflows/docker-build.yml/badge.svg)](https://github.com/spiderhash-io/webhook/actions/workflows/docker-build.yml)
[![Security Scan](https://github.com/spiderhash-io/webhook/actions/workflows/security-scan.yml/badge.svg)](https://github.com/spiderhash-io/webhook/actions/workflows/security-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.2.0-green.svg)](https://github.com/spiderhash-io/webhook/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/spiderhash/webhook)](https://hub.docker.com/r/spiderhash/webhook)
[![Tests](https://img.shields.io/badge/tests-3%2C300%2B%20passing-brightgreen)](https://github.com/spiderhash-io/webhook)

[Documentation](https://github.com/spiderhash-io/webhook/tree/main/docs) · [Quick Start](#quick-start) · [Configuration](#configuration) · [Docker Hub](https://hub.docker.com/r/spiderhash/webhook)

</div>

---

Core Webhook Module is a FastAPI-powered webhook gateway that receives incoming HTTP webhooks, validates them against 12 authentication methods, and routes payloads to 18 output destinations. Define everything in a simple JSON config, deploy with Docker, and start receiving webhooks in minutes.

```
  Webhook Sources        Core Webhook Module              Destinations

                    +------------------------------+
  GitHub     --->   |                              |  --->  Kafka
  Stripe     --->   |  Authenticate                |  --->  PostgreSQL, MySQL
  Shopify    --->   |  JWT / HMAC / OAuth          |  --->  Redis, RabbitMQ
  Twilio     --->   |  Bearer / Basic / IP         |  --->  S3, ClickHouse
  Any HTTP   --->   |                              |  --->  MQTT, WebSocket
                    |  Validate & Route            |  --->  AWS SQS, GCP Pub/Sub
                    |  Chain to multiple           |  --->  ActiveMQ, ZeroMQ
                    |  destinations                |  --->  HTTP, Disk, Log
                    +------------------------------+
```

---

## Quick Start

### 1. Create a webhook config

```json
{
  "my_webhook": {
    "data_type": "json",
    "module": "log",
    "authorization": "Bearer my-secret-token"
  }
}
```

Save this as `webhooks.json`.

### 2. Run with Docker

```bash
docker run -p 8000:8000 \
  -v $(pwd)/webhooks.json:/app/webhooks.json \
  -e WEBHOOKS_CONFIG_FILE=/app/webhooks.json \
  spiderhash/webhook:0.2.0
```

### 3. Send a webhook

```bash
curl -X POST http://localhost:8000/webhook/my_webhook \
  -H "Authorization: Bearer my-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"event": "order.created", "data": {"id": 123, "total": 49.99}}'
```

That's it. Your webhook is validated and routed. Open `http://localhost:8000/docs` for the auto-generated API docs.

---

## Docker Compose

```yaml
services:
  webhook:
    image: spiderhash/webhook:0.2.0
    ports:
      - "8000:8000"
    volumes:
      - ./webhooks.json:/app/webhooks.json:ro
      - ./connections.json:/app/connections.json:ro
    environment:
      - WEBHOOKS_CONFIG_FILE=/app/webhooks.json
      - CONNECTIONS_CONFIG_FILE=/app/connections.json
    restart: unless-stopped
```

```bash
docker compose up -d
```

**Supported architectures:** `linux/amd64`, `linux/arm64`

16 pre-built compose scenarios are included in `docker/compose/` for every supported destination (Kafka, Redis, RabbitMQ, PostgreSQL, MQTT, S3, and more).

---

## Three Things That Make This Different

### 1. Simple JSON Config — Receive & Route

One JSON file defines your webhooks. Pick a destination, set auth, done.

```json
{
  "github_events": {
    "data_type": "json",
    "module": "kafka",
    "connection": "kafka_prod",
    "module-config": {
      "topic": "github_events"
    },
    "authorization": "Bearer {$GITHUB_TOKEN}",
    "hmac": {
      "secret": "{$GITHUB_SECRET}",
      "header": "X-Hub-Signature-256",
      "algorithm": "sha256"
    }
  }
}
```

Environment variables (`{$VAR}` or `{$VAR:default}`) and Vault secrets (`{$vault:path#field}`) are resolved automatically.

### 2. Webhook Chaining — Multiple Destinations

Route a single webhook to multiple destinations in sequence or parallel. Archive to S3, queue to Kafka, store in PostgreSQL — all from one incoming request.

```json
{
  "order_events": {
    "data_type": "json",
    "chain": [
      {
        "module": "postgresql",
        "connection": "db_prod",
        "module-config": { "table": "orders" }
      },
      {
        "module": "kafka",
        "connection": "kafka_prod",
        "module-config": { "topic": "order_events" }
      },
      {
        "module": "s3",
        "connection": "s3_archive",
        "module-config": { "bucket": "webhook-archive", "prefix": "orders" }
      }
    ],
    "chain-config": {
      "execution": "parallel",
      "continue_on_error": true,
      "timeout": 30
    },
    "authorization": "Bearer {$ORDER_SECRET}"
  }
}
```

Sequential or parallel execution, per-module retry, timeout protection, and automatic task cancellation on failure.

### 3. Webhook Connect — Cloud-to-Local Relay

Receive webhooks at a public cloud endpoint and stream them to services behind firewalls or NAT. Like ngrok, but for webhooks — with message queuing, ACK/NACK, retries, and dead-letter handling.

```
  Cloud (public IP)                       Your Network (behind firewall)

  +------------------------+              +------------------------------+
  |                        |  WebSocket   |                              |
  |  Webhook Receiver      | ---------->  |  Local Connector             |
  |  validates, queues,    |              |  forwards to your            |
  |  retries, DLQ          | <-- ACK ---  |  local services              |
  |                        |              |                              |
  +------------------------+              +------------------------------+
```

**Cloud side** — use the `webhook_connect` module:
```json
{
  "github_to_local": {
    "data_type": "json",
    "module": "webhook_connect",
    "module-config": {
      "channel": "my-channel",
      "channel_token": "{$CHANNEL_TOKEN}"
    },
    "hmac": {
      "secret": "{$GITHUB_SECRET}",
      "header": "X-Hub-Signature-256",
      "algorithm": "sha256"
    }
  }
}
```

**Local side** — connect and forward to local HTTP targets:
```json
{
  "cloud_url": "https://webhooks.example.com",
  "channel": "my-channel",
  "token": "your-channel-token",
  "protocol": "websocket",
  "default_target": {
    "url": "http://localhost:8080/webhook",
    "method": "POST",
    "timeout_seconds": 30
  }
}
```

```bash
python -m src.connector.main --config connector.json
```

WebSocket, SSE, and Long-Poll protocols supported. Token-based auth with rotation. Channel-based isolation.

---

## Features

| | Feature | Details |
|---|---|---|
| **Auth** | **12 Authentication Methods** | JWT, HMAC-SHA256/SHA1/SHA512, OAuth 1.0, OAuth 2.0, Bearer, Basic, Digest, IP Whitelist, Header, Query Param, reCAPTCHA v2/v3, JSON Schema |
| **Route** | **18 Output Destinations** | Kafka, PostgreSQL, MySQL, Redis (RQ + Pub/Sub), RabbitMQ, S3, ClickHouse, MQTT, WebSocket, AWS SQS, GCP Pub/Sub, ActiveMQ, ZeroMQ, HTTP, Disk, Log |
| **Chain** | **Multi-Destination Routing** | Sequential or parallel execution with per-module retry, timeout protection, and continue-on-error |
| **Relay** | **Cloud-to-Local Connect** | Receive webhooks behind firewalls via WebSocket/SSE with ACK/NACK, retries, and dead-letter queue |
| **Config** | **Live Reload** | Hot-reload JSON configs or use etcd for distributed config with namespace isolation |
| **Secrets** | **Vault Integration** | HashiCorp Vault secrets via `{$vault:path#field}` syntax with AppRole auth and TTL caching |
| **Analytics** | **ClickHouse Analytics** | Automatic webhook event logging with distributed analytics processing |
| **Security** | **Enterprise-Grade** | SSRF prevention, constant-time comparison, credential redaction, rate limiting, payload validation |

---

## Output Modules

| Module | Destination | Connection Required |
|--------|-------------|:---:|
| `log` | stdout / structured logging | No |
| `save_to_disk` | Local filesystem | No |
| `http_webhook` | HTTP POST to any URL | No |
| `kafka` | Apache Kafka | Yes |
| `rabbitmq` | RabbitMQ | Yes |
| `redis_rq` | Redis (RQ job queue) | Yes |
| `redis_publish` | Redis (Pub/Sub) | Yes |
| `postgresql` | PostgreSQL (JSONB/relational/hybrid) | Yes |
| `mysql` | MySQL / MariaDB (JSON/relational/hybrid) | Yes |
| `clickhouse` | ClickHouse | Yes |
| `s3` | Amazon S3 / MinIO | Yes |
| `mqtt` | MQTT broker (Mosquitto, etc.) | Yes |
| `websocket` | WebSocket endpoint | No |
| `aws_sqs` | AWS SQS | Yes |
| `gcp_pubsub` | Google Cloud Pub/Sub | Yes |
| `activemq` | Apache ActiveMQ | Yes |
| `zeromq` | ZeroMQ | No |
| `webhook_connect` | Cloud-to-local relay | No |

Modules with connections use `connections.json` for shared connection pools with automatic lifecycle management.

---

## Authentication Methods

| Method | Config Key | Use Case |
|--------|-----------|----------|
| Bearer Token | `authorization` | Simple token auth |
| Basic Auth | `basic_auth` | Username/password |
| JWT | `jwt` | Token validation with issuer/audience/expiry |
| HMAC | `hmac` | Signature verification (GitHub, Stripe, etc.) |
| OAuth 2.0 | `oauth2` | Token introspection or JWT validation with scopes |
| OAuth 1.0 | `oauth1` | Legacy API signatures (Twitter, etc.) |
| HTTP Digest | `digest_auth` | Challenge-response (RFC 7616) |
| IP Whitelist | `ip_whitelist` | Restrict by source IP |
| Header Auth | `header_auth` | Custom header API keys (X-API-Key) |
| Query Param | `query_auth` | Query string API keys |
| reCAPTCHA | `recaptcha` | Google reCAPTCHA v2/v3 bot protection |
| JSON Schema | `json_schema` | Payload structure validation |

All methods can be **combined** — e.g., Bearer + HMAC + IP Whitelist on a single webhook. All secret comparisons use constant-time algorithms.

---

## Configuration

### Configuration Backends

| Backend | Env Var | Description |
|---------|---------|-------------|
| **File** (default) | `CONFIG_BACKEND=file` | JSON files with env var substitution and Vault secrets |
| **etcd** | `CONFIG_BACKEND=etcd` | Distributed config with namespace isolation and real-time watch |

### Environment Variable Substitution

```json
{
  "my_webhook": {
    "module": "rabbitmq",
    "connection": "rmq_prod",
    "authorization": "Bearer {$WEBHOOK_SECRET}",
    "module-config": {
      "queue_name": "{$QUEUE_NAME:default_queue}"
    }
  }
}
```

- `{$VAR}` — required env var
- `{$VAR:default}` — with default value
- `{$vault:path/to/secret#field}` — HashiCorp Vault reference

### Live Config Reload

```bash
# File watching (automatic)
export CONFIG_FILE_WATCHING_ENABLED=true

# Or manual reload via API
curl -X POST http://localhost:8000/admin/reload-config \
  -H "Authorization: Bearer admin_token"
```

Zero-downtime config updates with validation and rollback on errors.

### Connections

External services are defined in `connections.json` and referenced by name:

```json
{
  "kafka_prod": {
    "type": "kafka",
    "bootstrap_servers": "{$KAFKA_BROKERS:localhost:9092}"
  },
  "db_prod": {
    "type": "postgresql",
    "host": "{$DB_HOST}",
    "port": 5432,
    "database": "{$DB_NAME}",
    "user": "{$DB_USER}",
    "password": "{$vault:database/prod#password}"
  }
}
```

---

## Development

```bash
# Install
make install

# Run dev server
make run

# Tests (3,300+ passing)
make test                # Unit tests
make test-all            # All tests
make test-cov            # With coverage

# Code quality
make format              # Black
make lint                # Flake8
make type-check          # Mypy
make security-scan       # Bandit + Safety

# Docker
make docker-build
make docker-up
```

See [DEVELOPMENT.md](docs/DEVELOPMENT.md) for full setup guide and [DEVELOPMENT_STANDARDS.md](docs/DEVELOPMENT_STANDARDS.md) for contribution standards.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/QUICKSTART.md) | Step-by-step getting started guide |
| [Architecture](docs/ARCHITECTURE.md) | System design, module system, adding new modules |
| [Development](docs/DEVELOPMENT.md) | Local dev setup and workflow |
| [Development Standards](docs/DEVELOPMENT_STANDARDS.md) | Code standards, templates, checklists |
| [Webhook Chaining](docs/WEBHOOK_CHAINING_FEATURE.md) | Multi-destination routing patterns |
| [Webhook Connect](docs/WEBHOOK_CONNECT.md) | Cloud-to-local relay setup |
| [Live Config Reload](docs/LIVE_CONFIG_RELOAD_FEATURE.md) | Hot-reload and pool versioning |
| [Distributed Config (etcd)](docs/DISTRIBUTED_CONFIG_ETCD.md) | etcd backend, namespaces, watch |
| [Vault Integration](docs/VAULT_INTEGRATION_GUIDE.md) | HashiCorp Vault secret management |
| [Release Process](docs/RELEASE_PROCESS.md) | Version bump, changelog, tagging, publishing |
| [Security Policy](SECURITY.md) | Vulnerability reporting |
| [Changelog](CHANGELOG.md) | Release history |

---

## Project Structure

```
src/
├── main.py                    # FastAPI app, routes, startup/shutdown
├── webhook.py                 # Core webhook processing and validation
├── config_manager.py          # Live config reload, provider delegation
├── config_provider.py         # ConfigProvider ABC
├── file_config_provider.py    # File-based config (JSON)
├── etcd_config_provider.py    # etcd config (cache + watch + reconnect)
├── vault_secret_resolver.py   # Vault secret resolution
├── validators.py              # 12 auth validators
├── chain_processor.py         # Multi-module sequential/parallel execution
├── connection_pool_registry.py # Connection lifecycle and versioning
├── rate_limiter.py            # Sliding window rate limiting
├── input_validator.py         # Payload validation and sanitization
├── modules/
│   ├── base.py                # Abstract base class for output modules
│   ├── registry.py            # Plugin registry
│   └── *.py                   # 18 output modules
├── webhook_connect/           # Cloud-side relay (WebSocket/SSE streaming)
│   ├── api.py                 # Streaming endpoints
│   ├── channel_manager.py     # Channel management and message queuing
│   └── admin_api.py           # Admin endpoints
└── connector/                 # Local-side connector
    ├── main.py                # Connector service
    ├── stream_client.py       # WebSocket/SSE clients
    └── processor.py           # Message processing and forwarding
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. The project has 3,300+ tests with 90%+ code coverage.

```bash
# Run tests before submitting
make test
make lint
make type-check
```

---

## License

[MIT](LICENSE) — use it however you want.
