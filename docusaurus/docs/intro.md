---
slug: /
---

# Introduction

Welcome to the Core Webhook Module documentation!

The Core Webhook Module is a flexible and configurable webhook receiver and processor built with FastAPI. It receives webhooks, validates them, and forwards the payloads to various destinations such as RabbitMQ, Redis, MQTT, disk, or stdout.

## Status

**Production-ready** with comprehensive security features, 2,493 passing tests, and support for multiple output destinations. All 11 authentication methods implemented!

## Key Features

### Core Functionality
- **Flexible Destinations**: Send webhook data to RabbitMQ, Redis (RQ), local disk, HTTP endpoints, ClickHouse, MQTT, WebSocket, PostgreSQL, MySQL/MariaDB, S3, Kafka, ActiveMQ, AWS SQS, GCP Pub/Sub, ZeroMQ, or stdout.
- **Webhook Chaining**: Send webhook payloads to multiple destinations in sequence or parallel.
- **Plugin Architecture**: Easy to extend with new modules without modifying core code.
- **Configuration-Driven**: Easy configuration via JSON files and environment variables.
- **Live Config Reload**: Hot-reload webhook and connection configurations without restarting the application.

### Security Features
- **11 Authentication Methods**: Bearer tokens, Basic Auth, JWT, HMAC, IP whitelisting, Header-based, Query parameter, Digest Auth, OAuth 1.0, OAuth 2.0, and reCAPTCHA.
- **Multi-Layer Validation**: Combine multiple validators for enhanced security.
- **Payload Validation**: Validates JSON payloads with size, depth, and string length checks.
- **JSON Schema Validation**: Validate incoming payloads against defined JSON schemas.
- **Rate Limiting**: Per-webhook rate limiting with configurable windows.
- **Credential Cleanup**: Automatically masks or removes credentials from payloads and headers.

## Quick Start

### Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn src.main:app --reload
```

### Basic Configuration

Create a `webhooks.json` file:

```json
{
    "my_webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer secret_token"
    }
}
```

Then send a webhook:

```bash
curl -X POST http://localhost:8000/webhook/my_webhook \
  -H "Authorization: Bearer secret_token" \
  -H "Content-Type: application/json" \
  -d '{"event": "test", "data": "example"}'
```

## Documentation Structure

- **[Getting Started](getting-started/installation)**: Installation and basic setup
- **[Modules](modules/intro)**: All 17 output modules
- **[Authentication](authentication/intro)**: All 11 authentication methods
- **[Features](features/intro)**: Core features like webhook chaining, rate limiting, etc.

## Test Status

**2,493 tests passing** ✅ with 90%+ code coverage.

Run tests with:
```bash
make test-all
pytest -v
```
