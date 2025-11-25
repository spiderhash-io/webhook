# Core Webhook Module

A flexible and configurable webhook receiver and processor built with FastAPI. It receives webhooks, validates them, and forwards the payloads to various destinations such as RabbitMQ, Redis, disk, or stdout.

## Features

### Core Functionality
- **Flexible Destinations**: Send webhook data to RabbitMQ, Redis (RQ), local disk, HTTP endpoints, or stdout.
- **Plugin Architecture**: Easy to extend with new modules without modifying core code.
- **Configuration-Driven**: Easy configuration via JSON files (`webhooks.json`, `connections.json`) and environment variables.
- **Statistics**: Tracks webhook usage statistics (requests per minute, hour, day, etc.) via `/stats`.

### Security Features
- **Authorization**: Supports Authorization header validation (including Bearer tokens).
- **HMAC Verification**: Validates webhook signatures using HMAC-SHA256/SHA1/SHA512.
- **IP Whitelisting**: Restrict webhooks to specific IP addresses.
- **Multi-Layer Validation**: Combine multiple validators (Authorization + HMAC + IP whitelist).
- **Payload Validation**: Validates JSON payloads.

## Project Structure

- `src/main.py`: Entry point, FastAPI app, and route definitions.
- `src/webhook.py`: Core logic for handling and processing webhooks.
- `src/config.py`: Configuration loading and injection.
- `src/modules/`: Output modules (RabbitMQ, Redis, etc.).
  - `base.py`: Abstract base class for all modules
  - `registry.py`: Module registry for plugin management
  - `log.py`, `save_to_disk.py`, `rabbitmq_module.py`, `redis_rq.py`: Individual modules
- `src/utils.py`: Utility functions and in-memory statistics.
- `ARCHITECTURE.md`: Detailed architecture documentation

**See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed architecture documentation and how to add new modules.**

## Installation & Running

### Local
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the server:
   ```bash
   uvicorn src.main:app --reload
   ```

### Docker
```bash
docker-compose up --build
```

## Configuration

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

#### Basic Authorization
```json
{
    "webhook_id": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer secret_token_123"
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
- [ ] **Persistent Statistics**: Move stats from in-memory (`src/utils.py`) to Redis or a database to survive restarts.
- [ ] **Dynamic OpenAPI Docs**: Generate OpenAPI documentation automatically based on `webhooks.json` config.
- [ ] **Payload Transformation**: Add a step to transform payload structure before sending to destination.
- [ ] **Retry Mechanism**: Implement retries for failed module executions (e.g., if RabbitMQ is down).

### 4. Testing & Documentation
- [ ] **Unit Tests**: Expand `tests/` to cover all modules and validation logic.
- [ ] **Integration Tests**: Test full flow with running RabbitMQ/Redis containers.
