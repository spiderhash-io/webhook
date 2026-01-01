# Webhook Configuration Agent Instructions

**Role**: Expert webhook engineer. Generate exact webhook configurations based on user requirements.

**Full Documentation**: https://spiderhash.com/webhook/agent-instructions.md

**Docker Image**: `spiderhash/webhook:latest`

**Interactive API Docs** (when running): http://localhost:8000/docs (Swagger UI) | http://localhost:8000/redoc (ReDoc)

---

## CORE PRINCIPLE: START SIMPLE

Always create the **simplest working configuration first**. Add advanced features (rate limiting, HMAC, chaining, etc.) only when explicitly requested.

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
- **Default**: `config/development/webhooks.json` and `config/development/connections.json`
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

## OUTPUT MODULES (17 Available)

| Module | Use Case | Requires Connection |
|--------|----------|---------------------|
| `log` | Debug/testing, print to console | No |
| `save_to_disk` | Save files locally | No |
| `rabbitmq` | Message queue | Yes |
| `redis_rq` | Task queue (RQ workers) | Yes |
| `redis_publish` | Pub/Sub messaging | No (inline config) |
| `kafka` | Event streaming | Yes |
| `mqtt` | IoT messaging | Yes |
| `postgresql` | Relational DB storage | Yes |
| `mysql` | Relational DB storage | Yes |
| `clickhouse` | Analytics database | Yes |
| `s3` | Object storage | Yes |
| `http_webhook` | Forward to another URL | No |
| `websocket` | Real-time forwarding | No |
| `activemq` | Enterprise messaging | Yes |
| `aws_sqs` | AWS queue | Yes |
| `gcp_pubsub` | GCP messaging | Yes |
| `zeromq` | High-perf messaging | Yes |

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
        "host": "localhost",
        "port": 5672,
        "user": "guest",
        "pass": "guest"
    }
}
```

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
        "host": "localhost",
        "port": 5432,
        "user": "postgres",
        "pass": "postgres",
        "database": "webhooks"
    }
}
```

**MySQL**
```json
// Same structure as PostgreSQL
{
    "mysql_conn": {
        "type": "mysql",
        "host": "localhost",
        "port": 3306,
        "user": "root",
        "pass": "password",
        "database": "webhooks"
    }
}
```

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

---

## AUTHENTICATION METHODS (11 Available)

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

**JWT**
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

### Advanced Auth (When Requested)

**HMAC Signature** (GitHub, Stripe, etc.)
```json
{
    "hmac": {
        "secret": "webhook_secret",
        "header": "X-Hub-Signature-256",  // GitHub format
        "algorithm": "sha256"
    }
}
```

**IP Whitelist**
```json
{
    "ip_whitelist": ["192.168.1.100", "10.0.0.0/8"]
}
```

**OAuth 2.0**
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

**reCAPTCHA**
```json
{
    "recaptcha": {
        "secret_key": "your_recaptcha_secret",
        "version": "v3",
        "token_source": "header",
        "token_field": "X-Recaptcha-Token",
        "min_score": 0.5
    }
}
```

### Combined Auth (Multi-Layer)
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
        "ip_whitelist": ["10.0.0.0/8"]
    }
}
```

---

## ADVANCED FEATURES (Only When Asked)

### Rate Limiting
```json
{
    "rate_limit": {
        "max_requests": 100,
        "window_seconds": 60
    }
}
```

### JSON Schema Validation
```json
{
    "json_schema": {
        "type": "object",
        "properties": {
            "event": {"type": "string"},
            "data": {"type": "object"}
        },
        "required": ["event", "data"]
    }
}
```

### Credential Cleanup
```json
{
    "credential_cleanup": {
        "enabled": true,
        "mode": "mask",  // or "remove"
        "fields": ["password", "api_key", "custom_secret"]
    }
}
```

### Webhook Chaining (Multiple Destinations)

**Sequential** (one after another)
```json
{
    "chained": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_conn",
                "module-config": {"bucket": "archive"}
            },
            {
                "module": "rabbitmq",
                "connection": "rmq_conn",
                "module-config": {"queue_name": "process"}
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": true
        }
    }
}
```

**Parallel** (all at once)
```json
{
    "chain-config": {
        "execution": "parallel",
        "continue_on_error": true
    }
}
```

### Retry Configuration
```json
{
    "retry": {
        "enabled": true,
        "max_attempts": 5,
        "initial_delay": 1.0,
        "max_delay": 10.0,
        "backoff_multiplier": 2.0
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
{
    "stripe": {
        "data_type": "json",
        "module": "postgresql",
        "connection": "pg_conn",
        "module-config": {"table": "stripe_events"},
        "hmac": {
            "secret": "{$STRIPE_WEBHOOK_SECRET}",
            "header": "Stripe-Signature",
            "algorithm": "sha256"
        }
    }
}
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

---

## DEPLOYMENT

### Docker (Single Instance)
```bash
docker pull spiderhash/webhook:latest

docker run --rm \
  -p 8000:8000 \
  -v "$(pwd)/config/development:/app/config/development:ro" \
  --env-file .env \
  spiderhash/webhook:latest
```

### Docker Compose
```yaml
services:
  webhook:
    image: spiderhash/webhook:latest
    ports:
      - "8000:8000"
    volumes:
      - ./config/development:/app/config/development:ro
    environment:
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
```

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

# Check stats
curl http://localhost:8000/stats
```

---

## RESPONSE FORMAT

When generating configs, always provide:

1. **webhooks.json** - Complete configuration
2. **connections.json** - If external services needed
3. **Environment variables** - Any secrets to set
4. **Test command** - curl example to test
5. **Comments** - Explain non-obvious settings

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

