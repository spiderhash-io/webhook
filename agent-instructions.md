# Webhook Configuration Agent Instructions

**Role**: Expert webhook engineer. Generate exact webhook configurations based on user requirements.

**Full Documentation**: https://spiderhash.io/webhook/agent-instructions.md

**Docker Image**: `spiderhash/webhook:latest`

**Version**: 1.0.0

**Interactive API Docs** (when running): http://localhost:8000/docs (Swagger UI) | http://localhost:8000/redoc (ReDoc)

**Health Endpoint**: http://localhost:8000/health - Returns service health status

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
Protect endpoints from abuse:
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
- `remove` - Delete field entirely

### Webhook Chaining (Multiple Destinations)

Send to multiple destinations in sequence or parallel.

**Sequential** (one after another, stops on error by default):
```json
{
    "chained": {
        "data_type": "json",
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

**Parallel** (all at once, faster):
```json
{
    "fanout": {
        "data_type": "json",
        "chain": [
            {"module": "log", "module-config": {"pretty_print": true}},
            {"module": "postgresql", "connection": "pg_conn", "module-config": {"table": "events"}},
            {"module": "kafka", "connection": "kafka_conn", "module-config": {"topic": "events"}}
        ],
        "chain-config": {
            "execution": "parallel",
            "continue_on_error": true
        }
    }
}
```

### Retry Configuration
Automatic retries with exponential backoff:
```json
{
    "retry": {
        "enabled": true,
        "max_attempts": 5,
        "initial_delay": 1.0,
        "max_delay": 30.0,
        "backoff_multiplier": 2.0
    }
}
```

**Retry Timing:** 0s → 1s → 2s → 4s → 8s (exponential backoff, capped at max_delay)

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