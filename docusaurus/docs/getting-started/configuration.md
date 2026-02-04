# Configuration

## Configuration Files

The Core Webhook Module uses two main configuration files:

- **`webhooks.json`**: Defines the webhooks to listen for
- **`connections.json`**: Defines connection details for modules (e.g., RabbitMQ, Redis)

## Environment Variable Substitution

Configuration files support environment variable substitution using the `{$VAR}` syntax. This allows you to keep sensitive data out of configuration files and use environment-specific values.

### Supported Patterns

1. **Simple replacement**: `{$VAR}` - Replace entire value with environment variable
2. **With default**: `{$VAR:default}` - Use environment variable or default value if not set
3. **Embedded in strings**: Variables can be embedded within strings: `"http://{$HOST}:{$PORT}/api"`

### Examples

**In `connections.json`:**
```json
{
    "redis_prod": {
        "type": "redis-rq",
        "host": "{$REDIS_HOST}",
        "port": "{$REDIS_PORT:6379}",
        "db": "{$REDIS_DB:0}"
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
        }
    }
}
```

## Basic Webhook Configuration

```json
{
    "webhook_id": {
        "data_type": "json",
        "module": "log",
        "authorization": "secret_token"
    }
}
```

## Connection Configuration

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

## Live Configuration Reload

The application supports hot-reloading of configuration files without restart.

### Setup

**1. Configure Admin Authentication (Required):**

:::warning
Admin API endpoints are **disabled** if `CONFIG_RELOAD_ADMIN_TOKEN` is not set.
They will return `403 Forbidden` for all requests.
:::

```bash
# Generate a secure token
export CONFIG_RELOAD_ADMIN_TOKEN=$(openssl rand -base64 32)
```

**2. Enable File Watching (Optional):**
```bash
export CONFIG_FILE_WATCHING_ENABLED=true
export CONFIG_RELOAD_DEBOUNCE_SECONDS=3.0
```

**3. Manual Reload via API:**
```bash
# Reload webhook configurations
curl -X POST http://localhost:8000/admin/reload-config \
  -H "Authorization: Bearer $CONFIG_RELOAD_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reload_webhooks": true}'

# Reload connection configurations
curl -X POST http://localhost:8000/admin/reload-config \
  -H "Authorization: Bearer $CONFIG_RELOAD_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reload_connections": true}'
```

**Features:**
- Automatic file watching with debouncing (default: 3 seconds)
- Thread-safe configuration updates
- Connection pool lifecycle management
- Validation before applying changes
- Rollback on errors
- Zero-downtime updates

See [Live Config Reload](../features/live-config-reload.md) for detailed documentation.

