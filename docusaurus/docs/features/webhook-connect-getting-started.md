# Getting Started with Webhook Connect

This guide walks you through setting up Webhook Connect step by step, from the simplest local development setup to a basic production configuration.

## Prerequisites

- Core Webhook Module installed
- Redis or RabbitMQ for message buffering
- Basic understanding of webhook configuration

## Step 1: Enable Webhook Connect on Cloud Receiver

First, enable the Webhook Connect feature on your cloud-side deployment.

### Environment Variables

```bash
# Enable the feature
export WEBHOOK_CONNECT_ENABLED=true

# Configure Redis as the message buffer
export WEBHOOK_CONNECT_REDIS_URL=redis://localhost:6379/0

# Set an admin token for channel management
export WEBHOOK_CONNECT_ADMIN_TOKEN=admin_secret_123
```

### Start the Cloud Receiver

```bash
# Using uvicorn directly
uvicorn src.main:app --host 0.0.0.0 --port 8000

# Or using make
make run
```

## Step 2: Configure a Webhook Channel

Create or update your `webhooks.json` to add a webhook that relays to a channel:

```json
{
    "my_relay": {
        "data_type": "json",
        "module": "webhook_connect",
        "module-config": {
            "channel": "my-channel",
            "channel_token": "secret_token_123"
        }
    }
}
```

This creates:
- A webhook endpoint at `/webhook/my_relay`
- A channel named `my-channel` for streaming
- Authentication token `secret_token_123` for connectors

## Step 3: Create Local Connector Configuration

The connector supports two delivery modes. Choose the one that fits your needs:

### Option A: HTTP Mode (Simple Forwarding)

Forward webhooks to a local HTTP endpoint. Best for development or when you have an existing HTTP service.

Create `connector.json`:

```json
{
    "cloud_url": "http://localhost:8000",
    "channel": "my-channel",
    "token": "secret_token_123",
    "protocol": "websocket",
    "default_target": {
        "url": "http://localhost:3000/webhooks",
        "method": "POST",
        "timeout_seconds": 30
    }
}
```

### Option B: Module Mode (Internal Modules)

Dispatch to CWM's built-in modules (log, kafka, save_to_disk, postgresql, etc.) using the standard `webhooks.json` format. Best when you want the connector to process webhooks directly without a separate HTTP service.

Create `connector.json`:

```json
{
    "cloud_url": "http://localhost:8000",
    "channel": "my-channel",
    "token": "secret_token_123",
    "protocol": "websocket",
    "webhooks_config": "./local-webhooks.json"
}
```

Create `local-webhooks.json` (same format as the main CWM webhooks.json):

```json
{
    "my_relay": {
        "module": "log",
        "module-config": {
            "pretty_print": true
        }
    }
}
```

The `webhook_id` from the cloud message maps to the key in your local `webhooks.json`. Auth fields (`authorization`, `data_type`, `rate_limit`) are ignored on the connector side since authentication is already handled on the cloud.

## Step 4: Start the Local Connector

```bash
# With config file
python -m src.connector.main --config connector.json

# Or with CLI arguments (HTTP mode)
python -m src.connector.main \
    --cloud-url http://localhost:8000 \
    --channel my-channel \
    --token secret_token_123 \
    --target-url http://localhost:3000/webhooks

# Or with CLI arguments (Module mode)
python -m src.connector.main \
    --cloud-url http://localhost:8000 \
    --channel my-channel \
    --token secret_token_123 \
    --webhooks-config ./local-webhooks.json
```

You should see output like:
```
============================================================
    Webhook Connect - Local Connector
============================================================
  Channel:   my-channel
  Protocol:  websocket
  Cloud URL: http://localhost:8000
  Mode:      module
============================================================
```

## Step 5: Test the Relay

Send a test webhook to the cloud receiver:

```bash
curl -X POST http://localhost:8000/webhook/my_relay \
  -H "Content-Type: application/json" \
  -d '{"event": "test", "message": "Hello from cloud!"}'
```

You should see the webhook logged in the connector output.

## Step 6: Add Authentication

Secure your webhook endpoint with authentication on the cloud side:

```json
{
    "secured_relay": {
        "data_type": "json",
        "module": "webhook_connect",
        "module-config": {
            "channel": "secure-channel",
            "channel_token": "ch_tok_secure_789"
        },
        "authorization": "Bearer webhook_secret_token",
        "hmac": {
            "secret": "hmac_secret_key",
            "header": "X-Signature",
            "algorithm": "sha256"
        }
    }
}
```

Now external services must provide:
- `Authorization: Bearer webhook_secret_token` header
- Valid HMAC signature in `X-Signature` header

The connector does **not** need to know about these auth settings — authentication is fully handled on the cloud side.

## Step 7: Route to Real Destinations

### HTTP Mode: Forward to Local Service

```json
{
    "cloud_url": "http://localhost:8000",
    "channel": "my-channel",
    "token": "secret_token_123",
    "default_target": {
        "url": "http://localhost:3000/webhooks",
        "method": "POST",
        "timeout_seconds": 30,
        "retry_enabled": true,
        "retry_max_attempts": 3
    }
}
```

### HTTP Mode: Route by Webhook ID

```json
{
    "cloud_url": "http://localhost:8000",
    "channel": "my-channel",
    "token": "secret_token_123",
    "default_target": {
        "url": "http://localhost:3000/default"
    },
    "targets": {
        "stripe_relay": {
            "url": "http://localhost:3000/stripe",
            "method": "POST"
        },
        "github_relay": {
            "url": "http://localhost:3000/github",
            "method": "POST"
        }
    }
}
```

### Module Mode: Route to PostgreSQL

`connector.json`:
```json
{
    "cloud_url": "http://localhost:8000",
    "channel": "my-channel",
    "token": "secret_token_123",
    "webhooks_config": "./local-webhooks.json",
    "connections_config": "./local-connections.json"
}
```

`local-webhooks.json`:
```json
{
    "my_relay": {
        "module": "postgresql",
        "connection": "local_db",
        "module-config": {
            "table": "webhook_events",
            "storage_mode": "json"
        }
    }
}
```

`local-connections.json`:
```json
{
    "local_db": {
        "type": "postgresql",
        "host": "localhost",
        "port": 5432,
        "database": "webhooks",
        "user": "postgres",
        "password": "password"
    }
}
```

### Module Mode: Route to Kafka

`local-webhooks.json`:
```json
{
    "my_relay": {
        "module": "kafka",
        "module-config": {
            "topic": "webhook-events",
            "bootstrap_servers": "localhost:9092"
        }
    }
}
```

### Module Mode: Chain to Multiple Destinations

`local-webhooks.json`:
```json
{
    "my_relay": {
        "chain": ["log", "postgresql"],
        "chain-config": {
            "execution": "parallel"
        },
        "connection": "local_db",
        "module-config": {
            "pretty_print": true
        }
    }
}
```

## Step 8: Use Docker Compose (Recommended)

For easier setup, use Docker Compose:

### docker-compose.yml

```yaml
version: "3.8"

services:
  # Message buffer
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  # Cloud receiver
  cloud-receiver:
    image: core-webhook-module:latest
    ports:
      - "8000:8000"
    environment:
      - WEBHOOK_CONNECT_ENABLED=true
      - WEBHOOK_CONNECT_REDIS_URL=redis://redis:6379/0
      - WEBHOOK_CONNECT_ADMIN_TOKEN=admin_secret
    volumes:
      - ./config/webhooks.json:/app/config/development/webhooks.json
    depends_on:
      - redis

  # Local connector (HTTP mode)
  connector:
    image: core-webhook-module:latest
    command: python -m src.connector.main --config /app/connector.json
    volumes:
      - ./connector.json:/app/connector.json
    depends_on:
      - cloud-receiver
```

Start everything:

```bash
docker-compose up -d
```

## Step 9: Test Resilience

Webhook Connect buffers messages when the connector is offline.

### Test Message Buffering

1. **Stop the connector:**
   ```bash
   docker-compose stop connector
   ```

2. **Send webhooks while connector is down:**
   ```bash
   curl -X POST http://localhost:8000/webhook/my_relay \
     -H "Content-Type: application/json" \
     -d '{"event": "while_offline", "seq": 1}'

   curl -X POST http://localhost:8000/webhook/my_relay \
     -H "Content-Type: application/json" \
     -d '{"event": "while_offline", "seq": 2}'
   ```

3. **Check queue depth:**
   ```bash
   curl -s http://localhost:8000/admin/webhook-connect/channels/my-channel \
     -H "Authorization: Bearer admin_secret" | jq
   ```

   Output shows messages queued:
   ```json
   {
     "name": "my-channel",
     "stats": {
       "messages_queued": 2,
       "connected_clients": 0
     }
   }
   ```

4. **Restart the connector:**
   ```bash
   docker-compose start connector
   ```

5. **Watch messages delivered:**
   ```bash
   docker-compose logs -f connector
   ```

   You'll see both queued messages delivered automatically.

## Verification Checklist

After setup, verify everything works:

- [ ] Cloud receiver starts without errors
- [ ] Connector connects successfully
- [ ] Test webhook reaches connector
- [ ] Webhook is processed by destination module
- [ ] Messages queue when connector is offline
- [ ] Queued messages deliver when connector reconnects
- [ ] Admin API shows channel stats

## Next Steps

- Learn about [advanced configurations](webhook-connect-advanced) including production deployment, token rotation, and performance tuning
- Review [troubleshooting guide](webhook-connect-troubleshooting) for common issues
- Read the [full Webhook Connect reference](webhook-connect) for all configuration options
