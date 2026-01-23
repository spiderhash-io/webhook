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

Create a `connector.json` file for the local connector:

```json
{
    "cloud": {
        "url": "http://localhost:8000/connect/stream",
        "connector_id": "my-local-connector"
    },
    "routes": {
        "my-channel": {
            "token": "secret_token_123",
            "module": "log"
        }
    }
}
```

This configures:
- Connection to the cloud receiver at `localhost:8000`
- Subscription to `my-channel`
- Logging received webhooks to stdout

## Step 4: Start the Local Connector

```bash
python -m src.connector.main --config connector.json
```

You should see output like:
```
Starting Webhook Connector...
Cloud URL: http://localhost:8000/connect/stream
Channels: ['my-channel']
[my-channel] Connecting to http://localhost:8000/connect/stream/my-channel...
[my-channel] Connected!
```

## Step 5: Test the Relay

Send a test webhook to the cloud receiver:

```bash
curl -X POST http://localhost:8000/webhook/my_relay \
  -H "Content-Type: application/json" \
  -d '{"event": "test", "message": "Hello from cloud!"}'
```

You should see the webhook logged in the connector output:
```
[my-channel] Received: msg_abc123def456
{"event": "test", "message": "Hello from cloud!"}
[my-channel] ACK: msg_abc123def456
```

## Step 6: Add Authentication

Secure your webhook endpoint with authentication:

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

## Step 7: Route to a Real Destination

Instead of just logging, route webhooks to a useful destination:

### Route to Redis Queue

```json
{
    "cloud": {
        "url": "http://localhost:8000/connect/stream",
        "connector_id": "processor-01"
    },
    "routes": {
        "my-channel": {
            "token": "secret_token_123",
            "module": "redis_rq",
            "connection": "local_redis",
            "module-config": {
                "queue_name": "webhook_processing"
            }
        }
    },
    "connections": {
        "local_redis": {
            "type": "redis",
            "host": "localhost",
            "port": 6379
        }
    }
}
```

### Route to PostgreSQL

```json
{
    "cloud": {
        "url": "http://localhost:8000/connect/stream",
        "connector_id": "db-writer-01"
    },
    "routes": {
        "my-channel": {
            "token": "secret_token_123",
            "module": "postgresql",
            "connection": "local_db",
            "module-config": {
                "table": "webhook_events",
                "storage_mode": "json"
            }
        }
    },
    "connections": {
        "local_db": {
            "type": "postgresql",
            "host": "localhost",
            "port": 5432,
            "database": "webhooks",
            "user": "postgres",
            "password": "password"
        }
    }
}
```

### Route to Kafka

```json
{
    "cloud": {
        "url": "http://localhost:8000/connect/stream",
        "connector_id": "kafka-publisher-01"
    },
    "routes": {
        "my-channel": {
            "token": "secret_token_123",
            "module": "kafka",
            "connection": "local_kafka",
            "module-config": {
                "topic": "webhook-events"
            }
        }
    },
    "connections": {
        "local_kafka": {
            "type": "kafka",
            "bootstrap_servers": "localhost:9092"
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

  # Local connector
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

## Common Patterns

### Pattern 1: Simple Logging (Development)

```json
{
    "routes": {
        "my-channel": {
            "token": "dev_token",
            "module": "log"
        }
    }
}
```

### Pattern 2: Save to Disk (Debugging)

```json
{
    "routes": {
        "my-channel": {
            "token": "debug_token",
            "module": "save_to_disk",
            "module-config": {
                "path": "/var/log/webhooks"
            }
        }
    }
}
```

### Pattern 3: Forward to Local HTTP Service

```json
{
    "routes": {
        "my-channel": {
            "token": "forward_token",
            "module": "http_webhook",
            "module-config": {
                "url": "http://localhost:3000/webhooks",
                "method": "POST"
            }
        }
    }
}
```

### Pattern 4: Multiple Destinations (Chaining)

```json
{
    "routes": {
        "my-channel": {
            "token": "chain_token",
            "chain": [
                {
                    "module": "postgresql",
                    "connection": "local_db",
                    "module-config": {
                        "table": "webhook_events"
                    }
                },
                {
                    "module": "redis_rq",
                    "connection": "local_redis",
                    "module-config": {
                        "queue_name": "processing"
                    }
                }
            ],
            "chain-config": {
                "execution": "parallel"
            }
        }
    }
}
```

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

- Learn about [advanced configurations](webhook-connect-advanced) including multi-channel setups, production deployment, and webhook chaining
- Review [troubleshooting guide](webhook-connect-troubleshooting) for common issues
- Read the [full Webhook Connect reference](webhook-connect) for all configuration options
