# Advanced Webhook Connect

This guide covers advanced configurations for Webhook Connect, including multi-channel setups, module mode, production deployment, security hardening, and performance tuning.

## Multi-Channel Configuration

### Cloud Receiver with Multiple Channels

Configure multiple webhooks to relay to different channels:

```json
{
    "stripe_relay": {
        "data_type": "json",
        "module": "webhook_connect",
        "module-config": {
            "channel": "stripe-payments",
            "channel_token": "{$STRIPE_CHANNEL_TOKEN}",
            "ttl_seconds": 86400,
            "max_queue_size": 10000
        },
        "hmac": {
            "secret": "{$STRIPE_WEBHOOK_SECRET}",
            "header": "X-Stripe-Signature",
            "algorithm": "sha256"
        }
    },
    "github_relay": {
        "data_type": "json",
        "module": "webhook_connect",
        "module-config": {
            "channel": "github-events",
            "channel_token": "{$GITHUB_CHANNEL_TOKEN}",
            "ttl_seconds": 43200
        },
        "hmac": {
            "secret": "{$GITHUB_WEBHOOK_SECRET}",
            "header": "X-Hub-Signature-256",
            "algorithm": "sha256"
        }
    },
    "shopify_relay": {
        "data_type": "json",
        "module": "webhook_connect",
        "module-config": {
            "channel": "shopify-orders",
            "channel_token": "{$SHOPIFY_CHANNEL_TOKEN}"
        },
        "hmac": {
            "secret": "{$SHOPIFY_WEBHOOK_SECRET}",
            "header": "X-Shopify-Hmac-SHA256",
            "algorithm": "sha256"
        }
    }
}
```

### One Connector Per Channel

Each connector subscribes to a single channel. To process multiple channels, run multiple connector instances:

**Connector 1 — Stripe payments (module mode):**

`connector-stripe.json`:
```json
{
    "cloud_url": "https://webhook-cloud.example.com",
    "channel": "stripe-payments",
    "token": "{$STRIPE_CHANNEL_TOKEN}",
    "protocol": "websocket",
    "max_concurrent_requests": 20,
    "webhooks_config": "./stripe-webhooks.json",
    "connections_config": "./connections.json"
}
```

`stripe-webhooks.json`:
```json
{
    "stripe_relay": {
        "module": "kafka",
        "module-config": {
            "topic": "payment-events",
            "bootstrap_servers": "kafka-1:9092,kafka-2:9092"
        }
    }
}
```

**Connector 2 — GitHub events (module mode with chaining):**

`connector-github.json`:
```json
{
    "cloud_url": "https://webhook-cloud.example.com",
    "channel": "github-events",
    "token": "{$GITHUB_CHANNEL_TOKEN}",
    "protocol": "websocket",
    "webhooks_config": "./github-webhooks.json",
    "connections_config": "./connections.json"
}
```

`github-webhooks.json`:
```json
{
    "github_relay": {
        "chain": ["postgresql", "redis_rq"],
        "chain-config": {
            "execution": "parallel"
        },
        "connection": "events_db",
        "module-config": {
            "table": "github_events"
        }
    }
}
```

**Connector 3 — Shopify orders (HTTP mode):**

`connector-shopify.json`:
```json
{
    "cloud_url": "https://webhook-cloud.example.com",
    "channel": "shopify-orders",
    "token": "{$SHOPIFY_CHANNEL_TOKEN}",
    "protocol": "websocket",
    "default_target": {
        "url": "http://order-service:8080/webhooks",
        "method": "POST",
        "timeout_seconds": 30,
        "retry_enabled": true,
        "retry_max_attempts": 5
    }
}
```

Shared `connections.json`:
```json
{
    "events_db": {
        "type": "postgresql",
        "host": "postgres-primary",
        "port": 5432,
        "database": "events",
        "user": "{$DB_USER}",
        "password": "{$DB_PASSWORD}"
    },
    "job_queue": {
        "type": "redis",
        "host": "redis-master",
        "port": 6379
    }
}
```

## Module Mode Deep Dive

Module mode lets the connector dispatch to the same internal modules used by the main webhook processor. This means you can reuse your existing `webhooks.json` configuration.

### How It Works

1. Cloud receiver receives webhook, buffers it with `webhook_id`
2. Connector receives the message containing `{webhook_id, payload, headers}`
3. ModuleProcessor looks up `webhook_id` in the local `webhooks.json`
4. Dispatches to the configured module (or chain) via ModuleRegistry/ChainProcessor
5. On success → ACK, on failure → NACK (with retry)

### Config Fields Used vs Ignored

The connector uses a subset of the webhook config fields:

| Field | Used | Notes |
|-------|------|-------|
| `module` | Yes | Which output module to use |
| `module-config` | Yes | Module-specific settings |
| `chain` | Yes | Multi-module chain |
| `chain-config` | Yes | Chain execution settings (sequential/parallel) |
| `connection` | Yes | Named connection reference |
| `authorization` | No | Auth handled on cloud side |
| `data_type` | No | Parsing handled on cloud side |
| `rate_limit` | No | Rate limiting handled on cloud side |
| `allowed_ips` | No | IP filtering handled on cloud side |
| `require_https` | No | Transport handled on cloud side |

### Webhook Chaining in Module Mode

Sequential processing — save to database, then queue for processing:

`webhooks.json`:
```json
{
    "payment-events": {
        "chain": [
            {
                "module": "postgresql",
                "connection": "primary_db",
                "module-config": {
                    "table": "payment_events",
                    "storage_mode": "json"
                }
            },
            {
                "module": "redis_rq",
                "connection": "job_redis",
                "module-config": {
                    "queue_name": "payment-processor"
                }
            },
            {
                "module": "http_webhook",
                "module-config": {
                    "url": "http://internal-api:8080/notify",
                    "method": "POST"
                }
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": false
        }
    }
}
```

Parallel fan-out — send to multiple destinations simultaneously:

```json
{
    "order-events": {
        "chain": [
            {
                "module": "postgresql",
                "connection": "orders_db",
                "module-config": { "table": "orders" }
            },
            {
                "module": "kafka",
                "module-config": {
                    "topic": "order-analytics",
                    "bootstrap_servers": "kafka:9092"
                }
            },
            {
                "module": "s3",
                "module-config": { "bucket": "order-archive" }
            }
        ],
        "chain-config": {
            "execution": "parallel",
            "continue_on_error": true
        }
    }
}
```

### Environment Variable Configuration

All connector settings can be set via environment variables:

```bash
export CONNECTOR_CLOUD_URL=https://webhook-cloud.example.com
export CONNECTOR_CHANNEL=my-channel
export CONNECTOR_TOKEN=secret_token
export CONNECTOR_PROTOCOL=websocket
export CONNECTOR_WEBHOOKS_CONFIG=/etc/cwm/webhooks.json
export CONNECTOR_CONNECTIONS_CONFIG=/etc/cwm/connections.json
export CONNECTOR_MAX_CONCURRENT_REQUESTS=20
export CONNECTOR_LOG_LEVEL=INFO
```

## Production Deployment

### High Availability Cloud Receiver

Deploy multiple cloud receiver instances behind a load balancer:

```yaml
# docker-compose.prod.yml
version: "3.8"

services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    depends_on:
      - cloud-receiver-1
      - cloud-receiver-2
      - cloud-receiver-3

  cloud-receiver-1:
    image: core-webhook-module:latest
    environment:
      - WEBHOOK_CONNECT_ENABLED=true
      - WEBHOOK_CONNECT_REDIS_URL=redis://redis-sentinel:26379/0
      - WEBHOOK_CONNECT_ADMIN_TOKEN=${ADMIN_TOKEN}
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G

  cloud-receiver-2:
    image: core-webhook-module:latest
    environment:
      - WEBHOOK_CONNECT_ENABLED=true
      - WEBHOOK_CONNECT_REDIS_URL=redis://redis-sentinel:26379/0
      - WEBHOOK_CONNECT_ADMIN_TOKEN=${ADMIN_TOKEN}

  cloud-receiver-3:
    image: core-webhook-module:latest
    environment:
      - WEBHOOK_CONNECT_ENABLED=true
      - WEBHOOK_CONNECT_REDIS_URL=redis://redis-sentinel:26379/0
      - WEBHOOK_CONNECT_ADMIN_TOKEN=${ADMIN_TOKEN}

  redis-sentinel:
    image: redis:7-alpine
    command: redis-sentinel /etc/redis/sentinel.conf
    volumes:
      - ./sentinel.conf:/etc/redis/sentinel.conf
```

### Kubernetes Deployment

```yaml
# cloud-receiver-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-cloud-receiver
spec:
  replicas: 3
  selector:
    matchLabels:
      app: webhook-cloud-receiver
  template:
    metadata:
      labels:
        app: webhook-cloud-receiver
    spec:
      containers:
      - name: webhook-receiver
        image: ghcr.io/your-org/core-webhook-module:latest
        ports:
        - containerPort: 8000
        env:
        - name: WEBHOOK_CONNECT_ENABLED
          value: "true"
        - name: WEBHOOK_CONNECT_REDIS_URL
          valueFrom:
            secretKeyRef:
              name: webhook-secrets
              key: redis-url
        - name: WEBHOOK_CONNECT_ADMIN_TOKEN
          valueFrom:
            secretKeyRef:
              name: webhook-secrets
              key: admin-token
        resources:
          requests:
            cpu: "500m"
            memory: "512Mi"
          limits:
            cpu: "2000m"
            memory: "2Gi"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: webhook-cloud-receiver
spec:
  selector:
    app: webhook-cloud-receiver
  ports:
  - port: 80
    targetPort: 8000
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: webhook-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - webhooks.example.com
    secretName: webhook-tls
  rules:
  - host: webhooks.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: webhook-cloud-receiver
            port:
              number: 80
```

### Connector Deployment

```yaml
# connector-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-connector-stripe
spec:
  replicas: 2
  selector:
    matchLabels:
      app: webhook-connector-stripe
  template:
    metadata:
      labels:
        app: webhook-connector-stripe
    spec:
      containers:
      - name: connector
        image: ghcr.io/your-org/core-webhook-module:latest
        command: ["python", "-m", "src.connector.main", "--config", "/config/connector.json"]
        volumeMounts:
        - name: config
          mountPath: /config
        env:
        - name: CONNECTOR_TOKEN
          valueFrom:
            secretKeyRef:
              name: channel-tokens
              key: stripe
      volumes:
      - name: config
        configMap:
          name: connector-stripe-config
```

## Security Hardening

### Token Rotation

Rotate channel tokens without downtime using the admin API:

```bash
# Rotate token with 1-hour grace period
curl -X POST https://webhook-cloud.example.com/admin/channels/stripe-payments/rotate-token \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"grace_period_seconds": 3600}'
```

Response:
```json
{
  "channel": "stripe-payments",
  "new_token": "ch_tok_new_xyz789...",
  "old_token_expires_at": "2026-01-16T11:30:00Z"
}
```

Update connectors with the new token during the grace period.

### Rate Limiting

Apply rate limits to webhook ingestion on the cloud side:

```json
{
    "stripe_relay": {
        "module": "webhook_connect",
        "module-config": {
            "channel": "stripe-payments",
            "channel_token": "token"
        },
        "rate_limit": {
            "max_requests": 1000,
            "window_seconds": 60
        }
    }
}
```

### Credential Cleanup

Automatically redact sensitive data:

```json
{
    "stripe_relay": {
        "module": "webhook_connect",
        "module-config": {
            "channel": "stripe-payments",
            "channel_token": "token"
        },
        "credential_cleanup": {
            "enabled": true,
            "mode": "mask",
            "fields": ["api_key", "secret", "password"]
        }
    }
}
```

## Performance Tuning

### Cloud Receiver Tuning

| Setting | Default | Description | Recommendation |
|---------|---------|-------------|----------------|
| `ttl_seconds` | 86400 | Message TTL | Reduce for high-volume channels |
| `max_queue_size` | 10000 | Max queued messages | Increase for burst tolerance |
| `max_connections` | 10 | Max connectors per channel | Increase for HA setups |
| `max_in_flight` | 100 | Unacked messages per connector | Tune based on processing speed |

### Connector Tuning

Key settings for high-throughput connectors:

```json
{
    "cloud_url": "https://webhook-cloud.example.com",
    "channel": "high-volume-channel",
    "token": "token",
    "protocol": "websocket",
    "max_concurrent_requests": 50,
    "reconnect_delay": 1.0,
    "max_reconnect_delay": 30.0,
    "heartbeat_timeout": 60.0,
    "webhooks_config": "./webhooks.json"
}
```

### Buffer Backend Selection

**Redis (Recommended for most cases):**
- Lower latency
- Simpler setup
- Good for up to ~10,000 msg/sec per channel

**RabbitMQ (For complex routing):**
- Better message guarantees
- Built-in dead letter handling
- Better for very high volumes

```bash
# Use RabbitMQ instead of Redis
export WEBHOOK_CONNECT_BUFFER=rabbitmq
export WEBHOOK_CONNECT_RABBITMQ_URL=amqp://user:pass@rabbitmq:5672/
```

## Monitoring

### Admin API Endpoints

```bash
# List all channels
curl -s https://cloud.example.com/admin/webhook-connect/channels \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Get channel details
curl -s https://cloud.example.com/admin/webhook-connect/channels/stripe-payments \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Get channel stats
curl -s https://cloud.example.com/admin/webhook-connect/channels/stripe-payments/stats \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# View dead letter queue
curl -s https://cloud.example.com/admin/webhook-connect/channels/stripe-payments/dead-letters \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Get overview of all channels
curl -s https://cloud.example.com/admin/webhook-connect/overview \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### Health Checks

**Cloud Receiver:**
```bash
curl http://cloud.example.com/admin/webhook-connect/health
# {"status": "healthy"}
```

## Related Documentation

- [Webhook Connect Overview](webhook-connect) - Architecture and concepts
- [Getting Started](webhook-connect-getting-started) - Basic setup guide
- [Troubleshooting](webhook-connect-troubleshooting) - Common issues and solutions
- [Webhook Chaining](webhook-chaining) - Multi-destination routing
