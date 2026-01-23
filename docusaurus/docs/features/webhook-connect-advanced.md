# Advanced Webhook Connect

This guide covers advanced configurations for Webhook Connect, including multi-channel setups, webhook chaining, production deployment, security hardening, and performance tuning.

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

### Connector Subscribing to Multiple Channels

```json
{
    "cloud": {
        "url": "wss://webhook-cloud.example.com/connect/stream",
        "connector_id": "prod-processor-01"
    },
    "concurrency": 20,
    "routes": {
        "stripe-payments": {
            "token": "{$STRIPE_CHANNEL_TOKEN}",
            "module": "kafka",
            "connection": "kafka_cluster",
            "module-config": {
                "topic": "payment-events"
            }
        },
        "github-events": {
            "token": "{$GITHUB_CHANNEL_TOKEN}",
            "chain": [
                {
                    "module": "postgresql",
                    "connection": "events_db",
                    "module-config": {
                        "table": "github_events"
                    }
                },
                {
                    "module": "redis_rq",
                    "connection": "job_queue",
                    "module-config": {
                        "queue_name": "ci-triggers"
                    }
                }
            ],
            "chain-config": {
                "execution": "parallel"
            }
        },
        "shopify-orders": {
            "token": "{$SHOPIFY_CHANNEL_TOKEN}",
            "module": "rabbitmq",
            "connection": "order_queue",
            "module-config": {
                "queue_name": "order-processing"
            }
        }
    },
    "connections": {
        "kafka_cluster": {
            "type": "kafka",
            "bootstrap_servers": "kafka-1:9092,kafka-2:9092,kafka-3:9092"
        },
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
        },
        "order_queue": {
            "type": "rabbitmq",
            "host": "rabbitmq-cluster",
            "port": 5672,
            "user": "{$RABBITMQ_USER}",
            "pass": "{$RABBITMQ_PASS}"
        }
    }
}
```

## Webhook Chaining with Relay

Combine Webhook Connect with chaining for complex local routing:

### Sequential Processing

Process webhooks in order - save to database, then queue for processing:

```json
{
    "routes": {
        "payment-events": {
            "token": "payment_token",
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
}
```

### Parallel Fan-Out

Send to multiple destinations simultaneously:

```json
{
    "routes": {
        "order-events": {
            "token": "order_token",
            "chain": [
                {
                    "module": "postgresql",
                    "connection": "orders_db",
                    "module-config": {
                        "table": "orders"
                    }
                },
                {
                    "module": "kafka",
                    "connection": "analytics_kafka",
                    "module-config": {
                        "topic": "order-analytics"
                    }
                },
                {
                    "module": "s3",
                    "connection": "archive_s3",
                    "module-config": {
                        "bucket": "order-archive"
                    }
                },
                {
                    "module": "http_webhook",
                    "module-config": {
                        "url": "http://notification-service/orders"
                    }
                }
            ],
            "chain-config": {
                "execution": "parallel",
                "continue_on_error": true
            }
        }
    }
}
```

### Mixed Sequential and Parallel (Advanced)

For complex workflows, run multiple connectors with different configurations:

**Connector 1 - Primary Processing:**
```json
{
    "routes": {
        "payment-events": {
            "token": "payment_token",
            "chain": [
                {
                    "module": "postgresql",
                    "connection": "primary_db",
                    "module-config": { "table": "payments" }
                }
            ]
        }
    }
}
```

**Connector 2 - Analytics:**
```json
{
    "routes": {
        "payment-events": {
            "token": "payment_token",
            "module": "kafka",
            "connection": "analytics_kafka",
            "module-config": { "topic": "payment-analytics" }
        }
    }
}
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
  name: webhook-connector
spec:
  replicas: 2
  selector:
    matchLabels:
      app: webhook-connector
  template:
    metadata:
      labels:
        app: webhook-connector
    spec:
      containers:
      - name: connector
        image: ghcr.io/your-org/core-webhook-module:latest
        command: ["python", "-m", "src.connector.main", "--config", "/config/connector.json"]
        volumeMounts:
        - name: config
          mountPath: /config
        env:
        - name: STRIPE_CHANNEL_TOKEN
          valueFrom:
            secretKeyRef:
              name: channel-tokens
              key: stripe
        - name: GITHUB_CHANNEL_TOKEN
          valueFrom:
            secretKeyRef:
              name: channel-tokens
              key: github
      volumes:
      - name: config
        configMap:
          name: connector-config
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

### IP Allowlisting

Restrict connector connections to specific IPs:

```json
{
    "stripe_relay": {
        "module": "webhook_connect",
        "module-config": {
            "channel": "stripe-payments",
            "channel_token": "token",
            "allowed_connector_ips": [
                "10.0.0.0/8",
                "192.168.1.100"
            ]
        }
    }
}
```

### Rate Limiting

Apply rate limits to webhook ingestion:

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

```json
{
    "cloud": {
        "url": "wss://webhook-cloud.example.com/connect/stream",
        "connector_id": "high-perf-connector"
    },
    "concurrency": 50,
    "routes": {
        "high-volume-channel": {
            "token": "token",
            "module": "kafka",
            "connection": "kafka_cluster",
            "module-config": {
                "topic": "events",
                "batch_size": 100,
                "linger_ms": 10
            }
        }
    }
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

### Prometheus Metrics

```
# Cloud Receiver Metrics
webhook_connect_messages_received_total{channel="stripe-payments"} 15000
webhook_connect_messages_queued{channel="stripe-payments"} 150
webhook_connect_messages_delivered_total{channel="stripe-payments"} 14850
webhook_connect_connections_active{channel="stripe-payments"} 2
webhook_connect_ingest_latency_seconds{channel="stripe-payments",quantile="0.95"} 0.025

# Connector Metrics
webhook_connector_messages_received_total{channel="stripe-payments"} 500
webhook_connector_messages_acked_total{channel="stripe-payments"} 498
webhook_connector_processing_latency_seconds{quantile="0.95"} 0.150
webhook_connector_connection_status{channel="stripe-payments"} 1
```

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
```

### Health Checks

**Cloud Receiver:**
```bash
curl http://cloud.example.com/health
# {"status": "healthy", "buffer": "connected", "channels": 5}
```

**Connector:**
```bash
curl http://connector:8080/health
# {"status": "healthy", "channels": {"stripe-payments": "connected"}}
```

## Related Documentation

- [Webhook Connect Overview](webhook-connect) - Architecture and concepts
- [Getting Started](webhook-connect-getting-started) - Basic setup guide
- [Troubleshooting](webhook-connect-troubleshooting) - Common issues and solutions
- [Webhook Chaining](webhook-chaining) - Multi-destination routing
