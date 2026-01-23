# Webhook Connect (Cloud-to-Local Relay)

Receive webhooks at a cloud endpoint and relay them to local networks behind firewalls or NAT. Similar to ngrok, but purpose-built for production webhook routing with message buffering, authentication, and reliable delivery.

## Overview

Webhook Connect enables secure, real-time forwarding of webhook data between geographically distributed locations through an HTTP-based relay system. It allows you to receive webhooks at one location and reliably deliver them to processing systems at another location, even when those systems are behind firewalls or in private networks.

**Key Benefits:**
- **Firewall-Friendly**: Only outbound HTTP/HTTPS connections required - no inbound ports needed
- **Reliable Delivery**: Messages are buffered during connector downtime and delivered when it reconnects
- **Same Module System**: Use all 17+ output modules on the local side
- **Webhook Chaining**: Combine with chaining to route to multiple local destinations
- **Production-Ready**: Built-in authentication, rate limiting, and monitoring

## Architecture

```
┌─────────────────┐      ┌─────────────────────────────────────────────────┐
│  External       │      │              Cloud Receiver                      │
│  Services       │      │  ┌─────────────────┐    ┌─────────────────────┐ │
│  (Stripe,       │ HTTP │  │  Webhook API    │    │  Message Buffer     │ │
│   GitHub,       │ ────►│  │  /webhook/{id}  │───►│  (Redis/RabbitMQ)   │ │
│   etc.)         │      │  │  - Validates    │    │  - Not exposed      │ │
└─────────────────┘      │  │  - Authenticates│    │  - Internal only    │ │
                         │  └─────────────────┘    └───────────┬─────────┘ │
                         │                                      │           │
                         │  ┌─────────────────────────────────┐ │           │
                         │  │  Streaming API                  │◄┘           │
                         │  │  /connect/stream/{channel}      │             │
                         │  │  - WebSocket or SSE             │             │
                         │  └───────────────┬─────────────────┘             │
                         └──────────────────┼───────────────────────────────┘
                                            │
                                            │ HTTP/WebSocket (outbound)
                                            ▼
                         ┌─────────────────────────────────────────────────┐
                         │              Local Connector                     │
                         │                                                  │
                         │  - Connects outbound via HTTP/WebSocket         │
                         │  - Receives webhooks from stream                │
                         │  - Routes to local destinations                 │
                         │                                                  │
                         │    ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐  │
                         │    │ Kafka  │ │ Redis  │ │Postgres│ │  HTTP  │  │
                         │    └────────┘ └────────┘ └────────┘ └────────┘  │
                         └─────────────────────────────────────────────────┘
```

## Communication Flow

1. **External Service** sends webhook via HTTP POST to Cloud Receiver
2. **Cloud Receiver** validates, authenticates, and buffers to internal queue
3. **Cloud Receiver** returns `200 OK` to External Service immediately
4. **Local Connector** connects outbound via WebSocket/SSE to Cloud Receiver
5. **Cloud Receiver** streams webhook data to Connector
6. **Connector** processes and routes to local destinations
7. **Connector** sends acknowledgment after successful delivery
8. **Cloud Receiver** removes message from queue

## Quick Start

### 1. Cloud Side Configuration

Enable Webhook Connect and configure a webhook to relay:

**Environment Variables:**
```bash
export WEBHOOK_CONNECT_ENABLED=true
export WEBHOOK_CONNECT_REDIS_URL=redis://localhost:6379/0
export WEBHOOK_CONNECT_ADMIN_TOKEN=your_admin_secret
```

**webhooks.json:**
```json
{
    "stripe_relay": {
        "data_type": "json",
        "module": "webhook_connect",
        "module-config": {
            "channel": "stripe-payments",
            "channel_token": "ch_tok_abc123secret",
            "ttl_seconds": 86400
        },
        "hmac": {
            "secret": "{$STRIPE_WEBHOOK_SECRET}",
            "header": "X-Stripe-Signature",
            "algorithm": "sha256"
        }
    }
}
```

### 2. Local Connector Configuration

Create `connector.json`:

```json
{
    "cloud": {
        "url": "wss://webhook-cloud.example.com/connect/stream",
        "connector_id": "local-dev-01"
    },
    "routes": {
        "stripe-payments": {
            "token": "ch_tok_abc123secret",
            "module": "log"
        }
    }
}
```

### 3. Start the Connector

```bash
python -m src.connector.main --config connector.json
```

### 4. Test the Flow

Send a webhook to the cloud receiver:

```bash
curl -X POST https://webhook-cloud.example.com/webhook/stripe_relay \
  -H "Content-Type: application/json" \
  -H "X-Stripe-Signature: t=1234567890,v1=..." \
  -d '{"type": "payment_intent.succeeded", "data": {...}}'
```

The webhook will be relayed to your local connector and logged to stdout.

## Use Cases

### Local Development

Receive real webhooks from Stripe, GitHub, etc. on your local machine without exposing ports:

```
Stripe ──HTTP──► Cloud Receiver ══WebSocket══► Developer Laptop ──► Local App
```

### On-Premises Processing

Process webhooks in data centers with strict firewall rules:

```
GitHub ──HTTP──► Cloud Receiver ══HTTPS══► Data Center Connector ──► Internal Kafka
```

### Multi-Region Routing

Receive webhooks in one region, process in another:

```
Payment Provider ──HTTP──► US Cloud ══HTTPS══► EU Connector ──► EU Database
```

### High Availability

Webhooks are buffered during connector downtime:

```
1. Webhooks arrive while connector is offline
2. Messages queue in Redis/RabbitMQ (up to 24h by default)
3. Connector reconnects
4. Buffered messages delivered automatically
```

## Configuration Reference

### Cloud Receiver Module Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `channel` | string | required | Unique channel name for this webhook stream |
| `channel_token` | string | required | Authentication token for connectors |
| `ttl_seconds` | int | `86400` | Message time-to-live (24 hours default) |
| `max_queue_size` | int | `10000` | Maximum messages in queue |
| `max_connections` | int | `10` | Maximum concurrent connectors |

### Local Connector Configuration

```json
{
    "cloud": {
        "url": "wss://host/connect/stream",
        "connector_id": "unique-id"
    },
    "concurrency": 10,
    "routes": {
        "channel-name": {
            "token": "channel_token",
            "module": "kafka",
            "connection": "local_kafka",
            "module-config": { ... }
        }
    },
    "connections": { ... }
}
```

## Streaming Protocols

### WebSocket (Primary)

Real-time, bidirectional communication with built-in heartbeats:

```
Connector ←──WebSocket──► Cloud Receiver
         ← webhooks
         → ack/nack
         ↔ heartbeat
```

### Server-Sent Events (SSE)

Simpler protocol, HTTP-native, auto-reconnect:

```
Connector ←──SSE──► Cloud Receiver  (webhooks)
Connector ──HTTP──► Cloud Receiver  (ack/nack)
```

### HTTP Long-Polling (Fallback)

Works in restrictive environments:

```
Connector ──poll──► Cloud Receiver  (get messages)
Connector ──HTTP──► Cloud Receiver  (ack/nack)
```

## Security Features

### Two-Layer Authentication

1. **Webhook Authentication**: External services authenticate using HMAC, JWT, Bearer tokens, etc. (11 methods)
2. **Channel Token Authentication**: Connectors authenticate with channel-specific tokens

### Channel Isolation

- Each channel has its own token
- Connectors only access channels they have tokens for
- Easy token rotation without affecting other channels

### Transport Security

- All connections use TLS/HTTPS
- WebSocket uses `wss://` protocol
- Certificate validation enabled by default

## Reliability Features

### At-Least-Once Delivery

Messages are acknowledged only after successful destination delivery:

1. Cloud sends message to Connector
2. Connector routes to destination (Kafka, DB, etc.)
3. Destination confirms success
4. Connector sends ACK to Cloud
5. Cloud removes message from queue

### Automatic Reconnection

Connector automatically reconnects on connection loss with exponential backoff.

### Dead Letter Queue

Messages that fail permanently go to a dead letter queue for manual inspection.

## Comparison with Alternatives

| Feature | Webhook Connect | ngrok | AWS EventBridge |
|---------|-----------------|-------|-----------------|
| Webhook-specific | Yes | No | Partial |
| Buffer during downtime | Yes | No | Yes |
| HTTP-only (firewall friendly) | Yes | Yes | Yes |
| Same config as direct webhooks | Yes | N/A | No |
| Built-in webhook authentication | Yes | Basic | Yes |
| Multiple local destinations | Yes | No | Yes |
| Self-hosted option | Yes | No | No |

## Related Documentation

- [Getting Started with Webhook Connect](webhook-connect-getting-started) - Step-by-step setup guide
- [Advanced Webhook Connect](webhook-connect-advanced) - Multi-channel, chaining, production deployment
- [Webhook Connect Troubleshooting](webhook-connect-troubleshooting) - Common issues and solutions
