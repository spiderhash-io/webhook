# Webhook Connect Scenario

This scenario demonstrates the **Webhook Connect** feature - a cloud-to-local webhook relay system similar to ngrok.

## Architecture

```
                                    ┌─────────────────┐
                                    │   External      │
                                    │   Webhook       │
                                    │   Source        │
                                    └────────┬────────┘
                                             │
                                             ▼
┌────────────────────────────────────────────────────────────────┐
│                        CLOUD                                    │
│  ┌──────────────────┐         ┌──────────────────┐            │
│  │  Cloud Receiver  │────────▶│      Redis       │            │
│  │   (port 8010)    │         │  (Message Queue) │            │
│  │                  │         └────────┬─────────┘            │
│  │  - Receives      │                  │                      │
│  │    webhooks      │                  │ Stream               │
│  │  - Queues to     │                  │ (WebSocket/SSE)      │
│  │    Redis         │                  │                      │
│  └──────────────────┘                  │                      │
└────────────────────────────────────────┼──────────────────────┘
                                         │
                                         ▼
┌────────────────────────────────────────────────────────────────┐
│                        LOCAL                                    │
│  ┌──────────────────┐         ┌──────────────────┐            │
│  │    Connector     │────────▶│  Local Processor │            │
│  │                  │   HTTP  │   (port 8011)    │            │
│  │  - Connects to   │         │                  │            │
│  │    cloud via SSE │         │  - Receives      │            │
│  │  - Forwards to   │         │    webhooks      │            │
│  │    local target  │         │  - Logs to disk  │            │
│  └──────────────────┘         └──────────────────┘            │
└────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Run Basic Test

```bash
cd docker/scenario/02_connector
chmod +x *.sh
./run_test.sh basic
```

### Run Resilience Test

This test demonstrates that webhooks are queued when the local processor is down, and delivered when it comes back up:

```bash
./run_test.sh resilience
```

## Manual Testing

### Step 1: Start Infrastructure

```bash
# Start Redis and Cloud Receiver
docker compose up -d redis cloud-receiver

# Wait for cloud-receiver to be healthy
docker compose ps
```

### Step 2: Send Webhooks (Cloud Only)

```bash
# Send 10 test webhooks to cloud
./send_webhooks.sh 10

# Check queue status
curl -s http://localhost:8010/admin/webhook-connect/channels/test-channel \
    -H "Authorization: Bearer admin_secret_123" | python3 -m json.tool
```

### Step 3: Start Local Components

```bash
# Start local processor and connector
docker compose --profile with-local --profile with-connector up -d

# Watch connector logs
docker compose logs -f connector
```

### Step 4: Verify Delivery

```bash
# Check if webhooks arrived at local processor
./verify_results.sh 10

# Or manually check the log file
cat logs/local/webhooks.log | python3 -m json.tool
```

## Configuration Files

### Cloud Receiver (`config/cloud/webhooks.json`)

```json
{
    "cloud-webhook": {
        "data_type": "json",
        "module": "webhook_connect",
        "module-config": {
            "channel": "test-channel",
            "channel_token": "channel_secret_token_123",
            "ttl_seconds": 3600
        }
    }
}
```

### Local Processor (`config/local/webhooks.json`)

```json
{
    "local-receiver": {
        "data_type": "json",
        "module": "save_to_disk",
        "module-config": {
            "path": "/app/logs/webhooks.log",
            "format": "json",
            "append": true
        }
    }
}
```

### Connector (`config/connector.json`)

```json
{
    "cloud_url": "http://cloud-receiver:8000",
    "channel": "test-channel",
    "token": "channel_secret_token_123",
    "protocol": "sse",
    "targets": {
        "default": {
            "url": "http://local-processor:8000/webhook/local-receiver"
        }
    }
}
```

## API Endpoints

### Cloud Receiver

| Endpoint | Description |
|----------|-------------|
| `POST /webhook/cloud-webhook` | Receive webhooks and queue them |
| `GET /connect/stream/{channel}/sse` | SSE stream for connectors |
| `GET /admin/webhook-connect/channels` | List all channels (admin) |
| `GET /admin/webhook-connect/channels/{name}` | Get channel details (admin) |
| `GET /health` | Health check |

### Local Processor

| Endpoint | Description |
|----------|-------------|
| `POST /webhook/local-receiver` | Receive forwarded webhooks |
| `GET /health` | Health check |

## Environment Variables

### Cloud Receiver

| Variable | Description | Default |
|----------|-------------|---------|
| `WEBHOOK_CONNECT_ENABLED` | Enable Webhook Connect | `false` |
| `WEBHOOK_CONNECT_REDIS_URL` | Redis URL for message buffer | `redis://localhost:6379/0` |
| `WEBHOOK_CONNECT_ADMIN_TOKEN` | Admin API token | none |

### Connector

| Variable | Description | Default |
|----------|-------------|---------|
| `CONNECTOR_CLOUD_URL` | Cloud receiver URL | required |
| `CONNECTOR_CHANNEL` | Channel name | required |
| `CONNECTOR_TOKEN` | Channel authentication token | required |
| `CONNECTOR_TARGET_URL` | Default target URL | required |
| `CONNECTOR_PROTOCOL` | `websocket` or `sse` | `sse` |

## Troubleshooting

### Check Service Status

```bash
docker compose ps
docker compose logs cloud-receiver
docker compose logs connector
docker compose logs local-processor
```

### Check Redis Queue

```bash
docker compose exec redis redis-cli
> KEYS webhook_connect:*
> XLEN webhook_connect:stream:test-channel
```

### Check Channel Stats

```bash
curl -s http://localhost:8010/admin/webhook-connect/channels/test-channel \
    -H "Authorization: Bearer admin_secret_123" | python3 -m json.tool
```

### Clean Up

```bash
docker compose down -v
rm -rf logs/local/* logs/cloud/*
```
