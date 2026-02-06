# Scenario 04: Advanced Connector Tests

Comprehensive test scenarios for Webhook Connect advanced features: multi-channel routing, WebSocket/SSE/long-poll protocols, admin API, token rotation, queue overflow, retry delivery, and target routing.

## Prerequisites

- Docker and Docker Compose
- `curl`, `bc`, `python3` (for JSON parsing)

## Quick Start

```bash
# Run all sub-tests
./run_test.sh all

# Run a specific sub-test
./run_test.sh admin-api
./run_test.sh multi-channel
./run_test.sh websocket
```

## Sub-Tests

| Test | What it validates |
|------|-------------------|
| `multi-channel` | 2 channels with independent SSE + WS connectors, messages route to correct local processors |
| `websocket` | Full WebSocket protocol flow: connect, stream webhooks, ACK delivery |
| `long-poll` | Long-poll returns 204 when empty, 200 with messages |
| `admin-api` | Health, channels list, channel details, stats, dead letters, overview, auth rejection |
| `token-rotation` | Rotate token via admin API, old token works during grace period, new token works, wrong token rejected |
| `target-routing` | Webhooks routed to correct local target based on connector config |
| `queue-overflow` | Sending beyond `max_queue_size` (3) causes rejection |
| `retry-delivery` | Webhooks queued while local is down are delivered when local starts |

## Architecture

```
                    cloud-webhook-alpha          cloud-webhook-beta
                          |                            |
                          v                            v
                    +----------------+           +----------------+
                    | cloud-receiver |           | cloud-receiver |
                    | (channel-alpha)|           | (channel-beta) |
                    +-------+--------+           +-------+--------+
                            |                            |
                        [Redis Buffer]               [Redis Buffer]
                            |                            |
                    +-------+--------+           +-------+--------+
                    | connector-sse  |           | connector-ws   |
                    | (SSE protocol) |           | (WS protocol)  |
                    +-------+--------+           +-------+--------+
                            |                            |
                            v                            v
                    +----------------+           +----------------+
                    | local-proc-a   |           | local-proc-b   |
                    | (save_to_disk) |           | (save_to_disk) |
                    +----------------+           +----------------+
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| redis | 6380 | Message buffer |
| cloud-receiver | 8010 | Webhook receiver + Webhook Connect |
| local-processor-a | 8011 | Local target A (channel-alpha) |
| local-processor-b | 8012 | Local target B (channel-beta) |
| connector-sse | - | SSE connector for channel-alpha |
| connector-ws | - | WebSocket connector for channel-beta |

## Configuration

- `config/cloud/webhooks.json` - 3 webhook endpoints: alpha, beta, overflow
- `config/connector-sse.json` - SSE connector for channel-alpha -> local-a
- `config/connector-ws.json` - WebSocket connector for channel-beta -> local-b
