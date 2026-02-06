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

| Service | Port | Profile | Description |
|---------|------|---------|-------------|
| redis | 6380 | (default) | Message buffer |
| cloud-receiver | 8010 | (default) | Webhook receiver + Webhook Connect |
| local-processor-a | 8011 | with-local | Local target A (channel-alpha) |
| local-processor-b | 8012 | with-local | Local target B (channel-beta) |
| connector-sse | - | with-connector-sse | SSE connector for channel-alpha |
| connector-ws | - | with-connector-ws | WebSocket connector for channel-beta |
| connector-module | - | with-connector-module | Module-mode connector for channel-module |
| flaky-target | 8013 | with-flaky | Configurable error target for retry testing |

## Configuration

- `config/cloud/webhooks.json` - 4 webhook endpoints: alpha, beta, overflow, module-mode
- `config/connector-sse.json` - SSE connector (HTTP mode) for channel-alpha -> local-a
- `config/connector-ws.json` - WebSocket connector (HTTP mode) for channel-beta -> local-b
- `config/connector-module.json` - Module-mode connector for channel-module (uses local webhooks.json)
- `config/module-webhooks.json` - Standard CWM webhooks.json for module-mode connector (save_to_disk)
