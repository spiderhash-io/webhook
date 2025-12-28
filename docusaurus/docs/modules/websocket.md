# WebSocket Module

The WebSocket Module forwards webhook payloads to WebSocket connections in real-time.

## Configuration

```json
{
    "websocket_realtime": {
        "data_type": "json",
        "module": "websocket",
        "module-config": {
            "url": "ws://localhost:8080/webhooks",
            "format": "json",
            "include_headers": true,
            "wait_for_response": false,
            "timeout": 10,
            "max_retries": 3
        },
        "authorization": "Bearer ws_secret"
    }
}
```

## Module Configuration Options

- `url`: WebSocket URL (ws:// or wss://) (required)
- `format`: Message format - "json" or "raw" (default: "json")
- `include_headers`: Whether to include HTTP headers (default: false)
- `wait_for_response`: Whether to wait for server response (default: false)
- `timeout`: Connection timeout in seconds (default: 10)
- `max_retries`: Maximum connection retry attempts (default: 3)

## Features

- Real-time bidirectional communication
- Secure WebSocket (WSS) support
- Automatic reconnection
- Response handling
- Connection pooling

