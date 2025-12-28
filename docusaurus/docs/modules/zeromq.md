# ZeroMQ Module

The ZeroMQ Module publishes webhook payloads to ZeroMQ sockets.

## Configuration

```json
{
    "zeromq_webhook": {
        "data_type": "json",
        "module": "zeromq",
        "module-config": {
            "endpoint": "tcp://localhost:5555",
            "socket_type": "PUB"
        },
        "authorization": "Bearer token"
    }
}
```

## Module Configuration Options

- `endpoint`: ZeroMQ endpoint URL (required, e.g., "tcp://localhost:5555")
- `socket_type`: Socket type - "PUB", "PUSH", "REQ" (default: "PUB")
- `bind`: Whether to bind or connect (default: false for connect)

## Connection Types

- `tcp://`: TCP connection
- `ipc://`: Inter-process communication
- `inproc://`: In-process communication

## Features

- Multiple socket types (PUB, PUSH, REQ)
- High-performance messaging
- Multiple transport protocols
- Connection pooling

