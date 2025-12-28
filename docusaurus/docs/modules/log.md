# Log Module

The Log Module outputs webhook payloads to stdout. This is useful for debugging and development.

## Configuration

```json
{
    "log_webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer token"
    }
}
```

## Features

- Simple stdout output
- No external dependencies
- Useful for testing and debugging
- Supports both JSON and blob data types

## Example

When a webhook is received, the payload is logged to stdout:

```
[INFO] Webhook received: {"event": "test", "data": "example"}
```

