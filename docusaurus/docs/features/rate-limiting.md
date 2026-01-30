# Rate Limiting

Per-webhook rate limiting with configurable windows to prevent abuse and ensure fair usage.

## Configuration

```json
{
    "rate_limited_webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer token",
        "rate_limit": {
            "max_requests": 100,
            "window_seconds": 60
        }
    }
}
```

## Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `max_requests` | integer | Yes | Maximum requests allowed in the window |
| `window_seconds` | integer | Yes | Time window in seconds |

## How It Works

Rate limiting uses a sliding window algorithm:

- **Tracking scope**: Requests are tracked **per webhook ID** (not per IP address)
- When the limit is exceeded, requests return `429 Too Many Requests`
- The counter uses a sliding window that automatically expires old requests

:::info Tracking Scope
Rate limits are applied per webhook endpoint. All requests to the same webhook share the rate limit counter, regardless of client IP. For per-IP rate limiting, use a reverse proxy like nginx.
:::

## Example

Allow 100 requests per minute to a webhook:

```json
{
    "api_webhook": {
        "data_type": "json",
        "module": "log",
        "rate_limit": {
            "max_requests": 100,
            "window_seconds": 60
        }
    }
}
```

## Response

When rate limit is exceeded:

```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{
    "error": "Rate limit exceeded. Retry after X seconds"
}
```

The response includes a `Retry-After` header indicating when the client can retry.

## Use Cases

### High-Traffic API Webhook

```json
{
    "high_volume_api": {
        "data_type": "json",
        "module": "kafka",
        "connection": "kafka_prod",
        "module-config": {
            "topic": "api_events"
        },
        "rate_limit": {
            "max_requests": 1000,
            "window_seconds": 60
        }
    }
}
```

### Strict Rate Limiting

```json
{
    "strict_webhook": {
        "data_type": "json",
        "module": "http_webhook",
        "module-config": {
            "url": "https://api.example.com/webhook"
        },
        "rate_limit": {
            "max_requests": 10,
            "window_seconds": 60
        }
    }
}
```

## Features

- Per-webhook rate tracking
- Sliding window algorithm
- Configurable limits and windows
- Clear error messages with retry timing
- No external dependencies (in-memory tracking)

## Limitations

- Rate limit state is stored in-memory and not shared across multiple server instances
- For distributed rate limiting, consider using Redis or a similar distributed store at the load balancer level
