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

- `max_requests`: Maximum number of requests allowed in the time window (required)
- `window_seconds`: Time window in seconds (required)

## How It Works

Rate limiting uses a sliding window algorithm:

- Each webhook has its own rate limit counter
- Requests are tracked per IP address (or client identifier)
- When the limit is exceeded, requests return `429 Too Many Requests`
- The counter resets based on the sliding window

## Example

Allow 100 requests per minute:

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

```json
{
    "error": "Rate limit exceeded",
    "detail": "Maximum 100 requests per 60 seconds"
}
```

HTTP Status: `429 Too Many Requests`

## Features

- Per-webhook configuration
- Per-IP tracking
- Sliding window algorithm
- Configurable limits and windows
- Clear error messages

