# HTTP Webhook Module

The HTTP Webhook Module forwards webhook payloads to external HTTP endpoints.

## Configuration

```json
{
    "http_forward_webhook": {
        "data_type": "json",
        "module": "http_webhook",
        "module-config": {
            "url": "https://api.example.com/webhooks",
            "method": "POST",
            "headers": {
                "Authorization": "Bearer {$API_TOKEN}",
                "X-Custom-Header": "value"
            },
            "timeout": 30,
            "retry": {
                "max_attempts": 3,
                "backoff": "exponential"
            }
        },
        "authorization": "Bearer token"
    }
}
```

## Module Configuration Options

- `url`: Target HTTP endpoint URL (required)
- `method`: HTTP method - GET, POST, PUT, PATCH, DELETE (default: "POST")
- `headers`: Custom headers to include in the request
- `timeout`: Request timeout in seconds (default: 30)
- `retry`: Retry configuration
  - `max_attempts`: Maximum retry attempts (default: 3)
  - `backoff`: Backoff strategy - "linear" or "exponential" (default: "exponential")

## Features

- HTTP/HTTPS support
- Custom headers
- Retry mechanism with backoff
- Timeout configuration
- Environment variable substitution in URLs and headers

