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
            "forward_headers": false
        },
        "authorization": "Bearer token"
    }
}
```

## Module Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `url` | string | Required | Target HTTP endpoint URL |
| `method` | string | `"POST"` | HTTP method: `POST`, `PUT`, or `PATCH` |
| `headers` | object | `{}` | Custom headers to include |
| `timeout` | integer | `30` | Request timeout in seconds |
| `forward_headers` | boolean | `false` | Forward incoming request headers |
| `allowed_headers` | array | - | Whitelist of headers to forward |
| `allowed_hosts` | array | - | Whitelist of allowed destination hosts |

:::warning Supported Methods
Only `POST`, `PUT`, and `PATCH` methods are supported. GET and DELETE are not available for forwarding webhook payloads.
:::

## Security Features

### SSRF Protection

URLs are validated to prevent Server-Side Request Forgery (SSRF):

- Only `http://` and `https://` schemes allowed
- Localhost and loopback addresses blocked
- Private IP ranges blocked (RFC 1918)
- Cloud metadata endpoints blocked (169.254.169.254)
- Octal and hex IP encoding detected and blocked

### Host Whitelist

For additional security, restrict destinations to specific hosts:

```json
{
    "secure_forward": {
        "module": "http_webhook",
        "module-config": {
            "url": "https://api.trusted.com/webhook",
            "allowed_hosts": [
                "api.trusted.com",
                "backup.trusted.com"
            ]
        }
    }
}
```

When `allowed_hosts` is configured, SSRF checks are bypassed for whitelisted hosts only.

### Header Sanitization

Headers are sanitized to prevent HTTP header injection:

- Hop-by-hop headers filtered (`Host`, `Connection`, `Transfer-Encoding`, etc.)
- Newlines and control characters blocked
- Header name/value length limits enforced

### Header Whitelist

Control which headers are forwarded:

```json
{
    "filtered_forward": {
        "module": "http_webhook",
        "module-config": {
            "url": "https://api.example.com/webhook",
            "forward_headers": true,
            "allowed_headers": [
                "content-type",
                "x-request-id",
                "x-correlation-id"
            ]
        }
    }
}
```

## Features

- HTTP/HTTPS support
- SSRF protection
- Custom and forwarded headers
- Header whitelist and sanitization
- Timeout configuration
- Environment variable substitution

## Example

### Basic Forwarding

```json
{
    "forward_to_api": {
        "data_type": "json",
        "module": "http_webhook",
        "module-config": {
            "url": "https://api.example.com/events",
            "method": "POST",
            "headers": {
                "Authorization": "Bearer {$API_TOKEN}"
            }
        },
        "authorization": "Bearer {$WEBHOOK_SECRET}"
    }
}
```

### With Header Forwarding

```json
{
    "proxy_webhook": {
        "data_type": "json",
        "module": "http_webhook",
        "module-config": {
            "url": "https://downstream.example.com/webhook",
            "method": "POST",
            "forward_headers": true,
            "allowed_headers": ["x-request-id", "x-trace-id"],
            "timeout": 60
        },
        "authorization": "Bearer token"
    }
}
```

### In a Chain

```json
{
    "multi_forward": {
        "data_type": "json",
        "chain": [
            {
                "module": "http_webhook",
                "module-config": {
                    "url": "https://primary.example.com/webhook"
                }
            },
            {
                "module": "http_webhook",
                "module-config": {
                    "url": "https://backup.example.com/webhook"
                }
            }
        ],
        "chain-config": {
            "execution": "parallel"
        },
        "authorization": "Bearer token"
    }
}
```
