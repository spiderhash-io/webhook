# IP Whitelisting

Restrict webhooks to specific IP addresses or IP ranges.

## Configuration

```json
{
    "secure_webhook": {
        "data_type": "json",
        "module": "save_to_disk",
        "module-config": {
            "path": "webhooks/secure"
        },
        "ip_whitelist": [
            "192.168.1.100",
            "10.0.0.50",
            "203.0.113.0/24"
        ]
    }
}
```

## Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `ip_whitelist` | array | Yes | Array of allowed IP addresses or CIDR ranges |
| `trusted_proxies` | array | No | List of trusted proxy IPs that can set forwarded headers |

## Trusted Proxies

When running behind a reverse proxy (nginx, AWS ALB, Cloudflare, etc.), configure `trusted_proxies` to correctly identify the real client IP:

```json
{
    "secure_webhook": {
        "data_type": "json",
        "module": "log",
        "ip_whitelist": [
            "203.0.113.0/24"
        ],
        "trusted_proxies": [
            "10.0.0.1",
            "10.0.0.2",
            "172.16.0.0/12"
        ]
    }
}
```

:::warning Security
Only add IPs to `trusted_proxies` that you control. The `X-Forwarded-For` and `X-Real-IP` headers are only trusted from these IPs. Requests from non-trusted proxies use the direct connection IP.
:::

You can also set trusted proxies globally via environment variable:

```bash
export TRUSTED_PROXY_IPS="10.0.0.1,10.0.0.2,172.16.0.0/12"
```

## Supported Formats

- Single IP: `"192.168.1.100"`
- CIDR range: `"192.168.1.0/24"`
- IPv6 addresses: `"2001:db8::1"`
- IPv6 CIDR: `"2001:db8::/32"`

## IP Resolution Order

1. Check if direct connection IP is a trusted proxy
2. If trusted, read `X-Forwarded-For` or `X-Real-IP` header
3. Sanitize header value (remove control characters, newlines)
4. Use the resulting IP for whitelist validation

## Usage

Only requests from whitelisted IPs will be accepted:

```bash
# From whitelisted IP - accepted
curl -X POST http://localhost:8000/webhook/secure_webhook \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'

# From non-whitelisted IP - rejected with 403 Forbidden
```

## Features

- IPv4 and IPv6 support
- CIDR range support
- Trusted proxy support for `X-Forwarded-For` / `X-Real-IP`
- Header sanitization (prevents injection attacks)
- IP normalization using Python `ipaddress` module

## Example: Behind Load Balancer

```json
{
    "production_webhook": {
        "data_type": "json",
        "module": "rabbitmq",
        "connection": "rabbitmq_prod",
        "module-config": {
            "queue_name": "events"
        },
        "ip_whitelist": [
            "52.89.214.238",
            "54.187.174.169",
            "54.187.205.235"
        ],
        "trusted_proxies": [
            "10.0.0.0/8"
        ],
        "authorization": "Bearer {$WEBHOOK_TOKEN}"
    }
}
```
