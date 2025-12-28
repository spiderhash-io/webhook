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

- `ip_whitelist`: Array of allowed IP addresses or CIDR ranges (required)

## Supported Formats

- Single IP: `"192.168.1.100"`
- CIDR range: `"192.168.1.0/24"`
- IPv6 addresses: `"2001:db8::1"`
- IPv6 CIDR: `"2001:db8::/32"`

## Usage

Only requests from whitelisted IPs will be accepted:

```bash
# From whitelisted IP
curl -X POST http://localhost:8000/webhook/secure_webhook \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'

# From non-whitelisted IP - will be rejected
```

## Features

- IPv4 and IPv6 support
- CIDR range support
- Fast IP matching
- X-Forwarded-For header support (for proxies)

