# IP Whitelisting

Restrict webhook access to specific IP addresses or IP ranges for enhanced security. This feature provides network-level access control by validating the client's IP address against a configured whitelist.

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

- **Single IPv4**: `"192.168.1.100"`
- **CIDR IPv4 Range**: `"192.168.1.0/24"` (allows 192.168.1.0 - 192.168.1.255)
- **Single IPv6**: `"2001:db8::1"`
- **CIDR IPv6 Range**: `"2001:db8::/32"`

## How It Works

1. **IP Extraction**: The system extracts the client IP address from the request
2. **Proxy Support**: When behind a reverse proxy, validates `X-Forwarded-For` and `X-Real-IP` headers from trusted proxies only
3. **IP Normalization**: Normalizes IPv4/IPv6 addresses for consistent comparison
4. **Whitelist Matching**: Checks if the normalized client IP matches any entry in the whitelist
5. **Access Decision**: Allows the request if IP matches, rejects with `403 Forbidden` if not

## Security Features

### Trusted Proxy Support

When deployed behind a reverse proxy (e.g., nginx, load balancer), configure trusted proxy IPs:

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
            "172.16.0.1"
        ]
    }
}
```

**Security Note**: Only `X-Forwarded-For` headers from trusted proxy IPs are accepted to prevent IP spoofing attacks.

### IP Spoofing Protection

- Uses `request.client.host` as the primary source (cannot be spoofed)
- Only trusts proxy headers when the actual client IP is a trusted proxy
- Logs security warnings when untrusted headers are detected
- Normalizes IP addresses to prevent bypass attempts

## Usage Examples

### Single IP Address

```json
{
    "api_webhook": {
        "data_type": "json",
        "module": "log",
        "ip_whitelist": [
            "192.168.1.100"
        ]
    }
}
```

### Multiple IP Addresses

```json
{
    "multi_ip_webhook": {
        "data_type": "json",
        "module": "log",
        "ip_whitelist": [
            "192.168.1.100",
            "10.0.0.50",
            "172.16.0.25"
        ]
    }
}
```

### CIDR Range

```json
{
    "range_webhook": {
        "data_type": "json",
        "module": "log",
        "ip_whitelist": [
            "203.0.113.0/24",
            "10.0.0.0/16"
        ]
    }
}
```

### IPv6 Support

```json
{
    "ipv6_webhook": {
        "data_type": "json",
        "module": "log",
        "ip_whitelist": [
            "2001:db8::1",
            "2001:db8::/32"
        ]
    }
}
```

## Combined with Other Security Features

IP whitelisting can be combined with other authentication methods for defense in depth:

```json
{
    "fully_secured": {
        "data_type": "json",
        "module": "rabbitmq",
        "connection": "rabbitmq_local",
        "module-config": {
            "queue_name": "secure_queue"
        },
        "authorization": "Bearer super_secret",
        "hmac": {
            "secret": "hmac_secret_key",
            "header": "X-HMAC-Signature",
            "algorithm": "sha256"
        },
        "ip_whitelist": [
            "203.0.113.0/24"
        ]
    }
}
```

## Error Response

When a request comes from a non-whitelisted IP:

```json
{
    "error": "IP validation failed",
    "detail": "IP 192.168.1.200 not in whitelist"
}
```

HTTP Status: `403 Forbidden`

## Features

- IPv4 and IPv6 support
- CIDR range support for network-level access control
- Fast IP matching with normalized comparison
- X-Forwarded-For header support (for reverse proxies)
- Trusted proxy validation to prevent IP spoofing
- Security logging for spoofing attempts
- Works seamlessly with other authentication methods

## Best Practices

1. **Use CIDR ranges** for dynamic IP addresses (e.g., cloud providers)
2. **Configure trusted proxies** when behind a load balancer or reverse proxy
3. **Combine with other auth methods** for multi-layer security
4. **Monitor security logs** for IP spoofing attempts
5. **Regularly review whitelist** to remove unused IPs

