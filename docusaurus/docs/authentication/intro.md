---
description: "Overview of 11 supported webhook authentication methods including Bearer, JWT, HMAC, OAuth, IP whitelisting, and more."
---

# Authentication Methods

The Core Webhook Module supports 11 different authentication methods to secure your webhook endpoints. You can combine multiple authentication methods for enhanced security.

## Available Authentication Methods

- **[Bearer Token](./bearer-token.md)** - Simple token-based authentication
- **[Basic Authentication](./basic-auth.md)** - HTTP Basic Auth
- **[JWT Authentication](./jwt.md)** - JSON Web Token validation
- **[HMAC Signature](./hmac.md)** - HMAC signature verification
- **[IP Whitelisting](./ip-whitelist.md)** - Restrict by IP address
- **[Header-based Authentication](./header-auth.md)** - API keys in custom headers
- **[Query Parameter Authentication](./query-auth.md)** - API keys in query parameters
- **[HTTP Digest Authentication](./digest-auth.md)** - HTTP Digest Auth
- **[OAuth 1.0](./oauth1.md)** - OAuth 1.0 signature validation
- **[OAuth 2.0](./oauth2.md)** - OAuth 2.0 token validation
- **[Google reCAPTCHA](./recaptcha.md)** - Bot protection with reCAPTCHA

## Combining Authentication Methods

You can combine multiple authentication methods for enhanced security:

```json
{
    "fully_secured": {
        "data_type": "json",
        "module": "rabbitmq",
        "authorization": "Bearer super_secret",
        "hmac": {
            "secret": "hmac_secret_key",
            "header": "X-HMAC-Signature",
            "algorithm": "sha256"
        },
        "ip_whitelist": [
            "203.0.113.0"
        ]
    }
}
```

All specified validators must pass for the webhook to be accepted.

