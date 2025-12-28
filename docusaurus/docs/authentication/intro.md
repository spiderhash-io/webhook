# Authentication Methods

The Core Webhook Module supports 11 different authentication methods to secure your webhook endpoints. You can combine multiple authentication methods for enhanced security.

## Available Authentication Methods

- **[Bearer Token](bearer-token)** - Simple token-based authentication
- **[Basic Authentication](basic-auth)** - HTTP Basic Auth
- **[JWT Authentication](jwt)** - JSON Web Token validation
- **[HMAC Signature](hmac)** - HMAC signature verification
- **[IP Whitelisting](ip-whitelist)** - Restrict by IP address
- **[Header-based Authentication](header-auth)** - API keys in custom headers
- **[Query Parameter Authentication](query-auth)** - API keys in query parameters
- **[HTTP Digest Authentication](digest-auth)** - HTTP Digest Auth
- **[OAuth 1.0](oauth1)** - OAuth 1.0 signature validation
- **[OAuth 2.0](oauth2)** - OAuth 2.0 token validation
- **[Google reCAPTCHA](recaptcha)** - Bot protection with reCAPTCHA

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

