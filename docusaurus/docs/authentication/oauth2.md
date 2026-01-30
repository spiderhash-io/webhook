# OAuth 2.0 Authentication

Authenticate webhooks using OAuth 2.0 access tokens with token introspection or JWT validation.

## Token Introspection

```json
{
    "oauth2_webhook": {
        "data_type": "json",
        "module": "log",
        "oauth2": {
            "token_type": "Bearer",
            "introspection_endpoint": "{$OAUTH2_INTROSPECTION_URL:https://auth.example.com/introspect}",
            "client_id": "{$OAUTH2_CLIENT_ID}",
            "client_secret": "{$OAUTH2_CLIENT_SECRET}",
            "required_scope": ["webhook:write", "webhook:read"],
            "validate_token": true
        }
    }
}
```

## JWT Token Validation

```json
{
    "oauth2_jwt_webhook": {
        "data_type": "json",
        "module": "log",
        "oauth2": {
            "token_type": "Bearer",
            "jwt_secret": "{$OAUTH2_JWT_SECRET}",
            "jwt_algorithms": ["HS256", "RS256"],
            "audience": "webhook-api",
            "issuer": "https://auth.example.com",
            "required_scope": ["read", "write"],
            "verify_exp": true
        }
    }
}
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `token_type` | string | `"Bearer"` | Token type in Authorization header |
| `introspection_endpoint` | string | - | OAuth 2.0 token introspection URL |
| `client_id` | string | - | Client ID for introspection endpoint |
| `client_secret` | string | - | Client secret for introspection endpoint |
| `jwt_secret` | string | - | Secret key for JWT validation |
| `jwt_algorithms` | array | `["HS256", "RS256"]` | Allowed JWT algorithms |
| `audience` | string | - | Required token audience (for JWT) |
| `issuer` | string | - | Required token issuer (for JWT) |
| `required_scope` | array | `[]` | List of required OAuth scopes |
| `validate_token` | boolean | `true` | Whether to validate token |
| `verify_exp` | boolean | `true` | Whether to verify token expiration |

## Supported JWT Algorithms

The following algorithms are allowed (strong algorithms only):

| Family | Algorithms |
|--------|------------|
| HMAC | `HS256`, `HS384`, `HS512` |
| RSA | `RS256`, `RS384`, `RS512` |
| ECDSA | `ES256`, `ES384`, `ES512` |
| RSA-PSS | `PS256`, `PS384`, `PS512` |

:::danger Blocked Algorithms
The `none` algorithm and weak algorithms are blocked to prevent signature bypass attacks.
:::

## Security Features

### SSRF Protection

The introspection endpoint is validated to prevent Server-Side Request Forgery (SSRF):

- Only `http://` and `https://` schemes allowed
- Localhost and loopback addresses blocked (`127.0.0.1`, `::1`, `localhost`)
- Private IP ranges blocked (RFC 1918)
- Cloud metadata endpoints blocked (`169.254.169.254`)

```json
{
    "oauth2": {
        "introspection_endpoint": "https://auth.example.com/introspect"
    }
}
```

### Algorithm Validation

- Only whitelisted algorithms are accepted
- Algorithm confusion attacks are prevented
- Case-normalized algorithm names

## Usage

Send requests with Bearer token:

```bash
curl -X POST http://localhost:8000/webhook/oauth2_webhook \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

## Features

- Token introspection (RFC 7662)
- JWT signature validation with 12 algorithms
- SSRF protection for introspection endpoints
- Scope validation
- Audience and issuer validation
- Expiration checking
- Algorithm whitelist (blocks `none` algorithm)
