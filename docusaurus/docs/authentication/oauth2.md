# OAuth 2.0 Authentication

Authenticate webhooks using OAuth 2.0 access tokens with token introspection or JWT validation.

## Token Introspection (Recommended)

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

- `token_type`: Token type in Authorization header (default: `"Bearer"`)
- `introspection_endpoint`: OAuth 2.0 token introspection endpoint URL
- `client_id` / `client_secret`: Client credentials for introspection endpoint
- `jwt_secret`: Secret key for JWT validation (alternative to introspection)
- `jwt_algorithms`: Allowed JWT algorithms (default: `["HS256", "RS256"]`)
- `audience`: Required token audience (for JWT)
- `issuer`: Required token issuer (for JWT)
- `required_scope`: List of required OAuth scopes
- `validate_token`: Whether to validate token (default: `true`)

## Usage

Send requests with Bearer token:

```bash
curl -X POST http://localhost:8000/webhook/oauth2_webhook \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

## Features

- Token introspection with active/inactive status
- JWT signature validation
- Scope validation
- Audience and issuer validation
- Expiration checking
- Network error handling

