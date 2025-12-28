# JWT Authentication

Full JWT token validation with issuer, audience, and expiration checks.

## Configuration

```json
{
    "jwt_auth_webhook": {
        "data_type": "json",
        "module": "log",
        "jwt": {
            "secret": "my_jwt_secret_key",
            "algorithm": "HS256",
            "issuer": "my-app",
            "audience": "webhook-api",
            "verify_exp": true
        }
    }
}
```

## Configuration Options

- `secret`: JWT secret key (required)
- `algorithm`: JWT algorithm - HS256, HS384, HS512, RS256, etc. (default: "HS256")
- `issuer`: Required token issuer (optional)
- `audience`: Required token audience (optional)
- `verify_exp`: Whether to verify token expiration (default: true)

## Usage

Send requests with JWT token in Authorization header:

```bash
curl -X POST http://localhost:8000/webhook/jwt_auth_webhook \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

## Features

- Full JWT validation (signature, expiration, issuer, audience)
- Multiple algorithm support (HS256, RS256, etc.)
- Configurable validation options
- Secure token verification

