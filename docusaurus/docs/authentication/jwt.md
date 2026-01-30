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

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `secret` | string | **Yes** | - | JWT secret key or RSA/EC public key |
| `algorithm` | string | No | `"HS256"` | JWT signing algorithm (see supported list below) |
| `issuer` | string | No | - | Required token issuer claim (`iss`) |
| `audience` | string | No | - | Required token audience claim (`aud`) |
| `verify_exp` | boolean | No | `true` | Whether to verify token expiration |

### Supported Algorithms

The following 12 algorithms are supported:

| Family | Algorithms | Key Type |
|--------|------------|----------|
| HMAC | `HS256`, `HS384`, `HS512` | Symmetric secret |
| RSA | `RS256`, `RS384`, `RS512` | RSA public key |
| ECDSA | `ES256`, `ES384`, `ES512` | EC public key |
| RSA-PSS | `PS256`, `PS384`, `PS512` | RSA public key |

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
- 12 algorithm support (HS256/384/512, RS256/384/512, ES256/384/512, PS256/384/512)
- Configurable validation options
- Secure token verification
- SSRF protection (blocks external key fetching)

