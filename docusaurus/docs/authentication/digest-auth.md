# HTTP Digest Authentication

Authenticate webhooks using HTTP Digest Authentication (RFC 7616), a challenge-response authentication method that doesn't transmit passwords in plain text.

## Configuration

```json
{
    "digest_auth_webhook": {
        "data_type": "json",
        "module": "log",
        "digest_auth": {
            "username": "{$DIGEST_USERNAME:webhook_user}",
            "password": "{$DIGEST_PASSWORD}",
            "realm": "{$DIGEST_REALM:Webhook API}",
            "algorithm": "MD5",
            "qop": "auth"
        }
    }
}
```

## Configuration Options

- `username`: Expected username (required)
- `password`: Expected password (required)
- `realm`: Authentication realm (default: `"Webhook API"`)
- `algorithm`: Hash algorithm (default: `"MD5"`)
- `qop`: Quality of protection (default: `"auth"`, can be empty for no qop)

## Usage

Send requests with Digest Authorization header:

```bash
curl -X POST http://localhost:8000/webhook/digest_auth_webhook \
  -H "Authorization: Digest username=\"webhook_user\", realm=\"Webhook API\", nonce=\"...\", uri=\"/webhook/digest_auth_webhook\", response=\"...\", ..." \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

## Features

- No password transmission (uses MD5 hash)
- Nonce-based challenge-response
- Constant-time response comparison (timing attack resistant)
- Realm validation
- URI and method validation

