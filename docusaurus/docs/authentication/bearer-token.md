# Bearer Token Authentication

Simple token-based authentication using the Authorization header with Bearer tokens.

## Configuration

```json
{
    "secure_webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer my_secret_token"
    }
}
```

## Usage

Send requests with the Bearer token in the Authorization header:

```bash
curl -X POST http://localhost:8000/webhook/secure_webhook \
  -H "Authorization: Bearer my_secret_token" \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

## Features

- Simple token validation
- Constant-time comparison (timing attack resistant)
- Supports "Bearer " prefix or plain token
- Case-sensitive token matching

