# Basic Authentication

HTTP Basic Authentication support with secure credential validation.

## Configuration

```json
{
    "basic_auth_webhook": {
        "data_type": "json",
        "module": "log",
        "basic_auth": {
            "username": "admin",
            "password": "secret_password_123"
        }
    }
}
```

## Usage

Send requests with Basic Auth credentials:

```bash
curl -X POST http://localhost:8000/webhook/basic_auth_webhook \
  -u admin:secret_password_123 \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

Or with explicit header:

```bash
curl -X POST http://localhost:8000/webhook/basic_auth_webhook \
  -H "Authorization: Basic YWRtaW46c2VjcmV0X3Bhc3N3b3JkXzEyMw==" \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

## Features

- Standard HTTP Basic Auth (RFC 7617)
- Base64 encoded credentials
- Constant-time comparison
- Username and password validation

