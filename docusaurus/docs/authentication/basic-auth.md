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
- Constant-time comparison (timing attack resistant)
- Username and password validation
- UTF-8 encoding with Latin-1 fallback for special characters

:::info Character Encoding
Credentials are decoded using UTF-8 encoding by default. If UTF-8 decoding fails (e.g., for legacy clients), the system falls back to Latin-1 (ISO-8859-1) encoding.
:::

