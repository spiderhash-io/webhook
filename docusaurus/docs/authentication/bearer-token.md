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
- Case-sensitive token matching

:::warning Bearer Prefix Required
The `Authorization` header **must** include the "Bearer " prefix (case-sensitive, with space). Plain tokens without the prefix will be rejected.

```bash
# Correct
Authorization: Bearer my_secret_token

# Incorrect - will fail
Authorization: my_secret_token
Authorization: bearer my_secret_token
Authorization: BEARER my_secret_token
```
:::

