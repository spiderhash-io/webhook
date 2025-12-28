# HMAC Signature Validation

Validates webhook signatures using HMAC-SHA256, SHA1, or SHA512. Commonly used by services like GitHub, Stripe, and Shopify.

## Configuration

```json
{
    "github_webhook": {
        "data_type": "json",
        "module": "log",
        "authorization": "Bearer token",
        "hmac": {
            "secret": "your_hmac_secret",
            "header": "X-Hub-Signature-256",
            "algorithm": "sha256"
        }
    }
}
```

## Configuration Options

- `secret`: HMAC secret key (required)
- `header`: Header name containing the signature (default: "X-Hub-Signature-256")
- `algorithm`: Hash algorithm - "sha256", "sha1", or "sha512" (default: "sha256")

## Usage

Send requests with HMAC signature in the specified header:

```bash
curl -X POST http://localhost:8000/webhook/github_webhook \
  -H "Authorization: Bearer token" \
  -H "X-Hub-Signature-256: sha256=abc123..." \
  -H "Content-Type: application/json" \
  -d '{"event": "test"}'
```

## Common Header Formats

- **GitHub**: `X-Hub-Signature-256` (sha256=...)
- **Stripe**: `Stripe-Signature` (t=timestamp,v1=signature)
- **Shopify**: `X-Shopify-Hmac-Sha256` (base64 encoded)

## Features

- Multiple hash algorithms (SHA256, SHA1, SHA512)
- Custom header support
- Constant-time comparison (timing attack resistant)
- Signature format validation

