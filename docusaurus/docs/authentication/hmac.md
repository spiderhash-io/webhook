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

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `secret` | string | **Yes** | - | HMAC secret key |
| `header` | string | No | `"X-Hub-Signature-256"` | Header name containing the signature |
| `algorithm` | string | No | `"sha256"` | Hash algorithm: `sha256`, `sha1`, or `sha512` |

:::info Header Name Lookup
Header names are case-insensitive for lookup. For example, `X-Hub-Signature-256`, `x-hub-signature-256`, and `X-HUB-SIGNATURE-256` all work.
:::

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

## Signature Format

Signatures must be provided in **hexadecimal format**. The signature can optionally include an algorithm prefix:

```
# With algorithm prefix (GitHub style)
sha256=abc123def456...

# Without prefix (plain hex)
abc123def456...
```

:::warning Base64 Not Supported
Base64-encoded signatures are not supported. If your webhook provider sends base64 signatures (like Shopify), you'll need to convert them to hex format or use a proxy.
:::

