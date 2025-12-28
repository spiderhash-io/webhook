# How to Receive Webhooks from Stripe

## Introduction

Stripe is one of the most popular payment processors, and receiving webhooks from Stripe is essential for handling payment events in real-time. This guide will walk you through setting up Core Webhook Module to receive and process Stripe webhooks securely.

## Understanding Stripe Webhooks

Stripe sends webhook events to notify your application about important events in your Stripe account, such as:
- Payment successes and failures
- Subscription updates
- Chargebacks and disputes
- Invoice payments
- Customer updates
- And many more...

### Stripe Webhook Security

Stripe uses **HMAC signature verification** to ensure webhook requests are authentic. Each webhook request includes:
- **X-Stripe-Signature header**: Contains a timestamp and signature in the format `t=<timestamp>,v1=<signature>`
- **Signing Secret**: A secret key unique to each webhook endpoint (starts with `whsec_`)
- **HMAC-SHA256**: The signature is computed using HMAC-SHA256 over the timestamp and request body

**Important**: Always verify webhook signatures to prevent unauthorized requests from being processed.

## Prerequisites

Before you begin, ensure you have:
1. Core Webhook Module installed and running
2. A Stripe account (test or live)
3. Access to your Stripe Dashboard
4. (Optional) ngrok or similar tool for local development

## Step-by-Step Setup

### Step 1: Configure Core Webhook Module

First, let's configure Core Webhook Module to receive Stripe webhooks. You'll need to set up:

1. **Webhook Configuration** (`webhooks.json`)
2. **Connection Configuration** (`connections.json`) - if storing in a database
3. **Environment Variables** - for sensitive data

#### Basic Stripe Webhook Configuration

Create or update your `webhooks.json` file:

```json
{
  "stripe_payments": {
    "data_type": "json",
    "module": "log",
    "hmac": {
      "secret": "{$STRIPE_WEBHOOK_SECRET}",
      "header": "X-Stripe-Signature",
      "algorithm": "sha256"
    },
    "rate_limit": {
      "max_requests": 100,
      "window_seconds": 60
    }
  }
}
```

**Configuration Explanation:**
- `stripe_payments`: Your webhook ID (used in the URL: `/webhook/stripe_payments`)
- `data_type`: `"json"` for JSON payloads
- `module`: Where to send the webhook data (we'll explore options below)
- `hmac`: HMAC signature validation configuration
  - `secret`: Your Stripe webhook signing secret (starts with `whsec_`)
  - `header`: Stripe's signature header name (`X-Stripe-Signature`)
  - `algorithm`: `sha256` (Stripe uses HMAC-SHA256)
- `rate_limit`: Optional rate limiting to prevent abuse

#### Using Environment Variables

For security, use environment variables for sensitive data. Create a `.env` file:

```bash
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_signing_secret_here
```

Then reference it in your configuration using `{$STRIPE_WEBHOOK_SECRET}`.

### Step 2: Get Your Stripe Webhook Signing Secret

1. **Log in to Stripe Dashboard**: Go to [https://dashboard.stripe.com](https://dashboard.stripe.com)

2. **Navigate to Webhooks**: 
   - Click on **Developers** in the left sidebar
   - Click on **Webhooks**

3. **Create or Select Endpoint**:
   - If you haven't created an endpoint yet, click **Add endpoint**
   - Enter your webhook URL (we'll set this up in the next step)
   - Select the events you want to receive
   - Click **Add endpoint**

4. **Get Signing Secret**:
   - Click on your webhook endpoint
   - Under **Signing secret**, click **Reveal**
   - Copy the secret (it starts with `whsec_`)

5. **Add to Environment Variables**:
   ```bash
   export STRIPE_WEBHOOK_SECRET=whsec_your_actual_secret_here
   ```

### Step 3: Set Up Your Webhook URL

#### For Production

If you're deploying to production, use your production URL:
```
https://yourdomain.com/webhook/stripe_payments
```

#### For Local Development

For local development, you'll need to expose your local server to the internet. Here are two options:

##### Option A: Using ngrok (Recommended)

1. **Install ngrok**: Download from [https://ngrok.com/download](https://ngrok.com/download)

2. **Start Core Webhook Module**:
   ```bash
   uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
   ```

3. **Start ngrok**:
   ```bash
   ngrok http 8000
   ```

4. **Copy the HTTPS URL**: ngrok will provide a URL like `https://abc123.ngrok.io`

5. **Use in Stripe Dashboard**: 
   - Webhook URL: `https://abc123.ngrok.io/webhook/stripe_payments`

##### Option B: Using Stripe CLI (Alternative)

Stripe CLI can forward webhooks to your local server:

1. **Install Stripe CLI**: Follow [Stripe CLI installation guide](https://stripe.com/docs/stripe-cli)

2. **Login to Stripe**:
   ```bash
   stripe login
   ```

3. **Forward webhooks**:
   ```bash
   stripe listen --forward-to localhost:8000/webhook/stripe_payments
   ```

4. **Get webhook signing secret**:
   ```bash
   stripe listen --print-secret
   ```

### Step 4: Configure Where to Send Webhook Data

Core Webhook Module supports multiple destinations. Here are common configurations:

#### Option 1: Log to Console (Development)

```json
{
  "stripe_payments": {
    "data_type": "json",
    "module": "log",
    "hmac": {
      "secret": "{$STRIPE_WEBHOOK_SECRET}",
      "header": "X-Stripe-Signature",
      "algorithm": "sha256"
    }
  }
}
```

#### Option 2: Save to Database (PostgreSQL)

```json
{
  "stripe_payments": {
    "data_type": "json",
    "module": "postgresql",
    "connection": "postgres_prod",
    "module-config": {
      "table": "stripe_events",
      "storage_mode": "json"
    },
    "hmac": {
      "secret": "{$STRIPE_WEBHOOK_SECRET}",
      "header": "X-Stripe-Signature",
      "algorithm": "sha256"
    }
  }
}
```

**Connection Configuration** (`connections.json`):
```json
{
  "postgres_prod": {
    "type": "postgresql",
    "host": "{$POSTGRES_HOST}",
    "port": 5432,
    "database": "{$POSTGRES_DB}",
    "user": "{$POSTGRES_USER}",
    "password": "{$POSTGRES_PASSWORD}"
  }
}
```

#### Option 3: Send to Message Queue (RabbitMQ)

```json
{
  "stripe_payments": {
    "data_type": "json",
    "module": "rabbitmq",
    "connection": "rabbitmq_prod",
    "module-config": {
      "queue_name": "stripe_events"
    },
    "hmac": {
      "secret": "{$STRIPE_WEBHOOK_SECRET}",
      "header": "X-Stripe-Signature",
      "algorithm": "sha256"
    }
  }
}
```

#### Option 4: Store in S3 (Archival)

```json
{
  "stripe_payments": {
    "data_type": "json",
    "module": "s3",
    "connection": "s3_storage",
    "module-config": {
      "bucket": "webhook-archive",
      "prefix": "stripe/events",
      "filename_pattern": "stripe_{timestamp}_{uuid}.json"
    },
    "hmac": {
      "secret": "{$STRIPE_WEBHOOK_SECRET}",
      "header": "X-Stripe-Signature",
      "algorithm": "sha256"
    }
  }
}
```

#### Option 5: Chain Multiple Destinations

You can send to multiple destinations using webhook chaining:

```json
{
  "stripe_payments": {
    "data_type": "json",
    "chain": [
      {
        "module": "postgresql",
        "connection": "postgres_prod",
        "module-config": {
          "table": "stripe_events"
        }
      },
      {
        "module": "rabbitmq",
        "connection": "rabbitmq_prod",
        "module-config": {
          "queue_name": "stripe_events"
        }
      }
    ],
    "chain-config": {
      "execution": "parallel",
      "continue_on_error": true
    },
    "hmac": {
      "secret": "{$STRIPE_WEBHOOK_SECRET}",
      "header": "X-Stripe-Signature",
      "algorithm": "sha256"
    }
  }
}
```

### Step 5: Start Core Webhook Module

```bash
# Install dependencies (if not already done)
pip install -r requirements.txt

# Start the server
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

The server will be available at:
- API: `http://localhost:8000`
- Webhook endpoint: `http://localhost:8000/webhook/stripe_payments`
- API Documentation: `http://localhost:8000/docs`

### Step 6: Test Your Webhook

#### Using Stripe Dashboard

1. **Go to Stripe Dashboard** > **Developers** > **Webhooks**
2. **Click on your webhook endpoint**
3. **Click "Send test webhook"**
4. **Select an event type** (e.g., `payment_intent.succeeded`)
5. **Click "Send test webhook"**

#### Using Stripe CLI

```bash
# Trigger a test event
stripe trigger payment_intent.succeeded

# Or forward events to your local server
stripe listen --forward-to localhost:8000/webhook/stripe_payments
```

#### Verify It's Working

Check your Core Webhook Module logs. You should see:
- Successful HMAC signature validation
- Webhook payload being processed
- Data being sent to your configured destination

## Understanding Stripe Webhook Events

### Common Stripe Events

Here are some common Stripe events you might want to handle:

- `payment_intent.succeeded` - Payment completed successfully
- `payment_intent.payment_failed` - Payment failed
- `charge.succeeded` - Charge succeeded
- `charge.failed` - Charge failed
- `customer.subscription.created` - New subscription created
- `customer.subscription.updated` - Subscription updated
- `customer.subscription.deleted` - Subscription cancelled
- `invoice.payment_succeeded` - Invoice paid
- `invoice.payment_failed` - Invoice payment failed
- `charge.dispute.created` - Chargeback/dispute created

### Event Payload Structure

Stripe webhook payloads follow this structure:

```json
{
  "id": "evt_1234567890",
  "object": "event",
  "api_version": "2023-10-16",
  "created": 1699123456,
  "data": {
    "object": {
      // Event-specific data (e.g., PaymentIntent, Charge, etc.)
    },
    "previous_attributes": {
      // Fields that changed (for update events)
    }
  },
  "livemode": false,
  "pending_webhooks": 1,
  "request": {
    "id": "req_1234567890",
    "idempotency_key": null
  },
  "type": "payment_intent.succeeded"
}
```

## Advanced Configuration

### Adding Rate Limiting

Protect your endpoint from abuse:

```json
{
  "stripe_payments": {
    "data_type": "json",
    "module": "log",
    "hmac": {
      "secret": "{$STRIPE_WEBHOOK_SECRET}",
      "header": "X-Stripe-Signature",
      "algorithm": "sha256"
    },
    "rate_limit": {
      "max_requests": 100,
      "window_seconds": 60
    }
  }
}
```

### Adding IP Whitelisting

Restrict access to Stripe's IP addresses (optional, as HMAC validation is usually sufficient):

```json
{
  "stripe_payments": {
    "data_type": "json",
    "module": "log",
    "hmac": {
      "secret": "{$STRIPE_WEBHOOK_SECRET}",
      "header": "X-Stripe-Signature",
      "algorithm": "sha256"
    },
    "ip_whitelist": [
      "54.187.174.169",
      "54.187.205.235",
      "54.187.216.72"
      // Add more Stripe IPs as needed
    ]
  }
}
```

**Note**: Stripe's IP addresses can change. HMAC signature validation is the recommended security method.

### Adding Retry Logic

Handle temporary failures with automatic retries:

```json
{
  "stripe_payments": {
    "data_type": "json",
    "module": "postgresql",
    "connection": "postgres_prod",
    "module-config": {
      "table": "stripe_events"
    },
    "hmac": {
      "secret": "{$STRIPE_WEBHOOK_SECRET}",
      "header": "X-Stripe-Signature",
      "algorithm": "sha256"
    },
    "retry": {
      "enabled": true,
      "max_attempts": 3,
      "initial_delay": 1.0,
      "max_delay": 60.0,
      "backoff_multiplier": 2.0
    }
  }
}
```

### Credential Cleanup

Automatically mask sensitive data before logging:

```json
{
  "stripe_payments": {
    "data_type": "json",
    "module": "log",
    "hmac": {
      "secret": "{$STRIPE_WEBHOOK_SECRET}",
      "header": "X-Stripe-Signature",
      "algorithm": "sha256"
    },
    "credential_cleanup": {
      "enabled": true,
      "mode": "mask",
      "fields": ["secret", "api_key", "private_key"]
    }
  }
}
```

## Troubleshooting

### Issue: HMAC Signature Validation Failing

**Symptoms**: Webhook requests are rejected with "Invalid HMAC signature"

**Solutions**:
1. **Verify your signing secret**: Make sure you're using the correct secret from Stripe Dashboard
2. **Check header name**: Ensure `header` is set to `"X-Stripe-Signature"` (case-sensitive)
3. **Verify algorithm**: Must be `"sha256"`
4. **Check environment variable**: Ensure `{$STRIPE_WEBHOOK_SECRET}` is properly set
5. **Raw body**: Make sure Core Webhook Module is receiving the raw request body (it does by default)

### Issue: Webhooks Not Being Received

**Symptoms**: No webhook events appearing in logs

**Solutions**:
1. **Check webhook URL**: Verify the URL in Stripe Dashboard matches your endpoint
2. **Check server status**: Ensure Core Webhook Module is running
3. **Check ngrok**: If using ngrok, verify it's running and forwarding correctly
4. **Check firewall**: Ensure port 8000 (or your port) is accessible
5. **Check Stripe Dashboard**: Look for failed webhook deliveries in Stripe Dashboard

### Issue: Webhook Events Not Processing

**Symptoms**: Webhooks received but not processed correctly

**Solutions**:
1. **Check module configuration**: Verify your module (log, postgresql, etc.) is configured correctly
2. **Check connection**: If using a database or message queue, verify connection details
3. **Check logs**: Look for error messages in Core Webhook Module logs
4. **Test module separately**: Try sending a test request directly to verify module functionality

## Security Best Practices

1. **Always Verify HMAC Signatures**: Never skip signature verification in production
2. **Use Environment Variables**: Never hardcode secrets in configuration files
3. **Use HTTPS**: Always use HTTPS in production (Stripe requires it)
4. **Monitor Webhook Failures**: Set up alerts for failed webhook deliveries
5. **Idempotency**: Handle duplicate events (Stripe may retry failed webhooks)
6. **Rate Limiting**: Use rate limiting to prevent abuse
7. **Credential Cleanup**: Enable credential cleanup to prevent sensitive data exposure in logs

## Complete Example Configuration

Here's a complete production-ready configuration:

**webhooks.json:**
```json
{
  "stripe_payments": {
    "data_type": "json",
    "module": "postgresql",
    "connection": "postgres_prod",
    "module-config": {
      "table": "stripe_events",
      "storage_mode": "json",
      "include_headers": true
    },
    "hmac": {
      "secret": "{$STRIPE_WEBHOOK_SECRET}",
      "header": "X-Stripe-Signature",
      "algorithm": "sha256"
    },
    "rate_limit": {
      "max_requests": 200,
      "window_seconds": 60
    },
    "retry": {
      "enabled": true,
      "max_attempts": 3,
      "initial_delay": 1.0,
      "max_delay": 60.0
    },
    "credential_cleanup": {
      "enabled": true,
      "mode": "mask"
    }
  }
}
```

**connections.json:**
```json
{
  "postgres_prod": {
    "type": "postgresql",
    "host": "{$POSTGRES_HOST}",
    "port": 5432,
    "database": "{$POSTGRES_DB}",
    "user": "{$POSTGRES_USER}",
    "password": "{$POSTGRES_PASSWORD}"
  }
}
```

**.env:**
```bash
STRIPE_WEBHOOK_SECRET=whsec_your_actual_secret_here
POSTGRES_HOST=localhost
POSTGRES_DB=webhook_db
POSTGRES_USER=webhook_user
POSTGRES_PASSWORD=your_secure_password
```

## Next Steps

1. **Set up monitoring**: Monitor webhook delivery success rates
2. **Handle events**: Implement business logic to process different event types
3. **Set up alerts**: Configure alerts for critical events (payment failures, chargebacks)
4. **Test thoroughly**: Test all event types you'll be handling
5. **Document your events**: Document which events your application handles

## Additional Resources

- [Stripe Webhooks Documentation](https://stripe.com/docs/webhooks)
- [Stripe Webhook Signature Verification](https://stripe.com/docs/webhooks/signatures)
- [Stripe Event Types Reference](https://stripe.com/docs/api/events/types)
- [Core Webhook Module README](../README.md)
- [Core Webhook Module Architecture](../docs/ARCHITECTURE.md)

## Conclusion

You now have Core Webhook Module configured to securely receive and process Stripe webhooks! The HMAC signature validation ensures that only authentic requests from Stripe are processed, and the flexible routing system allows you to send webhook data to any destination you need.

Remember to:
- Always verify HMAC signatures
- Use environment variables for secrets
- Test thoroughly before going to production
- Monitor webhook delivery success rates

Happy webhook processing! 🎉

---

*This is part 2 of our blog series. Check out [Part 1: What is This Tool?](001_what_is_this_tool.md) for an overview of Core Webhook Module.*

