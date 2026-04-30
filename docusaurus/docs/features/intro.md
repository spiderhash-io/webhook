---
description: "Overview of Core Webhook Module features including chaining, rate limiting, schema validation, credential cleanup, and live config reload."
---

# Core Features

The Core Webhook Module includes several powerful features for processing and managing webhooks.

## Available Features

- **[Webhook Chaining](./webhook-chaining.md)** - Send payloads to multiple destinations in sequence or parallel
  - [Getting Started](./webhook-chaining-getting-started.md) - Step-by-step guide
  - [Advanced Usage](./webhook-chaining-advanced.md) - Per-module configs, retries, and best practices
  - [Troubleshooting](./webhook-chaining-troubleshooting.md) - Common issues and solutions
- **[Webhook Connect](./webhook-connect.md)** - Cloud-to-local webhook relay system (similar to ngrok)
  - [Getting Started](./webhook-connect-getting-started.md) - Step-by-step setup guide
  - [Advanced Usage](./webhook-connect-advanced.md) - Multi-channel, production deployment, security
  - [Troubleshooting](./webhook-connect-troubleshooting.md) - Common issues and solutions
- **[Rate Limiting](./rate-limiting.md)** - Per-webhook rate limiting
- **[JSON Schema Validation](./json-schema.md)** - Validate payload structure
- **[Credential Cleanup](./credential-cleanup.md)** - Automatic credential masking
- **[IP Whitelisting](./ip-whitelisting.md)** - Restrict access by IP address
- **[Retry Handling](./retry-handling.md)** - Automatic retry with exponential backoff
- **[Live Config Reload](./live-config-reload.md)** - Hot-reload configurations
- **[Distributed Config (etcd)](./distributed-config-etcd.md)** - Distributed, namespace-scoped configuration via etcd
- **[Vault Secret Management](./vault-secrets.md)** - Resolve secrets from HashiCorp Vault
- **[Connection Pooling](./connection-pooling.md)** - Efficient connection management
- **[Statistics](./statistics.md)** - Webhook usage tracking
- **[ClickHouse Analytics](./clickhouse-analytics.md)** - Analytics and monitoring

