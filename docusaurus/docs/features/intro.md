# Core Features

The Core Webhook Module includes several powerful features for processing and managing webhooks.

## Available Features

- **[Webhook Chaining](webhook-chaining)** - Send payloads to multiple destinations in sequence or parallel
  - [Getting Started](webhook-chaining-getting-started) - Step-by-step guide
  - [Advanced Usage](webhook-chaining-advanced) - Per-module configs, retries, and best practices
  - [Troubleshooting](webhook-chaining-troubleshooting) - Common issues and solutions
- **[Webhook Connect](webhook-connect)** - Cloud-to-local webhook relay system (similar to ngrok)
  - [Getting Started](webhook-connect-getting-started) - Step-by-step setup guide
  - [Advanced Usage](webhook-connect-advanced) - Multi-channel, production deployment, security
  - [Troubleshooting](webhook-connect-troubleshooting) - Common issues and solutions
- **[Rate Limiting](rate-limiting)** - Per-webhook rate limiting
- **[JSON Schema Validation](json-schema)** - Validate payload structure
- **[Credential Cleanup](credential-cleanup)** - Automatic credential masking
- **[IP Whitelisting](ip-whitelisting)** - Restrict access by IP address
- **[Retry Handling](retry-handling)** - Automatic retry with exponential backoff
- **[Live Config Reload](live-config-reload)** - Hot-reload configurations
- **[Distributed Config (etcd)](distributed-config-etcd)** - Distributed, namespace-scoped configuration via etcd
- **[Vault Secret Management](vault-secrets)** - Resolve secrets from HashiCorp Vault
- **[Connection Pooling](connection-pooling)** - Efficient connection management
- **[Statistics](statistics)** - Webhook usage tracking
- **[ClickHouse Analytics](clickhouse-analytics)** - Analytics and monitoring

