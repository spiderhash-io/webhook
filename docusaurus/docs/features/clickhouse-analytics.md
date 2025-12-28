# ClickHouse Analytics

Automatic logging of all webhook events to ClickHouse for analytics and monitoring.

## Overview

The ClickHouse Analytics feature automatically logs all webhook events to ClickHouse, providing:

- Long-term event storage
- Analytics and reporting
- Performance monitoring
- Error tracking

## Configuration

ClickHouse analytics is configured via environment variables:

```bash
CLICKHOUSE_ENABLED=true
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=8123
CLICKHOUSE_DATABASE=webhooks
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=
CLICKHOUSE_TABLE=webhook_events
```

## Data Schema

Events are stored with the following structure:

- `webhook_id`: Webhook identifier
- `timestamp`: Event timestamp
- `payload`: Webhook payload (JSON)
- `headers`: HTTP headers (JSON)
- `status`: Processing status
- `error`: Error message (if any)
- `processing_time_ms`: Processing time in milliseconds

## Features

- Automatic event logging
- High-performance columnar storage
- Time-series optimization
- Credential cleanup (automatic)
- Distributed architecture support
- Analytics processor for aggregated statistics

## Analytics Processor

A separate analytics processor reads from ClickHouse and calculates aggregated statistics:

- Request counts by time period
- Error rates
- Average processing times
- Top webhooks by volume
- Performance metrics

