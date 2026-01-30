# Statistics

Internal metrics for monitoring webhook processing performance.

## Overview

The webhook module tracks internal execution metrics for chain processing and task management. These metrics are used for monitoring and debugging purposes.

:::info Planned Feature
A dedicated `/stats` endpoint for per-webhook request statistics is planned for a future release. Currently, statistics are available through:
- ClickHouse Analytics (if enabled) - see [ClickHouse Analytics](clickhouse-analytics)
- Application logs
- Internal metrics
:::

## Internal Metrics

The following metrics are tracked internally:

### Chain Execution Metrics

| Metric | Description |
|--------|-------------|
| `chain_executions_total` | Total number of chain executions |
| `chain_executions_failed` | Number of failed chain executions |
| `tasks_dropped` | Tasks dropped due to queue limits |

### Available via ClickHouse

If ClickHouse Analytics is enabled, detailed per-webhook statistics are available:

```sql
-- Requests per webhook in last hour
SELECT
    webhook_id,
    count() as request_count,
    avg(processing_time_ms) as avg_processing_time
FROM webhook_events
WHERE timestamp > now() - INTERVAL 1 HOUR
GROUP BY webhook_id
ORDER BY request_count DESC;

-- Error rate by webhook
SELECT
    webhook_id,
    countIf(status != 'success') / count() * 100 as error_rate_percent
FROM webhook_events
WHERE timestamp > now() - INTERVAL 24 HOUR
GROUP BY webhook_id;
```

## Health Check

Basic application health is available via:

```bash
curl http://localhost:8000/health
```

Response:
```json
{
    "status": "healthy"
}
```

## Related Documentation

- [ClickHouse Analytics](clickhouse-analytics) - Detailed webhook analytics and statistics
- [Live Config Reload](live-config-reload) - Configuration management and status
