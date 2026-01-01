# Retry Handling

Automatic retry mechanism for failed module executions with exponential backoff. This feature ensures webhook processing reliability by automatically retrying failed operations with configurable delays and attempt limits.

## Configuration

```json
{
    "reliable_webhook": {
        "data_type": "json",
        "module": "rabbitmq",
        "connection": "rabbitmq_local",
        "module-config": {
            "queue_name": "events"
        },
        "retry": {
            "enabled": true,
            "max_attempts": 5,
            "initial_delay": 1.0,
            "max_delay": 10.0,
            "backoff_multiplier": 2.0
        }
    }
}
```

## Configuration Options

- `enabled`: Enable retry mechanism (default: `false`)
- `max_attempts`: Maximum number of retry attempts (default: `3`, max: `20`)
- `initial_delay`: Initial delay in seconds before first retry (default: `1.0`, max: `60.0`)
- `max_delay`: Maximum delay in seconds between retries (default: `60.0`, max: `60.0`)
- `backoff_multiplier`: Multiplier for exponential backoff (default: `2.0`, max: `10.0`)
- `retryable_errors`: List of error types that should be retried (optional)
- `non_retryable_errors`: List of error types that should not be retried (optional)

## How It Works

1. **Initial Attempt**: Module executes normally
2. **Error Detection**: If an error occurs, the system checks if it's retryable
3. **Backoff Calculation**: Calculates delay using exponential backoff formula: `delay = initial_delay * (backoff_multiplier ^ attempt)`
4. **Retry Execution**: Waits for the calculated delay, then retries
5. **Success or Failure**: Continues until success or max attempts reached

## Exponential Backoff

The retry mechanism uses exponential backoff to gradually increase delays between attempts:

- **Attempt 1**: Immediate (no delay)
- **Attempt 2**: `initial_delay` seconds
- **Attempt 3**: `initial_delay * backoff_multiplier` seconds
- **Attempt 4**: `initial_delay * (backoff_multiplier ^ 2)` seconds
- And so on...

Delays are capped at `max_delay` to prevent excessive waiting times.

## Default Retryable Errors

The following error types are retried by default:

- `ConnectionError`
- `ConnectionRefusedError`
- `TimeoutError`
- `OSError`

## Default Non-Retryable Errors

The following error types are **not** retried (fail immediately):

- `AuthenticationError`
- `PermissionError`
- `ValueError`
- `KeyError`
- `TypeError`

## Examples

### Basic Retry Configuration

```json
{
    "webhook_with_retry": {
        "data_type": "json",
        "module": "postgresql",
        "connection": "postgres_local",
        "module-config": {
            "table": "events"
        },
        "retry": {
            "enabled": true,
            "max_attempts": 3
        }
    }
}
```

### Custom Retry Configuration

```json
{
    "custom_retry_webhook": {
        "data_type": "json",
        "module": "s3",
        "connection": "s3_storage",
        "module-config": {
            "bucket": "webhooks"
        },
        "retry": {
            "enabled": true,
            "max_attempts": 5,
            "initial_delay": 2.0,
            "max_delay": 30.0,
            "backoff_multiplier": 2.5
        }
    }
}
```

### Custom Error Types

```json
{
    "selective_retry_webhook": {
        "data_type": "json",
        "module": "kafka",
        "connection": "kafka_local",
        "module-config": {
            "topic": "events"
        },
        "retry": {
            "enabled": true,
            "max_attempts": 4,
            "retryable_errors": [
                "ConnectionError",
                "TimeoutError",
                "KafkaError"
            ],
            "non_retryable_errors": [
                "AuthenticationError",
                "ValueError"
            ]
        }
    }
}
```

### Retry in Webhook Chains

Retry can be configured per-module in webhook chains:

```json
{
    "chained_with_retry": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_storage",
                "module-config": {
                    "bucket": "archive"
                },
                "retry": {
                    "enabled": true,
                    "max_attempts": 3
                }
            },
            {
                "module": "rabbitmq",
                "connection": "rabbitmq_local",
                "module-config": {
                    "queue_name": "process"
                },
                "retry": {
                    "enabled": true,
                    "max_attempts": 5,
                    "initial_delay": 2.0
                }
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": true
        }
    }
}
```

## Backoff Calculation Examples

### Example 1: Default Configuration
- `initial_delay`: 1.0s
- `max_delay`: 60.0s
- `backoff_multiplier`: 2.0
- `max_attempts`: 3

**Retry Timeline:**
- Attempt 1: Immediate
- Attempt 2: Wait 1.0s → Retry
- Attempt 3: Wait 2.0s → Retry
- Final: Success or failure

### Example 2: Aggressive Retry
- `initial_delay`: 0.5s
- `max_delay`: 10.0s
- `backoff_multiplier`: 2.0
- `max_attempts`: 5

**Retry Timeline:**
- Attempt 1: Immediate
- Attempt 2: Wait 0.5s → Retry
- Attempt 3: Wait 1.0s → Retry
- Attempt 4: Wait 2.0s → Retry
- Attempt 5: Wait 4.0s → Retry
- Final: Success or failure

### Example 3: Conservative Retry
- `initial_delay`: 5.0s
- `max_delay`: 60.0s
- `backoff_multiplier`: 2.0
- `max_attempts`: 4

**Retry Timeline:**
- Attempt 1: Immediate
- Attempt 2: Wait 5.0s → Retry
- Attempt 3: Wait 10.0s → Retry
- Attempt 4: Wait 20.0s → Retry
- Final: Success or failure

## Security Features

### DoS Protection

The retry handler includes security limits to prevent resource exhaustion attacks:

- **Maximum Attempts**: Capped at 20 (prevents infinite retries)
- **Maximum Delay**: Capped at 60 seconds (prevents excessive waiting)
- **Maximum Backoff Multiplier**: Capped at 10.0 (prevents exponential explosion)
- **Configuration Validation**: All values are validated and sanitized

### Error Classification

- **Unknown Errors**: Default to non-retryable (fail-safe)
- **Security Errors**: Never retried (authentication, permission errors)
- **Transient Errors**: Retried (connection, timeout errors)

## Best Practices

1. **Use appropriate max_attempts**: Balance between reliability and resource usage
   - Network issues: 3-5 attempts
   - Database issues: 5-10 attempts
   - External APIs: 3-5 attempts

2. **Configure initial_delay**: Start with 1-2 seconds for most cases
   - Fast recovery: 0.5-1.0s
   - Normal: 1.0-2.0s
   - Conservative: 5.0s+

3. **Set max_delay**: Cap delays to prevent excessive waiting
   - Quick operations: 10-30s
   - Normal operations: 30-60s
   - Long operations: 60s (max)

4. **Customize error types**: Specify retryable/non-retryable errors for your use case

5. **Monitor retry patterns**: Check logs for frequent retries indicating underlying issues

## Features

- Exponential backoff with configurable multiplier
- Configurable retry attempts and delays
- Custom error type classification
- Security limits to prevent DoS attacks
- Per-module retry configuration in chains
- Automatic error detection and classification
- Detailed logging for debugging

