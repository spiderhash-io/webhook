# Advanced Webhook Chaining

This guide covers advanced features and best practices for webhook chaining.

## Per-Module Configuration

Each module in a chain can have its own configuration, connection, and retry settings. This allows fine-grained control over each step in your chain.

### Module-Specific Configuration

Use `module-config` to configure each module individually:

```json
{
    "advanced_chain": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_production",
                "module-config": {
                    "bucket": "webhook-archive",
                    "prefix": "production/events",
                    "filename_pattern": "webhook_{timestamp}.json"
                }
            },
            {
                "module": "redis_rq",
                "connection": "redis_staging",
                "module-config": {
                    "queue_name": "process_events",
                    "function": "process_webhook"
                }
            },
            {
                "module": "postgresql",
                "connection": "postgres_analytics",
                "module-config": {
                    "table": "webhook_events",
                    "schema": "analytics"
                }
            }
        ],
        "chain-config": {
            "execution": "sequential"
        },
        "authorization": "Bearer secret"
    }
}
```

### Different Connections per Module

Each module can use a different connection, allowing you to route data to different environments or services:

```json
{
    "multi_environment_chain": {
        "data_type": "json",
        "chain": [
            {
                "module": "postgresql",
                "connection": "postgres_production",  // Production DB
                "module-config": {
                    "table": "events"
                }
            },
            {
                "module": "postgresql",
                "connection": "postgres_analytics",  // Analytics DB
                "module-config": {
                    "table": "events"
                }
            }
        ],
        "chain-config": {
            "execution": "parallel"
        },
        "authorization": "Bearer secret"
    }
}
```

## Per-Module Retry Configuration

Each module can have its own retry strategy:

```json
{
    "chain_with_retries": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_storage",
                "module-config": {
                    "bucket": "webhooks"
                },
                "retry": {
                    "enabled": true,
                    "max_attempts": 5,
                    "initial_delay": 1.0,
                    "max_delay": 60.0,
                    "backoff_multiplier": 2.0
                }
            },
            {
                "module": "http_webhook",
                "module-config": {
                    "url": "https://api.example.com/webhooks",
                    "method": "POST"
                },
                "retry": {
                    "enabled": true,
                    "max_attempts": 3,
                    "initial_delay": 0.5
                }
            },
            {
                "module": "log"  // No retry needed for logging
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": false
        },
        "authorization": "Bearer secret"
    }
}
```

### Retry Configuration Options

- **`enabled`** (boolean): Enable retries for this module
- **`max_attempts`** (integer): Maximum number of retry attempts (default: 3)
- **`initial_delay`** (float): Initial delay in seconds before first retry (default: 1.0)
- **`max_delay`** (float): Maximum delay between retries in seconds (default: 60.0)
- **`backoff_multiplier`** (float): Multiplier for exponential backoff (default: 2.0)

## Configuration Inheritance

Chain items inherit configuration from the base webhook config, but can override it:

```json
{
    "inheritance_example": {
        "data_type": "json",
        "authorization": "Bearer secret",  // Inherited by all modules
        "rate_limit": {  // Inherited by all modules
            "max_requests": 100,
            "window_seconds": 60
        },
        "chain": [
            {
                "module": "s3",
                "connection": "s3_storage",
                // Inherits: authorization, rate_limit, data_type
                "module-config": {
                    "bucket": "webhooks"  // Module-specific
                }
            },
            {
                "module": "redis_rq",
                "connection": "redis_local",
                // Inherits: authorization, rate_limit, data_type
                "module-config": {
                    "queue_name": "events"  // Module-specific
                }
            }
        ],
        "chain-config": {
            "execution": "sequential"
        }
    }
}
```

## Error Handling Strategies

### Best-Effort Delivery (Default)

Continue executing all modules even if some fail:

```json
{
    "best_effort": {
        "data_type": "json",
        "chain": ["s3", "redis_rq", "log"],
        "chain-config": {
            "execution": "parallel",
            "continue_on_error": true  // Default
        },
        "authorization": "Bearer secret"
    }
}
```

**Use when:** All destinations are independent and partial success is acceptable.

### Fail-Fast Strategy

Stop chain execution on first error:

```json
{
    "fail_fast": {
        "data_type": "json",
        "chain": [
            {
                "module": "postgresql",
                "connection": "postgres_local",
                "module-config": {
                    "table": "events"
                }
            },
            {
                "module": "kafka",
                "connection": "kafka_local",
                "module-config": {
                    "topic": "events"
                }
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": false  // Stop on first error
        },
        "authorization": "Bearer secret"
    }
}
```

**Use when:** Later modules depend on earlier ones succeeding.

### Selective Error Handling

Combine retries with error handling:

```json
{
    "selective_handling": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_storage",
                "module-config": {
                    "bucket": "webhooks"
                },
                "retry": {
                    "enabled": true,
                    "max_attempts": 5  // Retry S3 up to 5 times
                }
            },
            {
                "module": "log"  // Always succeeds, no retry needed
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": true  // Continue even if S3 fails after retries
        },
        "authorization": "Bearer secret"
    }
}
```

## Performance Optimization

### Choosing Execution Mode

**Sequential** - Use when:
- Modules depend on each other
- Order matters
- You need to ensure one completes before the next starts

**Parallel** - Use when:
- Modules are independent
- You want to minimize total latency
- You have sufficient resources (task manager capacity)

### Chain Length Considerations

- **Sequential chains**: Keep under 5-10 modules to avoid excessive latency
- **Parallel chains**: Limited by TaskManager capacity (default: 100 concurrent tasks)
- **Memory usage**: Each module gets a copy of the payload

### Resource Management

Monitor these metrics when using chains:

- **Task Manager**: Number of concurrent tasks
- **Memory**: Payload size × number of modules
- **Connections**: Each module opens its own connections

## Security Best Practices

### Chain Length Limits

The system enforces a maximum chain length of 20 modules to prevent DoS attacks. Plan your chains accordingly.

### Credential Cleanup

Credential cleanup applies to all modules in a chain:

```json
{
    "secure_chain": {
        "data_type": "json",
        "chain": ["s3", "redis_rq"],
        "chain-config": {
            "execution": "sequential"
        },
        "authorization": "Bearer secret",
        "credential_cleanup": {
            "enabled": true,
            "mode": "mask",
            "fields": ["password", "api_key", "secret"]
        }
    }
}
```

### Module Validation

All modules in a chain are validated before execution:
- Module names must exist in ModuleRegistry
- Configuration structure is validated
- Type checking prevents injection attacks

## Complex Use Cases

### Data Transformation Pipeline

Transform data through multiple steps:

```json
{
    "transformation_pipeline": {
        "data_type": "json",
        "chain": [
            {
                "module": "postgresql",
                "connection": "postgres_staging",
                "module-config": {
                    "table": "raw_events"
                }
            },
            {
                "module": "http_webhook",
                "module-config": {
                    "url": "https://transform.example.com/process",
                    "method": "POST"
                },
                "retry": {
                    "enabled": true,
                    "max_attempts": 3
                }
            },
            {
                "module": "postgresql",
                "connection": "postgres_production",
                "module-config": {
                    "table": "processed_events"
                }
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": false
        },
        "authorization": "Bearer secret"
    }
}
```

### Multi-Region Replication

Send to multiple regions simultaneously:

```json
{
    "multi_region": {
        "data_type": "json",
        "chain": [
            {
                "module": "s3",
                "connection": "s3_us_east",
                "module-config": {
                    "bucket": "webhooks-us"
                }
            },
            {
                "module": "s3",
                "connection": "s3_eu_west",
                "module-config": {
                    "bucket": "webhooks-eu"
                }
            },
            {
                "module": "s3",
                "connection": "s3_ap_southeast",
                "module-config": {
                    "bucket": "webhooks-ap"
                }
            }
        ],
        "chain-config": {
            "execution": "parallel"
        },
        "authorization": "Bearer secret"
    }
}
```

### Audit Trail

Create comprehensive audit trails:

```json
{
    "audit_trail": {
        "data_type": "json",
        "chain": [
            {
                "module": "postgresql",
                "connection": "postgres_audit",
                "module-config": {
                    "table": "audit_log"
                }
            },
            {
                "module": "s3",
                "connection": "s3_archive",
                "module-config": {
                    "bucket": "audit-archive",
                    "prefix": "webhooks"
                }
            },
            {
                "module": "log"  // Also log for immediate visibility
            }
        ],
        "chain-config": {
            "execution": "parallel"
        },
        "authorization": "Bearer secret"
    }
}
```

## Monitoring and Debugging

### Execution Summary

Chain execution results include:
- Total modules executed
- Success/failure count
- Per-module results with error messages

Check application logs for chain execution summaries:
```
Chain execution for webhook 'my_chain': 2/3 modules succeeded, 1 failed
  - Module 's3' succeeded
  - Module 'redis_rq' failed: Connection timeout
  - Module 'log' succeeded
```

### Logging Best Practices

- Always include `log` module in chains for debugging
- Use structured logging for better analysis
- Monitor chain execution metrics

## Related Documentation

- [Getting Started Guide](webhook-chaining-getting-started)
- [Troubleshooting](webhook-chaining-troubleshooting)
- [Full Reference](webhook-chaining)
