# Webhook Destination Chaining Feature

## Overview
Enable webhooks to send payloads to multiple destinations in sequence or parallel. Examples: save to S3 then Redis, save to DB then RabbitMQ.

## Configuration Format

### Option 1: Simple Array (Backward Compatible)
```json
{
  "chained_webhook": {
    "data_type": "json",
    "chain": ["s3", "redis_rq"],
    "chain-config": {
      "execution": "sequential",
      "continue_on_error": true
    },
    "authorization": "Bearer token"
  }
}
```

### Option 2: Detailed Chain with Per-Module Config
```json
{
  "chained_webhook": {
    "data_type": "json",
    "chain": [
      {
        "module": "s3",
        "connection": "s3_storage",
        "module-config": {
          "bucket": "webhooks",
          "prefix": "archive"
        },
        "retry": {
          "enabled": true,
          "max_attempts": 3
        }
      },
      {
        "module": "redis_rq",
        "connection": "redis_local",
        "module-config": {
          "queue_name": "processing"
        }
      }
    ],
    "chain-config": {
      "execution": "sequential",
      "continue_on_error": true
    },
    "authorization": "Bearer token"
  }
}
```

**Backward Compatibility**: Keep `module` field for single destinations. If both `module` and `chain` are present, `chain` takes precedence.

## Implementation Details

### 1. Configuration Validation
- **File**: `src/config.py` or new `src/chain_validator.py`
- Validate chain format (array of strings or objects)
- Ensure all modules in chain exist in ModuleRegistry
- Validate chain-config options (execution: "sequential"|"parallel", continue_on_error: bool)
- Support per-module configs when chain items are objects

### 2. WebhookHandler Updates
- **File**: `src/webhook.py`
- Modify `process_webhook()` to detect `chain` vs `module`
- If `chain` exists, process chain instead of single module
- If `module` exists (legacy), process single module (backward compatible)

### 3. Chain Processing Logic
- **New File**: `src/chain_processor.py`
- `ChainProcessor` class to handle chain execution
- Support sequential execution (one after another)
- Support parallel execution (all at once using asyncio.gather)
- Error handling: continue on error (best-effort) as per user requirement
- Per-module retry support (each module can have its own retry config)
- Track success/failure for each module in chain

### 4. Execution Flow
```
WebhookHandler.process_webhook()
  ├─> Detect chain vs module
  ├─> If chain:
  │    ├─> Create ChainProcessor
  │    ├─> Parse chain config
  │    ├─> For each module in chain:
  │    │    ├─> Instantiate module
  │    │    ├─> Apply per-module retry if configured
  │    │    └─> Execute (sequential or parallel)
  │    └─> Continue on error (log but don't stop)
  └─> If module (legacy):
       └─> Execute single module (existing logic)
```

### 5. Error Handling
- **Strategy**: Continue on error (best-effort)
- Log each module's success/failure
- Return success if at least one module succeeds (or all succeed, configurable)
- Track detailed results per module for monitoring

### 6. Retry Integration
- Per-module retry: Each chain item can have its own `retry` config
- Use existing `retry_handler.execute_with_retry()` for each module
- Retry applies independently to each module in chain

## Limitations & Considerations

### Performance
- **Sequential chains**: Latency = sum of all module latencies
  - Example: S3 (200ms) + Redis (50ms) = 250ms total
  - 5 modules could add 1-2 seconds
- **Parallel chains**: Latency = slowest module
  - Example: S3 (200ms) + Redis (50ms) = 200ms total
  - Better for independent destinations

### Resource Usage
- **Task Manager**: Each module creates a task (default limit: 100 concurrent)
  - Parallel chain of 5 modules = 5 tasks per webhook
  - Sequential chain = 1 task at a time
- **Memory**: Payload copied for each module (not shared)
- **Connections**: Each module opens its own connections (S3, Redis, etc.)

### Practical Limits
- **No hard technical limit** on chain length
- **Recommended limits**:
  - Sequential: 5-10 modules (beyond that, latency becomes significant)
  - Parallel: Limited by task manager (100 concurrent tasks default)
- **Configuration complexity**: More modules = more complex configs

### Best Practices
- Use sequential for dependent operations (save to DB, then notify via RMQ)
- Use parallel for independent operations (save to S3 and Redis simultaneously)
- Monitor task manager metrics when using parallel chains
- Consider payload size (large payloads × many modules = high memory usage)

## Testing Requirements

### Unit Tests
- Chain configuration validation
- Sequential execution
- Parallel execution
- Error handling (continue on error)
- Per-module retry
- Backward compatibility (single `module` still works)

### Integration Tests
- Real chain: S3 → Redis
- Real chain: DB → RabbitMQ
- Chain with failures (one module fails, others succeed)
- Chain with retries

## Files to Modify

1. **src/webhook.py**: Update `process_webhook()` to handle chains
2. **src/chain_processor.py**: New file for chain processing logic
3. **src/config.py**: Add chain validation (or create `src/chain_validator.py`)
4. **webhooks.example.json**: Add chain examples
5. **README.md**: Document chain feature with examples
6. **tests/**: Add unit and integration tests for chains

## Migration Path

- **Backward Compatible**: Existing `module` configs continue to work
- **No Breaking Changes**: All existing webhooks function as before
- **Gradual Adoption**: Teams can migrate to chains when needed

## Examples

### Example 1: Save to S3 then Redis (Sequential)
```json
{
  "s3_then_redis": {
    "data_type": "json",
    "chain": [
      {
        "module": "s3",
        "connection": "s3_storage",
        "module-config": {
          "bucket": "webhook-archive",
          "prefix": "events"
        }
      },
      {
        "module": "redis_rq",
        "connection": "redis_local",
        "module-config": {
          "queue_name": "process_events"
        }
      }
    ],
    "chain-config": {
      "execution": "sequential",
      "continue_on_error": true
    },
    "authorization": "Bearer secret"
  }
}
```

### Example 2: Save to DB and RabbitMQ (Parallel)
```json
{
  "db_and_rmq": {
    "data_type": "json",
    "chain": [
      {
        "module": "postgresql",
        "connection": "postgres_local",
        "module-config": {
          "table": "webhook_events"
        }
      },
      {
        "module": "rabbitmq",
        "connection": "rabbitmq_local",
        "queue_name": "event_queue"
      }
    ],
    "chain-config": {
      "execution": "parallel",
      "continue_on_error": true
    },
    "authorization": "Bearer secret"
  }
}
```

### Example 3: Simple Array Format
```json
{
  "simple_chain": {
    "data_type": "json",
    "chain": ["s3", "redis_rq"],
    "chain-config": {
      "execution": "sequential"
    },
    "authorization": "Bearer secret"
  }
}
```

