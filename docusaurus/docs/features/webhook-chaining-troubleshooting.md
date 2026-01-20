# Webhook Chaining Troubleshooting

Common issues and solutions when working with webhook chains.

## Configuration Issues

### Chain Not Executing

**Symptoms:** Webhook is accepted but chain doesn't execute.

**Possible Causes:**

1. **Invalid chain configuration**
   ```json
   // ❌ Wrong: chain is not an array
   {
       "chain": "s3"
   }
   
   // ✅ Correct: chain is an array
   {
       "chain": ["s3"]
   }
   ```

2. **Missing module in chain**
   ```json
   // ❌ Wrong: module doesn't exist
   {
       "chain": ["nonexistent_module"]
   }
   
   // ✅ Correct: use valid module name
   {
       "chain": ["log"]
   }
   ```

3. **Chain length exceeds limit**
   - Maximum chain length is 20 modules
   - Check error message: "Chain length X exceeds security limit 20"

**Solution:** Validate your configuration using the chain validator. Check application logs for validation errors.

### Module Not Found Error

**Error:** `Chain item X: module 'module_name' is not registered`

**Causes:**
- Typo in module name
- Module not available in ModuleRegistry
- Module name case sensitivity

**Solution:**
- Verify module name spelling
- Check available modules in ModuleRegistry
- Use lowercase module names (e.g., `"redis_rq"` not `"RedisRQ"`)

### Invalid Chain Configuration

**Error:** `Invalid chain configuration: ...`

**Common Issues:**

1. **Chain item must be string or object**
   ```json
   // ❌ Wrong
   {
       "chain": [123, true]
   }
   
   // ✅ Correct
   {
       "chain": ["log", {"module": "s3"}]
   }
   ```

2. **Missing module field in object**
   ```json
   // ❌ Wrong
   {
       "chain": [{"connection": "redis_local"}]
   }
   
   // ✅ Correct
   {
       "chain": [{"module": "redis_rq", "connection": "redis_local"}]
   }
   ```

3. **Invalid chain-config values**
   ```json
   // ❌ Wrong
   {
       "chain-config": {
           "execution": "invalid_mode"
       }
   }
   
   // ✅ Correct
   {
       "chain-config": {
           "execution": "sequential"  // or "parallel"
       }
   }
   ```

## Execution Issues

### Chain Stops After First Module

**Symptoms:** Only first module executes, others don't run.

**Causes:**

1. **`continue_on_error: false` with sequential execution**
   ```json
   {
       "chain-config": {
           "execution": "sequential",
           "continue_on_error": false  // Stops on first error
       }
   }
   ```

2. **First module fails and stops chain**

**Solution:**
- Set `continue_on_error: true` to continue on errors
- Check first module's error logs
- Ensure first module succeeds or handle errors appropriately

### Modules Execute Out of Order (Parallel Mode)

**Symptoms:** Modules complete in different order than configured.

**Expected Behavior:** In parallel mode, modules execute simultaneously and may complete in any order.

**Solution:** Use `sequential` execution mode if order matters:

```json
{
    "chain-config": {
        "execution": "sequential"  // Ensures order
    }
}
```

### Some Modules Succeed, Others Fail

**Symptoms:** Partial success in chain execution.

**Expected Behavior:** When `continue_on_error: true`, modules execute independently.

**Solution:**
- Check logs for individual module failures
- Review error messages for each failed module
- Consider adding retries to critical modules:

```json
{
    "module": "s3",
    "retry": {
        "enabled": true,
        "max_attempts": 3
    }
}
```

## Connection Issues

### Connection Not Found

**Error:** `Connection 'connection_name' not found`

**Causes:**
- Connection not defined in `connections.json`
- Typo in connection name
- Connection configuration file not loaded

**Solution:**
1. Verify connection exists in `connections.json`
2. Check connection name spelling
3. Ensure connection config file is loaded
4. Restart application if config was updated

### Connection Timeout

**Symptoms:** Module hangs or times out.

**Causes:**
- Network issues
- Service unavailable
- Connection pool exhausted

**Solution:**
- Check network connectivity
- Verify service is running
- Review connection pool settings
- Add retry configuration:

```json
{
    "module": "http_webhook",
    "retry": {
        "enabled": true,
        "max_attempts": 3,
        "initial_delay": 1.0
    }
}
```

## Performance Issues

### Chain Execution Too Slow

**Symptoms:** High latency for chain execution.

**Causes:**

1. **Sequential execution with many modules**
   - Latency = sum of all module latencies
   - Example: 5 modules × 200ms each = 1000ms total

2. **Slow modules blocking chain**

**Solutions:**

1. **Use parallel execution** (if modules are independent):
   ```json
   {
       "chain-config": {
           "execution": "parallel"  // Faster for independent modules
       }
   }
   ```

2. **Optimize slow modules**
   - Review module-specific configurations
   - Check connection settings
   - Monitor module execution times

3. **Reduce chain length**
   - Keep sequential chains under 5-10 modules
   - Consider splitting into multiple webhooks

### High Memory Usage

**Symptoms:** Application using excessive memory.

**Causes:**
- Large payloads × many modules = multiple copies in memory
- Parallel execution increases concurrent memory usage

**Solutions:**
- Reduce chain length
- Use sequential execution to limit concurrent memory
- Optimize payload size if possible
- Monitor TaskManager capacity

### Task Manager Capacity Exceeded

**Error:** `Could not create task for chain execution`

**Causes:**
- Too many parallel chains executing simultaneously
- Default limit: 100 concurrent tasks

**Solutions:**
- Reduce parallel chain usage
- Increase TaskManager capacity (if needed)
- Use sequential execution for some chains
- Monitor task manager metrics

## Retry Issues

### Retries Not Working

**Symptoms:** Module fails immediately without retrying.

**Causes:**

1. **Retry not enabled**
   ```json
   // ❌ Wrong: retry disabled
   {
       "retry": {
           "enabled": false
       }
   }
   
   // ✅ Correct: retry enabled
   {
       "retry": {
           "enabled": true,
           "max_attempts": 3
       }
   }
   ```

2. **Retry config at wrong level**
   ```json
   // ❌ Wrong: retry at chain-config level
   {
       "chain-config": {
           "retry": {...}
       }
   }
   
   // ✅ Correct: retry at module level
   {
       "chain": [{
           "module": "s3",
           "retry": {...}
       }]
   }
   ```

**Solution:** Ensure retry is configured per-module, not at chain level.

### Too Many Retries

**Symptoms:** Chain takes very long due to excessive retries.

**Causes:**
- High `max_attempts` value
- Long delays between retries

**Solution:** Adjust retry configuration:

```json
{
    "retry": {
        "enabled": true,
        "max_attempts": 3,  // Reduce if needed
        "initial_delay": 0.5,  // Reduce delay
        "max_delay": 10.0  // Cap maximum delay
    }
}
```

## Error Messages

### Understanding Error Messages

**Chain Validation Errors:**
- `Chain must be a list/array` - Chain is not an array
- `Chain must contain at least 1 module` - Empty chain
- `Chain length X exceeds security limit 20` - Too many modules
- `Chain item X: module 'name' is not registered` - Invalid module name
- `Chain item X: missing required 'module' field` - Module field missing

**Execution Errors:**
- `Chain execution stopped at module X` - Sequential chain stopped due to error
- `Module 'name' failed: error_message` - Individual module failure

### Getting More Details

Enable debug logging to see detailed chain execution:

```python
# In your application configuration
import logging
logging.getLogger('src.chain_processor').setLevel(logging.DEBUG)
```

## Best Practices

### Debugging Tips

1. **Start simple**: Begin with a single module, then add more
2. **Use log module**: Always include `log` module for debugging
3. **Test sequentially first**: Use sequential mode to see execution order
4. **Check logs**: Review application logs for detailed error messages
5. **Validate config**: Ensure configuration is valid before deployment

### Common Patterns

**Safe Chain (with logging and error handling):**
```json
{
    "safe_chain": {
        "data_type": "json",
        "chain": [
            "log",  // Always log first
            {
                "module": "s3",
                "retry": {
                    "enabled": true,
                    "max_attempts": 3
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

**Production Chain (with monitoring):**
```json
{
    "production_chain": {
        "data_type": "json",
        "chain": [
            {
                "module": "postgresql",
                "connection": "postgres_prod",
                "retry": {
                    "enabled": true,
                    "max_attempts": 5
                }
            },
            {
                "module": "log"  // Always log for monitoring
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": false  // Fail fast in production
        },
        "authorization": "Bearer secret"
    }
}
```

## Getting Help

If you're still experiencing issues:

1. **Check logs**: Review application logs for detailed error messages
2. **Validate configuration**: Ensure JSON is valid and structure is correct
3. **Test modules individually**: Verify each module works standalone
4. **Review documentation**: Check [main chaining guide](webhook-chaining) and [advanced guide](webhook-chaining-advanced)

## Related Documentation

- [Webhook Chaining Overview](webhook-chaining)
- [Getting Started Guide](webhook-chaining-getting-started)
- [Advanced Usage](webhook-chaining-advanced)
