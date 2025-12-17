# Webhook Chaining: Stability and Security Documentation

## Overview

This document outlines the stability and security measures implemented for the webhook chaining feature. It covers security controls, stability guarantees, resource limits, and best practices.

## Security Measures

### 1. Configuration Validation

#### Chain Length Limits
- **Maximum Chain Length**: 20 modules (configurable via `ChainValidator.MAX_CHAIN_LENGTH`)
- **Minimum Chain Length**: 1 module
- **Purpose**: Prevents DoS attacks via excessive chain length that could exhaust system resources

#### Module Validation
- All modules in chain must be registered in `ModuleRegistry`
- Module names are validated using `ModuleRegistry._validate_module_name()` to prevent injection attacks
- Invalid module references are rejected before execution

#### Type Validation
- Chain must be a list/array (rejects strings, dicts, etc.)
- Chain items must be strings or dictionaries (rejects other types)
- All configuration fields are type-checked to prevent type confusion attacks

#### Field Validation
- Unknown fields in chain items are rejected
- Unknown fields in chain-config are rejected
- Prevents injection of malicious configuration

### 2. Execution Security

#### Execution Mode Validation
- Only `sequential` and `parallel` execution modes are allowed
- Invalid execution modes are rejected

#### Error Handling
- Module instantiation errors are caught and logged
- Execution errors are handled gracefully
- Errors don't expose internal system details to clients

#### Resource Management
- Chain execution uses `TaskManager` for concurrency control
- Task timeouts prevent resource exhaustion
- Semaphore-based limiting prevents DoS via concurrent chains

### 3. Input Sanitization

#### Module Configuration
- Module configurations are deep-copied to prevent modification
- Per-module configs are merged safely
- Connection details are validated before use

#### Payload and Headers
- Credential cleanup is applied to payloads and headers
- Original data is preserved for validation
- Cleaned data is passed to modules

### 4. Retry Security

#### Retry Limits
- Per-module retry configurations are validated
- `max_attempts` must be a positive integer
- Retry limits prevent infinite retry loops
- Retry handler enforces security limits (see `retry_handler.py`)

#### Retry Validation
- Retry configs are validated at chain validation time
- Invalid retry configurations are rejected
- Retry handler performs additional validation during execution

## Stability Guarantees

### 1. Backward Compatibility

#### Single Module Support
- Existing webhook configurations with `module` field continue to work
- No breaking changes to existing functionality
- Chain feature is opt-in (only used when `chain` field is present)

#### Configuration Precedence
- If both `chain` and `module` are present, `chain` takes precedence
- This allows gradual migration from single module to chain

### 2. Error Recovery

#### Continue on Error
- `continue_on_error: true` allows chain to continue even if a module fails
- Failed modules are logged but don't stop the chain
- Useful for best-effort delivery to multiple destinations

#### Stop on Error
- `continue_on_error: false` stops chain execution on first failure
- Remaining modules are marked as not executed
- Useful for dependent operations (e.g., save to DB then notify)

### 3. Resource Limits

#### Task Manager Integration
- Chain execution uses `TaskManager` for concurrency control
- Default limit: 100 concurrent tasks
- Configurable via `MAX_CONCURRENT_TASKS` environment variable
- Prevents resource exhaustion from too many concurrent chains

#### Memory Management
- Payloads are deep-copied for each module (not shared)
- Prevents accidental modification between modules
- Memory usage scales with chain length and payload size

#### Connection Management
- Each module opens its own connections
- Connection pools are reused when available
- Connections are properly closed on errors

### 4. Execution Modes

#### Sequential Execution
- Modules execute one after another
- Latency = sum of all module latencies
- Lower resource usage (one task at a time)
- Better for dependent operations

#### Parallel Execution
- All modules execute simultaneously
- Latency = slowest module latency
- Higher resource usage (multiple tasks)
- Better for independent operations

## Resource Limits and Recommendations

### Chain Length Recommendations

#### Sequential Chains
- **Recommended**: 5-10 modules
- **Maximum**: 20 modules (security limit)
- **Consideration**: Latency increases linearly with chain length

#### Parallel Chains
- **Recommended**: 3-5 modules
- **Maximum**: Limited by task manager (default 100 concurrent tasks)
- **Consideration**: Resource usage increases with chain length

### Payload Size Considerations

- Large payloads × many modules = high memory usage
- Consider payload size when designing chains
- Use blob data type for large payloads when appropriate

### Task Manager Limits

- **Default Concurrent Tasks**: 100
- **Configurable**: Via `MAX_CONCURRENT_TASKS` environment variable
- **Security Limit**: 10,000 (prevents DoS)
- **Task Timeout**: 300 seconds (5 minutes) default

## Security Best Practices

### 1. Configuration Security

#### Validate All Configurations
- Use `ChainValidator.validate_chain_config()` before processing
- Validate at configuration load time (in `ConfigManager`)
- Reject invalid configurations early

#### Limit Chain Length
- Don't exceed recommended limits (5-10 for sequential, 3-5 for parallel)
- Monitor chain execution times
- Consider splitting very long chains

#### Use Registered Modules Only
- Only use modules registered in `ModuleRegistry`
- Don't attempt to use unregistered or malicious modules
- Validate module names before execution

### 2. Error Handling

#### Log All Failures
- Chain execution logs all module failures
- Monitor logs for patterns of failures
- Investigate repeated failures

#### Use Continue on Error Appropriately
- Use `continue_on_error: true` for independent operations
- Use `continue_on_error: false` for dependent operations
- Don't use continue_on_error for critical operations

### 3. Resource Management

#### Monitor Task Manager Metrics
- Track active tasks, queue usage, timeouts
- Alert on high queue usage (>80%)
- Scale resources if needed

#### Limit Concurrent Chains
- Use task manager limits to prevent overload
- Consider rate limiting at webhook level
- Monitor memory usage

### 4. Testing

#### Unit Tests
- Test all validation logic
- Test error handling
- Test edge cases (empty chains, invalid configs)

#### Integration Tests
- Test real chain execution
- Test with actual modules
- Test error scenarios

#### Security Tests
- Test DoS attack prevention
- Test injection attack prevention
- Test resource exhaustion scenarios

## Monitoring and Observability

### Metrics to Monitor

#### Chain Execution Metrics
- Total chains executed
- Successful chains vs failed chains
- Average chain execution time
- Per-module success/failure rates

#### Resource Metrics
- Task manager queue usage
- Active tasks count
- Task timeouts
- Memory usage

#### Error Metrics
- Module instantiation failures
- Module execution failures
- Chain validation failures
- Configuration errors

### Logging

#### Chain Execution Logs
- Chain start/completion
- Module execution results
- Error details (server-side only)
- Execution summary

#### Security Logs
- Invalid configuration attempts
- DoS attack attempts (excessive chain length)
- Module injection attempts
- Resource exhaustion warnings

## Troubleshooting

### Common Issues

#### Chain Execution Fails
- Check chain configuration validity
- Verify all modules are registered
- Check module-specific errors in logs
- Verify connection configurations

#### High Resource Usage
- Reduce chain length
- Use sequential execution instead of parallel
- Increase task manager limits (if appropriate)
- Monitor payload sizes

#### Module Failures
- Check module-specific logs
- Verify connection configurations
- Test modules individually
- Check retry configurations

### Debugging

#### Enable Debug Logging
- Set log level to DEBUG
- Enable detailed chain execution logs
- Monitor task manager metrics

#### Test Individual Modules
- Test modules outside of chain
- Verify module configurations
- Check module dependencies

## Migration Guide

### From Single Module to Chain

1. **Start with Simple Chain**
   ```json
   {
     "webhook_id": {
       "chain": ["module1", "module2"],
       "chain-config": {
         "execution": "sequential"
       }
     }
   }
   ```

2. **Add Per-Module Configuration**
   ```json
   {
     "webhook_id": {
       "chain": [
         {
           "module": "module1",
           "connection": "conn1"
         },
         {
           "module": "module2",
           "module-config": {"option": "value"}
         }
       ]
     }
   }
   ```

3. **Add Retry Configuration**
   ```json
   {
     "webhook_id": {
       "chain": [
         {
           "module": "module1",
           "retry": {
             "enabled": true,
             "max_attempts": 3
           }
         }
       ]
     }
   }
   ```

### Backward Compatibility

- Existing configurations continue to work
- No changes required for single-module webhooks
- Chain feature is opt-in

## Security Checklist

- [ ] Chain length is within recommended limits
- [ ] All modules are registered and validated
- [ ] Configuration is validated before execution
- [ ] Error handling is appropriate for use case
- [ ] Resource limits are configured appropriately
- [ ] Monitoring is in place
- [ ] Security tests are passing
- [ ] Logging is configured
- [ ] Credential cleanup is enabled (if applicable)

## References

- `src/chain_validator.py`: Chain configuration validation
- `src/chain_processor.py`: Chain execution logic
- `src/webhook.py`: Webhook handler with chain support
- `src/config_manager.py`: Configuration validation
- `docs/WEBHOOK_CHAINING_FEATURE.md`: Feature documentation

