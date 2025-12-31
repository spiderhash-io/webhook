# Architecture Documentation

## Overview

The Core Webhook Module uses a **plugin-based architecture** that makes it easy to add new processing modules without modifying core code.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     FastAPI Application                      │
│                         (main.py)                            │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    WebhookHandler                            │
│                     (webhook.py)                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ 1. Validate Authorization                            │   │
│  │ 2. Parse Payload (JSON/Blob)                         │   │
│  │ 3. Get Module from Registry                          │   │
│  │ 4. Instantiate & Execute Module                      │   │
│  └──────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    ModuleRegistry                            │
│                    (modules/registry.py)                     │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Module Name → Module Class Mapping                  │   │
│  │  - log → LogModule                                   │   │
│  │  - save_to_disk → SaveToDiskModule                   │   │
│  │  - rabbitmq → RabbitMQModule                         │   │
│  │  - redis_rq → RedisRQModule                          │   │
│  └──────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      BaseModule                              │
│                   (modules/base.py)                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Abstract Base Class                                 │   │
│  │  - process(payload, headers) [abstract]              │   │
│  │  - setup() [optional]                                │   │
│  │  - teardown() [optional]                             │   │
│  └──────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  LogModule   │   │SaveToDisk    │   │ RabbitMQ     │  ...
│              │   │Module        │   │ Module       │
└──────────────┘   └──────────────┘   └──────────────┘
```

## Key Components

### 1. BaseModule (Abstract Base Class)
- **Location**: `src/modules/base.py`
- **Purpose**: Defines the interface all modules must implement
- **Methods**:
  - `process(payload, headers)`: Main processing logic (required)
  - `setup()`: Optional initialization (e.g., create connections)
  - `teardown()`: Optional cleanup (e.g., close connections)

### 2. ModuleRegistry
- **Location**: `src/modules/registry.py`
- **Purpose**: Central registry for all available modules
- **Features**:
  - Maps module names to module classes
  - Allows dynamic module registration
  - Validates modules inherit from BaseModule

### 3. WebhookHandler
- **Location**: `src/webhook.py`
- **Purpose**: Orchestrates webhook processing
- **Flow**:
  1. Validate authorization
  2. Parse payload based on data_type
  3. Look up module in registry
  4. Instantiate module with config
  5. Execute module asynchronously

### 4. Individual Modules
Each module inherits from `BaseModule` and implements specific functionality:

- **LogModule**: Prints to stdout
- **SaveToDiskModule**: Saves to file system
- **RabbitMQModule**: Publishes to RabbitMQ
- **RedisRQModule**: Queues to Redis RQ
- **RedisPublishModule**: Publishes to Redis Pub/Sub channels
- **HTTPWebhookModule**: Forwards to HTTP endpoints
- **KafkaModule**: Publishes to Kafka topics
- **S3Module**: Stores to AWS S3
- **WebSocketModule**: Sends to WebSocket connections
- **ClickHouseModule**: Stores to ClickHouse database
- **MQTTModule**: Publishes to MQTT brokers
- **ZeroMQModule**: Publishes via ZeroMQ
- **ActiveMQModule**: Publishes to ActiveMQ
- **AWSSQSModule**: Sends to AWS SQS queues
- **GCPPubSubModule**: Publishes to GCP Pub/Sub topics
- **PostgreSQLModule**: Stores to PostgreSQL database
- **MySQLModule**: Stores to MySQL/MariaDB database

## Adding a New Module

To add a new module (e.g., Kafka, S3, Websockets):

### Step 1: Create Module File
```python
# src/modules/my_module.py
from typing import Any, Dict
from src.modules.base import BaseModule

class MyModule(BaseModule):
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        # Your processing logic here
        pass
    
    async def setup(self) -> None:
        # Optional: Initialize connections
        pass
    
    async def teardown(self) -> None:
        # Optional: Cleanup
        pass
```

### Step 2: Register Module
```python
# src/modules/registry.py
from src.modules.my_module import MyModule

class ModuleRegistry:
    _modules: Dict[str, Type[BaseModule]] = {
        # ... existing modules ...
        'my_module': MyModule,
    }
```

### Step 3: Configure Webhook
```json
{
    "webhook_id": {
        "data_type": "json",
        "module": "my_module",
        "module-config": {
            "option1": "value1"
        },
        "connection": "my_connection"
    }
}
```

## Configuration System

### Webhook Configuration (`webhooks.json`)
```json
{
    "webhook_id": {
        "data_type": "json|blob",
        "module": "module_name",
        "module-config": {
            "module_specific_options": "value"
        },
        "authorization": "Bearer token",
        "connection": "connection_name"
    }
}
```

### Connection Configuration (`connections.json`)
```json
{
    "connection_name": {
        "type": "rabbitmq|redis-rq|kafka",
        "host": "{$ENV_VAR}",
        "port": 5672,
        "user": "guest",
        "pass": "guest"
    }
}
```

## Benefits of This Architecture

1. **Extensibility**: Add new modules without modifying core code
2. **Testability**: Each module can be tested independently
3. **Maintainability**: Clear separation of concerns
4. **Flexibility**: Easy to swap or disable modules
5. **Type Safety**: Abstract base class ensures consistent interface
6. **Configuration-Driven**: No code changes needed for new webhooks

## Future Enhancements

### Implemented Features
1. **Module Chaining**: ✅ Multiple modules per webhook (sequential or parallel execution)
2. **Error Handling**: ✅ Retry logic with per-module retry configuration
3. **Hot Reload**: ✅ Live configuration reload without restart (ConfigManager + ConfigFileWatcher)

### Planned Features
1. **Middleware System**: Add pre/post processing hooks
2. **Conditional Routing**: Route based on payload content
3. **Metrics**: Per-module performance tracking
4. **Module Hot Reload**: Update module code without restart (currently requires restart)

### Example: Middleware System
```python
class BaseMiddleware(ABC):
    @abstractmethod
    async def before_process(self, payload, headers):
        pass
    
    @abstractmethod
    async def after_process(self, payload, headers, result):
        pass

# Usage
class RateLimitMiddleware(BaseMiddleware):
    async def before_process(self, payload, headers):
        # Check rate limit
        pass
```

### Example: Module Chaining (Implemented)
```json
{
    "webhook_id": {
        "data_type": "json",
        "chain": [
            {
                "module": "log",
                "module-config": {}
            },
            {
                "module": "save_to_disk",
                "module-config": {"path": "archive"}
            },
            {
                "module": "rabbitmq",
                "connection": "rabbitmq_local",
                "module-config": {"queue_name": "processing"}
            }
        ],
        "chain-config": {
            "execution": "sequential",
            "continue_on_error": true
        }
    }
}
```

See `docs/WEBHOOK_CHAINING_FEATURE.md` for detailed documentation.

## Testing Strategy

1. **Unit Tests**: Test each module in isolation
2. **Integration Tests**: Test with real connections (Docker)
3. **End-to-End Tests**: Full webhook flow
4. **Performance Tests**: Load testing with multiple modules

## Security Considerations

1. **Module Validation**: Only registered modules can execute
2. **Configuration Validation**: Validate config before module instantiation
3. **Sandboxing**: Consider isolating module execution
4. **Audit Logging**: Track which modules process which webhooks
