# Live Config Reload Feature

## Overview

✅ **IMPLEMENTED** - Webhook configurations (`webhooks.json`) and connection configurations (`connections.json`) can now be reloaded dynamically without requiring application restart or downtime. This feature is implemented using `ConfigManager` and `ConfigFileWatcher`.

## Implementation Status

✅ **FULLY IMPLEMENTED** - The live config reload feature is implemented and active.

### Current Architecture

**Files**: 
- `src/config_manager.py` - ConfigManager for async-safe config management
- `src/config_watcher.py` - ConfigFileWatcher for file system monitoring
- `src/connection_pool_registry.py` - ConnectionPoolRegistry for pool lifecycle management

1. **Configuration Loading**:
   - `ConfigManager` loads `webhooks.json` and `connections.json` at startup
   - Environment variable substitution is applied via `load_env_vars()`
   - Connection pools are managed via `ConnectionPoolRegistry` with versioning

2. **Usage**:
   - Configs are accessed via `ConfigManager` in `src/main.py`
   - Each webhook request gets config from `ConfigManager.get_webhook_config()`
   - Connection details are accessed via `ConfigManager.get_all_connection_configs()`

3. **Connection Management**:
   - **ConnectionPoolRegistry**: Manages connection pools with versioning and graceful migration
   - **Pool Versioning**: Old pools remain active during migration period
   - **Graceful Migration**: New requests use new pools, old requests complete with old pools

### Implemented Features

1. ✅ **Runtime Updates**: Config changes applied without restart
2. ✅ **Connection Pool Lifecycle**: Pools are versioned and migrated gracefully
3. ✅ **Validation on Reload**: Changes are validated before applying
4. ✅ **In-Flight Requests**: Requests continue with old config during migration
5. ✅ **File Watching**: Automatic reload on file changes (with debouncing)
6. ✅ **API Endpoint**: Manual reload via `/admin/reload-config`

## Implemented Features

### Core Functionality

1. ✅ **File Watching**: `ConfigFileWatcher` monitors `webhooks.json` and `connections.json` for changes
2. ✅ **Hot Reload**: Configurations reload without restarting the application
3. ✅ **Connection Pool Management**: 
   - `ConnectionPoolRegistry` creates new pools for new/modified connections
   - Old pools are marked deprecated and closed after migration timeout
   - In-flight requests continue using old pools
4. ✅ **Validation**: Configurations validated before applying (module existence, connection validation)
5. ✅ **Thread Safety**: Read-Copy-Update (RCU) pattern ensures safe concurrent access
6. ✅ **Error Handling**: On validation failure, old config remains active

### Design Questions

**Q1: Reload Trigger Method**
- **Option A**: File system watching (automatic on file change)
- **Option B**: API endpoint (manual trigger via HTTP request)
- **Option C**: Both (file watching + API endpoint)
- **Recommendation**: Option C (both) for flexibility

**Q2: Reload Scope**
- **Option A**: Reload both `webhooks.json` and `connections.json` together
- **Option B**: Reload independently (webhooks separate from connections)
- **Option C**: Reload individual webhook entries (partial reload)
- **Recommendation**: Option B (independent) for granular control

**Q3: Connection Pool Strategy**
- **Option A**: Lazy migration (keep old pools, create new ones, migrate gradually)
- **Option B**: Immediate replacement (close old, create new)
- **Option C**: Connection pool versioning (tag pools, migrate requests gradually)
- **Recommendation**: Option A (lazy migration) for zero downtime

**Q4: Validation Strategy**
- **Option A**: Validate entire config before applying (atomic)
- **Option B**: Validate incrementally (webhook by webhook)
- **Option C**: Validate and apply in transaction (rollback on error)
- **Recommendation**: Option A (atomic validation) for consistency

**Q5: In-Flight Request Handling**
- **Option A**: Allow in-flight requests to complete with old config
- **Option B**: Block new requests during reload (brief downtime)
- **Option C**: Queue requests during reload
- **Recommendation**: Option A (allow completion) for zero downtime

## Proposed Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Config Manager (Singleton)                  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  File Watcher (watchdog)                          │  │
│  │  - Monitors webhooks.json                          │  │
│  │  - Monitors connections.json                      │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Config Reloader                                    │  │
│  │  - Loads and validates configs                     │  │
│  │  - Manages connection pools                        │  │
│  │  - Thread-safe config updates                      │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Connection Pool Manager                           │  │
│  │  - Creates new pools                               │  │
│  │  - Migrates old pools                              │  │
│  │  - Closes unused pools                             │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Components

#### 1. ConfigManager (Singleton)

**Location**: `src/config_manager.py`

**Responsibilities**:
- Thread-safe config storage
- File watching coordination
- Reload orchestration
- Connection pool lifecycle management

**Key Methods**:
```python
class ConfigManager:
    async def reload_webhooks(self) -> ReloadResult
    async def reload_connections(self) -> ReloadResult
    async def reload_all(self) -> ReloadResult
    def get_webhook_config(self, webhook_id: str) -> Dict
    def get_connection_config(self, connection_name: str) -> Dict
    async def start_file_watching(self)
    async def stop_file_watching(self)
```

#### 2. File Watcher

**Location**: `src/config_watcher.py`

**Responsibilities**:
- Monitor file system changes using `watchdog` library
- Debounce rapid file changes
- Trigger reload on file modification

**Key Features**:
- Debounce: Wait 2-5 seconds after last change before reloading
- Atomic writes: Detect file replacement vs. in-place edits
- Error handling: Log errors, don't crash on file system issues

#### 3. Connection Pool Manager

**Location**: `src/connection_pool_manager.py`

**Responsibilities**:
- Track active connection pools
- Create new pools for new/modified connections
- Migrate requests from old to new pools
- Close unused pools after migration period

**Key Features**:
- Pool versioning: Tag pools with config version/timestamp
- Graceful migration: Allow old pools to drain before closing
- Connection cleanup: Close unused connections after timeout

#### 4. API Endpoint

**Location**: `src/main.py`

**Endpoint**: `POST /admin/reload-config`

**Status**: ✅ **IMPLEMENTED**

**Features**:
- ✅ Authentication required (via `CONFIG_RELOAD_ADMIN_TOKEN` environment variable)
- ✅ Reload webhooks, connections, or both
- ✅ Return reload status and errors
- ✅ Validation before applying

**Additional Endpoint**: `GET /admin/config-status` - Returns current config status

### Implementation Details

#### Thread Safety

**Approach**: Read-Copy-Update (RCU) pattern

1. **Read Phase**: Requests read from current config (no locks)
2. **Update Phase**: Reload creates new config dict, atomically swaps reference
3. **Migration Phase**: Old configs remain valid until all in-flight requests complete

**Implementation**:
```python
import asyncio
from typing import Dict, Any

class ConfigManager:
    def __init__(self):
        self._webhook_config: Dict[str, Any] = {}
        self._connection_config: Dict[str, Any] = {}
        self._lock = asyncio.Lock()
        self._readers = 0  # Track active readers
        self._reload_in_progress = False
```

#### File Watching

**Library**: `watchdog` (Python file system monitoring)

**Implementation**:
```python
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class ConfigFileHandler(FileSystemEventHandler):
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.debounce_timer = None
    
    def on_modified(self, event):
        if event.src_path.endswith('webhooks.json'):
            self._debounce_reload('webhooks')
        elif event.src_path.endswith('connections.json'):
            self._debounce_reload('connections')
```

#### Connection Pool Migration

**Strategy**: Lazy Migration with Timeout

1. **New Config Loaded**: Create new connection pools
2. **Old Pools Marked**: Mark old pools as "deprecated" but keep active
3. **Gradual Migration**: New requests use new pools, old requests complete with old pools
4. **Cleanup**: After timeout (e.g., 5 minutes), close old pools

**Implementation**:
```python
class ConnectionPoolManager:
    def __init__(self):
        self._pools: Dict[str, PoolEntry] = {}
        self._migration_timeout = 300  # 5 minutes
    
    class PoolEntry:
        pool: Any
        created_at: float
        deprecated_at: Optional[float]
        active_requests: int
```

#### Validation

**Validation Steps**:
1. **JSON Syntax**: Validate JSON is valid
2. **Schema Validation**: Validate structure matches expected format
3. **Module Validation**: Ensure all modules exist in registry
4. **Connection Validation**: Validate connection details (host, port, etc.)
5. **Dependency Check**: Ensure webhooks reference valid connections

**Error Handling**:
- If validation fails, keep old config active
- Log detailed error messages
- Return validation errors to admin API

### API Design

#### Reload Endpoint

**Endpoint**: `POST /admin/reload-config`

**Request**:
```json
{
  "reload_webhooks": true,
  "reload_connections": true,
  "validate_only": false
}
```

**Response (Success)**:
```json
{
  "status": "success",
  "reloaded": {
    "webhooks": true,
    "connections": true
  },
  "stats": {
    "webhooks_added": 2,
    "webhooks_removed": 1,
    "webhooks_modified": 3,
    "connections_added": 1,
    "connections_removed": 0,
    "connections_modified": 2
  }
}
```

**Response (Error)**:
```json
{
  "status": "error",
  "error": "Validation failed",
  "details": {
    "webhook_id": "invalid_webhook",
    "error": "Module 'invalid_module' not found"
  }
}
```

#### Status Endpoint

**Endpoint**: `GET /admin/config-status`

**Response**:
```json
{
  "last_reload": "2024-01-15T10:30:00Z",
  "reload_in_progress": false,
  "file_watching_enabled": true,
  "webhooks_count": 15,
  "connections_count": 8,
  "connection_pools": {
    "active": 5,
    "deprecated": 2,
    "migrating": 1
  }
}
```

### Configuration

#### Environment Variables

```bash
# Enable file watching (default: false)
CONFIG_FILE_WATCHING_ENABLED=true

# Debounce delay in seconds (default: 3)
CONFIG_RELOAD_DEBOUNCE_SECONDS=3

# Connection pool migration timeout in seconds (default: 300)
CONFIG_POOL_MIGRATION_TIMEOUT=300

# Admin API token for reload endpoint
CONFIG_RELOAD_ADMIN_TOKEN=your_secret_token_here
```

### Error Scenarios

#### 1. Invalid JSON

**Behavior**: 
- Keep old config active
- Log error
- Return error in API response

#### 2. Missing Module

**Behavior**:
- Validate all modules exist before applying
- If any module missing, reject entire reload
- Keep old config active

#### 3. Invalid Connection

**Behavior**:
- Validate connection details (host, port, credentials)
- If invalid, reject reload for that connection
- Other valid connections can still be updated

#### 4. File Deleted

**Behavior**:
- If `webhooks.json` deleted, keep current config (don't clear)
- If `connections.json` deleted, keep current config
- Log warning

#### 5. Concurrent Reloads

**Behavior**:
- Use lock to prevent concurrent reloads
- Queue reload requests if one in progress
- Return status indicating reload queued

### Testing Strategy

#### Unit Tests

1. **ConfigManager Tests**:
   - Thread-safe config updates
   - Concurrent read/write operations
   - Validation error handling
   - Connection pool creation/cleanup

2. **File Watcher Tests**:
   - File change detection
   - Debounce behavior
   - Multiple rapid changes

3. **Connection Pool Manager Tests**:
   - Pool migration
   - Old pool cleanup
   - Concurrent pool access

#### Integration Tests

1. **Live Reload Test**:
   - Modify `webhooks.json` file
   - Verify new webhook available immediately
   - Verify old webhook still works during migration

2. **Connection Reload Test**:
   - Modify `connections.json` file
   - Verify new connection pools created
   - Verify old pools closed after migration

3. **Error Recovery Test**:
   - Introduce invalid config
   - Verify old config remains active
   - Fix config and verify reload succeeds

### Security Considerations

1. **Admin API Authentication**:
   - Require authentication token for reload endpoint
   - Use environment variable for token (not in code)
   - Rate limit reload requests

2. **File System Access**:
   - Only watch specific files (not entire directories)
   - Validate file paths to prevent directory traversal
   - Use absolute paths for config files

3. **Config Validation**:
   - Validate all inputs before applying
   - Prevent injection attacks in config values
   - Sanitize error messages

### Performance Considerations

1. **File Watching Overhead**:
   - Minimal: File system events are efficient
   - Debounce prevents excessive reloads

2. **Config Reload Overhead**:
   - Reload is async and non-blocking
   - In-flight requests unaffected
   - New requests use new config immediately

3. **Connection Pool Migration**:
   - Old pools remain active during migration
   - Memory usage may temporarily increase
   - Cleanup happens after timeout

### Migration Path

1. **Phase 1**: Implement ConfigManager with thread-safe storage
2. **Phase 2**: Add file watching capability
3. **Phase 3**: Implement connection pool migration
4. **Phase 4**: Add admin API endpoints
5. **Phase 5**: Add comprehensive tests
6. **Phase 6**: Documentation and deployment

### Limitations

1. **Module Code Changes**: Still require restart (module code not reloadable)
2. **Environment Variables**: Changes require restart (env vars loaded at startup)
3. **Connection Pool Cleanup**: Old pools may persist for migration timeout period
4. **File System**: Requires file system access (not suitable for read-only deployments)

### Alternatives Considered

1. **Database-Backed Config**: Store configs in database instead of files
   - **Pros**: Better for distributed systems, easier to update
   - **Cons**: Requires database, more complex setup
   - **Decision**: Keep file-based for simplicity, add DB option later

2. **Signal-Based Reload**: Use SIGHUP signal to trigger reload
   - **Pros**: Standard Unix pattern, simple
   - **Cons**: Requires process access, not suitable for containers
   - **Decision**: Use API endpoint + file watching for flexibility

3. **Config Service**: Separate microservice for config management
   - **Pros**: Centralized config, better for multi-instance deployments
   - **Cons**: Additional service, network dependency
   - **Decision**: Keep in-process for now, can extract later

## Implementation Details

### Answers to Design Questions

1. **Reload Trigger**: ✅ Both - Automatic file watching (default) + Manual API endpoint
2. **Connection Pool Strategy**: ✅ Grace period - Old pools kept for migration timeout (default: 5 minutes)
3. **Partial Reloads**: ✅ Full file reload - Reload entire `webhooks.json` or `connections.json` file
4. **Validation Strictness**: ✅ Atomic validation - Invalid config blocks entire reload, old config remains active
5. **Admin API**: ✅ Authentication required - Uses `CONFIG_RELOAD_ADMIN_TOKEN` environment variable
6. **Error Notification**: ✅ Logs + API response - Errors logged and returned in API response
7. **Rollback**: ✅ Automatic - On validation failure, old config remains active (no rollback needed)
8. **Multi-Instance**: ✅ Per-instance - Each instance watches its own config files independently

## Usage

### Automatic File Watching

File watching is enabled by default. Set environment variable to disable:
```bash
CONFIG_FILE_WATCHING_ENABLED=false
```

### Manual Reload via API

```bash
curl -X POST http://localhost:8000/admin/reload-config \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reload_webhooks": true, "reload_connections": true}'
```

### Configuration

Environment variables:
- `CONFIG_FILE_WATCHING_ENABLED` - Enable/disable file watching (default: true)
- `CONFIG_RELOAD_DEBOUNCE_SECONDS` - Debounce delay in seconds (default: 3.0)
- `CONFIG_RELOAD_ADMIN_TOKEN` - Admin token for API endpoints (required; admin API is disabled if unset)

### Migration Note

**Breaking Change:** Admin endpoints (`/admin/reload-config`, `/admin/config-status`) now require `CONFIG_RELOAD_ADMIN_TOKEN` to be set. Previously, these endpoints were accessible without authentication when this environment variable was unset.

**What changed:**
- Admin endpoints return `403 Forbidden` when `CONFIG_RELOAD_ADMIN_TOKEN` is not set (previously worked without auth)
- Whitespace-only tokens (e.g., `"   "`) are treated as unconfigured and return `403` (previously returned `401`)

**Action required for existing deployments:**
```bash
export CONFIG_RELOAD_ADMIN_TOKEN="your-secure-random-token-here"
```

Generate a secure token:
```bash
# Linux/macOS
openssl rand -base64 32

# Or use Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Status

✅ **Feature Complete** - All planned functionality has been implemented and is in use.
