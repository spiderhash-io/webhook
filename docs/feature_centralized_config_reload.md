# Centralized Configuration Reload Feature - Push-Based Approach

## Overview

This document describes the **Push-Based Approach** for implementing centralized configuration management across multiple webhook instances. This approach allows a centralized UI to manage and synchronize configuration changes to all webhook instances in real-time.

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Centralized Management UI                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Instance Discovery & Registry                         │  │
│  │  - Service discovery (DNS, Consul, etc.)               │  │
│  │  - Manual instance registration                        │  │
│  │  - Health monitoring                                   │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Configuration Management                              │  │
│  │  - Edit webhooks.json / connections.json               │  │
│  │  - Validate configurations                             │  │
│  │  - Version control / rollback                         │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Sync Coordinator                                      │  │
│  │  - Broadcast config updates to all instances          │  │
│  │  - Track sync status per instance                     │  │
│  │  - Handle failures and retries                        │  │
│  └───────────────────────────────────────────────────────┘  │
└───────────────────────────┬───────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Instance 1  │  │  Instance 2  │  │  Instance N  │
│  :8000       │  │  :8001       │  │  :800N       │
│              │  │              │  │              │
│ /admin/*     │  │ /admin/*     │  │ /admin/*     │
└──────────────┘  └──────────────┘  └──────────────┘
```

### Flow Diagram

```
User edits config in UI
        │
        ▼
UI validates config
        │
        ▼
UI calls /admin/config-update on each instance (parallel)
        │
        ├──► Instance 1: Write file → Reload → Return status
        ├──► Instance 2: Write file → Reload → Return status
        └──► Instance N: Write file → Reload → Return status
        │
        ▼
UI aggregates results and displays sync status
```

## Implementation

### 1. Enhanced Admin API Endpoints

#### New Endpoint: `/admin/config-update`

**Purpose**: Receive configuration updates from centralized UI and apply them to the instance.

**Location**: `src/main.py`

**Implementation**:

```python
@app.post("/admin/config-update")
async def receive_config_update(request: Request):
    """
    Receive config update from centralized UI.
    
    This endpoint allows the centralized UI to push configuration
    updates directly to this instance. The config is written to the
    local file and then reloaded.
    
    Request Body:
    {
        "type": "webhooks" | "connections",
        "config": { ... },  # Full config object
        "version": "optional-version-hash",
        "source": "ui"  # Source identifier
    }
    
    Returns:
    {
        "status": "success" | "error",
        "error": "error message if failed",
        "details": { ... },  # ReloadResult details
        "instance_id": "instance-identifier"
    }
    """
    global config_manager
    
    if not config_manager:
        raise HTTPException(status_code=503, detail="ConfigManager not initialized")
    
    # Authentication
    admin_token = os.getenv("CONFIG_RELOAD_ADMIN_TOKEN", "").strip()
    if admin_token:
        auth_header = request.headers.get("authorization", "")
        if not auth_header:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Extract token
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        else:
            token = auth_header.strip()
        
        # Constant-time comparison
        import hmac
        if not hmac.compare_digest(token.encode('utf-8'), admin_token.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    # Parse request body
    try:
        body = await request.json()
        config_type = body.get("type")
        config_data = body.get("config")
        version = body.get("version")  # Optional version tracking
        source = body.get("source", "ui")  # Source identifier
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid request body: {str(e)}")
    
    # Validate required fields
    if config_type not in ["webhooks", "connections"]:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid config type: {config_type}. Must be 'webhooks' or 'connections'"
        )
    
    if not config_data or not isinstance(config_data, dict):
        raise HTTPException(status_code=400, detail="Config data must be a non-empty dictionary")
    
    # Determine config file path
    config_file = "webhooks.json" if config_type == "webhooks" else "connections.json"
    
    # Write config to file atomically
    try:
        # Write to temporary file first, then rename (atomic operation)
        temp_file = f"{config_file}.tmp"
        with open(temp_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        # Atomic rename
        import shutil
        shutil.move(temp_file, config_file)
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to write config file: {str(e)}"
        )
    
    # Trigger reload
    try:
        if config_type == "webhooks":
            result = await config_manager.reload_webhooks()
        else:
            result = await config_manager.reload_connections()
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "error": f"Reload failed: {str(e)}",
                "instance_id": os.getenv("INSTANCE_ID", socket.gethostname())
            }
        )
    
    # Return result
    response_data = {
        "status": "success" if result.success else "error",
        "error": result.error,
        "details": result.details,
        "timestamp": result.timestamp,
        "instance_id": os.getenv("INSTANCE_ID", socket.gethostname()),
        "version": version  # Echo back version for tracking
    }
    
    if result.success:
        return JSONResponse(content=response_data)
    else:
        return JSONResponse(status_code=400, content=response_data)
```

#### New Endpoint: `/admin/instance-info`

**Purpose**: Return instance metadata for discovery and monitoring.

**Implementation**:

```python
@app.get("/admin/instance-info")
async def get_instance_info():
    """
    Return instance metadata for discovery.
    
    This endpoint provides information about the current instance
    for use by the centralized UI for instance discovery and monitoring.
    
    Returns:
    {
        "instance_id": "unique-instance-identifier",
        "hostname": "hostname",
        "version": "application-version",
        "uptime_seconds": 12345,
        "webhooks_count": 10,
        "connections_count": 5,
        "config_version": "config-hash",
        "last_reload": "2024-01-15T10:30:00Z"
    }
    """
    global config_manager
    
    import socket
    import time
    
    # Get instance ID (from env or hostname)
    instance_id = os.getenv("INSTANCE_ID", socket.gethostname())
    
    # Calculate uptime (if tracked)
    # For now, return None if not tracked
    uptime = None  # Could be tracked in app startup
    
    # Get config stats
    webhooks_count = 0
    connections_count = 0
    config_version = None
    last_reload = None
    
    if config_manager:
        webhooks_count = len(config_manager._webhook_config)
        connections_count = len(config_manager._connection_config)
        last_reload = config_manager._last_reload.isoformat() if config_manager._last_reload else None
        
        # Calculate config version hash
        import hashlib
        config_str = json.dumps(config_manager._webhook_config, sort_keys=True)
        config_version = hashlib.sha256(config_str.encode()).hexdigest()[:16]
    
    return JSONResponse(content={
        "instance_id": instance_id,
        "hostname": socket.gethostname(),
        "version": "1.0.0",  # Could be from __version__ or env
        "uptime_seconds": uptime,
        "webhooks_count": webhooks_count,
        "connections_count": connections_count,
        "config_version": config_version,
        "last_reload": last_reload
    })
```

#### New Endpoint: `/admin/config-version`

**Purpose**: Return current configuration version/hash for sync verification.

**Implementation**:

```python
@app.get("/admin/config-version")
async def get_config_version():
    """
    Return current config version/hash.
    
    This endpoint returns a hash of the current configuration,
    useful for verifying that all instances are in sync.
    
    Returns:
    {
        "webhooks_version": "hash-of-webhooks-config",
        "connections_version": "hash-of-connections-config",
        "last_reload": "2024-01-15T10:30:00Z"
    }
    """
    global config_manager
    
    if not config_manager:
        raise HTTPException(status_code=503, detail="ConfigManager not initialized")
    
    import hashlib
    
    # Calculate version hashes
    webhooks_str = json.dumps(config_manager._webhook_config, sort_keys=True)
    webhooks_version = hashlib.sha256(webhooks_str.encode()).hexdigest()[:16]
    
    connections_str = json.dumps(config_manager._connection_config, sort_keys=True)
    connections_version = hashlib.sha256(connections_str.encode()).hexdigest()[:16]
    
    return JSONResponse(content={
        "webhooks_version": webhooks_version,
        "connections_version": connections_version,
        "last_reload": config_manager._last_reload.isoformat() if config_manager._last_reload else None
    })
```

### 2. Centralized UI Backend - Sync Coordinator

**Location**: `ui/backend/sync_coordinator.py` (new file)

**Implementation**:

```python
"""
Configuration Sync Coordinator for Centralized UI.

This module handles synchronizing configuration changes
to multiple webhook instances.
"""
import asyncio
import httpx
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class InstanceInfo:
    """Information about a webhook instance."""
    url: str
    instance_id: Optional[str] = None
    health_status: str = "unknown"  # "healthy", "unhealthy", "unknown"
    last_check: Optional[datetime] = None


@dataclass
class SyncResult:
    """Result of a sync operation to a single instance."""
    instance_url: str
    success: bool
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None


class ConfigSyncCoordinator:
    """
    Coordinates configuration synchronization across multiple instances.
    
    Features:
    - Parallel sync to all instances
    - Retry logic for failed syncs
    - Health checking
    - Version verification
    """
    
    def __init__(
        self,
        instances: List[str],
        admin_token: str,
        timeout: float = 10.0,
        max_retries: int = 2
    ):
        """
        Initialize sync coordinator.
        
        Args:
            instances: List of instance URLs (e.g., ["http://instance1:8000", ...])
            admin_token: Admin authentication token
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts for failed syncs
        """
        self.instances = [InstanceInfo(url=url) for url in instances]
        self.admin_token = admin_token
        self.timeout = timeout
        self.max_retries = max_retries
    
    async def sync_config_to_all(
        self,
        config_type: str,
        config_data: dict,
        version: Optional[str] = None
    ) -> Dict[str, SyncResult]:
        """
        Sync configuration to all registered instances.
        
        Args:
            config_type: "webhooks" or "connections"
            config_data: Full configuration dictionary
            version: Optional version identifier for tracking
        
        Returns:
            Dictionary mapping instance URLs to SyncResult objects
        """
        # Sync to all instances in parallel
        tasks = [
            self._sync_to_instance(instance.url, config_type, config_data, version)
            for instance in self.instances
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Build result dictionary
        sync_results = {}
        for instance, result in zip(self.instances, results):
            if isinstance(result, Exception):
                sync_results[instance.url] = SyncResult(
                    instance_url=instance.url,
                    success=False,
                    error=str(result)
                )
            else:
                sync_results[instance.url] = result
        
        return sync_results
    
    async def sync_config_to_selected(
        self,
        instance_urls: List[str],
        config_type: str,
        config_data: dict,
        version: Optional[str] = None
    ) -> Dict[str, SyncResult]:
        """
        Sync configuration to selected instances only.
        
        Args:
            instance_urls: List of instance URLs to sync to
            config_type: "webhooks" or "connections"
            config_data: Full configuration dictionary
            version: Optional version identifier
        
        Returns:
            Dictionary mapping instance URLs to SyncResult objects
        """
        tasks = [
            self._sync_to_instance(url, config_type, config_data, version)
            for url in instance_urls
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        sync_results = {}
        for url, result in zip(instance_urls, results):
            if isinstance(result, Exception):
                sync_results[url] = SyncResult(
                    instance_url=url,
                    success=False,
                    error=str(result)
                )
            else:
                sync_results[url] = result
        
        return sync_results
    
    async def _sync_to_instance(
        self,
        instance_url: str,
        config_type: str,
        config_data: dict,
        version: Optional[str] = None,
        retry_count: int = 0
    ) -> SyncResult:
        """
        Sync configuration to a single instance with retry logic.
        
        Args:
            instance_url: URL of the instance
            config_type: "webhooks" or "connections"
            config_data: Full configuration dictionary
            version: Optional version identifier
            retry_count: Current retry attempt
        
        Returns:
            SyncResult object
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{instance_url}/admin/config-update",
                    json={
                        "type": config_type,
                        "config": config_data,
                        "version": version,
                        "source": "centralized-ui"
                    },
                    headers={
                        "Authorization": f"Bearer {self.admin_token}",
                        "Content-Type": "application/json"
                    }
                )
                
                response.raise_for_status()
                result_data = response.json()
                
                return SyncResult(
                    instance_url=instance_url,
                    success=result_data.get("status") == "success",
                    error=result_data.get("error"),
                    details=result_data.get("details"),
                    timestamp=result_data.get("timestamp")
                )
        
        except httpx.TimeoutException:
            error_msg = f"Request timeout after {self.timeout}s"
            if retry_count < self.max_retries:
                # Retry with exponential backoff
                await asyncio.sleep(2 ** retry_count)
                return await self._sync_to_instance(
                    instance_url, config_type, config_data, version, retry_count + 1
                )
            return SyncResult(
                instance_url=instance_url,
                success=False,
                error=error_msg
            )
        
        except httpx.HTTPStatusError as e:
            error_msg = f"HTTP {e.response.status_code}: {e.response.text}"
            return SyncResult(
                instance_url=instance_url,
                success=False,
                error=error_msg
            )
        
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            if retry_count < self.max_retries:
                await asyncio.sleep(2 ** retry_count)
                return await self._sync_to_instance(
                    instance_url, config_type, config_data, version, retry_count + 1
                )
            return SyncResult(
                instance_url=instance_url,
                success=False,
                error=error_msg
            )
    
    async def verify_all_instances_in_sync(
        self,
        config_type: str
    ) -> Dict[str, Any]:
        """
        Verify that all instances have the same configuration version.
        
        Args:
            config_type: "webhooks" or "connections"
        
        Returns:
            Dictionary with sync status information
        """
        tasks = [
            self._get_instance_version(instance.url, config_type)
            for instance in self.instances
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        versions = {}
        for instance, result in zip(self.instances, results):
            if isinstance(result, Exception):
                versions[instance.url] = {"error": str(result)}
            else:
                versions[instance.url] = result
        
        # Check if all versions match
        successful_versions = [
            v.get("version") for v in versions.values()
            if "version" in v and "error" not in v
        ]
        
        all_same = len(set(successful_versions)) <= 1 if successful_versions else False
        
        return {
            "in_sync": all_same,
            "versions": versions,
            "expected_version": successful_versions[0] if successful_versions else None
        }
    
    async def _get_instance_version(
        self,
        instance_url: str,
        config_type: str
    ) -> Dict[str, Any]:
        """Get configuration version from an instance."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{instance_url}/admin/config-version",
                    headers={"Authorization": f"Bearer {self.admin_token}"}
                )
                response.raise_for_status()
                data = response.json()
                
                version_key = f"{config_type}_version" if config_type == "webhooks" else "connections_version"
                return {
                    "version": data.get(version_key),
                    "last_reload": data.get("last_reload")
                }
        except Exception as e:
            return {"error": str(e)}
    
    async def check_instance_health(self, instance_url: str) -> Dict[str, Any]:
        """Check health status of an instance."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"{instance_url}/admin/instance-info",
                    headers={"Authorization": f"Bearer {self.admin_token}"}
                )
                response.raise_for_status()
                return {
                    "healthy": True,
                    "info": response.json()
                }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }
    
    async def discover_instances(self, base_urls: List[str]) -> List[InstanceInfo]:
        """
        Discover instances from a list of potential base URLs.
        
        Args:
            base_urls: List of potential instance URLs to check
        
        Returns:
            List of discovered InstanceInfo objects
        """
        tasks = [self.check_instance_health(url) for url in base_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        discovered = []
        for url, result in zip(base_urls, results):
            if isinstance(result, dict) and result.get("healthy"):
                info = result.get("info", {})
                discovered.append(InstanceInfo(
                    url=url,
                    instance_id=info.get("instance_id"),
                    health_status="healthy",
                    last_check=datetime.now()
                ))
        
        return discovered
```

### 3. Centralized UI Frontend - Configuration Manager

**Location**: `ui/frontend/ConfigManager.js` (example JavaScript/TypeScript)

**Implementation**:

```javascript
/**
 * Configuration Manager for Centralized UI
 * Handles configuration editing and synchronization
 */
class ConfigManager {
  constructor(apiBaseUrl, adminToken) {
    this.apiBaseUrl = apiBaseUrl;
    this.adminToken = adminToken;
    this.instances = [];
  }

  /**
   * Register instances for management
   */
  async registerInstances(instanceUrls) {
    this.instances = instanceUrls;
    // Verify all instances are reachable
    await this.verifyInstances();
  }

  /**
   * Verify all registered instances are healthy
   */
  async verifyInstances() {
    const healthChecks = await Promise.all(
      this.instances.map(url => this.checkInstanceHealth(url))
    );
    return healthChecks;
  }

  /**
   * Check health of a single instance
   */
  async checkInstanceHealth(instanceUrl) {
    try {
      const response = await fetch(`${instanceUrl}/admin/instance-info`, {
        headers: {
          'Authorization': `Bearer ${this.adminToken}`
        }
      });
      if (response.ok) {
        const info = await response.json();
        return { url: instanceUrl, healthy: true, info };
      }
      return { url: instanceUrl, healthy: false, error: 'HTTP error' };
    } catch (error) {
      return { url: instanceUrl, healthy: false, error: error.message };
    }
  }

  /**
   * Sync configuration to all instances
   */
  async syncConfigToAll(configType, configData) {
    // 1. Validate config
    const validation = await this.validateConfig(configType, configData);
    if (!validation.valid) {
      throw new Error(`Validation failed: ${validation.errors.join(', ')}`);
    }

    // 2. Generate version hash
    const version = this.generateVersionHash(configData);

    // 3. Show confirmation dialog
    const confirmed = await this.showConfirmationDialog(
      `Apply changes to ${this.instances.length} instances?`
    );
    if (!confirmed) {
      return { cancelled: true };
    }

    // 4. Sync to all instances
    const syncResults = await this.syncCoordinator.syncConfigToAll(
      configType,
      configData,
      version
    );

    // 5. Display results
    this.displaySyncResults(syncResults);

    // 6. Verify sync
    const verification = await this.verifyAllInstancesInSync(configType);
    if (!verification.in_sync) {
      console.warn('Warning: Not all instances are in sync!');
      this.showSyncWarning(verification);
    }

    return {
      success: Object.values(syncResults).every(r => r.success),
      results: syncResults,
      verification
    };
  }

  /**
   * Sync configuration to selected instances
   */
  async syncConfigToSelected(instanceUrls, configType, configData) {
    const validation = await this.validateConfig(configType, configData);
    if (!validation.valid) {
      throw new Error(`Validation failed: ${validation.errors.join(', ')}`);
    }

    const version = this.generateVersionHash(configData);
    const syncResults = await this.syncCoordinator.syncConfigToSelected(
      instanceUrls,
      configType,
      configData,
      version
    );

    this.displaySyncResults(syncResults);
    return syncResults;
  }

  /**
   * Verify all instances are in sync
   */
  async verifyAllInstancesInSync(configType) {
    const verification = await this.syncCoordinator.verifyAllInstancesInSync(
      configType
    );
    return verification;
  }

  /**
   * Validate configuration before syncing
   */
  async validateConfig(configType, configData) {
    // Basic validation
    if (!configData || typeof configData !== 'object') {
      return { valid: false, errors: ['Config must be an object'] };
    }

    // Type-specific validation
    if (configType === 'webhooks') {
      return this.validateWebhooksConfig(configData);
    } else if (configType === 'connections') {
      return this.validateConnectionsConfig(configData);
    }

    return { valid: true, errors: [] };
  }

  /**
   * Validate webhooks configuration
   */
  validateWebhooksConfig(config) {
    const errors = [];
    
    for (const [webhookId, webhookConfig] of Object.entries(config)) {
      if (!webhookConfig.module) {
        errors.push(`Webhook '${webhookId}' missing required 'module' field`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate connections configuration
   */
  validateConnectionsConfig(config) {
    const errors = [];
    
    for (const [connName, connConfig] of Object.entries(config)) {
      if (!connConfig.type) {
        errors.push(`Connection '${connName}' missing required 'type' field`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Generate version hash for configuration
   */
  generateVersionHash(configData) {
    // Simple hash - in production, use proper hashing library
    const str = JSON.stringify(configData, Object.keys(configData).sort());
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }

  /**
   * Display sync results to user
   */
  displaySyncResults(results) {
    const successCount = Object.values(results).filter(r => r.success).length;
    const totalCount = Object.keys(results).length;
    
    console.log(`Sync completed: ${successCount}/${totalCount} instances updated`);
    
    // Display detailed results in UI
    for (const [url, result] of Object.entries(results)) {
      if (result.success) {
        console.log(`✓ ${url}: Success`);
      } else {
        console.error(`✗ ${url}: ${result.error}`);
      }
    }
  }

  /**
   * Show sync warning if instances are out of sync
   */
  showSyncWarning(verification) {
    console.warn('Instances are out of sync:', verification.versions);
    // Display warning in UI
  }

  /**
   * Show confirmation dialog (placeholder)
   */
  async showConfirmationDialog(message) {
    return confirm(message); // Replace with proper UI dialog
  }
}
```

## Usage Example

### Backend Usage (Python)

```python
# Initialize sync coordinator
coordinator = ConfigSyncCoordinator(
    instances=[
        "http://webhook-1:8000",
        "http://webhook-2:8000",
        "http://webhook-3:8000"
    ],
    admin_token=os.getenv("CONFIG_RELOAD_ADMIN_TOKEN"),
    timeout=10.0
)

# Load configuration
with open("webhooks.json", "r") as f:
    webhook_config = json.load(f)

# Sync to all instances
results = await coordinator.sync_config_to_all(
    config_type="webhooks",
    config_data=webhook_config,
    version="v1.2.3"
)

# Check results
for url, result in results.items():
    if result.success:
        print(f"✓ {url}: Success")
    else:
        print(f"✗ {url}: {result.error}")

# Verify all instances are in sync
verification = await coordinator.verify_all_instances_in_sync("webhooks")
if verification["in_sync"]:
    print("All instances are in sync!")
else:
    print("Warning: Instances are out of sync")
```

### Frontend Usage (JavaScript)

```javascript
// Initialize config manager
const configManager = new ConfigManager(
  'http://ui-backend:3000',
  process.env.ADMIN_TOKEN
);

// Register instances
await configManager.registerInstances([
  'http://webhook-1:8000',
  'http://webhook-2:8000',
  'http://webhook-3:8000'
]);

// Load and edit configuration
const webhookConfig = await loadConfigFromFile('webhooks.json');
webhookConfig['new_webhook'] = {
  module: 'rabbitmq',
  connection: 'rabbitmq_prod',
  authorization: 'Bearer token123'
};

// Sync to all instances
try {
  const result = await configManager.syncConfigToAll('webhooks', webhookConfig);
  if (result.success) {
    console.log('Configuration synced successfully!');
  } else {
    console.error('Some instances failed to sync');
  }
} catch (error) {
  console.error('Sync failed:', error);
}
```

## Security Considerations

### 1. Authentication
- All admin endpoints require `CONFIG_RELOAD_ADMIN_TOKEN`
- Use constant-time comparison (hmac.compare_digest) to prevent timing attacks
- Token should be stored securely (environment variables, secrets manager)

### 2. Network Security
- Use HTTPS for all API communications
- Validate SSL certificates
- Consider VPN or private network for admin endpoints

### 3. Input Validation
- Validate all configuration data before writing to files
- Sanitize file paths to prevent directory traversal
- Validate JSON structure and required fields

### 4. Access Control
- Implement role-based access control in UI
- Log all configuration changes for audit
- Require approval workflow for production changes

### 5. Error Handling
- Don't expose sensitive information in error messages
- Log errors securely
- Implement rate limiting on admin endpoints

## Implementation Steps

### Phase 1: Backend API Enhancement
1. Add `/admin/config-update` endpoint to `src/main.py`
2. Add `/admin/instance-info` endpoint
3. Add `/admin/config-version` endpoint
4. Add atomic file writing (temp file + rename)
5. Update existing `/admin/reload-config` to work with new endpoint

### Phase 2: Sync Coordinator
1. Create `ui/backend/sync_coordinator.py`
2. Implement parallel sync logic
3. Implement retry logic with exponential backoff
4. Implement version verification
5. Add health checking

### Phase 3: Frontend Integration
1. Create configuration editor UI
2. Implement instance discovery/registration
3. Implement sync UI with progress tracking
4. Add sync result visualization
5. Add version verification UI

### Phase 4: Testing
1. Unit tests for sync coordinator
2. Integration tests for multi-instance sync
3. Error handling tests (network failures, timeouts)
4. Security tests (authentication, authorization)
5. Performance tests (sync time, concurrent syncs)

### Phase 5: Documentation
1. API documentation for new endpoints
2. UI user guide
3. Deployment guide
4. Troubleshooting guide

## Advantages of Push-Based Approach

1. **Real-time Updates**: Changes are applied immediately to all instances
2. **Centralized Control**: Single point of control for all instances
3. **Error Visibility**: Immediate feedback on sync success/failure per instance
4. **Selective Sync**: Can sync to specific instances if needed
5. **Version Tracking**: Can track which version each instance has
6. **No Shared Storage Required**: Doesn't require shared filesystem or database

## Limitations

1. **Network Dependency**: Requires network connectivity to all instances
2. **Sequential Failure Handling**: If one instance fails, others may still succeed (requires handling)
3. **No Automatic Discovery**: Instances must be manually registered (can be enhanced with service discovery)
4. **UI Dependency**: Requires UI to be available for sync operations

## Future Enhancements

1. **Service Discovery**: Automatic instance discovery (Consul, Kubernetes, etc.)
2. **Config Versioning**: Store config history with rollback capability
3. **Dry-Run Mode**: Validate configs without applying
4. **Batch Operations**: Update multiple configs in one operation
5. **Webhook Notifications**: Notify external systems on config changes
6. **Config Templates**: Reusable configuration templates
7. **Diff View**: Show differences between current and proposed config
8. **Scheduled Syncs**: Schedule config updates for specific times

