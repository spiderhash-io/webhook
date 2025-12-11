"""
Config Manager for thread-safe configuration management and live reload.

This module provides:
- Thread-safe config storage using Read-Copy-Update (RCU) pattern
- Configuration validation
- Reload orchestration
- Integration with ConnectionPoolRegistry
"""
import json
import asyncio
import os
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass

from src.utils import load_env_vars, sanitize_error_message
from src.config import _validate_connection_host, _validate_connection_port
from src.modules.registry import ModuleRegistry
from src.connection_pool_registry import (
    ConnectionPoolRegistry,
    create_rabbitmq_pool,
    create_redis_pool,
    create_postgresql_pool,
    create_mysql_pool
)


@dataclass
class ReloadResult:
    """Result of a configuration reload operation."""
    success: bool
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class ConfigManager:
    """
    Thread-safe configuration manager with live reload support.
    
    Features:
    - Read-Copy-Update (RCU) pattern for thread-safe updates
    - Configuration validation before applying changes
    - Integration with ConnectionPoolRegistry for pool management
    - Support for webhook and connection config reloading
    """
    
    def __init__(
        self,
        webhook_config_file: str = "webhooks.json",
        connection_config_file: str = "connections.json",
        pool_registry: Optional[ConnectionPoolRegistry] = None
    ):
        """
        Initialize ConfigManager.
        
        Args:
            webhook_config_file: Path to webhooks.json file
            connection_config_file: Path to connections.json file
            pool_registry: Optional ConnectionPoolRegistry instance (creates new if None)
        """
        self.webhook_config_file = webhook_config_file
        self.connection_config_file = connection_config_file
        self.pool_registry = pool_registry or ConnectionPoolRegistry()
        
        # Thread-safe config storage
        self._webhook_config: Dict[str, Any] = {}
        self._connection_config: Dict[str, Any] = {}
        self._lock = asyncio.Lock()
        self._reload_in_progress = False
        self._last_reload: Optional[datetime] = None
    
    async def initialize(self) -> ReloadResult:
        """
        Initialize config manager by loading initial configurations.
        
        Returns:
            ReloadResult indicating success or failure
        """
        try:
            # Load webhooks
            webhook_result = await self.reload_webhooks()
            if not webhook_result.success:
                return webhook_result
            
            # Load connections
            connection_result = await self.reload_connections()
            if not connection_result.success:
                return connection_result
            
            return ReloadResult(
                success=True,
                details={
                    "webhooks_loaded": len(self._webhook_config),
                    "connections_loaded": len(self._connection_config)
                }
            )
        except Exception as e:
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "ConfigManager.initialize")
            return ReloadResult(
                success=False,
                error=f"Initialization failed: {sanitized_error}"
            )
    
    async def reload_webhooks(self) -> ReloadResult:
        """
        Reload webhook configuration from file.
        
        Returns:
            ReloadResult with reload status and statistics
        """
        async with self._lock:
            if self._reload_in_progress:
                return ReloadResult(
                    success=False,
                    error="Reload already in progress"
                )
            
            self._reload_in_progress = True
        
        try:
            # Load and validate new config
            new_config = await self._load_webhook_config()
            
            # Validate config
            validation_error = await self._validate_webhook_config(new_config)
            if validation_error:
                return ReloadResult(
                    success=False,
                    error=f"Validation failed: {validation_error}"
                )
            
            # Calculate changes
            old_keys = set(self._webhook_config.keys())
            new_keys = set(new_config.keys())
            added = new_keys - old_keys
            removed = old_keys - new_keys
            modified = {k for k in new_keys & old_keys if self._webhook_config[k] != new_config[k]}
            
            # Apply new config (atomic update)
            async with self._lock:
                self._webhook_config = new_config
                self._last_reload = datetime.now(timezone.utc)
                self._reload_in_progress = False
            
            return ReloadResult(
                success=True,
                details={
                    "webhooks_added": len(added),
                    "webhooks_removed": len(removed),
                    "webhooks_modified": len(modified),
                    "total_webhooks": len(new_config)
                }
            )
        except FileNotFoundError:
            # If file doesn't exist, keep current config
            async with self._lock:
                self._reload_in_progress = False
            return ReloadResult(
                success=False,
                error="webhooks.json file not found"
            )
        except json.JSONDecodeError as e:
            async with self._lock:
                self._reload_in_progress = False
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "ConfigManager.reload_webhooks")
            return ReloadResult(
                success=False,
                error=f"Invalid JSON in webhooks.json: {sanitized_error}"
            )
        except Exception as e:
            async with self._lock:
                self._reload_in_progress = False
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "ConfigManager.reload_webhooks")
            return ReloadResult(
                success=False,
                error=f"Failed to reload webhooks: {sanitized_error}"
            )
    
    async def reload_connections(self) -> ReloadResult:
        """
        Reload connection configuration from file.
        
        Returns:
            ReloadResult with reload status and statistics
        """
        async with self._lock:
            if self._reload_in_progress:
                return ReloadResult(
                    success=False,
                    error="Reload already in progress"
                )
            
            self._reload_in_progress = True
        
        try:
            # Load and validate new config
            new_config = await self._load_connection_config()
            
            # Validate config
            validation_error = await self._validate_connection_config(new_config)
            if validation_error:
                return ReloadResult(
                    success=False,
                    error=f"Validation failed: {validation_error}"
                )
            
            # Calculate changes
            old_keys = set(self._connection_config.keys())
            new_keys = set(new_config.keys())
            added = new_keys - old_keys
            removed = old_keys - new_keys
            modified = {k for k in new_keys & old_keys if self._connection_config[k] != new_config[k]}
            
            # Update connection pools for changed connections
            for conn_name in added | modified:
                conn_config = new_config[conn_name]
                await self._update_connection_pool(conn_name, conn_config)
            
            # Apply new config (atomic update)
            async with self._lock:
                self._connection_config = new_config
                self._last_reload = datetime.now(timezone.utc)
                self._reload_in_progress = False
            
            return ReloadResult(
                success=True,
                details={
                    "connections_added": len(added),
                    "connections_removed": len(removed),
                    "connections_modified": len(modified),
                    "total_connections": len(new_config)
                }
            )
        except FileNotFoundError:
            async with self._lock:
                self._reload_in_progress = False
            return ReloadResult(
                success=False,
                error="connections.json file not found"
            )
        except json.JSONDecodeError as e:
            async with self._lock:
                self._reload_in_progress = False
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "ConfigManager.reload_connections")
            return ReloadResult(
                success=False,
                error=f"Invalid JSON in connections.json: {sanitized_error}"
            )
        except Exception as e:
            async with self._lock:
                self._reload_in_progress = False
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "ConfigManager.reload_connections")
            return ReloadResult(
                success=False,
                error=f"Failed to reload connections: {sanitized_error}"
            )
    
    async def reload_all(self) -> ReloadResult:
        """
        Reload both webhook and connection configurations.
        
        Returns:
            ReloadResult with combined reload status
        """
        webhook_result = await self.reload_webhooks()
        connection_result = await self.reload_connections()
        
        if webhook_result.success and connection_result.success:
            return ReloadResult(
                success=True,
                details={
                    "webhooks": webhook_result.details,
                    "connections": connection_result.details
                }
            )
        else:
            errors = []
            if not webhook_result.success:
                errors.append(f"Webhooks: {webhook_result.error}")
            if not connection_result.success:
                errors.append(f"Connections: {connection_result.error}")
            
            return ReloadResult(
                success=False,
                error="; ".join(errors),
                details={
                    "webhooks": webhook_result.details,
                    "connections": connection_result.details
                }
            )
    
    def get_webhook_config(self, webhook_id: str) -> Optional[Dict[str, Any]]:
        """
        Get webhook configuration by ID (thread-safe read).
        
        Args:
            webhook_id: Webhook identifier
            
        Returns:
            Webhook configuration dictionary or None if not found
        """
        return self._webhook_config.get(webhook_id)
    
    def get_connection_config(self, connection_name: str) -> Optional[Dict[str, Any]]:
        """
        Get connection configuration by name (thread-safe read).
        
        Args:
            connection_name: Connection name
            
        Returns:
            Connection configuration dictionary or None if not found
        """
        return self._connection_config.get(connection_name)
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current status of the config manager.
        
        Returns:
            Dictionary with status information
        """
        pool_info = self.pool_registry.get_all_pools_info()
        
        return {
            "last_reload": self._last_reload.isoformat() if self._last_reload else None,
            "reload_in_progress": self._reload_in_progress,
            "webhooks_count": len(self._webhook_config),
            "connections_count": len(self._connection_config),
            "connection_pools": {
                "active": len([p for p in pool_info.values() if not p.get("deprecated", False)]),
                "deprecated": len([p for p in pool_info.values() if p.get("deprecated", False)])
            },
            "pool_details": pool_info
        }
    
    async def _load_webhook_config(self) -> Dict[str, Any]:
        """Load webhook config from file with environment variable substitution."""
        if not os.path.exists(self.webhook_config_file):
            return {}
        
        with open(self.webhook_config_file, 'r') as f:
            config = json.load(f)
        
        # Apply environment variable substitution
        config = load_env_vars(config)
        
        return config
    
    async def _load_connection_config(self) -> Dict[str, Any]:
        """Load connection config from file with environment variable substitution."""
        if not os.path.exists(self.connection_config_file):
            raise FileNotFoundError(f"{self.connection_config_file} not found")
        
        with open(self.connection_config_file, 'r') as f:
            config = json.load(f)
        
        # Apply environment variable substitution
        config = load_env_vars(config)
        
        return config
    
    async def _validate_webhook_config(self, config: Dict[str, Any]) -> Optional[str]:
        """
        Validate webhook configuration.
        
        Args:
            config: Webhook configuration dictionary
            
        Returns:
            Error message if validation fails, None if valid
        """
        for webhook_id, webhook_config in config.items():
            # Validate webhook ID
            if not webhook_id or not isinstance(webhook_id, str):
                return f"Invalid webhook ID: {webhook_id}"
            
            # Validate module exists
            module_name = webhook_config.get('module')
            if not module_name:
                return f"Webhook '{webhook_id}' is missing required 'module' field"
            
            try:
                ModuleRegistry.get(module_name)
            except KeyError:
                return f"Webhook '{webhook_id}' uses unknown module '{module_name}'"
            except Exception as e:
                # SECURITY: Sanitize error message to prevent information disclosure
                sanitized_error = sanitize_error_message(e, f"ConfigManager._validate_webhook_config")
                return f"Webhook '{webhook_id}' module validation error: {sanitized_error}"
            
            # Validate connection reference if present
            connection_name = webhook_config.get('connection')
            if connection_name:
                # Check if connection exists in current config
                if connection_name not in self._connection_config:
                    # This is OK during initial load, connection might be loaded later
                    pass
        
        return None
    
    async def _validate_connection_config(self, config: Dict[str, Any]) -> Optional[str]:
        """
        Validate connection configuration.
        
        Args:
            config: Connection configuration dictionary
            
        Returns:
            Error message if validation fails, None if valid
        """
        for conn_name, conn_config in config.items():
            # Validate connection name
            if not conn_name or not isinstance(conn_name, str):
                return f"Invalid connection name: {conn_name}"
            
            # Validate connection type
            conn_type = conn_config.get('type')
            if not conn_type:
                return f"Connection '{conn_name}' is missing required 'type' field"
            
            # Validate host and port for connections that need them
            if conn_type in ['rabbitmq', 'redis-rq', 'postgresql', 'mysql', 'clickhouse']:
                host = conn_config.get('host')
                port = conn_config.get('port')
                
                if not host:
                    return f"Connection '{conn_name}' is missing required 'host' field"
                
                if not port:
                    return f"Connection '{conn_name}' is missing required 'port' field"
                
                # Validate host (SSRF protection)
                try:
                    _validate_connection_host(host, conn_type)
                except ValueError as e:
                    return f"Connection '{conn_name}' host validation failed: {str(e)}"
                
                # Validate port
                try:
                    _validate_connection_port(port, conn_type)
                except ValueError as e:
                    return f"Connection '{conn_name}' port validation failed: {str(e)}"
        
        return None
    
    async def _update_connection_pool(self, connection_name: str, connection_config: Dict[str, Any]) -> None:
        """
        Update connection pool for a connection.
        
        Args:
            connection_name: Name of the connection
            connection_config: Connection configuration
        """
        conn_type = connection_config.get('type')
        
        # Select appropriate factory function
        if conn_type == 'rabbitmq':
            factory = create_rabbitmq_pool
        elif conn_type == 'redis-rq':
            factory = create_redis_pool
        elif conn_type == 'postgresql' or conn_type == 'postgres':
            factory = create_postgresql_pool
        elif conn_type == 'mysql' or conn_type == 'mariadb':
            factory = create_mysql_pool
        else:
            # Other connection types don't use pools
            return
        
        # Get or create pool (registry handles versioning and migration)
        # Handle pool creation errors gracefully - reload shouldn't fail if connection is temporarily unavailable
        try:
            await self.pool_registry.get_pool(connection_name, connection_config, factory)
        except Exception as e:
            # Log error but don't fail reload - pool will be created when actually needed
            print(f"Warning: Failed to create pool for connection '{connection_name}': {e}")

