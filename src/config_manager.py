"""
Config Manager for async-safe configuration management and live reload.

This module provides:
- Async-safe config storage using Read-Copy-Update (RCU) pattern
- Configuration validation
- Reload orchestration
- Integration with ConnectionPoolRegistry
- Pluggable config backends via ConfigProvider (file, etcd)
"""

import json
import asyncio
import os
import copy
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass

from src.utils import load_env_vars, sanitize_error_message
from src.config import _validate_connection_host, _validate_connection_port
from src.config_provider import ConfigProvider

logger = logging.getLogger(__name__)
from src.modules.registry import ModuleRegistry
from src.connection_pool_registry import (
    ConnectionPoolRegistry,
    create_rabbitmq_pool,
    create_redis_pool,
    create_postgresql_pool,
    create_mysql_pool,
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
    Async-safe configuration manager with live reload support.

    Features:
    - Read-Copy-Update (RCU) pattern for async-safe updates
    - Configuration validation before applying changes
    - Integration with ConnectionPoolRegistry for pool management
    - Support for webhook and connection config reloading
    """

    def __init__(
        self,
        webhook_config_file: str = "webhooks.json",
        connection_config_file: str = "connections.json",
        pool_registry: Optional[ConnectionPoolRegistry] = None,
        provider: Optional[ConfigProvider] = None,
    ):
        """
        Initialize ConfigManager.

        Args:
            webhook_config_file: Path to webhooks.json file
            connection_config_file: Path to connections.json file
            pool_registry: Optional ConnectionPoolRegistry instance (creates new if None)
            provider: Optional ConfigProvider backend. When set, config reads
                      are delegated to the provider instead of internal dicts.
        """
        self.webhook_config_file = webhook_config_file
        self.connection_config_file = connection_config_file
        self.pool_registry = pool_registry or ConnectionPoolRegistry()
        self.provider = provider

        self._webhook_config: Dict[str, Any] = {}
        self._connection_config: Dict[str, Any] = {}
        self._lock: Optional[asyncio.Lock] = None
        self._reload_in_progress = False
        self._last_reload: Optional[datetime] = None
        # Gate for provider reads: only delegate to provider after validation passes.
        # Ensures reads fall back to internal cache (last known-good) on failure.
        self._provider_validated = False

    @classmethod
    async def create(
        cls,
        backend: str = "file",
        webhook_config_file: str = "webhooks.json",
        connection_config_file: str = "connections.json",
        pool_registry: Optional[ConnectionPoolRegistry] = None,
        **kwargs: Any,
    ) -> "ConfigManager":
        """
        Factory method to create a ConfigManager with the specified backend.

        Args:
            backend: Config backend type — "file" (default) or "etcd".
            webhook_config_file: Path to webhooks.json (file backend).
            connection_config_file: Path to connections.json (file backend).
            pool_registry: Optional ConnectionPoolRegistry instance.
            **kwargs: Backend-specific options passed to the provider constructor.
                For etcd: host, port, prefix, namespace, username, password.

        Returns:
            An initialized ConfigManager instance.
        """
        if backend == "file":
            from src.file_config_provider import FileConfigProvider

            provider = FileConfigProvider(
                webhook_config_file=webhook_config_file,
                connection_config_file=connection_config_file,
            )
        elif backend == "etcd":
            from src.etcd_config_provider import EtcdConfigProvider

            provider = EtcdConfigProvider(**kwargs)
        else:
            raise ValueError(f"Unknown config backend: {backend!r}")

        manager = cls(
            webhook_config_file=webhook_config_file,
            connection_config_file=connection_config_file,
            pool_registry=pool_registry,
            provider=provider,
        )
        return manager

    def _get_lock(self) -> asyncio.Lock:
        """Get or create the async lock (lazy initialization)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def initialize(self) -> ReloadResult:
        """
        Initialize config manager by loading initial configurations.

        When a provider is set, delegates initialization to the provider.
        Otherwise falls back to the legacy file-reload path.

        Returns:
            ReloadResult indicating success or failure
        """
        try:
            if self.provider:
                await self.provider.initialize()
                # Sync internal caches from provider for backward compat
                webhook_config = self.provider.get_all_webhook_configs()
                connection_config = self.provider.get_all_connection_configs()

                # Validate configs (same rules as legacy path)
                validation_error = await self._validate_webhook_config(webhook_config)
                if validation_error:
                    return ReloadResult(
                        success=False,
                        error=f"Validation failed: {validation_error}",
                    )
                validation_error = await self._validate_connection_config(
                    connection_config
                )
                if validation_error:
                    return ReloadResult(
                        success=False,
                        error=f"Validation failed: {validation_error}",
                    )

                self._webhook_config = webhook_config
                self._connection_config = connection_config
                self._provider_validated = True
                self._last_reload = datetime.now(timezone.utc)
                return ReloadResult(
                    success=True,
                    details={
                        "webhooks_loaded": len(self._webhook_config),
                        "connections_loaded": len(self._connection_config),
                        "backend": self.provider.get_status().get("backend", "unknown"),
                    },
                )

            # Legacy path: load from files directly
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
                    "connections_loaded": len(self._connection_config),
                },
            )
        except Exception as e:
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "ConfigManager.initialize")
            return ReloadResult(
                success=False, error=f"Initialization failed: {sanitized_error}"
            )

    async def reload_webhooks(self) -> ReloadResult:
        """
        Reload webhook configuration from file (or provider).

        Returns:
            ReloadResult with reload status and statistics
        """
        # If using a file provider, delegate reload to it
        if self.provider:
            from src.file_config_provider import FileConfigProvider

            if isinstance(self.provider, FileConfigProvider):
                try:
                    old_keys = set(self._webhook_config.keys())
                    new_config = self.provider.reload_webhooks()

                    # Validate before applying
                    validation_error = await self._validate_webhook_config(new_config)
                    if validation_error:
                        # Fail closed: stop delegating reads to provider
                        self._provider_validated = False
                        return ReloadResult(
                            success=False,
                            error=f"Validation failed: {validation_error}",
                        )

                    new_keys = set(new_config.keys())
                    self._webhook_config = new_config
                    self._provider_validated = True
                    self._last_reload = datetime.now(timezone.utc)
                    return ReloadResult(
                        success=True,
                        details={
                            "webhooks_added": len(new_keys - old_keys),
                            "webhooks_removed": len(old_keys - new_keys),
                            "total_webhooks": len(new_config),
                        },
                    )
                except Exception as e:
                    self._provider_validated = False
                    sanitized_error = sanitize_error_message(
                        e, "ConfigManager.reload_webhooks"
                    )
                    return ReloadResult(
                        success=False,
                        error=f"Failed to reload webhooks: {sanitized_error}",
                    )
            else:
                # Non-file providers manage their own updates (e.g., etcd watch)
                return ReloadResult(
                    success=True,
                    details={"note": "Provider manages its own updates"},
                )

        async with self._get_lock():
            if self._reload_in_progress:
                return ReloadResult(success=False, error="Reload already in progress")

            self._reload_in_progress = True

        try:
            # Load and validate new config
            new_config = await self._load_webhook_config()

            # Validate config
            validation_error = await self._validate_webhook_config(new_config)
            if validation_error:
                return ReloadResult(
                    success=False, error=f"Validation failed: {validation_error}"
                )

            # Calculate changes
            old_keys = set(self._webhook_config.keys())
            new_keys = set(new_config.keys())
            added = new_keys - old_keys
            removed = old_keys - new_keys
            modified = {
                k
                for k in new_keys & old_keys
                if self._webhook_config[k] != new_config[k]
            }

            # Apply new config (atomic update)
            async with self._get_lock():
                self._webhook_config = new_config
                self._last_reload = datetime.now(timezone.utc)
                self._reload_in_progress = False

            return ReloadResult(
                success=True,
                details={
                    "webhooks_added": len(added),
                    "webhooks_removed": len(removed),
                    "webhooks_modified": len(modified),
                    "total_webhooks": len(new_config),
                },
            )
        except FileNotFoundError:
            # If file doesn't exist, keep current config
            async with self._get_lock():
                self._reload_in_progress = False
            return ReloadResult(success=False, error="webhooks.json file not found")
        except json.JSONDecodeError as e:
            async with self._get_lock():
                self._reload_in_progress = False
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "ConfigManager.reload_webhooks")
            return ReloadResult(
                success=False, error=f"Invalid JSON in webhooks.json: {sanitized_error}"
            )
        except Exception as e:
            async with self._get_lock():
                self._reload_in_progress = False
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "ConfigManager.reload_webhooks")
            return ReloadResult(
                success=False, error=f"Failed to reload webhooks: {sanitized_error}"
            )

    async def reload_connections(self) -> ReloadResult:
        """
        Reload connection configuration from file (or provider).

        Returns:
            ReloadResult with reload status and statistics
        """
        # If using a file provider, delegate reload to it
        if self.provider:
            from src.file_config_provider import FileConfigProvider

            if isinstance(self.provider, FileConfigProvider):
                try:
                    old_keys = set(self._connection_config.keys())
                    new_config = self.provider.reload_connections()

                    # Validate before applying
                    validation_error = await self._validate_connection_config(
                        new_config
                    )
                    if validation_error:
                        # Fail closed: stop delegating reads to provider
                        self._provider_validated = False
                        return ReloadResult(
                            success=False,
                            error=f"Validation failed: {validation_error}",
                        )

                    new_keys = set(new_config.keys())
                    self._connection_config = new_config
                    self._provider_validated = True
                    self._last_reload = datetime.now(timezone.utc)
                    return ReloadResult(
                        success=True,
                        details={
                            "connections_added": len(new_keys - old_keys),
                            "connections_removed": len(old_keys - new_keys),
                            "total_connections": len(new_config),
                        },
                    )
                except Exception as e:
                    self._provider_validated = False
                    sanitized_error = sanitize_error_message(
                        e, "ConfigManager.reload_connections"
                    )
                    return ReloadResult(
                        success=False,
                        error=f"Failed to reload connections: {sanitized_error}",
                    )
            else:
                # Non-file providers manage their own updates
                return ReloadResult(
                    success=True,
                    details={"note": "Provider manages its own updates"},
                )

        async with self._get_lock():
            if self._reload_in_progress:
                return ReloadResult(success=False, error="Reload already in progress")

            self._reload_in_progress = True

        try:
            # Load and validate new config
            new_config = await self._load_connection_config()

            # Validate config
            validation_error = await self._validate_connection_config(new_config)
            if validation_error:
                return ReloadResult(
                    success=False, error=f"Validation failed: {validation_error}"
                )

            # Calculate changes
            old_keys = set(self._connection_config.keys())
            new_keys = set(new_config.keys())
            added = new_keys - old_keys
            removed = old_keys - new_keys
            modified = {
                k
                for k in new_keys & old_keys
                if self._connection_config[k] != new_config[k]
            }

            # Update connection pools for changed connections
            for conn_name in added | modified:
                conn_config = new_config[conn_name]
                await self._update_connection_pool(conn_name, conn_config)

            # Apply new config (atomic update)
            async with self._get_lock():
                self._connection_config = new_config
                self._last_reload = datetime.now(timezone.utc)
                self._reload_in_progress = False

            return ReloadResult(
                success=True,
                details={
                    "connections_added": len(added),
                    "connections_removed": len(removed),
                    "connections_modified": len(modified),
                    "total_connections": len(new_config),
                },
            )
        except FileNotFoundError:
            async with self._get_lock():
                self._reload_in_progress = False
            return ReloadResult(success=False, error="connections.json file not found")
        except json.JSONDecodeError as e:
            async with self._get_lock():
                self._reload_in_progress = False
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(
                e, "ConfigManager.reload_connections"
            )
            return ReloadResult(
                success=False,
                error=f"Invalid JSON in connections.json: {sanitized_error}",
            )
        except Exception as e:
            async with self._get_lock():
                self._reload_in_progress = False
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(
                e, "ConfigManager.reload_connections"
            )
            return ReloadResult(
                success=False, error=f"Failed to reload connections: {sanitized_error}"
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
                    "connections": connection_result.details,
                },
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
                    "connections": connection_result.details,
                },
            )

    def get_webhook_config(
        self, webhook_id: str, namespace: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get webhook configuration by ID (async-safe read).

        Args:
            webhook_id: Webhook identifier
            namespace: Optional namespace (only meaningful for etcd backend)

        Returns:
            Webhook configuration dictionary or None if not found
        """
        if self.provider and self._provider_validated:
            return self.provider.get_webhook_config(webhook_id, namespace=namespace)
        return self._webhook_config.get(webhook_id)

    def get_all_webhook_configs(
        self, namespace: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get all webhook configurations (async-safe read).

        Args:
            namespace: Optional namespace (only meaningful for etcd backend)

        Returns:
            Copy of all webhook configurations.
            Safe to modify without affecting internal state.
        """
        if self.provider and self._provider_validated:
            return self.provider.get_all_webhook_configs(namespace=namespace)
        return copy.deepcopy(self._webhook_config)

    def get_connection_config(self, connection_name: str) -> Optional[Dict[str, Any]]:
        """
        Get connection configuration by name (async-safe read).

        Args:
            connection_name: Connection name

        Returns:
            Connection configuration dictionary or None if not found
        """
        if self.provider and self._provider_validated:
            return self.provider.get_connection_config(connection_name)
        return self._connection_config.get(connection_name)

    def get_all_connection_configs(self) -> Dict[str, Any]:
        """
        Get all connection configurations (async-safe read).

        Returns:
            Copy of all connection configurations.
            Safe to modify without affecting internal state.
        """
        if self.provider and self._provider_validated:
            return self.provider.get_all_connection_configs()
        return copy.deepcopy(self._connection_config)

    def get_status(self) -> Dict[str, Any]:
        """
        Get current status of the config manager.

        Returns:
            Dictionary with status information
        """
        pool_info = self.pool_registry.get_all_pools_info()

        status: Dict[str, Any] = {
            "last_reload": self._last_reload.isoformat() if self._last_reload else None,
            "reload_in_progress": self._reload_in_progress,
            "webhooks_count": len(self._webhook_config),
            "connections_count": len(self._connection_config),
            "connection_pools": {
                "active": len(
                    [p for p in pool_info.values() if not p.get("deprecated", False)]
                ),
                "deprecated": len(
                    [p for p in pool_info.values() if p.get("deprecated", False)]
                ),
            },
            "pool_details": pool_info,
        }

        if self.provider:
            status["provider"] = self.provider.get_status()

        return status

    async def _load_webhook_config(self) -> Dict[str, Any]:
        """Load webhook config from file with environment variable substitution."""
        if not os.path.exists(self.webhook_config_file):
            # Default logging webhook when webhooks.json is not provided
            logger.info(
                "webhooks.json not found. Using default logging webhook with pretty print to console."
            )
            logger.info(
                "Default logging endpoint enabled. All webhook requests will be logged to console."
            )
            logger.info(
                "Sensitive data redaction is ENABLED by default. Set 'redact_sensitive: false' in module-config to disable."
            )
            return {
                "default": {
                    "data_type": "json",
                    "module": "log",
                    "module-config": {
                        "pretty_print": True,
                        "redact_sensitive": True,  # Default: redact sensitive data for security
                    },
                }
            }

        with open(self.webhook_config_file, "r") as f:
            config = json.load(f)

        # Apply environment variable substitution
        config = load_env_vars(config)

        return config

    async def _load_connection_config(self) -> Dict[str, Any]:
        """Load connection config from file with environment variable substitution."""
        if not os.path.exists(self.connection_config_file):
            raise FileNotFoundError(f"{self.connection_config_file} not found")

        with open(self.connection_config_file, "r") as f:
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
        from src.chain_validator import ChainValidator

        for webhook_id, webhook_config in config.items():
            # Validate webhook ID
            if not webhook_id or not isinstance(webhook_id, str):
                return f"Invalid webhook ID: {webhook_id}"

            # Check if chain is configured (chain takes precedence over module)
            chain = webhook_config.get("chain")
            if chain is not None:
                # Validate chain configuration
                is_valid, error = ChainValidator.validate_chain_config(webhook_config)
                if not is_valid:
                    return f"Webhook '{webhook_id}' has invalid chain configuration: {error}"
            else:
                # Backward compatibility: validate module exists
                module_name = webhook_config.get("module")
                if not module_name:
                    return f"Webhook '{webhook_id}' is missing required 'module' field (or 'chain' field)"

                try:
                    ModuleRegistry.get(module_name)
                except KeyError:
                    return f"Webhook '{webhook_id}' uses unknown module '{module_name}'"
                except Exception as e:
                    # SECURITY: Sanitize error message to prevent information disclosure
                    sanitized_error = sanitize_error_message(
                        e, f"ConfigManager._validate_webhook_config"
                    )
                    return f"Webhook '{webhook_id}' module validation error: {sanitized_error}"

            # Validate connection reference if present
            connection_name = webhook_config.get("connection")
            if connection_name:
                # Check if connection exists in current config
                if connection_name not in self._connection_config:
                    # This is OK during initial load, connection might be loaded later
                    pass

        return None

    async def _validate_connection_config(
        self, config: Dict[str, Any]
    ) -> Optional[str]:
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
            conn_type = conn_config.get("type")
            if not conn_type:
                return f"Connection '{conn_name}' is missing required 'type' field"

            # Validate host and port for connections that need them
            if conn_type in [
                "rabbitmq",
                "redis-rq",
                "postgresql",
                "mysql",
                "clickhouse",
            ]:
                host = conn_config.get("host")
                port = conn_config.get("port")

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

    async def _update_connection_pool(
        self, connection_name: str, connection_config: Dict[str, Any]
    ) -> None:
        """
        Update connection pool for a connection.

        Args:
            connection_name: Name of the connection
            connection_config: Connection configuration
        """
        conn_type = connection_config.get("type")

        # Select appropriate factory function
        if conn_type == "rabbitmq":
            factory = create_rabbitmq_pool
        elif conn_type == "redis-rq":
            factory = create_redis_pool
        elif conn_type in ["postgresql", "postgres"]:
            factory = create_postgresql_pool
        elif conn_type in ["mysql", "mariadb"]:
            factory = create_mysql_pool
        else:
            # Other connection types don't use pools
            return

        # Get or create pool (registry handles versioning and migration)
        # Handle pool creation errors gracefully - reload shouldn't fail if connection is temporarily unavailable
        try:
            await self.pool_registry.get_pool(
                connection_name, connection_config, factory
            )
        except Exception as e:
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(
                e, "ConfigManager._update_connection_pool"
            )
            logger.warning(
                f"Failed to create pool for connection '{connection_name}': {sanitized_error}"
            )
