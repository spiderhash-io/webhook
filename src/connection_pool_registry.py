"""
Connection Pool Registry for managing connection pools independently from configuration.

This module provides a registry for connection pools that supports:
- Pool versioning and graceful migration
- Independent lifecycle management from config
- Factory functions for different connection types
- Automatic cleanup of deprecated pools
"""
import asyncio
import time
import hashlib
import json
from typing import Any, Dict, Optional, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class PoolInfo:
    """Information about a connection pool."""
    connection_name: str
    pool: Any
    created_at: float
    deprecated_at: Optional[float] = None
    version: int = 1
    config_hash: str = ""
    active_requests: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class ConnectionPoolRegistry:
    """
    Registry for managing connection pools with versioning and graceful migration.
    
    Features:
    - Pool versioning: Track multiple versions of pools for same connection
    - Graceful migration: Old pools remain active during transition
    - Automatic cleanup: Deprecated pools are closed after timeout
    - Async-safe: Safe for concurrent async access
    """
    
    def __init__(self, migration_timeout: float = 300.0):
        """
        Initialize connection pool registry.
        
        Args:
            migration_timeout: Time in seconds before deprecated pools are cleaned up (default: 5 minutes)
            
        Raises:
            ValueError: If migration_timeout is negative or invalid
            TypeError: If migration_timeout is not a number
        """
        # Security: Validate migration_timeout to prevent DoS
        if not isinstance(migration_timeout, (int, float)):
            raise TypeError(f"migration_timeout must be a number, got {type(migration_timeout).__name__}")
        if migration_timeout < 0:
            raise ValueError(f"migration_timeout must be >= 0, got {migration_timeout}")
        if migration_timeout > 86400 * 365:  # Max 1 year (prevent overflow)
            raise ValueError(f"migration_timeout exceeds maximum limit (1 year), got {migration_timeout}")
        
        self._pools: Dict[str, PoolInfo] = {}  # connection_name -> PoolInfo
        self._deprecated_pools: Dict[str, PoolInfo] = {}  # connection_name -> PoolInfo (old version)
        self._lock: Optional[asyncio.Lock] = None  # Lazy initialization to avoid event loop requirement
        self.migration_timeout = migration_timeout
        self._version_counter: Dict[str, int] = {}  # connection_name -> version
    
    def _get_lock(self) -> asyncio.Lock:
        """Get or create the async lock (lazy initialization)."""
        if self._lock is None:
            try:
                self._lock = asyncio.Lock()
            except RuntimeError:
                # If no event loop exists, create a new one (for testing scenarios)
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._lock = asyncio.Lock()
        return self._lock
    
    async def get_pool(
        self,
        connection_name: str,
        connection_config: Dict[str, Any],
        pool_factory: Callable[[Dict[str, Any]], Awaitable[Any]]
    ) -> Any:
        """
        Get or create a connection pool for the given connection.
        
        Args:
            connection_name: Name of the connection
            connection_config: Connection configuration dictionary
            pool_factory: Async function that creates a pool from config
            
        Returns:
            Connection pool object
            
        Raises:
            TypeError: If connection_name is not a string or pool_factory is not callable
            ValueError: If connection_name is empty or too long
        """
        # Security: Validate connection_name to prevent injection and DoS
        if not isinstance(connection_name, str):
            raise TypeError(f"connection_name must be a string, got {type(connection_name).__name__}")
        if not connection_name:
            raise ValueError("connection_name cannot be empty")
        if len(connection_name) > 256:  # Prevent DoS via extremely long names
            raise ValueError(f"connection_name too long: {len(connection_name)} characters (max: 256)")
        
        # Security: Validate connection_config
        if connection_config is None:
            raise ValueError("connection_config cannot be None")
        if not isinstance(connection_config, dict):
            raise TypeError(f"connection_config must be a dictionary, got {type(connection_config).__name__}")
        
        # Security: Validate pool_factory is callable
        if not callable(pool_factory):
            raise TypeError(f"pool_factory must be callable, got {type(pool_factory).__name__}")
        
        # Security: Use full SHA256 hash to prevent hash collisions
        # Using only 16 chars (64 bits) can cause collisions with different configs
        try:
            # Security: Prevent JSON DoS via circular references and deeply nested structures
            config_str = json.dumps(connection_config, sort_keys=True, default=str)
        except (TypeError, ValueError, RecursionError) as e:
            raise ValueError(f"Invalid connection_config: {str(e)}") from e
        
        # Use full 64-char SHA256 hash to prevent collisions
        config_hash = hashlib.sha256(config_str.encode()).hexdigest()
        
        async with self._get_lock():
            # Check if we have an active pool with matching config
            if connection_name in self._pools:
                pool_info = self._pools[connection_name]
                # Security: Compare full hash AND config string to prevent collisions
                if pool_info.config_hash == config_hash:
                    # Double-check config string matches (defense in depth against hash collisions)
                    stored_config_str = pool_info.metadata.get("config_str", "")
                    if stored_config_str == config_str:
                        # Same config, reuse existing pool
                        pool_info.active_requests += 1
                        return pool_info.pool
                
                # Config changed (hash or config string differs), deprecate old pool
                pool_info.deprecated_at = time.time()
                self._deprecated_pools[connection_name] = pool_info
                del self._pools[connection_name]
            
            # Create new pool
            try:
                pool = await pool_factory(connection_config)
            except Exception as e:
                # Security: Sanitize error messages to prevent information disclosure
                from src.utils import sanitize_error_message
                error_msg = sanitize_error_message(e, "ConnectionPoolRegistry.get_pool")
                raise RuntimeError(f"Failed to create connection pool: {error_msg}") from e
            
            # Increment version
            version = self._version_counter.get(connection_name, 0) + 1
            self._version_counter[connection_name] = version
            
            # Security: Store config_str for comparison but not the full config dict
            # Note: config_str contains serialized config (may include sensitive data in JSON form)
            # This allows config comparison without storing the full config dict object
            safe_metadata = {
                "host": connection_config.get("host", ""),
                "port": connection_config.get("port", ""),
                "type": connection_config.get("type", ""),
                "config_str": config_str  # Store for comparison (contains serialized config)
            }
            
            # Create new pool info
            pool_info = PoolInfo(
                connection_name=connection_name,
                pool=pool,
                created_at=time.time(),
                version=version,
                config_hash=config_hash,
                active_requests=1,
                metadata=safe_metadata
            )
            
            self._pools[connection_name] = pool_info
            return pool
    
    async def release_pool(self, connection_name: str, pool: Any) -> None:
        """
        Release a pool (decrement active request count).
        
        Args:
            connection_name: Name of the connection
            pool: Pool object (for validation)
        """
        # Security: Validate connection_name
        if not isinstance(connection_name, str):
            return  # Silently ignore invalid input
        
        async with self._get_lock():
            # Security: Only decrement if pool object matches exactly (prevent wrong pool release)
            if connection_name in self._pools:
                pool_info = self._pools[connection_name]
                if pool_info.pool is pool:  # Identity check (is, not ==)
                    pool_info.active_requests = max(0, pool_info.active_requests - 1)
    
    async def cleanup_deprecated_pools(self) -> int:
        """
        Clean up deprecated pools that have exceeded migration timeout.
        
        Returns:
            Number of pools cleaned up
        """
        current_time = time.time()
        cleaned = 0
        
        async with self._get_lock():
            to_remove = []
            for connection_name, pool_info in self._deprecated_pools.items():
                if pool_info.deprecated_at:
                    elapsed = current_time - pool_info.deprecated_at
                    if elapsed >= self.migration_timeout:
                        to_remove.append(connection_name)
            
            for connection_name in to_remove:
                pool_info = self._deprecated_pools[connection_name]
                try:
                    # Try to close the pool if it has a close method
                    if hasattr(pool_info.pool, 'close'):
                        if asyncio.iscoroutinefunction(pool_info.pool.close):
                            await pool_info.pool.close()
                        else:
                            pool_info.pool.close()
                    # Try close_all for pools that have it
                    elif hasattr(pool_info.pool, 'close_all'):
                        if asyncio.iscoroutinefunction(pool_info.pool.close_all):
                            await pool_info.pool.close_all()
                        else:
                            pool_info.pool.close_all()
                except Exception as e:
                    # Security: Sanitize error messages to prevent information disclosure
                    from src.utils import sanitize_error_message
                    error_msg = sanitize_error_message(e, "ConnectionPoolRegistry.cleanup_deprecated_pools")
                    print(f"Warning: Error closing deprecated pool {connection_name}: {error_msg}")
                
                del self._deprecated_pools[connection_name]
                cleaned += 1
        
        return cleaned
    
    def get_pool_info(self, connection_name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a connection pool.
        
        Args:
            connection_name: Name of the connection
            
        Returns:
            Dictionary with pool information or None if not found
        """
        # Security: Validate connection_name
        if not isinstance(connection_name, str):
            return None
        if connection_name in self._pools:
            pool_info = self._pools[connection_name]
            return {
                "connection_name": pool_info.connection_name,
                "version": pool_info.version,
                "created_at": datetime.fromtimestamp(pool_info.created_at, tz=timezone.utc).isoformat(),
                "active_requests": pool_info.active_requests,
                "deprecated": False
            }
        elif connection_name in self._deprecated_pools:
            pool_info = self._deprecated_pools[connection_name]
            return {
                "connection_name": pool_info.connection_name,
                "version": pool_info.version,
                "created_at": datetime.fromtimestamp(pool_info.created_at, tz=timezone.utc).isoformat(),
                "deprecated_at": datetime.fromtimestamp(pool_info.deprecated_at, tz=timezone.utc).isoformat() if pool_info.deprecated_at else None,
                "active_requests": pool_info.active_requests,
                "deprecated": True
            }
        return None
    
    def get_all_pools_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Get information about all connection pools.
        
        Returns:
            Dictionary mapping connection names to pool information
        """
        result = {}
        for connection_name in set(self._pools.keys()) | set(self._deprecated_pools.keys()):
            info = self.get_pool_info(connection_name)
            if info:
                result[connection_name] = info
        return result
    
    async def close_all_pools(self) -> None:
        """Close all pools (active and deprecated)."""
        async with self._get_lock():
            all_pools = list(self._pools.values()) + list(self._deprecated_pools.values())
            for pool_info in all_pools:
                try:
                    if hasattr(pool_info.pool, 'close'):
                        if asyncio.iscoroutinefunction(pool_info.pool.close):
                            await pool_info.pool.close()
                        else:
                            pool_info.pool.close()
                    elif hasattr(pool_info.pool, 'close_all'):
                        if asyncio.iscoroutinefunction(pool_info.pool.close_all):
                            await pool_info.pool.close_all()
                        else:
                            pool_info.pool.close_all()
                except Exception as e:
                    # Security: Sanitize error messages to prevent information disclosure
                    from src.utils import sanitize_error_message
                    error_msg = sanitize_error_message(e, "ConnectionPoolRegistry.close_all_pools")
                    print(f"Warning: Error closing pool {pool_info.connection_name}: {error_msg}")
            
            self._pools.clear()
            self._deprecated_pools.clear()


# Factory functions for different connection types

async def create_rabbitmq_pool(connection_config: Dict[str, Any]) -> Any:
    """Create a RabbitMQ connection pool."""
    from src.modules.rabbitmq import RabbitMQConnectionPool
    
    pool = RabbitMQConnectionPool()
    await pool.create_pool(
        host=connection_config.get("host", "localhost"),
        port=connection_config.get("port", 5672),
        login=connection_config.get("user", "guest"),
        password=connection_config.get("pass", "guest")
    )
    return pool


async def create_redis_pool(connection_config: Dict[str, Any]) -> Any:
    """Create a Redis connection for RQ."""
    from redis import Redis
    
    return Redis(
        host=connection_config.get("host", "localhost"),
        port=connection_config.get("port", 6379),
        db=connection_config.get("db", 0)
    )


async def create_postgresql_pool(connection_config: Dict[str, Any]) -> Any:
    """Create a PostgreSQL connection pool."""
    import asyncpg
    
    # Build connection string or use individual parameters
    host = connection_config.get("host", "localhost")
    port = connection_config.get("port", 5432)
    user = connection_config.get("user", "postgres")
    password = connection_config.get("password", "")
    database = connection_config.get("database", "postgres")
    
    return await asyncpg.create_pool(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        min_size=1,
        max_size=10
    )


async def create_mysql_pool(connection_config: Dict[str, Any]) -> Any:
    """Create a MySQL/MariaDB connection pool."""
    import aiomysql
    
    host = connection_config.get("host", "localhost")
    port = connection_config.get("port", 3306)
    user = connection_config.get("user", "root")
    password = connection_config.get("password", "")
    database = connection_config.get("database", "mysql")
    
    return await aiomysql.create_pool(
        host=host,
        port=port,
        user=user,
        password=password,
        db=database,
        minsize=1,
        maxsize=10
    )

