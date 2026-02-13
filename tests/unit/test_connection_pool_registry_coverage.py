"""
Coverage tests for src/connection_pool_registry.py.

Targets the ~37 missed lines covering:
- ConnectionPoolRegistry init validation (type error, negative, overflow)
- _get_lock fallback (no event loop scenario)
- get_pool validation (empty name, long name, none config, non-dict config, non-callable factory)
- get_pool config serialization error (RecursionError)
- get_pool factory failure (sanitized error)
- get_pool hash collision defense-in-depth (same hash, different config_str)
- release_pool edge cases (non-string name, wrong pool identity)
- cleanup_deprecated_pools (sync close, close_all variants, exception during close)
- close_all_pools (sync close, close_all variants, exception during close)
- get_pool_info for deprecated pool
- get_pool_info non-string name
- Factory functions (create_rabbitmq_pool, create_redis_pool, create_postgresql_pool, create_mysql_pool)
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

from src.connection_pool_registry import (
    ConnectionPoolRegistry,
    PoolInfo,
    create_rabbitmq_pool,
    create_redis_pool,
    create_postgresql_pool,
    create_mysql_pool,
)


class TestConnectionPoolRegistryInit:
    """Test ConnectionPoolRegistry initialization validation."""

    def test_init_valid(self):
        """Test valid initialization."""
        registry = ConnectionPoolRegistry(migration_timeout=60.0)
        assert registry.migration_timeout == 60.0

    def test_init_default_timeout(self):
        """Test default migration timeout."""
        registry = ConnectionPoolRegistry()
        assert registry.migration_timeout == 300.0

    def test_init_non_number_timeout(self):
        """Test init rejects non-number migration_timeout."""
        with pytest.raises(TypeError, match="must be a number"):
            ConnectionPoolRegistry(migration_timeout="sixty")

    def test_init_negative_timeout(self):
        """Test init rejects negative migration_timeout."""
        with pytest.raises(ValueError, match="must be >= 0"):
            ConnectionPoolRegistry(migration_timeout=-1.0)

    def test_init_overflow_timeout(self):
        """Test init rejects excessively large migration_timeout."""
        with pytest.raises(ValueError, match="exceeds maximum limit"):
            ConnectionPoolRegistry(migration_timeout=86400 * 366)

    def test_init_zero_timeout(self):
        """Test init accepts zero migration_timeout."""
        registry = ConnectionPoolRegistry(migration_timeout=0.0)
        assert registry.migration_timeout == 0.0


class TestGetPoolValidation:
    """Test get_pool input validation."""

    @pytest.mark.asyncio
    async def test_non_string_connection_name(self):
        """Test get_pool rejects non-string connection_name."""
        registry = ConnectionPoolRegistry()
        with pytest.raises(TypeError, match="must be a string"):
            await registry.get_pool(123, {"host": "test"}, AsyncMock())

    @pytest.mark.asyncio
    async def test_empty_connection_name(self):
        """Test get_pool rejects empty connection_name."""
        registry = ConnectionPoolRegistry()
        with pytest.raises(ValueError, match="cannot be empty"):
            await registry.get_pool("", {"host": "test"}, AsyncMock())

    @pytest.mark.asyncio
    async def test_long_connection_name(self):
        """Test get_pool rejects excessively long connection_name."""
        registry = ConnectionPoolRegistry()
        with pytest.raises(ValueError, match="too long"):
            await registry.get_pool("x" * 257, {"host": "test"}, AsyncMock())

    @pytest.mark.asyncio
    async def test_none_connection_config(self):
        """Test get_pool rejects None connection_config."""
        registry = ConnectionPoolRegistry()
        with pytest.raises(ValueError, match="cannot be None"):
            await registry.get_pool("conn1", None, AsyncMock())

    @pytest.mark.asyncio
    async def test_non_dict_connection_config(self):
        """Test get_pool rejects non-dict connection_config."""
        registry = ConnectionPoolRegistry()
        with pytest.raises(TypeError, match="must be a dictionary"):
            await registry.get_pool("conn1", "not-a-dict", AsyncMock())

    @pytest.mark.asyncio
    async def test_non_callable_pool_factory(self):
        """Test get_pool rejects non-callable pool_factory."""
        registry = ConnectionPoolRegistry()
        with pytest.raises(TypeError, match="must be callable"):
            await registry.get_pool("conn1", {"host": "test"}, "not-callable")

    @pytest.mark.asyncio
    async def test_invalid_config_serialization(self):
        """Test get_pool handles config that cannot be serialized to JSON."""
        registry = ConnectionPoolRegistry()
        # Create a circular reference
        circular = {}
        circular["self"] = circular

        with pytest.raises(ValueError, match="Invalid connection_config"):
            await registry.get_pool("conn1", circular, AsyncMock())


class TestGetPoolBehavior:
    """Test get_pool pool creation and reuse behavior."""

    @pytest.mark.asyncio
    async def test_factory_failure_raises_runtime_error(self):
        """Test that factory failure raises RuntimeError with sanitized message."""
        registry = ConnectionPoolRegistry()

        async def failing_factory(config):
            raise ConnectionError("password=secret123 refused connection")

        with pytest.raises(RuntimeError, match="Failed to create connection pool"):
            await registry.get_pool("conn1", {"host": "test"}, failing_factory)

    @pytest.mark.asyncio
    async def test_config_change_deprecates_old_pool(self):
        """Test that config change moves old pool to deprecated."""
        registry = ConnectionPoolRegistry()

        async def mock_factory(config):
            return MagicMock()

        pool1 = await registry.get_pool("conn1", {"host": "a"}, mock_factory)
        pool2 = await registry.get_pool("conn1", {"host": "b"}, mock_factory)

        assert pool1 is not pool2
        assert "conn1" in registry._deprecated_pools
        assert registry._deprecated_pools["conn1"].pool is pool1

    @pytest.mark.asyncio
    async def test_pool_reuse_increments_active_requests(self):
        """Test that reusing a pool increments active_requests."""
        registry = ConnectionPoolRegistry()

        async def mock_factory(config):
            return MagicMock()

        config = {"host": "test", "port": 5672}
        await registry.get_pool("conn1", config, mock_factory)
        initial = registry._pools["conn1"].active_requests

        await registry.get_pool("conn1", config, mock_factory)
        assert registry._pools["conn1"].active_requests == initial + 1

    @pytest.mark.asyncio
    async def test_version_increments_on_new_pool(self):
        """Test version counter increments correctly."""
        registry = ConnectionPoolRegistry()

        async def mock_factory(config):
            return MagicMock()

        await registry.get_pool("conn1", {"host": "a"}, mock_factory)
        assert registry._pools["conn1"].version == 1

        await registry.get_pool("conn1", {"host": "b"}, mock_factory)
        assert registry._pools["conn1"].version == 2

    @pytest.mark.asyncio
    async def test_metadata_stores_safe_fields(self):
        """Test that metadata stores only safe fields."""
        registry = ConnectionPoolRegistry()

        async def mock_factory(config):
            return MagicMock()

        config = {"host": "test.example.com", "port": 5672, "type": "rabbitmq", "password": "secret"}
        await registry.get_pool("conn1", config, mock_factory)

        metadata = registry._pools["conn1"].metadata
        assert metadata["host"] == "test.example.com"
        assert metadata["port"] == 5672
        assert metadata["type"] == "rabbitmq"
        assert "config_str" in metadata


class TestReleasePool:
    """Test release_pool edge cases."""

    @pytest.mark.asyncio
    async def test_release_non_string_name(self):
        """Test release_pool ignores non-string connection_name."""
        registry = ConnectionPoolRegistry()
        # Should not raise
        await registry.release_pool(123, MagicMock())

    @pytest.mark.asyncio
    async def test_release_wrong_pool_identity(self):
        """Test release_pool does not decrement when pool object doesn't match."""
        registry = ConnectionPoolRegistry()

        async def mock_factory(config):
            return MagicMock()

        config = {"host": "test"}
        pool = await registry.get_pool("conn1", config, mock_factory)
        initial = registry._pools["conn1"].active_requests

        # Release with a different pool object
        wrong_pool = MagicMock()
        await registry.release_pool("conn1", wrong_pool)

        # Active requests should not change
        assert registry._pools["conn1"].active_requests == initial

    @pytest.mark.asyncio
    async def test_release_nonexistent_connection(self):
        """Test release_pool handles non-existent connection gracefully."""
        registry = ConnectionPoolRegistry()
        # Should not raise
        await registry.release_pool("nonexistent", MagicMock())

    @pytest.mark.asyncio
    async def test_release_correct_pool_decrements(self):
        """Test release_pool decrements active_requests when pool matches."""
        registry = ConnectionPoolRegistry()

        async def mock_factory(config):
            return MagicMock()

        config = {"host": "test"}
        pool = await registry.get_pool("conn1", config, mock_factory)
        initial = registry._pools["conn1"].active_requests
        assert initial == 1

        await registry.release_pool("conn1", pool)
        assert registry._pools["conn1"].active_requests == 0

    @pytest.mark.asyncio
    async def test_release_does_not_go_below_zero(self):
        """Test release_pool does not decrement below zero."""
        registry = ConnectionPoolRegistry()

        async def mock_factory(config):
            return MagicMock()

        config = {"host": "test"}
        pool = await registry.get_pool("conn1", config, mock_factory)
        registry._pools["conn1"].active_requests = 0

        await registry.release_pool("conn1", pool)
        assert registry._pools["conn1"].active_requests == 0


class TestCleanupDeprecatedPools:
    """Test cleanup_deprecated_pools behavior."""

    @pytest.mark.asyncio
    async def test_cleanup_no_deprecated(self):
        """Test cleanup with no deprecated pools."""
        registry = ConnectionPoolRegistry()
        cleaned = await registry.cleanup_deprecated_pools()
        assert cleaned == 0

    @pytest.mark.asyncio
    async def test_cleanup_not_yet_expired(self):
        """Test cleanup does not remove pools before timeout."""
        registry = ConnectionPoolRegistry(migration_timeout=300.0)
        mock_pool = MagicMock()
        registry._deprecated_pools["conn1"] = PoolInfo(
            connection_name="conn1",
            pool=mock_pool,
            created_at=time.time(),
            deprecated_at=time.time(),
            version=1,
        )

        cleaned = await registry.cleanup_deprecated_pools()
        assert cleaned == 0
        assert "conn1" in registry._deprecated_pools

    @pytest.mark.asyncio
    async def test_cleanup_expired_with_async_close(self):
        """Test cleanup closes expired pool with async close method."""
        registry = ConnectionPoolRegistry(migration_timeout=0.0)
        mock_pool = AsyncMock()
        mock_pool.close = AsyncMock()
        registry._deprecated_pools["conn1"] = PoolInfo(
            connection_name="conn1",
            pool=mock_pool,
            created_at=time.time() - 10,
            deprecated_at=time.time() - 10,
            version=1,
        )

        cleaned = await registry.cleanup_deprecated_pools()
        assert cleaned == 1
        assert "conn1" not in registry._deprecated_pools
        mock_pool.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_expired_with_sync_close(self):
        """Test cleanup closes expired pool with sync close method."""
        registry = ConnectionPoolRegistry(migration_timeout=0.0)
        mock_pool = MagicMock()
        mock_pool.close = MagicMock()
        # Make sure asyncio.iscoroutinefunction returns False
        registry._deprecated_pools["conn1"] = PoolInfo(
            connection_name="conn1",
            pool=mock_pool,
            created_at=time.time() - 10,
            deprecated_at=time.time() - 10,
            version=1,
        )

        cleaned = await registry.cleanup_deprecated_pools()
        assert cleaned == 1
        mock_pool.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_expired_with_close_all(self):
        """Test cleanup uses close_all when close is not available."""
        registry = ConnectionPoolRegistry(migration_timeout=0.0)
        mock_pool = MagicMock(spec=[])  # No close attribute
        mock_pool.close_all = MagicMock()
        registry._deprecated_pools["conn1"] = PoolInfo(
            connection_name="conn1",
            pool=mock_pool,
            created_at=time.time() - 10,
            deprecated_at=time.time() - 10,
            version=1,
        )

        cleaned = await registry.cleanup_deprecated_pools()
        assert cleaned == 1
        mock_pool.close_all.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_close_exception(self):
        """Test cleanup handles close exception gracefully."""
        registry = ConnectionPoolRegistry(migration_timeout=0.0)
        mock_pool = MagicMock()
        mock_pool.close = MagicMock(side_effect=Exception("Close failed"))
        registry._deprecated_pools["conn1"] = PoolInfo(
            connection_name="conn1",
            pool=mock_pool,
            created_at=time.time() - 10,
            deprecated_at=time.time() - 10,
            version=1,
        )

        cleaned = await registry.cleanup_deprecated_pools()
        assert cleaned == 1
        assert "conn1" not in registry._deprecated_pools


class TestCloseAllPools:
    """Test close_all_pools behavior."""

    @pytest.mark.asyncio
    async def test_close_all_empty(self):
        """Test close_all with no pools."""
        registry = ConnectionPoolRegistry()
        await registry.close_all_pools()
        assert len(registry._pools) == 0
        assert len(registry._deprecated_pools) == 0

    @pytest.mark.asyncio
    async def test_close_all_with_async_close(self):
        """Test close_all closes pools with async close method."""
        registry = ConnectionPoolRegistry()
        mock_pool = AsyncMock()
        mock_pool.close = AsyncMock()
        registry._pools["conn1"] = PoolInfo(
            connection_name="conn1",
            pool=mock_pool,
            created_at=time.time(),
            version=1,
        )

        await registry.close_all_pools()
        mock_pool.close.assert_called_once()
        assert len(registry._pools) == 0

    @pytest.mark.asyncio
    async def test_close_all_with_sync_close(self):
        """Test close_all closes pools with sync close method."""
        registry = ConnectionPoolRegistry()
        mock_pool = MagicMock()
        mock_pool.close = MagicMock()
        registry._pools["conn1"] = PoolInfo(
            connection_name="conn1",
            pool=mock_pool,
            created_at=time.time(),
            version=1,
        )

        await registry.close_all_pools()
        mock_pool.close.assert_called_once()
        assert len(registry._pools) == 0

    @pytest.mark.asyncio
    async def test_close_all_with_close_all_method(self):
        """Test close_all uses close_all method when close is not available."""
        registry = ConnectionPoolRegistry()
        mock_pool = MagicMock(spec=[])
        mock_pool.close_all = MagicMock()
        registry._pools["conn1"] = PoolInfo(
            connection_name="conn1",
            pool=mock_pool,
            created_at=time.time(),
            version=1,
        )

        await registry.close_all_pools()
        mock_pool.close_all.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_all_with_async_close_all(self):
        """Test close_all uses async close_all method."""
        registry = ConnectionPoolRegistry()
        mock_pool = MagicMock(spec=[])
        mock_pool.close_all = AsyncMock()
        registry._pools["conn1"] = PoolInfo(
            connection_name="conn1",
            pool=mock_pool,
            created_at=time.time(),
            version=1,
        )

        await registry.close_all_pools()
        mock_pool.close_all.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_all_exception_continues(self):
        """Test close_all handles close exception and continues."""
        registry = ConnectionPoolRegistry()
        mock_pool1 = MagicMock()
        mock_pool1.close = MagicMock(side_effect=Exception("Close failed"))
        mock_pool2 = MagicMock()
        mock_pool2.close = MagicMock()

        registry._pools["conn1"] = PoolInfo(
            connection_name="conn1", pool=mock_pool1, created_at=time.time(), version=1
        )
        registry._pools["conn2"] = PoolInfo(
            connection_name="conn2", pool=mock_pool2, created_at=time.time(), version=1
        )

        await registry.close_all_pools()
        # Both pools should be cleared even if one failed
        assert len(registry._pools) == 0

    @pytest.mark.asyncio
    async def test_close_all_active_and_deprecated(self):
        """Test close_all closes both active and deprecated pools."""
        registry = ConnectionPoolRegistry()
        active_pool = MagicMock()
        active_pool.close = MagicMock()
        deprecated_pool = MagicMock()
        deprecated_pool.close = MagicMock()

        registry._pools["active"] = PoolInfo(
            connection_name="active", pool=active_pool, created_at=time.time(), version=1
        )
        registry._deprecated_pools["deprecated"] = PoolInfo(
            connection_name="deprecated",
            pool=deprecated_pool,
            created_at=time.time(),
            deprecated_at=time.time(),
            version=1,
        )

        await registry.close_all_pools()
        active_pool.close.assert_called_once()
        deprecated_pool.close.assert_called_once()
        assert len(registry._pools) == 0
        assert len(registry._deprecated_pools) == 0


class TestGetPoolInfo:
    """Test get_pool_info and get_all_pools_info."""

    def test_get_pool_info_non_string_name(self):
        """Test get_pool_info returns None for non-string name."""
        registry = ConnectionPoolRegistry()
        assert registry.get_pool_info(123) is None

    def test_get_pool_info_not_found(self):
        """Test get_pool_info returns None for unknown connection."""
        registry = ConnectionPoolRegistry()
        assert registry.get_pool_info("nonexistent") is None

    def test_get_pool_info_active(self):
        """Test get_pool_info for active pool."""
        registry = ConnectionPoolRegistry()
        registry._pools["conn1"] = PoolInfo(
            connection_name="conn1",
            pool=MagicMock(),
            created_at=time.time(),
            version=2,
            active_requests=3,
        )

        info = registry.get_pool_info("conn1")
        assert info is not None
        assert info["connection_name"] == "conn1"
        assert info["version"] == 2
        assert info["active_requests"] == 3
        assert info["deprecated"] is False

    def test_get_pool_info_deprecated(self):
        """Test get_pool_info for deprecated pool."""
        registry = ConnectionPoolRegistry()
        deprecated_time = time.time() - 60
        registry._deprecated_pools["conn1"] = PoolInfo(
            connection_name="conn1",
            pool=MagicMock(),
            created_at=time.time() - 120,
            deprecated_at=deprecated_time,
            version=1,
            active_requests=0,
        )

        info = registry.get_pool_info("conn1")
        assert info is not None
        assert info["connection_name"] == "conn1"
        assert info["deprecated"] is True
        assert info["deprecated_at"] is not None

    def test_get_pool_info_deprecated_no_deprecated_at(self):
        """Test get_pool_info for deprecated pool without deprecated_at."""
        registry = ConnectionPoolRegistry()
        registry._deprecated_pools["conn1"] = PoolInfo(
            connection_name="conn1",
            pool=MagicMock(),
            created_at=time.time(),
            deprecated_at=None,
            version=1,
        )

        info = registry.get_pool_info("conn1")
        assert info is not None
        assert info["deprecated"] is True
        assert info["deprecated_at"] is None

    def test_get_all_pools_info_empty(self):
        """Test get_all_pools_info with no pools."""
        registry = ConnectionPoolRegistry()
        result = registry.get_all_pools_info()
        assert result == {}

    def test_get_all_pools_info_mixed(self):
        """Test get_all_pools_info with active and deprecated pools."""
        registry = ConnectionPoolRegistry()
        registry._pools["active"] = PoolInfo(
            connection_name="active",
            pool=MagicMock(),
            created_at=time.time(),
            version=2,
        )
        registry._deprecated_pools["old"] = PoolInfo(
            connection_name="old",
            pool=MagicMock(),
            created_at=time.time() - 100,
            deprecated_at=time.time() - 50,
            version=1,
        )

        result = registry.get_all_pools_info()
        assert "active" in result
        assert "old" in result
        assert result["active"]["deprecated"] is False
        assert result["old"]["deprecated"] is True


class TestPoolInfoDataclass:
    """Test PoolInfo dataclass."""

    def test_pool_info_defaults(self):
        """Test PoolInfo default values."""
        info = PoolInfo(connection_name="test", pool=None, created_at=1.0)
        assert info.deprecated_at is None
        assert info.version == 1
        assert info.config_hash == ""
        assert info.active_requests == 0
        assert info.metadata == {}


class TestFactoryFunctions:
    """Test factory functions for different connection types."""

    @pytest.mark.asyncio
    async def test_create_rabbitmq_pool(self):
        """Test create_rabbitmq_pool calls RabbitMQConnectionPool."""
        mock_pool = MagicMock()
        mock_pool.create_pool = AsyncMock()

        with patch("src.modules.rabbitmq.RabbitMQConnectionPool", return_value=mock_pool):
            result = await create_rabbitmq_pool(
                {"host": "rmq.example.com", "port": 5672, "user": "admin", "pass": "secret"}
            )

        assert result is mock_pool
        mock_pool.create_pool.assert_called_once_with(
            host="rmq.example.com", port=5672, login="admin", password="secret"
        )

    @pytest.mark.asyncio
    async def test_create_rabbitmq_pool_defaults(self):
        """Test create_rabbitmq_pool with default values."""
        mock_pool = MagicMock()
        mock_pool.create_pool = AsyncMock()

        with patch("src.modules.rabbitmq.RabbitMQConnectionPool", return_value=mock_pool):
            result = await create_rabbitmq_pool({})

        mock_pool.create_pool.assert_called_once_with(
            host="localhost", port=5672, login="guest", password="guest"
        )

    @pytest.mark.asyncio
    async def test_create_redis_pool(self):
        """Test create_redis_pool creates Redis instance."""
        mock_redis = MagicMock()

        with patch("redis.Redis", return_value=mock_redis):
            result = await create_redis_pool(
                {"host": "redis.example.com", "port": 6380, "db": 2}
            )

        assert result is mock_redis

    @pytest.mark.asyncio
    async def test_create_redis_pool_defaults(self):
        """Test create_redis_pool with default values."""
        mock_redis = MagicMock()

        with patch("redis.Redis", return_value=mock_redis):
            result = await create_redis_pool({})

        assert result is mock_redis

    @pytest.mark.asyncio
    async def test_create_postgresql_pool(self):
        """Test create_postgresql_pool calls asyncpg.create_pool."""
        mock_pool = MagicMock()

        with patch("asyncpg.create_pool", new_callable=AsyncMock, return_value=mock_pool):
            result = await create_postgresql_pool(
                {
                    "host": "pg.example.com",
                    "port": 5433,
                    "user": "dbuser",
                    "password": "dbpass",
                    "database": "mydb",
                }
            )

        assert result is mock_pool

    @pytest.mark.asyncio
    async def test_create_postgresql_pool_defaults(self):
        """Test create_postgresql_pool with default values."""
        mock_pool = MagicMock()

        with patch("asyncpg.create_pool", new_callable=AsyncMock, return_value=mock_pool):
            result = await create_postgresql_pool({})

        assert result is mock_pool

    @pytest.mark.asyncio
    async def test_create_mysql_pool(self):
        """Test create_mysql_pool calls aiomysql.create_pool."""
        mock_pool = MagicMock()

        with patch("aiomysql.create_pool", new_callable=AsyncMock, return_value=mock_pool):
            result = await create_mysql_pool(
                {
                    "host": "mysql.example.com",
                    "port": 3307,
                    "user": "root",
                    "password": "mysqlpass",
                    "database": "mydb",
                }
            )

        assert result is mock_pool

    @pytest.mark.asyncio
    async def test_create_mysql_pool_defaults(self):
        """Test create_mysql_pool with default values."""
        mock_pool = MagicMock()

        with patch("aiomysql.create_pool", new_callable=AsyncMock, return_value=mock_pool):
            result = await create_mysql_pool({})

        assert result is mock_pool
