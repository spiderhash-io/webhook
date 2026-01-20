"""
Integration tests for config_manager.py.
Tests cover missing coverage areas including reload error paths, connection pool updates, and edge cases.
"""

import pytest
import asyncio
import json
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from tempfile import NamedTemporaryFile

from src.config_manager import ConfigManager, ReloadResult
from src.connection_pool_registry import ConnectionPoolRegistry


class TestConfigManagerReloadWebhooks:
    """Test reload_webhooks method error paths."""

    @pytest.mark.asyncio
    async def test_reload_webhooks_file_not_found(self):
        """Test reload_webhooks when file doesn't exist."""
        manager = ConfigManager(webhook_config_file="nonexistent_file.json")

        result = await manager.reload_webhooks()

        # When file doesn't exist, _load_webhook_config returns default logging webhook
        # So reload succeeds with 1 webhook (the default)
        assert result.success is True
        assert result.details["total_webhooks"] == 1
        assert manager.get_webhook_config("default") is not None
        assert manager._reload_in_progress is False

    @pytest.mark.asyncio
    async def test_reload_webhooks_invalid_json(self):
        """Test reload_webhooks with invalid JSON."""
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json content {")
            temp_file = f.name

        try:
            manager = ConfigManager(webhook_config_file=temp_file)
            result = await manager.reload_webhooks()

            assert result.success is False
            assert (
                "invalid json" in result.error.lower() or "json" in result.error.lower()
            )
            assert manager._reload_in_progress is False
        finally:
            os.unlink(temp_file)

    @pytest.mark.asyncio
    async def test_reload_webhooks_generic_error(self):
        """Test reload_webhooks with generic exception."""
        manager = ConfigManager(webhook_config_file="test.json")

        with patch.object(
            manager, "_load_webhook_config", side_effect=Exception("Permission denied")
        ):
            result = await manager.reload_webhooks()

            assert result.success is False
            assert manager._reload_in_progress is False


class TestConfigManagerReloadConnections:
    """Test reload_connections method error paths."""

    @pytest.mark.asyncio
    async def test_reload_connections_file_not_found(self):
        """Test reload_connections when file doesn't exist."""
        manager = ConfigManager(connection_config_file="nonexistent_file.json")

        result = await manager.reload_connections()

        # _load_connection_config raises FileNotFoundError when file doesn't exist
        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_reload_connections_invalid_json(self):
        """Test reload_connections with invalid JSON."""
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json {")
            temp_file = f.name

        try:
            manager = ConfigManager(connection_config_file=temp_file)
            result = await manager.reload_connections()

            assert result.success is False
            assert (
                "invalid json" in result.error.lower() or "json" in result.error.lower()
            )
        finally:
            os.unlink(temp_file)


class TestConfigManagerUpdateConnectionPool:
    """Test _update_connection_pool method."""

    @pytest.mark.asyncio
    async def test_update_connection_pool_rabbitmq(self):
        """Test updating connection pool for RabbitMQ."""
        manager = ConfigManager()
        # Don't initialize to avoid file loading

        connection_config = {"type": "rabbitmq", "host": "localhost", "port": 5672}

        with patch.object(
            manager.pool_registry, "get_pool", AsyncMock()
        ) as mock_get_pool:
            await manager._update_connection_pool("test_rabbitmq", connection_config)

            # Should try to get pool for rabbitmq connection
            assert mock_get_pool.called

    @pytest.mark.asyncio
    async def test_update_connection_pool_redis_rq(self):
        """Test updating connection pool for Redis RQ."""
        manager = ConfigManager()
        # Don't initialize to avoid file loading

        connection_config = {"type": "redis-rq", "host": "localhost", "port": 6379}

        with patch.object(
            manager.pool_registry, "get_pool", AsyncMock()
        ) as mock_get_pool:
            await manager._update_connection_pool("test_redis", connection_config)

            assert mock_get_pool.called

    @pytest.mark.asyncio
    async def test_update_connection_pool_postgresql(self):
        """Test updating connection pool for PostgreSQL."""
        manager = ConfigManager()
        # Don't initialize to avoid file loading

        connection_config = {"type": "postgresql", "host": "localhost", "port": 5432}

        with patch.object(
            manager.pool_registry, "get_pool", AsyncMock()
        ) as mock_get_pool:
            await manager._update_connection_pool("test_postgres", connection_config)

            assert mock_get_pool.called

    @pytest.mark.asyncio
    async def test_update_connection_pool_mysql(self):
        """Test updating connection pool for MySQL."""
        manager = ConfigManager()
        # Don't initialize to avoid file loading

        connection_config = {"type": "mysql", "host": "localhost", "port": 3306}

        with patch.object(
            manager.pool_registry, "get_pool", AsyncMock()
        ) as mock_get_pool:
            await manager._update_connection_pool("test_mysql", connection_config)

            assert mock_get_pool.called

    @pytest.mark.asyncio
    async def test_update_connection_pool_with_error(self):
        """Test updating connection pool with error handling."""
        manager = ConfigManager()
        # Don't initialize to avoid file loading

        connection_config = {"type": "rabbitmq", "host": "localhost", "port": 5672}

        with patch.object(
            manager.pool_registry,
            "get_pool",
            AsyncMock(side_effect=Exception("Connection failed")),
        ):
            # Should handle error gracefully
            await manager._update_connection_pool("test_rabbitmq", connection_config)

            # Should not raise exception


class TestConfigManagerWebhookConfig:
    """Test webhook config management."""

    @pytest.mark.asyncio
    async def test_reload_webhooks_updates_config(self):
        """Test that reload_webhooks updates the webhook config."""
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "webhook1": {
                        "data_type": "json",
                        "module": "log",  # Module name as string
                    }
                },
                f,
            )
            temp_file = f.name

        try:
            manager = ConfigManager(webhook_config_file=temp_file)
            result = await manager.reload_webhooks()

            assert result.success is True
            assert manager.get_webhook_config("webhook1") is not None
            assert manager.get_webhook_config("webhook1")["module"] == "log"
            assert manager.get_webhook_config("webhook1")["data_type"] == "json"
        finally:
            os.unlink(temp_file)


class TestConfigManagerGetConnectionConfig:
    """Test get_connection_config edge cases."""

    def test_get_connection_config_nonexistent(self):
        """Test getting non-existent connection config."""
        manager = ConfigManager()
        # Don't initialize to avoid file loading

        result = manager.get_connection_config("nonexistent")

        assert result is None

    def test_get_connection_config_after_reload(self):
        """Test getting connection config after reload."""
        manager = ConfigManager()
        # Don't initialize to avoid file loading

        # Set connection config directly
        manager._connection_config = {
            "test_conn": {"type": "redis", "host": "localhost"}
        }

        result = manager.get_connection_config("test_conn")

        assert result == {"type": "redis", "host": "localhost"}
