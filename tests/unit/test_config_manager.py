"""Tests for ConfigManager."""

import pytest
import json
import tempfile
import os
import asyncio
from unittest.mock import patch, AsyncMock
from src.config_manager import ConfigManager, ReloadResult


class TestConfigManager:
    """Test suite for ConfigManager."""

    @pytest.fixture
    def temp_webhook_config(self, tmp_path):
        """Create temporary webhook config file."""
        config = {"test_webhook": {"data_type": "json", "module": "log"}}
        config_file = tmp_path / "webhooks.json"
        with open(config_file, "w") as f:
            json.dump(config, f)
        yield str(config_file)

    @pytest.fixture
    def temp_connection_config(self, tmp_path):
        """Create temporary connection config file."""
        config = {
            "test_connection": {
                "type": "rabbitmq",
                "host": "rabbitmq.example.com",
                "port": 5672,
            }
        }
        config_file = tmp_path / "connections.json"
        with open(config_file, "w") as f:
            json.dump(config, f)
        yield str(config_file)

    @pytest.fixture
    def config_manager(self, temp_webhook_config, temp_connection_config):
        """Create ConfigManager instance with temp config files."""
        return ConfigManager(
            webhook_config_file=temp_webhook_config,
            connection_config_file=temp_connection_config,
        )

    @pytest.mark.asyncio
    async def test_initialize_loads_configs(self, config_manager):
        """Test that initialize loads both configs."""
        # Mock pool creation to avoid actual connection attempts
        with patch.object(
            config_manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_get_pool:
            mock_get_pool.return_value = AsyncMock()
            result = await config_manager.initialize()

            assert result.success is True
            assert config_manager.get_webhook_config("test_webhook") is not None
            assert config_manager.get_connection_config("test_connection") is not None

    @pytest.mark.asyncio
    async def test_reload_webhooks(self, config_manager, temp_webhook_config):
        """Test reloading webhook configuration."""
        await config_manager.initialize()

        # Modify config file
        new_config = {
            "test_webhook": {"data_type": "json", "module": "log"},
            "new_webhook": {"data_type": "json", "module": "log"},
        }
        with open(temp_webhook_config, "w") as f:
            json.dump(new_config, f)

        result = await config_manager.reload_webhooks()

        assert result.success is True
        assert result.details["webhooks_added"] == 1
        assert config_manager.get_webhook_config("new_webhook") is not None

    @pytest.mark.asyncio
    async def test_reload_connections(self, config_manager, temp_connection_config):
        """Test reloading connection configuration."""
        # Mock pool creation to avoid actual connection attempts
        with patch.object(
            config_manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_get_pool:
            mock_get_pool.return_value = AsyncMock()
            await config_manager.initialize()

            # Modify config file (use valid hostnames to pass SSRF validation)
            new_config = {
                "test_connection": {
                    "type": "rabbitmq",
                    "host": "rabbitmq.example.com",
                    "port": 5672,
                },
                "new_connection": {
                    "type": "redis-rq",
                    "host": "redis.example.com",
                    "port": 6379,
                },
            }
            with open(temp_connection_config, "w") as f:
                json.dump(new_config, f)

            result = await config_manager.reload_connections()

            assert result.success is True
            assert result.details["connections_added"] == 1
            assert config_manager.get_connection_config("new_connection") is not None

    @pytest.mark.asyncio
    async def test_get_webhook_config(self, config_manager):
        """Test getting webhook config."""
        await config_manager.initialize()

        config = config_manager.get_webhook_config("test_webhook")
        assert config is not None
        assert config["module"] == "log"

        # Test non-existent webhook
        assert config_manager.get_webhook_config("nonexistent") is None

    @pytest.mark.asyncio
    async def test_get_connection_config(self, config_manager):
        """Test getting connection config."""
        # Mock pool creation to avoid actual connection attempts
        with patch.object(
            config_manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_get_pool:
            mock_get_pool.return_value = AsyncMock()
            await config_manager.initialize()

            config = config_manager.get_connection_config("test_connection")
            assert config is not None
            assert config["type"] == "rabbitmq"

            # Test non-existent connection
            assert config_manager.get_connection_config("nonexistent") is None

    @pytest.mark.asyncio
    async def test_get_all_connection_configs(self, config_manager):
        """Test getting all connection configs."""
        # Mock pool creation to avoid actual connection attempts
        with patch.object(
            config_manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_get_pool:
            mock_get_pool.return_value = AsyncMock()
            await config_manager.initialize()

            all_configs = config_manager.get_all_connection_configs()
            # Should return a dict-like object (copy of the config)
            assert hasattr(all_configs, "__getitem__") and hasattr(all_configs, "keys")
            assert "test_connection" in all_configs
            assert all_configs["test_connection"]["type"] == "rabbitmq"

            # Subsequent calls return fresh copies (not cached snapshot)
            all_configs2 = config_manager.get_all_connection_configs()
            assert (
                all_configs is not all_configs2
            ), "get_all_connection_configs should return a fresh copy per call"

            # External mutations should not affect internal state
            mutable_copy = config_manager.get_all_connection_configs()
            mutable_copy["test_connection"]["type"] = "modified"
            current_config = config_manager.get_connection_config("test_connection")
            assert (
                current_config["type"] == "rabbitmq"
            ), "Internal state should remain unchanged"

    @pytest.mark.asyncio
    async def test_invalid_webhook_config_rejected(
        self, config_manager, temp_webhook_config
    ):
        """Test that invalid webhook config is rejected."""
        await config_manager.initialize()

        # Create invalid config (missing module)
        invalid_config = {
            "invalid_webhook": {
                "data_type": "json"
                # Missing module
            }
        }
        with open(temp_webhook_config, "w") as f:
            json.dump(invalid_config, f)

        result = await config_manager.reload_webhooks()

        assert result.success is False
        assert "Validation failed" in result.error or "error" in result.error.lower()
        # Old config should still be active
        assert config_manager.get_webhook_config("test_webhook") is not None

    @pytest.mark.asyncio
    async def test_reload_all(self, config_manager):
        """Test reloading both webhooks and connections."""
        # Mock pool creation to avoid actual connection attempts
        with patch.object(
            config_manager.pool_registry, "get_pool", new_callable=AsyncMock
        ) as mock_get_pool:
            mock_get_pool.return_value = AsyncMock()
            await config_manager.initialize()

            result = await config_manager.reload_all()

            assert result.success is True
            assert "webhooks" in result.details
            assert "connections" in result.details

    @pytest.mark.asyncio
    async def test_get_status(self, config_manager):
        """Test getting config manager status."""
        await config_manager.initialize()

        status = config_manager.get_status()

        assert "last_reload" in status
        assert "reload_in_progress" in status
        assert "webhooks_count" in status
        assert "connections_count" in status
        assert "connection_pools" in status

    @pytest.mark.asyncio
    async def test_concurrent_reloads(self, config_manager):
        """Test that concurrent reloads are handled correctly."""
        await config_manager.initialize()

        # Start two reloads concurrently
        task1 = config_manager.reload_webhooks()
        task2 = config_manager.reload_webhooks()

        results = await asyncio.gather(task1, task2)

        # At least one should succeed, and if both succeed that's also acceptable
        # (race condition: both might start before lock is acquired)
        success_count = sum(1 for r in results if r.success)
        queued_count = sum(
            1
            for r in results
            if not r.success and r.error and "progress" in r.error.lower()
        )

        # Either one succeeds and one is queued, or both succeed (race condition)
        assert success_count >= 1, "At least one reload should succeed"
        assert success_count + queued_count == 2, "Both reloads should complete"
