"""
Tests for FileConfigProvider.

Verifies that the file-based configuration provider correctly loads,
reloads, and serves webhook/connection configs from JSON files.
"""

import json
import os
import pytest

from src.file_config_provider import FileConfigProvider


@pytest.fixture
def tmp_config_dir(tmp_path):
    """Create temporary config files for testing."""
    webhooks_file = tmp_path / "webhooks.json"
    connections_file = tmp_path / "connections.json"

    webhooks_data = {
        "hook1": {
            "data_type": "json",
            "module": "log",
            "module-config": {"pretty_print": True},
        },
        "hook2": {
            "data_type": "json",
            "module": "save_to_disk",
            "module-config": {"path": "/tmp/webhooks"},
        },
    }
    connections_data = {
        "redis_main": {
            "type": "redis-rq",
            "host": "redis.example.com",
            "port": 6379,
        },
    }

    webhooks_file.write_text(json.dumps(webhooks_data))
    connections_file.write_text(json.dumps(connections_data))

    return tmp_path, str(webhooks_file), str(connections_file)


class TestFileConfigProviderInit:
    """Tests for FileConfigProvider initialization."""

    def test_default_file_paths(self):
        """Provider should use default file paths if none specified."""
        provider = FileConfigProvider()
        assert provider.webhook_config_file == "webhooks.json"
        assert provider.connection_config_file == "connections.json"

    def test_custom_file_paths(self):
        """Provider should accept custom file paths."""
        provider = FileConfigProvider(
            webhook_config_file="/custom/webhooks.json",
            connection_config_file="/custom/connections.json",
        )
        assert provider.webhook_config_file == "/custom/webhooks.json"
        assert provider.connection_config_file == "/custom/connections.json"

    def test_type_validation_webhook_file(self):
        """Provider should reject non-string webhook config file path."""
        with pytest.raises(TypeError, match="webhook_config_file must be a string"):
            FileConfigProvider(webhook_config_file=123)

    def test_type_validation_connection_file(self):
        """Provider should reject non-string connection config file path."""
        with pytest.raises(TypeError, match="connection_config_file must be a string"):
            FileConfigProvider(connection_config_file=None)


class TestFileConfigProviderInitialize:
    """Tests for FileConfigProvider.initialize()."""

    @pytest.mark.asyncio
    async def test_initialize_loads_configs(self, tmp_config_dir):
        """Initialize should load both webhook and connection configs."""
        _, webhooks_file, connections_file = tmp_config_dir

        provider = FileConfigProvider(
            webhook_config_file=webhooks_file,
            connection_config_file=connections_file,
        )
        await provider.initialize()

        assert provider._initialized is True
        assert len(provider._webhook_config) == 2
        assert len(provider._connection_config) == 1

    @pytest.mark.asyncio
    async def test_initialize_missing_webhooks_uses_default(self, tmp_path):
        """Missing webhooks.json should produce default logging webhook."""
        connections_file = tmp_path / "connections.json"
        connections_file.write_text(json.dumps({}))

        provider = FileConfigProvider(
            webhook_config_file=str(tmp_path / "nonexistent.json"),
            connection_config_file=str(connections_file),
        )
        await provider.initialize()

        assert "default" in provider._webhook_config
        assert provider._webhook_config["default"]["module"] == "log"

    @pytest.mark.asyncio
    async def test_initialize_missing_connections_returns_empty(self, tmp_path):
        """Missing connections.json should produce empty dict."""
        webhooks_file = tmp_path / "webhooks.json"
        webhooks_file.write_text(json.dumps({"h1": {"module": "log"}}))

        provider = FileConfigProvider(
            webhook_config_file=str(webhooks_file),
            connection_config_file=str(tmp_path / "nonexistent.json"),
        )
        await provider.initialize()

        assert provider._connection_config == {}


class TestFileConfigProviderReads:
    """Tests for read operations."""

    @pytest.mark.asyncio
    async def test_get_webhook_config_found(self, tmp_config_dir):
        """Should return config for existing webhook ID."""
        _, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        config = provider.get_webhook_config("hook1")
        assert config is not None
        assert config["module"] == "log"

    @pytest.mark.asyncio
    async def test_get_webhook_config_not_found(self, tmp_config_dir):
        """Should return None for missing webhook ID."""
        _, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        assert provider.get_webhook_config("nonexistent") is None

    @pytest.mark.asyncio
    async def test_get_webhook_config_namespace_ignored(self, tmp_config_dir):
        """Namespace parameter should be ignored by file provider."""
        _, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        config = provider.get_webhook_config("hook1", namespace="anything")
        assert config is not None
        assert config["module"] == "log"

    @pytest.mark.asyncio
    async def test_get_all_webhook_configs(self, tmp_config_dir):
        """Should return all webhook configs."""
        _, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        configs = provider.get_all_webhook_configs()
        assert len(configs) == 2
        assert "hook1" in configs
        assert "hook2" in configs

    @pytest.mark.asyncio
    async def test_get_all_webhook_configs_namespace_ignored(self, tmp_config_dir):
        """Namespace parameter should be ignored for get_all_webhook_configs."""
        _, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        configs = provider.get_all_webhook_configs(namespace="ns1")
        assert len(configs) == 2

    @pytest.mark.asyncio
    async def test_get_connection_config_found(self, tmp_config_dir):
        """Should return config for existing connection."""
        _, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        config = provider.get_connection_config("redis_main")
        assert config is not None
        assert config["type"] == "redis-rq"

    @pytest.mark.asyncio
    async def test_get_connection_config_not_found(self, tmp_config_dir):
        """Should return None for missing connection."""
        _, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        assert provider.get_connection_config("nonexistent") is None

    @pytest.mark.asyncio
    async def test_get_all_connection_configs(self, tmp_config_dir):
        """Should return all connection configs."""
        _, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        configs = provider.get_all_connection_configs()
        assert len(configs) == 1
        assert "redis_main" in configs


class TestFileConfigProviderReload:
    """Tests for reload operations."""

    @pytest.mark.asyncio
    async def test_reload_webhooks(self, tmp_config_dir):
        """Reload should pick up file changes."""
        tmp_path, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        assert len(provider._webhook_config) == 2

        # Modify the file
        new_data = {"hook3": {"module": "log"}}
        with open(webhooks_file, "w") as f:
            json.dump(new_data, f)

        result = provider.reload_webhooks()
        assert len(result) == 1
        assert "hook3" in result
        assert provider.get_webhook_config("hook3") is not None
        assert provider.get_webhook_config("hook1") is None

    @pytest.mark.asyncio
    async def test_reload_connections(self, tmp_config_dir):
        """Reload should pick up connection file changes."""
        tmp_path, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        # Modify the file
        new_data = {
            "pg_main": {"type": "postgresql", "host": "pg.example.com", "port": 5432},
        }
        with open(connections_file, "w") as f:
            json.dump(new_data, f)

        result = provider.reload_connections()
        assert len(result) == 1
        assert "pg_main" in result


class TestFileConfigProviderStatus:
    """Tests for status reporting."""

    @pytest.mark.asyncio
    async def test_status_before_init(self):
        """Status should report not initialized."""
        provider = FileConfigProvider()
        status = provider.get_status()
        assert status["backend"] == "file"
        assert status["initialized"] is False

    @pytest.mark.asyncio
    async def test_status_after_init(self, tmp_config_dir):
        """Status should report correct counts after init."""
        _, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        status = provider.get_status()
        assert status["backend"] == "file"
        assert status["initialized"] is True
        assert status["webhooks_count"] == 2
        assert status["connections_count"] == 1


class TestFileConfigProviderShutdown:
    """Tests for shutdown."""

    @pytest.mark.asyncio
    async def test_shutdown_clears_initialized(self, tmp_config_dir):
        """Shutdown should mark provider as not initialized."""
        _, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()
        assert provider._initialized is True

        await provider.shutdown()
        assert provider._initialized is False


class TestFileConfigProviderReturnsCopy:
    """Tests that returned dicts don't mutate internal state."""

    @pytest.mark.asyncio
    async def test_get_all_webhook_configs_returns_copy(self, tmp_config_dir):
        """Modifying returned dict should not affect internal state."""
        _, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        configs = provider.get_all_webhook_configs()
        configs["injected"] = {"module": "malicious"}

        # Internal state should be unchanged
        assert "injected" not in provider._webhook_config

    @pytest.mark.asyncio
    async def test_get_all_connection_configs_returns_copy(self, tmp_config_dir):
        """Modifying returned dict should not affect internal state."""
        _, webhooks_file, connections_file = tmp_config_dir
        provider = FileConfigProvider(webhooks_file, connections_file)
        await provider.initialize()

        configs = provider.get_all_connection_configs()
        configs["injected"] = {"type": "malicious"}

        # Internal state should be unchanged
        assert "injected" not in provider._connection_config
