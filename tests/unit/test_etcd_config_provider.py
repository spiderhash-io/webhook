"""
Tests for EtcdConfigProvider.

All etcd interactions are mocked — no real etcd server needed.
"""

import json
import asyncio
import threading
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from src.etcd_config_provider import (
    EtcdConfigProvider,
    _validate_namespace,
    NAMESPACE_PATTERN,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_metadata(key: str):
    """Create a mock metadata object with a key attribute."""
    m = MagicMock()
    m.key = key.encode("utf-8")
    return m


def _make_put_event(key: str, value: dict):
    """Create a mock PutEvent."""
    evt = MagicMock()
    evt.key = key.encode("utf-8")
    evt.value = json.dumps(value).encode("utf-8")
    # Make isinstance checks work with a __class__ name
    evt.__class__.__name__ = "PutEvent"
    return evt


def _make_delete_event(key: str):
    """Create a mock DeleteEvent."""
    evt = MagicMock()
    evt.key = key.encode("utf-8")
    evt.__class__.__name__ = "DeleteEvent"
    return evt


# ---------------------------------------------------------------------------
# Namespace validation
# ---------------------------------------------------------------------------

class TestNamespaceValidation:
    """Tests for namespace string validation."""

    def test_valid_namespace(self):
        """Standard alphanumeric namespace should pass."""
        assert _validate_namespace("default") is True
        assert _validate_namespace("ns-1") is True
        assert _validate_namespace("my_namespace") is True
        assert _validate_namespace("A") is True

    def test_invalid_namespace_empty(self):
        """Empty string should fail."""
        assert _validate_namespace("") is False

    def test_invalid_namespace_spaces(self):
        """Spaces should fail."""
        assert _validate_namespace("my namespace") is False

    def test_invalid_namespace_too_long(self):
        """Over 64 chars should fail."""
        assert _validate_namespace("a" * 65) is False

    def test_invalid_namespace_special_chars(self):
        """Special characters should fail."""
        assert _validate_namespace("ns/sub") is False
        assert _validate_namespace("ns..sub") is False
        assert _validate_namespace("ns@sub") is False


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------

class TestEtcdConfigProviderInit:
    """Tests for constructor validation."""

    def test_default_values(self):
        """Constructor should set sensible defaults."""
        provider = EtcdConfigProvider()
        assert provider._host == "localhost"
        assert provider._port == 2379
        assert provider._prefix == "/cwm/"
        assert provider._default_namespace == "default"

    def test_custom_values(self):
        """Constructor should accept custom values."""
        provider = EtcdConfigProvider(
            host="etcd.example.com",
            port=2380,
            prefix="/myapp",
            namespace="production",
        )
        assert provider._host == "etcd.example.com"
        assert provider._port == 2380
        assert provider._prefix == "/myapp/"
        assert provider._default_namespace == "production"

    def test_invalid_host(self):
        """Empty host should raise ValueError."""
        with pytest.raises(ValueError, match="host must be a non-empty string"):
            EtcdConfigProvider(host="")

    def test_invalid_port(self):
        """Invalid port should raise ValueError."""
        with pytest.raises(ValueError, match="port must be an integer"):
            EtcdConfigProvider(port=0)

    def test_invalid_port_too_high(self):
        """Port > 65535 should raise ValueError."""
        with pytest.raises(ValueError, match="port must be an integer"):
            EtcdConfigProvider(port=70000)

    def test_invalid_namespace(self):
        """Invalid namespace format should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid namespace"):
            EtcdConfigProvider(namespace="bad namespace!")


# ---------------------------------------------------------------------------
# Cache operations (unit-test the cache logic directly)
# ---------------------------------------------------------------------------

class TestCacheOperations:
    """Tests for the in-memory cache operations."""

    def test_process_put_webhook(self):
        """PUT event for a webhook should update the cache."""
        provider = EtcdConfigProvider()
        config = {"module": "log", "data_type": "json"}
        value = json.dumps(config).encode("utf-8")

        provider._process_put_event("/cwm/ns1/webhooks/hook1", value)

        assert "ns1" in provider._cache
        assert provider._cache["ns1"]["hook1"] == config

    def test_process_put_connection(self):
        """PUT event for a connection should update connections cache."""
        provider = EtcdConfigProvider()
        config = {"type": "redis-rq", "host": "redis.local", "port": 6379}
        value = json.dumps(config).encode("utf-8")

        provider._process_put_event("/cwm/global/connections/redis_main", value)

        assert provider._connections_cache["redis_main"] == config

    def test_process_put_applies_env_var_substitution(self, monkeypatch):
        """PUT events should apply env var substitution for etcd compatibility."""
        provider = EtcdConfigProvider()
        monkeypatch.setenv("ETCD_TEST_TOKEN", "token_from_env")

        config = {
            "data_type": "json",
            "module": "log",
            "authorization": "Bearer {$ETCD_TEST_TOKEN}",
        }
        value = json.dumps(config).encode("utf-8")

        provider._process_put_event("/cwm/ns1/webhooks/hook1", value)

        assert provider._cache["ns1"]["hook1"]["authorization"] == "Bearer token_from_env"

    def test_process_put_invalid_json(self):
        """Invalid JSON should be skipped gracefully."""
        provider = EtcdConfigProvider()
        provider._process_put_event("/cwm/ns1/webhooks/hook1", b"not-json")

        assert "ns1" not in provider._cache

    def test_process_put_non_dict_value(self):
        """Non-dict JSON value should be skipped."""
        provider = EtcdConfigProvider()
        provider._process_put_event("/cwm/ns1/webhooks/hook1", b'"a string"')

        assert "ns1" not in provider._cache

    def test_process_put_invalid_namespace(self):
        """Invalid namespace in key should be skipped."""
        provider = EtcdConfigProvider()
        config = json.dumps({"module": "log"}).encode("utf-8")

        provider._process_put_event("/cwm/bad namespace!/webhooks/hook1", config)

        assert "bad namespace!" not in provider._cache

    def test_process_put_unrecognized_key(self):
        """Unrecognized key path should be ignored."""
        provider = EtcdConfigProvider()
        config = json.dumps({"foo": "bar"}).encode("utf-8")

        provider._process_put_event("/cwm/something/else", config)

        assert len(provider._cache) == 0
        assert len(provider._connections_cache) == 0

    def test_process_delete_webhook(self):
        """DELETE event for a webhook should remove it from cache."""
        provider = EtcdConfigProvider()
        provider._cache["ns1"] = {"hook1": {"module": "log"}, "hook2": {"module": "s3"}}

        provider._process_delete_event("/cwm/ns1/webhooks/hook1")

        assert "hook1" not in provider._cache["ns1"]
        assert "hook2" in provider._cache["ns1"]

    def test_process_delete_last_webhook_cleans_namespace(self):
        """Deleting last webhook in a namespace should remove the namespace."""
        provider = EtcdConfigProvider()
        provider._cache["ns1"] = {"hook1": {"module": "log"}}

        provider._process_delete_event("/cwm/ns1/webhooks/hook1")

        assert "ns1" not in provider._cache

    def test_process_delete_connection(self):
        """DELETE event for a connection should remove it."""
        provider = EtcdConfigProvider()
        provider._connections_cache["redis_main"] = {"type": "redis-rq"}

        provider._process_delete_event("/cwm/global/connections/redis_main")

        assert "redis_main" not in provider._connections_cache

    def test_process_delete_nonexistent_key(self):
        """DELETE for nonexistent key should not raise."""
        provider = EtcdConfigProvider()
        # Should not raise
        provider._process_delete_event("/cwm/ns1/webhooks/nonexistent")
        provider._process_delete_event("/cwm/global/connections/nonexistent")


# ---------------------------------------------------------------------------
# Read methods
# ---------------------------------------------------------------------------

class TestReadMethods:
    """Tests for read operations on the cache."""

    def _make_provider(self):
        """Create a provider with pre-populated cache."""
        provider = EtcdConfigProvider(namespace="default")
        provider._cache = {
            "default": {
                "hook1": {"module": "log"},
                "hook2": {"module": "s3"},
            },
            "staging": {
                "hook1": {"module": "kafka"},
            },
        }
        provider._connections_cache = {
            "redis_main": {"type": "redis-rq", "host": "redis.local"},
        }
        return provider

    def test_get_webhook_config_default_namespace(self):
        """Should look up in default namespace when none specified."""
        provider = self._make_provider()
        config = provider.get_webhook_config("hook1")
        assert config == {"module": "log"}

    def test_get_webhook_config_explicit_namespace(self):
        """Should look up in specified namespace."""
        provider = self._make_provider()
        config = provider.get_webhook_config("hook1", namespace="staging")
        assert config == {"module": "kafka"}

    def test_get_webhook_config_not_found(self):
        """Should return None for missing webhook."""
        provider = self._make_provider()
        assert provider.get_webhook_config("nonexistent") is None

    def test_get_webhook_config_wrong_namespace(self):
        """Should return None when webhook not in specified namespace."""
        provider = self._make_provider()
        assert provider.get_webhook_config("hook2", namespace="staging") is None

    def test_get_all_webhook_configs_default(self):
        """Should return all webhooks in default namespace."""
        provider = self._make_provider()
        configs = provider.get_all_webhook_configs()
        assert len(configs) == 2
        assert "hook1" in configs
        assert "hook2" in configs

    def test_get_all_webhook_configs_explicit(self):
        """Should return all webhooks in specified namespace."""
        provider = self._make_provider()
        configs = provider.get_all_webhook_configs(namespace="staging")
        assert len(configs) == 1
        assert "hook1" in configs

    def test_get_all_webhook_configs_empty_namespace(self):
        """Should return empty dict for nonexistent namespace."""
        provider = self._make_provider()
        configs = provider.get_all_webhook_configs(namespace="nonexistent")
        assert configs == {}

    def test_get_connection_config(self):
        """Should return connection config."""
        provider = self._make_provider()
        config = provider.get_connection_config("redis_main")
        assert config["type"] == "redis-rq"

    def test_get_connection_config_not_found(self):
        """Should return None for missing connection."""
        provider = self._make_provider()
        assert provider.get_connection_config("nonexistent") is None

    def test_get_all_connection_configs(self):
        """Should return all connection configs."""
        provider = self._make_provider()
        configs = provider.get_all_connection_configs()
        assert len(configs) == 1
        assert "redis_main" in configs

    def test_get_all_returns_copy(self):
        """Modifying returned dict should not affect cache."""
        provider = self._make_provider()
        configs = provider.get_all_webhook_configs()
        configs["injected"] = {"module": "evil"}
        assert "injected" not in provider._cache["default"]


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

class TestStatus:
    """Tests for get_status()."""

    def test_status_fields(self):
        """Status should include all expected fields."""
        provider = EtcdConfigProvider(
            host="etcd.example.com", port=2380, namespace="prod"
        )
        provider._cache = {"prod": {"h1": {}}, "staging": {"h2": {}}}
        provider._connections_cache = {"c1": {}}
        provider._initialized = True
        provider._connected = True

        status = provider.get_status()

        assert status["backend"] == "etcd"
        assert status["initialized"] is True
        assert status["connected"] is True
        assert status["host"] == "etcd.example.com"
        assert status["port"] == 2380
        assert status["default_namespace"] == "prod"
        assert status["namespaces_count"] == 2
        assert set(status["namespaces"]) == {"prod", "staging"}
        assert status["total_webhooks"] == 2
        assert status["connections_count"] == 1


# ---------------------------------------------------------------------------
# get_namespaces
# ---------------------------------------------------------------------------

class TestGetNamespaces:
    """Tests for get_namespaces()."""

    def test_returns_namespace_list(self):
        """Should return list of all namespaces."""
        provider = EtcdConfigProvider()
        provider._cache = {"ns1": {}, "ns2": {}, "ns3": {}}
        assert sorted(provider.get_namespaces()) == ["ns1", "ns2", "ns3"]

    def test_empty_when_no_data(self):
        """Should return empty list when no data loaded."""
        provider = EtcdConfigProvider()
        assert provider.get_namespaces() == []


# ---------------------------------------------------------------------------
# Initialize (mocked etcd3)
# ---------------------------------------------------------------------------

class TestInitialize:
    """Tests for initialize() with mocked etcd3."""

    @pytest.mark.asyncio
    async def test_initialize_loads_data(self):
        """Initialize should load all keys from etcd prefix."""
        provider = EtcdConfigProvider()

        mock_client = MagicMock()
        # Simulate get_prefix returning two webhook keys + one connection
        hook_config = json.dumps({"module": "log"}).encode("utf-8")
        conn_config = json.dumps({"type": "redis-rq"}).encode("utf-8")

        mock_client.get_prefix.return_value = [
            (hook_config, _make_metadata("/cwm/default/webhooks/hook1")),
            (hook_config, _make_metadata("/cwm/staging/webhooks/hook2")),
            (conn_config, _make_metadata("/cwm/global/connections/redis1")),
        ]
        mock_client.watch_prefix.return_value = (iter([]), MagicMock())

        with patch("src.etcd_config_provider.EtcdConfigProvider._create_client", return_value=mock_client):
            # Don't start real watch thread
            with patch.object(provider, "_start_watch"):
                await provider.initialize()

        assert provider._initialized is True
        assert provider.get_webhook_config("hook1", namespace="default") == {"module": "log"}
        assert provider.get_webhook_config("hook2", namespace="staging") == {"module": "log"}
        assert provider.get_connection_config("redis1") == {"type": "redis-rq"}

    @pytest.mark.asyncio
    async def test_initialize_handles_empty_etcd(self):
        """Initialize with empty etcd should succeed with empty caches."""
        provider = EtcdConfigProvider()

        mock_client = MagicMock()
        mock_client.get_prefix.return_value = []
        mock_client.watch_prefix.return_value = (iter([]), MagicMock())

        with patch("src.etcd_config_provider.EtcdConfigProvider._create_client", return_value=mock_client):
            with patch.object(provider, "_start_watch"):
                await provider.initialize()

        assert provider._initialized is True
        assert provider._cache == {}
        assert provider._connections_cache == {}


# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------

class TestShutdown:
    """Tests for shutdown()."""

    @pytest.mark.asyncio
    async def test_shutdown_clears_state(self):
        """Shutdown should clear initialized flag and close client."""
        provider = EtcdConfigProvider()
        provider._initialized = True
        provider._connected = True
        mock_client = MagicMock()
        provider._client = mock_client

        await provider.shutdown()

        assert provider._initialized is False
        assert provider._connected is False
        mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_cancels_watch(self):
        """Shutdown should call the watch cancel function."""
        provider = EtcdConfigProvider()
        mock_cancel = MagicMock()
        provider._watch_id = mock_cancel
        provider._client = MagicMock()

        await provider.shutdown()

        mock_cancel.assert_called_once()


# ---------------------------------------------------------------------------
# on_config_change
# ---------------------------------------------------------------------------

class TestConfigChangeCallbacks:
    """Tests for change callback registration."""

    def test_register_callback(self):
        """Should store callback in list."""
        provider = EtcdConfigProvider()
        callback = MagicMock()
        provider.on_config_change(callback)
        assert callback in provider._change_callbacks

    def test_multiple_callbacks(self):
        """Should support multiple callbacks."""
        provider = EtcdConfigProvider()
        cb1 = MagicMock()
        cb2 = MagicMock()
        provider.on_config_change(cb1)
        provider.on_config_change(cb2)
        assert len(provider._change_callbacks) == 2


# ---------------------------------------------------------------------------
# Full reload
# ---------------------------------------------------------------------------

class TestFullReload:
    """Tests for _full_reload()."""

    def test_full_reload_clears_and_repopulates(self):
        """Full reload should clear existing cache and repopulate."""
        provider = EtcdConfigProvider()
        provider._cache = {"old_ns": {"old_hook": {}}}
        provider._connections_cache = {"old_conn": {}}

        mock_client = MagicMock()
        new_config = json.dumps({"module": "kafka"}).encode("utf-8")
        mock_client.get_prefix.return_value = [
            (new_config, _make_metadata("/cwm/new_ns/webhooks/new_hook")),
        ]
        provider._client = mock_client

        provider._full_reload()

        assert "old_ns" not in provider._cache
        assert "old_conn" not in provider._connections_cache
        assert provider.get_webhook_config("new_hook", namespace="new_ns") == {"module": "kafka"}

    def test_full_reload_without_client(self):
        """Full reload without client should be a no-op."""
        provider = EtcdConfigProvider()
        provider._client = None
        provider._full_reload()  # Should not raise
        assert provider._cache == {}


# ---------------------------------------------------------------------------
# ConfigManager factory integration
# ---------------------------------------------------------------------------

class TestConfigManagerFactory:
    """Test that ConfigManager.create() works with etcd backend."""

    @pytest.mark.asyncio
    async def test_create_file_backend(self, tmp_path):
        """Factory with backend='file' should create FileConfigProvider."""
        from src.config_manager import ConfigManager

        webhooks_file = tmp_path / "webhooks.json"
        webhooks_file.write_text(json.dumps({"h1": {"module": "log"}}))
        connections_file = tmp_path / "connections.json"
        connections_file.write_text(json.dumps({}))

        manager = await ConfigManager.create(
            backend="file",
            webhook_config_file=str(webhooks_file),
            connection_config_file=str(connections_file),
        )

        assert manager.provider is not None
        from src.file_config_provider import FileConfigProvider
        assert isinstance(manager.provider, FileConfigProvider)

    @pytest.mark.asyncio
    async def test_create_etcd_backend(self):
        """Factory with backend='etcd' should create EtcdConfigProvider."""
        from src.config_manager import ConfigManager

        mock_client = MagicMock()
        mock_client.get_prefix.return_value = []
        mock_client.watch_prefix.return_value = (iter([]), MagicMock())

        with patch("src.etcd_config_provider.EtcdConfigProvider._create_client", return_value=mock_client):
            with patch("src.etcd_config_provider.EtcdConfigProvider._start_watch"):
                manager = await ConfigManager.create(
                    backend="etcd",
                    host="etcd.example.com",
                    port=2379,
                )

        assert manager.provider is not None
        assert isinstance(manager.provider, EtcdConfigProvider)

    @pytest.mark.asyncio
    async def test_create_unknown_backend(self):
        """Factory with unknown backend should raise ValueError."""
        from src.config_manager import ConfigManager

        with pytest.raises(ValueError, match="Unknown config backend"):
            await ConfigManager.create(backend="consul")
