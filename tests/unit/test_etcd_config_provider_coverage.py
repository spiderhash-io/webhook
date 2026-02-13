"""
Coverage tests for src/etcd_config_provider.py.

Targets the ~72 missed lines covering:
- EtcdConfigProvider init validation
- _apply_put: various key formats, invalid JSON, non-dict values
- _process_put_event, _process_delete_event
- _notify_change
- shutdown
- get_webhook_config, get_all_webhook_configs, get_connection_config
- get_status, get_namespaces
- on_config_change
- _validate_namespace
"""

import pytest
import json
import threading
from unittest.mock import Mock, MagicMock, patch, AsyncMock

from src.etcd_config_provider import (
    EtcdConfigProvider,
    _validate_namespace,
    NAMESPACE_PATTERN,
)


class TestValidateNamespace:
    """Test _validate_namespace function."""

    def test_valid_namespaces(self):
        """Test valid namespace strings."""
        assert _validate_namespace("default") is True
        assert _validate_namespace("staging") is True
        assert _validate_namespace("my-namespace") is True
        assert _validate_namespace("my_namespace") is True
        assert _validate_namespace("a" * 64) is True
        assert _validate_namespace("A123") is True

    def test_invalid_namespaces(self):
        """Test invalid namespace strings."""
        assert _validate_namespace("") is False
        assert _validate_namespace("a" * 65) is False
        assert _validate_namespace("has spaces") is False
        assert _validate_namespace("has/slash") is False
        assert _validate_namespace("has.dot") is False
        assert _validate_namespace("has@at") is False


class TestEtcdConfigProviderInit:
    """Test EtcdConfigProvider initialization validation."""

    def test_init_valid(self):
        """Test valid initialization."""
        provider = EtcdConfigProvider(
            host="etcd.example.com", port=2379, prefix="/cwm/", namespace="default"
        )
        assert provider._host == "etcd.example.com"
        assert provider._port == 2379
        assert provider._prefix == "/cwm/"
        assert provider._default_namespace == "default"

    def test_init_empty_host(self):
        """Test init rejects empty host."""
        with pytest.raises(ValueError, match="non-empty string"):
            EtcdConfigProvider(host="")

    def test_init_non_string_host(self):
        """Test init rejects non-string host."""
        with pytest.raises(ValueError, match="non-empty string"):
            EtcdConfigProvider(host=123)

    def test_init_invalid_port(self):
        """Test init rejects invalid port."""
        with pytest.raises(ValueError, match="integer between 1 and 65535"):
            EtcdConfigProvider(port=0)

        with pytest.raises(ValueError, match="integer between 1 and 65535"):
            EtcdConfigProvider(port=70000)

        with pytest.raises(ValueError, match="integer between 1 and 65535"):
            EtcdConfigProvider(port="not-a-port")

    def test_init_empty_prefix(self):
        """Test init rejects empty prefix."""
        with pytest.raises(ValueError, match="non-empty string"):
            EtcdConfigProvider(prefix="")

    def test_init_invalid_namespace(self):
        """Test init rejects invalid namespace format."""
        with pytest.raises(ValueError, match="Invalid namespace"):
            EtcdConfigProvider(namespace="invalid/namespace")

    def test_init_none_namespace_uses_default(self):
        """Test init uses 'default' namespace when None."""
        provider = EtcdConfigProvider(namespace=None)
        assert provider._default_namespace == "default"

    def test_init_prefix_trailing_slash(self):
        """Test init normalizes prefix to have trailing slash."""
        provider = EtcdConfigProvider(prefix="/cwm")
        assert provider._prefix == "/cwm/"

    def test_init_with_credentials(self):
        """Test init stores username and password."""
        provider = EtcdConfigProvider(username="user", password="pass")
        assert provider._username == "user"
        assert provider._password == "pass"


class TestApplyPut:
    """Test EtcdConfigProvider._apply_put method."""

    def test_apply_put_webhook(self):
        """Test _apply_put correctly parses webhook key."""
        provider = EtcdConfigProvider(prefix="/cwm/")
        cache = {}
        connections = {}
        value = json.dumps({"module": "log"}).encode()

        provider._apply_put("/cwm/staging/webhooks/my-hook", value, cache, connections)

        assert "staging" in cache
        assert "my-hook" in cache["staging"]
        assert cache["staging"]["my-hook"]["module"] == "log"

    def test_apply_put_connection(self):
        """Test _apply_put correctly parses connection key."""
        provider = EtcdConfigProvider(prefix="/cwm/")
        cache = {}
        connections = {}
        value = json.dumps({"type": "rabbitmq", "host": "rmq.example.com"}).encode()

        provider._apply_put("/cwm/global/connections/my-rmq", value, cache, connections)

        assert "my-rmq" in connections
        assert connections["my-rmq"]["type"] == "rabbitmq"

    def test_apply_put_unrecognized_key(self):
        """Test _apply_put ignores unrecognized key patterns."""
        provider = EtcdConfigProvider(prefix="/cwm/")
        cache = {}
        connections = {}
        value = json.dumps({"data": "test"}).encode()

        provider._apply_put("/cwm/random/unknown", value, cache, connections)

        assert len(cache) == 0
        assert len(connections) == 0

    def test_apply_put_invalid_json(self):
        """Test _apply_put handles invalid JSON gracefully."""
        provider = EtcdConfigProvider(prefix="/cwm/")
        cache = {}
        connections = {}
        value = b"not valid json"

        provider._apply_put("/cwm/staging/webhooks/my-hook", value, cache, connections)

        assert len(cache) == 0

    def test_apply_put_non_dict_value(self):
        """Test _apply_put skips non-dict values."""
        provider = EtcdConfigProvider(prefix="/cwm/")
        cache = {}
        connections = {}
        value = json.dumps([1, 2, 3]).encode()  # List, not dict

        provider._apply_put("/cwm/staging/webhooks/my-hook", value, cache, connections)

        assert len(cache) == 0

    def test_apply_put_invalid_namespace(self):
        """Test _apply_put skips invalid namespace."""
        provider = EtcdConfigProvider(prefix="/cwm/")
        cache = {}
        connections = {}
        value = json.dumps({"module": "log"}).encode()

        provider._apply_put("/cwm/bad/ns/webhooks/hook", value, cache, connections)

        # Should be treated as unrecognized key (4 parts, not 3)
        assert len(cache) == 0


class TestProcessPutAndDelete:
    """Test _process_put_event and _process_delete_event."""

    def test_process_put_event(self):
        """Test _process_put_event updates cache under lock."""
        provider = EtcdConfigProvider(prefix="/cwm/")
        value = json.dumps({"module": "log"}).encode()

        provider._process_put_event("/cwm/default/webhooks/hook1", value)

        assert "default" in provider._cache
        assert "hook1" in provider._cache["default"]

    def test_process_delete_event_webhook(self):
        """Test _process_delete_event removes webhook from cache."""
        provider = EtcdConfigProvider(prefix="/cwm/")
        provider._cache = {"default": {"hook1": {"module": "log"}, "hook2": {"module": "save_to_disk"}}}

        provider._process_delete_event("/cwm/default/webhooks/hook1")

        assert "hook1" not in provider._cache.get("default", {})
        assert "hook2" in provider._cache["default"]

    def test_process_delete_event_last_webhook_removes_namespace(self):
        """Test _process_delete_event removes empty namespace."""
        provider = EtcdConfigProvider(prefix="/cwm/")
        provider._cache = {"staging": {"hook1": {"module": "log"}}}

        provider._process_delete_event("/cwm/staging/webhooks/hook1")

        assert "staging" not in provider._cache

    def test_process_delete_event_connection(self):
        """Test _process_delete_event removes connection from cache."""
        provider = EtcdConfigProvider(prefix="/cwm/")
        provider._connections_cache = {"my-rmq": {"type": "rabbitmq"}}

        provider._process_delete_event("/cwm/global/connections/my-rmq")

        assert "my-rmq" not in provider._connections_cache

    def test_process_delete_event_nonexistent(self):
        """Test _process_delete_event handles non-existent key gracefully."""
        provider = EtcdConfigProvider(prefix="/cwm/")
        # Should not raise
        provider._process_delete_event("/cwm/default/webhooks/nonexistent")


class TestNotifyChange:
    """Test _notify_change method."""

    def test_notify_change_no_callbacks(self):
        """Test _notify_change does nothing when no callbacks registered."""
        provider = EtcdConfigProvider()
        # Should not raise
        provider._notify_change("put", "/cwm/test/key", b'{"data":"test"}')

    def test_notify_change_no_loop(self):
        """Test _notify_change does nothing when no event loop."""
        provider = EtcdConfigProvider()
        provider._change_callbacks = [AsyncMock()]
        provider._loop = None
        # Should not raise
        provider._notify_change("put", "/cwm/test/key", b'{"data":"test"}')

    def test_notify_change_with_none_value(self):
        """Test _notify_change with None value (delete event)."""
        provider = EtcdConfigProvider()
        mock_loop = MagicMock()
        provider._loop = mock_loop
        mock_callback = AsyncMock()
        provider._change_callbacks = [mock_callback]

        provider._notify_change("delete", "/cwm/test/key", None)

        mock_loop.call_soon_threadsafe.assert_called_once()

    def test_notify_change_with_invalid_json_value(self):
        """Test _notify_change handles invalid JSON value."""
        provider = EtcdConfigProvider()
        mock_loop = MagicMock()
        provider._loop = mock_loop
        mock_callback = AsyncMock()
        provider._change_callbacks = [mock_callback]

        provider._notify_change("put", "/cwm/test/key", b"not json")

        mock_loop.call_soon_threadsafe.assert_called_once()


class TestShutdown:
    """Test EtcdConfigProvider.shutdown method."""

    @pytest.mark.asyncio
    async def test_shutdown_without_client(self):
        """Test shutdown when no client is created."""
        provider = EtcdConfigProvider()
        await provider.shutdown()
        assert provider._connected is False
        assert provider._initialized is False

    @pytest.mark.asyncio
    async def test_shutdown_with_watch_id(self):
        """Test shutdown cancels watch."""
        provider = EtcdConfigProvider()
        mock_cancel = MagicMock()
        provider._watch_id = mock_cancel

        await provider.shutdown()

        mock_cancel.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_watch_cancel_exception(self):
        """Test shutdown handles watch cancel exception."""
        provider = EtcdConfigProvider()
        mock_cancel = MagicMock(side_effect=Exception("Cancel error"))
        provider._watch_id = mock_cancel

        await provider.shutdown()

        # Should not raise, watch_id should be cleared
        assert provider._watch_id is None

    @pytest.mark.asyncio
    async def test_shutdown_with_client(self):
        """Test shutdown closes client."""
        provider = EtcdConfigProvider()
        mock_client = MagicMock()
        provider._client = mock_client

        await provider.shutdown()

        mock_client.close.assert_called_once()
        assert provider._client is None

    @pytest.mark.asyncio
    async def test_shutdown_client_close_exception(self):
        """Test shutdown handles client close exception."""
        provider = EtcdConfigProvider()
        mock_client = MagicMock()
        mock_client.close.side_effect = Exception("Close error")
        provider._client = mock_client

        await provider.shutdown()

        assert provider._client is None


class TestConfigAccess:
    """Test config access methods."""

    def test_get_webhook_config_found(self):
        """Test getting existing webhook config."""
        provider = EtcdConfigProvider(namespace="default")
        provider._cache = {"default": {"hook1": {"module": "log"}}}

        config = provider.get_webhook_config("hook1")
        assert config == {"module": "log"}

    def test_get_webhook_config_not_found(self):
        """Test getting non-existent webhook config."""
        provider = EtcdConfigProvider(namespace="default")
        provider._cache = {}

        config = provider.get_webhook_config("nonexistent")
        assert config is None

    def test_get_webhook_config_with_namespace(self):
        """Test getting webhook config with explicit namespace."""
        provider = EtcdConfigProvider(namespace="default")
        provider._cache = {"staging": {"hook1": {"module": "log"}}}

        config = provider.get_webhook_config("hook1", namespace="staging")
        assert config == {"module": "log"}

    def test_get_all_webhook_configs(self):
        """Test getting all webhook configs for a namespace."""
        provider = EtcdConfigProvider(namespace="default")
        provider._cache = {
            "default": {"hook1": {"module": "log"}, "hook2": {"module": "save_to_disk"}}
        }

        configs = provider.get_all_webhook_configs()
        assert len(configs) == 2
        assert "hook1" in configs
        assert "hook2" in configs

    def test_get_all_webhook_configs_empty_namespace(self):
        """Test getting all webhook configs for non-existent namespace."""
        provider = EtcdConfigProvider(namespace="default")
        provider._cache = {}

        configs = provider.get_all_webhook_configs()
        assert configs == {}

    def test_get_connection_config(self):
        """Test getting connection config."""
        provider = EtcdConfigProvider()
        provider._connections_cache = {"my-rmq": {"type": "rabbitmq"}}

        config = provider.get_connection_config("my-rmq")
        assert config == {"type": "rabbitmq"}

    def test_get_all_connection_configs(self):
        """Test getting all connection configs."""
        provider = EtcdConfigProvider()
        provider._connections_cache = {
            "rmq": {"type": "rabbitmq"},
            "redis": {"type": "redis-rq"},
        }

        configs = provider.get_all_connection_configs()
        assert len(configs) == 2


class TestGetStatus:
    """Test get_status method."""

    def test_get_status(self):
        """Test get_status returns correct information."""
        provider = EtcdConfigProvider(
            host="etcd.example.com",
            port=2379,
            prefix="/cwm/",
            namespace="default",
        )
        provider._initialized = True
        provider._connected = True
        provider._cache = {
            "default": {"hook1": {}, "hook2": {}},
            "staging": {"hook3": {}},
        }
        provider._connections_cache = {"conn1": {}}

        status = provider.get_status()

        assert status["backend"] == "etcd"
        assert status["initialized"] is True
        assert status["connected"] is True
        assert status["host"] == "etcd.example.com"
        assert status["port"] == 2379
        assert status["namespaces_count"] == 2
        assert status["total_webhooks"] == 3
        assert status["connections_count"] == 1


class TestGetNamespaces:
    """Test get_namespaces method."""

    def test_get_namespaces(self):
        """Test get_namespaces returns list of namespaces."""
        provider = EtcdConfigProvider()
        provider._cache = {"default": {}, "staging": {}, "prod": {}}

        namespaces = provider.get_namespaces()
        assert set(namespaces) == {"default", "staging", "prod"}


class TestOnConfigChange:
    """Test on_config_change callback registration."""

    def test_on_config_change(self):
        """Test registering a config change callback."""
        provider = EtcdConfigProvider()
        mock_callback = AsyncMock()

        provider.on_config_change(mock_callback)

        assert mock_callback in provider._change_callbacks
