"""
Unit tests for Connector Module Processor.

Tests the ModuleProcessor which dispatches webhook messages to internal modules
(log, kafka, save_to_disk, etc.) using the standard webhooks.json config format.
"""

import asyncio
import json
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.connector.config import ConnectorConfig, TargetConfig
from src.connector.module_processor import ModuleProcessor, load_json_config


# --- Fixtures ---


@pytest.fixture
def base_config():
    """Create a base ConnectorConfig in module mode."""
    return ConnectorConfig(
        cloud_url="https://cloud.example.com",
        channel="test-channel",
        token="test-token",
        webhooks_config="/path/to/webhooks.json",
    )


@pytest.fixture
def sample_webhooks():
    """Standard webhooks.json content."""
    return {
        "order-events": {
            "module": "log",
            "module-config": {"pretty_print": True},
        },
        "payment-events": {
            "module": "save_to_disk",
            "module-config": {"path": "/data/payments"},
        },
        "audit-trail": {
            "chain": ["log", "save_to_disk"],
            "chain-config": {"execution": "sequential"},
            "module-config": {"pretty_print": True},
        },
        "with-connection": {
            "module": "log",
            "connection": "my-db",
            "module-config": {},
        },
    }


@pytest.fixture
def sample_connections():
    """Standard connections.json content."""
    return {
        "my-db": {
            "host": "localhost",
            "port": 5432,
            "user": "admin",
            "password": "secret",
            "database": "webhooks",
        }
    }


@pytest.fixture
def ack_callback():
    return AsyncMock(return_value=True)


@pytest.fixture
def nack_callback():
    return AsyncMock(return_value=True)


@pytest.fixture
def processor(base_config, sample_webhooks, sample_connections, ack_callback, nack_callback):
    """Create a ModuleProcessor instance."""
    return ModuleProcessor(
        config=base_config,
        webhooks=sample_webhooks,
        connections=sample_connections,
        ack_callback=ack_callback,
        nack_callback=nack_callback,
    )


# --- Config validation tests ---


class TestConnectorConfigModuleMode:
    """Tests for ConnectorConfig module-mode fields."""

    def test_delivery_mode_http_with_default_target(self):
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="tok",
            default_target=TargetConfig(url="http://localhost:8000"),
        )
        assert config.delivery_mode == "http"

    def test_delivery_mode_http_with_targets(self):
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="tok",
            targets={"wh1": TargetConfig(url="http://localhost:8000")},
        )
        assert config.delivery_mode == "http"

    def test_delivery_mode_module(self):
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="tok",
            webhooks_config="/path/to/webhooks.json",
        )
        assert config.delivery_mode == "module"

    def test_delivery_mode_default_http(self):
        config = ConnectorConfig()
        assert config.delivery_mode == "http"

    def test_validate_no_target_no_webhooks(self):
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="tok",
        )
        errors = config.validate()
        assert any("Either default_target/targets or webhooks_config" in e for e in errors)

    def test_validate_both_http_and_module(self):
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="tok",
            default_target=TargetConfig(url="http://localhost:8000"),
            webhooks_config="/path/to/webhooks.json",
        )
        errors = config.validate()
        assert any("Cannot configure both" in e for e in errors)

    def test_validate_targets_and_module(self):
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="tok",
            targets={"wh1": TargetConfig(url="http://localhost:8000")},
            webhooks_config="/path/to/webhooks.json",
        )
        errors = config.validate()
        assert any("Cannot configure both" in e for e in errors)

    def test_validate_module_mode_ok(self):
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="tok",
            webhooks_config="/path/to/webhooks.json",
        )
        errors = config.validate()
        assert not errors

    def test_validate_http_mode_ok(self):
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="tok",
            default_target=TargetConfig(url="http://localhost:8000"),
        )
        errors = config.validate()
        assert not errors

    def test_from_dict_module_mode(self):
        data = {
            "cloud_url": "https://example.com",
            "channel": "ch",
            "token": "tok",
            "webhooks_config": "/path/to/webhooks.json",
            "connections_config": "/path/to/connections.json",
        }
        config = ConnectorConfig.from_dict(data)
        assert config.webhooks_config == "/path/to/webhooks.json"
        assert config.connections_config == "/path/to/connections.json"
        assert config.delivery_mode == "module"

    def test_from_env_module_mode(self):
        env = {
            "CONNECTOR_CLOUD_URL": "https://example.com",
            "CONNECTOR_CHANNEL": "ch",
            "CONNECTOR_TOKEN": "tok",
            "CONNECTOR_WEBHOOKS_CONFIG": "/etc/webhooks.json",
            "CONNECTOR_CONNECTIONS_CONFIG": "/etc/connections.json",
        }
        with patch.dict(os.environ, env, clear=False):
            config = ConnectorConfig.from_env()
        assert config.webhooks_config == "/etc/webhooks.json"
        assert config.connections_config == "/etc/connections.json"

    def test_to_dict_module_mode(self):
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="tok",
            webhooks_config="/path/to/webhooks.json",
        )
        d = config.to_dict()
        assert d["delivery_mode"] == "module"
        assert d["has_webhooks_config"] is True

    def test_to_dict_http_mode(self):
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="tok",
            default_target=TargetConfig(url="http://localhost:8000"),
        )
        d = config.to_dict()
        assert d["delivery_mode"] == "http"
        assert d["has_webhooks_config"] is False


# --- load_json_config tests ---


class TestLoadJsonConfig:
    """Tests for load_json_config utility."""

    def test_load_valid_json(self, tmp_path):
        path = tmp_path / "test.json"
        data = {"webhook1": {"module": "log"}}
        path.write_text(json.dumps(data))

        result = load_json_config(str(path))
        assert result == data

    def test_load_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_json_config("/nonexistent/path/file.json")

    def test_load_invalid_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not json {{{")

        with pytest.raises(json.JSONDecodeError):
            load_json_config(str(path))

    def test_load_non_object_json(self, tmp_path):
        path = tmp_path / "array.json"
        path.write_text('["item1", "item2"]')

        with pytest.raises(ValueError, match="Expected JSON object"):
            load_json_config(str(path))


# --- ModuleProcessor lifecycle tests ---


class TestModuleProcessorLifecycle:
    """Tests for ModuleProcessor start/stop lifecycle."""

    async def test_start(self, processor):
        await processor.start()
        assert processor._running is True

    async def test_start_idempotent(self, processor):
        await processor.start()
        await processor.start()  # Should not error
        assert processor._running is True

    async def test_stop(self, processor):
        await processor.start()
        await processor.stop()
        assert processor._running is False

    async def test_stats_initial(self, processor):
        stats = processor.get_stats()
        assert stats["messages_delivered"] == 0
        assert stats["messages_failed"] == 0
        assert stats["messages_skipped"] == 0
        assert stats["in_flight_count"] == 0
        assert stats["webhooks_count"] == 4
        assert stats["connections_count"] == 1


# --- ModuleProcessor dispatch tests ---


class TestModuleProcessorDispatch:
    """Tests for ModuleProcessor message dispatching."""

    async def test_process_missing_message_id(self, processor, nack_callback):
        await processor.start()
        await processor.process({"webhook_id": "order-events", "payload": {}})
        # Should be silently ignored (no message_id to NACK)
        nack_callback.assert_not_called()

    async def test_process_missing_webhook_id(self, processor, nack_callback):
        await processor.start()
        await processor.process({"message_id": "msg-1", "payload": {}})
        # Allow task to run
        await asyncio.sleep(0.01)
        nack_callback.assert_called_once_with("msg-1", False)

    async def test_process_unknown_webhook_id(self, processor, nack_callback):
        await processor.start()
        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "nonexistent-webhook",
            "payload": {"key": "value"},
        })
        await asyncio.sleep(0.01)
        nack_callback.assert_called_once_with("msg-1", False)
        assert processor._stats.messages_skipped == 1

    async def test_process_not_running(self, processor, ack_callback, nack_callback):
        # Don't call start()
        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "order-events",
            "payload": {},
        })
        await asyncio.sleep(0.01)
        ack_callback.assert_not_called()
        nack_callback.assert_not_called()

    async def test_process_single_module_success(
        self, processor, ack_callback, nack_callback
    ):
        await processor.start()

        mock_module_instance = MagicMock()
        mock_module_instance.process = AsyncMock()
        mock_module_instance.teardown = AsyncMock()
        mock_module_class = MagicMock(return_value=mock_module_instance)

        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_module_class
        processor._ModuleRegistry = mock_registry

        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "order-events",
            "payload": {"order_id": 123},
            "headers": {"Content-Type": "application/json"},
        })

        # Wait for async task to complete
        await asyncio.sleep(0.05)

        mock_registry.get.assert_called_once_with("log")
        mock_module_instance.process.assert_called_once_with(
            {"order_id": 123}, {"Content-Type": "application/json"}
        )
        mock_module_instance.teardown.assert_called_once()
        ack_callback.assert_called_once_with("msg-1")
        assert processor._stats.messages_delivered == 1

    async def test_process_module_failure_nacks_with_retry(
        self, processor, ack_callback, nack_callback
    ):
        await processor.start()

        mock_module_instance = MagicMock()
        mock_module_instance.process = AsyncMock(side_effect=RuntimeError("connection refused"))
        mock_module_instance.teardown = AsyncMock()
        mock_module_class = MagicMock(return_value=mock_module_instance)

        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_module_class
        processor._ModuleRegistry = mock_registry

        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "order-events",
            "payload": {"data": "test"},
        })

        await asyncio.sleep(0.05)

        ack_callback.assert_not_called()
        nack_callback.assert_called_once_with("msg-1", True)
        assert processor._stats.messages_failed == 1

    async def test_process_with_connection_injection(
        self, processor, ack_callback
    ):
        await processor.start()

        mock_module_instance = MagicMock()
        mock_module_instance.process = AsyncMock()
        mock_module_instance.teardown = AsyncMock()
        mock_module_class = MagicMock(return_value=mock_module_instance)

        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_module_class
        processor._ModuleRegistry = mock_registry

        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "with-connection",
            "payload": {"data": "test"},
        })

        await asyncio.sleep(0.05)

        # Verify the module was instantiated with connection_details
        call_args = mock_module_class.call_args
        config_arg = call_args[0][0]
        assert "connection_details" in config_arg
        assert config_arg["connection_details"]["host"] == "localhost"
        assert config_arg["connection_details"]["port"] == 5432
        assert config_arg["_webhook_id"] == "with-connection"

    async def test_process_chain_success(
        self, processor, ack_callback, nack_callback
    ):
        await processor.start()

        # Mock ChainProcessor
        mock_chain_result_1 = MagicMock()
        mock_chain_result_1.success = True
        mock_chain_result_1.module_name = "log"
        mock_chain_result_2 = MagicMock()
        mock_chain_result_2.success = True
        mock_chain_result_2.module_name = "save_to_disk"

        mock_chain_processor = MagicMock()
        mock_chain_processor.execute = AsyncMock(
            return_value=[mock_chain_result_1, mock_chain_result_2]
        )

        mock_chain_class = MagicMock(return_value=mock_chain_processor)
        processor._ChainProcessor = mock_chain_class

        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "audit-trail",
            "payload": {"audit": "data"},
            "headers": {},
        })

        await asyncio.sleep(0.05)

        mock_chain_class.assert_called_once()
        mock_chain_processor.execute.assert_called_once()
        ack_callback.assert_called_once_with("msg-1")
        assert processor._stats.messages_delivered == 1

    async def test_process_chain_partial_failure(
        self, processor, ack_callback, nack_callback
    ):
        await processor.start()

        mock_chain_result_1 = MagicMock()
        mock_chain_result_1.success = True
        mock_chain_result_1.module_name = "log"
        mock_chain_result_2 = MagicMock()
        mock_chain_result_2.success = False
        mock_chain_result_2.module_name = "save_to_disk"

        mock_chain_processor = MagicMock()
        mock_chain_processor.execute = AsyncMock(
            return_value=[mock_chain_result_1, mock_chain_result_2]
        )

        mock_chain_class = MagicMock(return_value=mock_chain_processor)
        processor._ChainProcessor = mock_chain_class

        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "audit-trail",
            "payload": {"audit": "data"},
        })

        await asyncio.sleep(0.05)

        # Chain failure should NACK with retry
        nack_callback.assert_called_once_with("msg-1", True)
        assert processor._stats.messages_failed == 1

    async def test_process_no_module_in_config(
        self, processor, nack_callback, sample_webhooks
    ):
        """Webhook config has no 'module' and no 'chain' → error."""
        await processor.start()

        # Add a broken webhook config
        processor.webhooks["broken"] = {"module-config": {}}

        mock_registry = MagicMock()
        processor._ModuleRegistry = mock_registry

        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "broken",
            "payload": {},
        })

        await asyncio.sleep(0.05)

        nack_callback.assert_called_once_with("msg-1", True)

    async def test_in_flight_tracking(self, processor, ack_callback):
        """Verify in-flight messages are tracked and cleaned up."""
        await processor.start()

        mock_module_instance = MagicMock()
        # Use an event to control when the module finishes
        event = asyncio.Event()

        async def slow_process(payload, headers):
            await event.wait()

        mock_module_instance.process = slow_process
        mock_module_instance.teardown = AsyncMock()
        mock_module_class = MagicMock(return_value=mock_module_instance)

        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_module_class
        processor._ModuleRegistry = mock_registry

        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "order-events",
            "payload": {},
        })

        await asyncio.sleep(0.01)
        assert processor.in_flight_count == 1

        # Release the module
        event.set()
        await asyncio.sleep(0.05)
        assert processor.in_flight_count == 0

    async def test_connection_not_found(
        self, processor, ack_callback
    ):
        """Connection name in webhook config but not in connections dict → no injection."""
        await processor.start()

        processor.webhooks["no-conn"] = {
            "module": "log",
            "connection": "nonexistent-connection",
        }

        mock_module_instance = MagicMock()
        mock_module_instance.process = AsyncMock()
        mock_module_instance.teardown = AsyncMock()
        mock_module_class = MagicMock(return_value=mock_module_instance)

        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_module_class
        processor._ModuleRegistry = mock_registry

        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "no-conn",
            "payload": {},
        })

        await asyncio.sleep(0.05)

        # Module should still be called (without connection_details)
        call_args = mock_module_class.call_args
        config_arg = call_args[0][0]
        assert "connection_details" not in config_arg
        ack_callback.assert_called_once()

    async def test_concurrent_processing(
        self, base_config, sample_webhooks, sample_connections, ack_callback, nack_callback
    ):
        """Verify concurrency is limited by semaphore."""
        # Set max_concurrent to 2
        base_config.max_concurrent_requests = 2
        proc = ModuleProcessor(
            config=base_config,
            webhooks=sample_webhooks,
            connections=sample_connections,
            ack_callback=ack_callback,
            nack_callback=nack_callback,
        )
        await proc.start()

        concurrent_count = 0
        max_concurrent = 0
        lock = asyncio.Lock()

        async def counting_process(payload, headers):
            nonlocal concurrent_count, max_concurrent
            async with lock:
                concurrent_count += 1
                max_concurrent = max(max_concurrent, concurrent_count)
            await asyncio.sleep(0.05)
            async with lock:
                concurrent_count -= 1

        mock_module_instance = MagicMock()
        mock_module_instance.process = counting_process
        mock_module_instance.teardown = AsyncMock()
        mock_module_class = MagicMock(return_value=mock_module_instance)

        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_module_class
        proc._ModuleRegistry = mock_registry

        # Send 4 messages
        for i in range(4):
            await proc.process({
                "message_id": f"msg-{i}",
                "webhook_id": "order-events",
                "payload": {},
            })

        # Wait for all to complete
        await asyncio.sleep(0.3)

        assert max_concurrent <= 2
        assert ack_callback.call_count == 4
        await proc.stop()

    async def test_stop_cancels_in_flight(self, processor):
        """Verify stop() cancels in-flight tasks."""
        await processor.start()

        event = asyncio.Event()

        async def blocking_process(payload, headers):
            await event.wait()

        mock_module_instance = MagicMock()
        mock_module_instance.process = blocking_process
        mock_module_instance.teardown = AsyncMock()
        mock_module_class = MagicMock(return_value=mock_module_instance)

        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_module_class
        processor._ModuleRegistry = mock_registry

        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "order-events",
            "payload": {},
        })

        await asyncio.sleep(0.01)
        assert processor.in_flight_count == 1

        await processor.stop()
        assert processor.in_flight_count == 0
        assert processor._running is False


class TestModuleProcessorChainConfig:
    """Tests for chain configuration handling in ModuleProcessor."""

    async def test_chain_receives_correct_config(
        self, processor, ack_callback
    ):
        await processor.start()

        captured_args = {}

        def capture_chain_init(*args, **kwargs):
            captured_args.update(kwargs)
            mock_proc = MagicMock()
            result = MagicMock()
            result.success = True
            result.module_name = "log"
            mock_proc.execute = AsyncMock(return_value=[result])
            return mock_proc

        processor._ChainProcessor = capture_chain_init

        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "audit-trail",
            "payload": {"data": "test"},
            "headers": {"X-Test": "1"},
        })

        await asyncio.sleep(0.05)

        assert captured_args["chain"] == ["log", "save_to_disk"]
        assert captured_args["chain_config"] == {"execution": "sequential"}
        assert captured_args["webhook_config"]["_webhook_id"] == "audit-trail"
        assert captured_args["connection_config"] is processor.connections
        ack_callback.assert_called_once()

    async def test_empty_headers_default(
        self, processor, ack_callback
    ):
        """Message without headers should default to empty dict."""
        await processor.start()

        mock_module_instance = MagicMock()
        mock_module_instance.process = AsyncMock()
        mock_module_instance.teardown = AsyncMock()
        mock_module_class = MagicMock(return_value=mock_module_instance)

        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_module_class
        processor._ModuleRegistry = mock_registry

        await processor.process({
            "message_id": "msg-1",
            "webhook_id": "order-events",
            "payload": {"key": "val"},
            # No "headers" key
        })

        await asyncio.sleep(0.05)

        mock_module_instance.process.assert_called_once_with({"key": "val"}, {})
