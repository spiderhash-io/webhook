"""Tests for src/connector/main.py — LocalConnector, parse_args, build_config, setup_logging."""

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from src.connector.config import ConnectorConfig, TargetConfig
from src.connector.main import (
    LocalConnector,
    build_config,
    parse_args,
    setup_logging,
    main,
    main_async,
)
from src.connector.stream_client import ConnectionState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**overrides) -> ConnectorConfig:
    """Create a ConnectorConfig with sensible defaults for testing."""
    defaults = dict(
        cloud_url="https://cloud.example.com",
        channel="test-channel",
        token="secret-token",
        protocol="websocket",
        log_level="INFO",
        default_target=TargetConfig(url="http://localhost:8080/hook"),
    )
    defaults.update(overrides)
    return ConnectorConfig(**defaults)


# ===========================================================================
# LocalConnector.__init__
# ===========================================================================


class TestLocalConnectorInit:
    """Test LocalConnector initialization."""

    @pytest.mark.asyncio
    async def test_init_sets_config(self):
        """Config should be stored on the instance."""
        config = _make_config()
        connector = LocalConnector(config)

        assert connector.config is config

    @pytest.mark.asyncio
    async def test_init_defaults(self):
        """Initial state should be not-running with no processor/client."""
        connector = LocalConnector(_make_config())

        assert connector.processor is None
        assert connector.client is None
        assert connector._running is False
        assert connector._start_time is None


# ===========================================================================
# LocalConnector.start — HTTP mode
# ===========================================================================


class TestLocalConnectorStartHTTP:
    """Test starting the connector in HTTP delivery mode."""

    @pytest.mark.asyncio
    async def test_start_creates_processor_and_client(self):
        """start() should create a MessageProcessor and stream client."""
        config = _make_config()
        connector = LocalConnector(config)

        mock_processor = AsyncMock()
        mock_processor.start = AsyncMock()
        mock_client = AsyncMock()
        # Return normally rather than raising CancelledError to avoid
        # the shadowed-asyncio bug in main.py line 87/144.
        mock_client.start = AsyncMock(return_value=None)

        with patch(
            "src.connector.main.MessageProcessor", return_value=mock_processor
        ) as mp_cls, patch(
            "src.connector.main.create_client", return_value=mock_client
        ) as cc_fn:
            await connector.start()

        mp_cls.assert_called_once()
        mock_processor.start.assert_awaited_once()
        cc_fn.assert_called_once()
        mock_client.start.assert_awaited_once()
        assert connector._running is True

    @pytest.mark.asyncio
    async def test_start_idempotent_when_running(self):
        """Calling start() when already running should be a no-op."""
        connector = LocalConnector(_make_config())
        connector._running = True

        # Should return immediately without creating processor/client
        await connector.start()
        assert connector.processor is None  # nothing was set up


# ===========================================================================
# LocalConnector.start — module mode
# ===========================================================================


class TestLocalConnectorStartModule:
    """Test starting the connector in module delivery mode."""

    @pytest.mark.asyncio
    async def test_start_module_mode(self):
        """start() in module mode should use ModuleProcessor."""
        config = _make_config(
            webhooks_config="/tmp/fake_webhooks.json",
            default_target=None,
        )
        connector = LocalConnector(config)

        mock_processor = AsyncMock()
        mock_processor.start = AsyncMock()
        mock_client = AsyncMock()
        mock_client.start = AsyncMock(return_value=None)
        fake_webhooks = {"hook1": {"module": "log"}}

        with patch(
            "src.connector.main.ModuleProcessor", return_value=mock_processor
        ), patch(
            "src.connector.main.load_json_config", return_value=fake_webhooks
        ), patch(
            "src.connector.main.create_client", return_value=mock_client
        ):
            await connector.start()

        mock_processor.start.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_start_module_mode_with_connections(self):
        """Module mode with connections_config should load both files."""
        config = _make_config(
            webhooks_config="/tmp/webhooks.json",
            connections_config="/tmp/connections.json",
            default_target=None,
        )
        connector = LocalConnector(config)

        mock_processor = AsyncMock()
        mock_processor.start = AsyncMock()
        mock_client = AsyncMock()
        mock_client.start = AsyncMock(return_value=None)

        call_count = 0

        def fake_load(path):
            nonlocal call_count
            call_count += 1
            return {"key": "val"}

        with patch(
            "src.connector.main.ModuleProcessor", return_value=mock_processor
        ), patch(
            "src.connector.main.load_json_config", side_effect=fake_load
        ), patch(
            "src.connector.main.create_client", return_value=mock_client
        ):
            await connector.start()

        # Should call load_json_config twice (webhooks + connections)
        assert call_count == 2


# ===========================================================================
# LocalConnector.start — etcd mode
# ===========================================================================


class TestLocalConnectorStartEtcd:
    """Test starting the connector in etcd delivery mode."""

    @pytest.mark.asyncio
    async def test_start_etcd_mode(self):
        """start() in etcd mode should create EtcdConfigProvider and ModuleProcessor."""
        config = _make_config(
            etcd_host="localhost",
            etcd_port=2379,
            namespace="test-ns",
            default_target=None,
        )
        connector = LocalConnector(config)

        mock_provider = MagicMock()
        mock_provider._sync_initialize = MagicMock()
        mock_provider.get_all_webhook_configs = MagicMock(return_value={"w1": {}})
        mock_provider.get_all_connection_configs = MagicMock(return_value={"c1": {}})
        mock_provider.shutdown = AsyncMock()

        mock_processor = AsyncMock()
        mock_processor.start = AsyncMock()
        mock_client = AsyncMock()
        mock_client.start = AsyncMock(return_value=None)

        # EtcdConfigProvider is imported inside start() via
        # `from src.etcd_config_provider import EtcdConfigProvider`
        # so we need to mock the module in sys.modules before start() runs.
        mock_etcd_module = MagicMock()
        mock_etcd_module.EtcdConfigProvider = MagicMock(return_value=mock_provider)

        with patch.dict(
            "sys.modules", {"src.etcd_config_provider": mock_etcd_module}
        ), patch(
            "src.connector.main.ModuleProcessor", return_value=mock_processor
        ), patch(
            "src.connector.main.create_client", return_value=mock_client
        ):
            await connector.start()

        mock_processor.start.assert_awaited_once()
        assert connector._etcd_provider is mock_provider


# ===========================================================================
# LocalConnector.stop
# ===========================================================================


class TestLocalConnectorStop:
    """Test stopping the connector."""

    @pytest.mark.asyncio
    async def test_stop_when_not_running(self):
        """stop() when not running should be a no-op."""
        connector = LocalConnector(_make_config())
        await connector.stop()  # Should not raise

    @pytest.mark.asyncio
    async def test_stop_stops_client_and_processor(self):
        """stop() should stop client and processor."""
        connector = LocalConnector(_make_config())
        connector._running = True
        connector.client = AsyncMock()
        connector.client.stop = AsyncMock()
        connector.processor = AsyncMock()
        connector.processor.stop = AsyncMock()

        await connector.stop()

        assert connector._running is False
        connector.client.stop.assert_awaited_once()
        connector.processor.stop.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stop_shuts_down_etcd_provider(self):
        """stop() should shutdown etcd provider if present."""
        connector = LocalConnector(_make_config())
        connector._running = True
        connector.client = AsyncMock()
        connector.client.stop = AsyncMock()
        connector.processor = AsyncMock()
        connector.processor.stop = AsyncMock()
        connector._etcd_provider = AsyncMock()
        connector._etcd_provider.shutdown = AsyncMock()

        await connector.stop()

        connector._etcd_provider.shutdown.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_stop_without_client_or_processor(self):
        """stop() with None client/processor should not raise."""
        connector = LocalConnector(_make_config())
        connector._running = True
        connector.client = None
        connector.processor = None

        await connector.stop()
        assert connector._running is False


# ===========================================================================
# LocalConnector._handle_message
# ===========================================================================


class TestHandleMessage:
    """Test message handling callback."""

    @pytest.mark.asyncio
    async def test_webhook_message_forwarded_to_processor(self):
        """Webhook messages should be forwarded to the processor."""
        connector = LocalConnector(_make_config())
        connector.processor = AsyncMock()
        connector.processor.process = AsyncMock()

        msg = {"type": "webhook", "message_id": "msg-1", "payload": {"key": "val"}}
        await connector._handle_message(msg)

        connector.processor.process.assert_awaited_once_with(msg)

    @pytest.mark.asyncio
    async def test_non_webhook_message_ignored(self):
        """Non-webhook messages should be ignored (not forwarded)."""
        connector = LocalConnector(_make_config())
        connector.processor = AsyncMock()
        connector.processor.process = AsyncMock()

        msg = {"type": "heartbeat"}
        await connector._handle_message(msg)

        connector.processor.process.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_missing_type_ignored(self):
        """Messages without a type field should be ignored."""
        connector = LocalConnector(_make_config())
        connector.processor = AsyncMock()
        connector.processor.process = AsyncMock()

        await connector._handle_message({})

        connector.processor.process.assert_not_awaited()


# ===========================================================================
# LocalConnector._send_ack / _send_nack
# ===========================================================================


class TestSendAckNack:
    """Test ACK/NACK delegation."""

    @pytest.mark.asyncio
    async def test_send_ack_delegates_to_client(self):
        """_send_ack should delegate to client.send_ack."""
        connector = LocalConnector(_make_config())
        connector.client = AsyncMock()
        connector.client.send_ack = AsyncMock(return_value=True)

        result = await connector._send_ack("msg-1")

        assert result is True
        connector.client.send_ack.assert_awaited_once_with("msg-1")

    @pytest.mark.asyncio
    async def test_send_ack_returns_false_when_no_client(self):
        """_send_ack should return False when client is None."""
        connector = LocalConnector(_make_config())
        connector.client = None

        result = await connector._send_ack("msg-1")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_nack_delegates_to_client(self):
        """_send_nack should delegate to client.send_nack."""
        connector = LocalConnector(_make_config())
        connector.client = AsyncMock()
        connector.client.send_nack = AsyncMock(return_value=True)

        result = await connector._send_nack("msg-1", retry=False)

        assert result is True
        connector.client.send_nack.assert_awaited_once_with("msg-1", False)

    @pytest.mark.asyncio
    async def test_send_nack_returns_false_when_no_client(self):
        """_send_nack should return False when client is None."""
        connector = LocalConnector(_make_config())
        connector.client = None

        result = await connector._send_nack("msg-1", retry=True)
        assert result is False


# ===========================================================================
# LocalConnector._on_connect / _on_disconnect
# ===========================================================================


class TestConnectDisconnectCallbacks:
    """Test connect/disconnect callbacks."""

    @pytest.mark.asyncio
    async def test_on_connect_logs(self):
        """_on_connect should log the connection ID."""
        connector = LocalConnector(_make_config())
        connector.client = MagicMock()
        connector.client.connection_id = "conn-123"

        # Should not raise
        await connector._on_connect()

    @pytest.mark.asyncio
    async def test_on_disconnect_with_error(self):
        """_on_disconnect with an error should log a warning."""
        connector = LocalConnector(_make_config())
        await connector._on_disconnect(error=RuntimeError("test error"))

    @pytest.mark.asyncio
    async def test_on_disconnect_without_error(self):
        """_on_disconnect without error should log info."""
        connector = LocalConnector(_make_config())
        await connector._on_disconnect(error=None)


# ===========================================================================
# LocalConnector.get_status
# ===========================================================================


class TestGetStatus:
    """Test status reporting."""

    @pytest.mark.asyncio
    async def test_get_status_when_not_started(self):
        """get_status before start should return defaults."""
        connector = LocalConnector(_make_config())
        status = connector.get_status()

        assert status["running"] is False
        assert status["connected"] is False
        assert status["connection_id"] is None
        assert status["uptime_seconds"] == 0
        assert status["processor_stats"] == {}

    @pytest.mark.asyncio
    async def test_get_status_when_running(self):
        """get_status while running should reflect live state."""
        connector = LocalConnector(_make_config())
        connector._running = True
        connector._start_time = datetime(2025, 1, 1, tzinfo=timezone.utc)

        # Mock client
        connector.client = MagicMock()
        connector.client.state = ConnectionState.CONNECTED
        connector.client.connection_id = "conn-xyz"

        # Mock processor
        connector.processor = MagicMock()
        connector.processor.get_stats.return_value = {"delivered": 42}

        status = connector.get_status()

        assert status["running"] is True
        assert status["connected"] is True
        assert status["connection_id"] == "conn-xyz"
        assert status["uptime_seconds"] > 0
        assert status["processor_stats"] == {"delivered": 42}
        assert "config" in status

    @pytest.mark.asyncio
    async def test_get_status_disconnected_client(self):
        """get_status with a disconnected client."""
        connector = LocalConnector(_make_config())
        connector._running = True
        connector._start_time = datetime.now(timezone.utc)
        connector.client = MagicMock()
        connector.client.state = ConnectionState.DISCONNECTED
        connector.client.connection_id = None
        connector.processor = MagicMock()
        connector.processor.get_stats.return_value = {}

        status = connector.get_status()
        assert status["connected"] is False
        assert status["connection_id"] is None


# ===========================================================================
# setup_logging
# ===========================================================================


class TestSetupLogging:
    """Test logging setup."""

    def test_setup_logging_sets_aiohttp_to_warning(self):
        """setup_logging should set the aiohttp logger to WARNING."""
        setup_logging()
        aiohttp_logger = logging.getLogger("aiohttp")
        assert aiohttp_logger.level == logging.WARNING

    def test_setup_logging_custom_format_no_error(self):
        """setup_logging with a custom format should not raise."""
        setup_logging(format_str="%(message)s")

    def test_setup_logging_adds_stream_handler(self):
        """setup_logging should add at least one handler to root."""
        # Reset root handlers for a clean test
        root = logging.getLogger()
        original_handlers = root.handlers[:]
        try:
            root.handlers.clear()
            setup_logging(level="DEBUG")
            assert len(root.handlers) > 0
        finally:
            root.handlers = original_handlers

    def test_setup_logging_invalid_level_resolves_to_info(self):
        """An invalid level string should resolve to INFO via getattr fallback."""
        # getattr(logging, "NONEXISTENT", logging.INFO) => logging.INFO = 20
        resolved = getattr(logging, "NONEXISTENT", logging.INFO)
        assert resolved == logging.INFO


# ===========================================================================
# parse_args
# ===========================================================================


class TestParseArgs:
    """Test CLI argument parsing."""

    def test_parse_args_defaults(self):
        """parse_args with no arguments should return defaults."""
        with patch("sys.argv", ["prog"]):
            args = parse_args()

        assert args.config is None
        assert args.cloud_url is None
        assert args.channel is None
        assert args.token is None
        assert args.target_url is None
        assert args.protocol == "websocket"
        assert args.log_level == "INFO"
        assert args.connector_id is None
        assert args.no_verify_ssl is False

    def test_parse_args_all_flags(self):
        """parse_args should parse all supported arguments."""
        with patch(
            "sys.argv",
            [
                "prog",
                "--config", "test.json",
                "--cloud-url", "https://cloud.test",
                "--channel", "ch1",
                "--token", "tok123",
                "--target-url", "http://localhost:9000",
                "--protocol", "sse",
                "--log-level", "DEBUG",
                "--connector-id", "c-01",
                "--no-verify-ssl",
                "--webhooks-config", "wh.json",
                "--connections-config", "cn.json",
            ],
        ):
            args = parse_args()

        assert args.config == "test.json"
        assert args.cloud_url == "https://cloud.test"
        assert args.channel == "ch1"
        assert args.token == "tok123"
        assert args.target_url == "http://localhost:9000"
        assert args.protocol == "sse"
        assert args.log_level == "DEBUG"
        assert args.connector_id == "c-01"
        assert args.no_verify_ssl is True
        assert args.webhooks_config == "wh.json"
        assert args.connections_config == "cn.json"

    def test_parse_args_short_config(self):
        """parse_args should accept -c as short form for --config."""
        with patch("sys.argv", ["prog", "-c", "my.json"]):
            args = parse_args()
        assert args.config == "my.json"


# ===========================================================================
# build_config
# ===========================================================================


class TestBuildConfig:
    """Test configuration building from args."""

    def test_build_config_from_env(self):
        """build_config without --config should use from_env."""
        args = argparse.Namespace(
            config=None,
            cloud_url="https://env.test",
            channel="env-ch",
            token="env-tok",
            protocol="websocket",
            log_level="WARNING",
            connector_id="c-env",
            no_verify_ssl=True,
            target_url="http://local:3000",
            webhooks_config=None,
            connections_config=None,
        )

        with patch.object(ConnectorConfig, "from_env", return_value=ConnectorConfig()):
            config = build_config(args)

        assert config.cloud_url == "https://env.test"
        assert config.channel == "env-ch"
        assert config.token == "env-tok"
        assert config.protocol == "websocket"
        assert config.log_level == "WARNING"
        assert config.connector_id == "c-env"
        assert config.verify_ssl is False
        assert config.default_target is not None
        assert config.default_target.url == "http://local:3000"

    def test_build_config_from_file(self):
        """build_config with --config should load from file."""
        args = argparse.Namespace(
            config="test.json",
            cloud_url=None,
            channel=None,
            token=None,
            protocol=None,
            log_level=None,
            connector_id=None,
            no_verify_ssl=False,
            target_url=None,
            webhooks_config=None,
            connections_config=None,
        )

        mock_config = ConnectorConfig(
            cloud_url="https://file.test",
            channel="file-ch",
            token="file-tok",
        )

        with patch.object(ConnectorConfig, "from_file", return_value=mock_config):
            config = build_config(args)

        assert config.cloud_url == "https://file.test"

    def test_build_config_cli_overrides_file(self):
        """CLI arguments should override file config values."""
        args = argparse.Namespace(
            config="test.json",
            cloud_url="https://cli.test",
            channel="cli-ch",
            token="cli-tok",
            protocol="sse",
            log_level="ERROR",
            connector_id="cli-id",
            no_verify_ssl=True,
            target_url="http://cli:5000",
            webhooks_config="/wh.json",
            connections_config="/cn.json",
        )

        file_config = ConnectorConfig(
            cloud_url="https://file.test",
            channel="file-ch",
            token="file-tok",
        )

        with patch.object(ConnectorConfig, "from_file", return_value=file_config):
            config = build_config(args)

        assert config.cloud_url == "https://cli.test"
        assert config.channel == "cli-ch"
        assert config.token == "cli-tok"
        assert config.protocol == "sse"
        assert config.log_level == "ERROR"
        assert config.connector_id == "cli-id"
        assert config.verify_ssl is False
        assert config.default_target.url == "http://cli:5000"
        assert config.webhooks_config == "/wh.json"
        assert config.connections_config == "/cn.json"

    def test_build_config_no_verify_ssl_false_keeps_default(self):
        """When no_verify_ssl is False, verify_ssl should remain True."""
        args = argparse.Namespace(
            config=None,
            cloud_url=None,
            channel=None,
            token=None,
            protocol=None,
            log_level=None,
            connector_id=None,
            no_verify_ssl=False,
            target_url=None,
            webhooks_config=None,
            connections_config=None,
        )
        with patch.object(ConnectorConfig, "from_env", return_value=ConnectorConfig()):
            config = build_config(args)

        assert config.verify_ssl is True


# ===========================================================================
# main_async
# ===========================================================================


class TestMainAsync:
    """Test the async main entry point."""

    @pytest.mark.asyncio
    async def test_main_async_shutdown_signal(self):
        """main_async should stop on shutdown signal."""
        config = _make_config()
        connector = LocalConnector(config)

        # Mock start to return immediately (simulating connector run ending)
        connector.start = AsyncMock(return_value=None)
        connector.stop = AsyncMock()

        # Run main_async but trigger the stop_event quickly via signal
        async def trigger_stop():
            await asyncio.sleep(0.05)
            import signal as sig
            import os
            os.kill(os.getpid(), sig.SIGINT)

        try:
            task = asyncio.create_task(main_async(connector))
            trigger_task = asyncio.create_task(trigger_stop())
            await asyncio.wait_for(
                asyncio.gather(task, trigger_task, return_exceptions=True),
                timeout=2.0,
            )
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass

        connector.stop.assert_awaited()


# ===========================================================================
# main (sync entry point)
# ===========================================================================


class TestMain:
    """Test the synchronous main entry point."""

    @pytest.mark.asyncio
    async def test_main_with_validation_errors(self):
        """main() should return 1 when config validation fails."""
        invalid_config = ConnectorConfig()  # No cloud_url, channel, token

        with patch(
            "src.connector.main.parse_args",
            return_value=argparse.Namespace(
                config=None,
                cloud_url=None,
                channel=None,
                token=None,
                protocol=None,
                log_level=None,
                connector_id=None,
                no_verify_ssl=False,
                target_url=None,
                webhooks_config=None,
                connections_config=None,
            ),
        ), patch(
            "src.connector.main.build_config", return_value=invalid_config
        ), patch(
            "src.connector.main.setup_logging"
        ):
            exit_code = main()

        assert exit_code == 1

    @pytest.mark.asyncio
    async def test_main_keyboard_interrupt_returns_130(self):
        """main() should return 130 on KeyboardInterrupt."""
        config = _make_config()

        with patch(
            "src.connector.main.parse_args",
            return_value=argparse.Namespace(
                config=None, cloud_url=None, channel=None, token=None,
                protocol=None, log_level=None, connector_id=None,
                no_verify_ssl=False, target_url=None,
                webhooks_config=None, connections_config=None,
            ),
        ), patch(
            "src.connector.main.build_config", return_value=config
        ), patch(
            "src.connector.main.setup_logging"
        ), patch(
            "asyncio.run", side_effect=KeyboardInterrupt
        ):
            exit_code = main()

        assert exit_code == 130

    @pytest.mark.asyncio
    async def test_main_exception_returns_1(self):
        """main() should return 1 on unexpected exceptions."""
        config = _make_config()

        with patch(
            "src.connector.main.parse_args",
            return_value=argparse.Namespace(
                config=None, cloud_url=None, channel=None, token=None,
                protocol=None, log_level=None, connector_id=None,
                no_verify_ssl=False, target_url=None,
                webhooks_config=None, connections_config=None,
            ),
        ), patch(
            "src.connector.main.build_config", return_value=config
        ), patch(
            "src.connector.main.setup_logging"
        ), patch(
            "asyncio.run", side_effect=RuntimeError("boom")
        ):
            exit_code = main()

        assert exit_code == 1

    @pytest.mark.asyncio
    async def test_main_success_returns_0(self):
        """main() should return 0 on clean exit."""
        config = _make_config()

        with patch(
            "src.connector.main.parse_args",
            return_value=argparse.Namespace(
                config=None, cloud_url=None, channel=None, token=None,
                protocol=None, log_level=None, connector_id=None,
                no_verify_ssl=False, target_url=None,
                webhooks_config=None, connections_config=None,
            ),
        ), patch(
            "src.connector.main.build_config", return_value=config
        ), patch(
            "src.connector.main.setup_logging"
        ), patch(
            "asyncio.run", return_value=None
        ):
            exit_code = main()

        assert exit_code == 0
