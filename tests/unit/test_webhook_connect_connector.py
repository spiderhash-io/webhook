"""
Unit tests for Webhook Connect Local Connector.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

# Import directly from config module to avoid importing modules with external dependencies
from src.connector.config import ConnectorConfig, TargetConfig


class TestTargetConfig:
    """Tests for TargetConfig."""

    def test_create_target(self):
        """Test creating a target config."""
        target = TargetConfig(
            url="http://localhost:8000/webhook",
            method="POST",
            timeout_seconds=30.0,
        )

        assert target.url == "http://localhost:8000/webhook"
        assert target.method == "POST"
        assert target.timeout_seconds == 30.0
        assert target.retry_enabled is True
        assert target.retry_max_attempts == 3

    def test_target_with_headers(self):
        """Test target config with custom headers."""
        target = TargetConfig(
            url="http://localhost:8000",
            headers={"X-API-Key": "secret", "Content-Type": "application/json"},
        )

        assert target.headers["X-API-Key"] == "secret"
        assert target.headers["Content-Type"] == "application/json"


class TestConnectorConfig:
    """Tests for ConnectorConfig."""

    def test_create_config(self):
        """Test creating a connector config."""
        config = ConnectorConfig(
            cloud_url="https://webhooks.example.com",
            channel="my-channel",
            token="secret-token",
        )

        assert config.cloud_url == "https://webhooks.example.com"
        assert config.channel == "my-channel"
        assert config.token == "secret-token"
        assert config.protocol == "websocket"

    def test_default_values(self):
        """Test default configuration values."""
        config = ConnectorConfig()

        assert config.protocol == "websocket"
        assert config.reconnect_delay == 1.0
        assert config.max_reconnect_delay == 60.0
        assert config.heartbeat_timeout == 60.0
        assert config.max_concurrent_requests == 10
        assert config.verify_ssl is True
        assert config.log_level == "INFO"

    def test_from_dict(self):
        """Test creating config from dictionary."""
        data = {
            "cloud_url": "https://api.example.com",
            "channel": "test-channel",
            "token": "test-token",
            "protocol": "sse",
            "reconnect_delay": 5.0,
            "max_concurrent_requests": 20,
        }

        config = ConnectorConfig.from_dict(data)

        assert config.cloud_url == "https://api.example.com"
        assert config.channel == "test-channel"
        assert config.protocol == "sse"
        assert config.reconnect_delay == 5.0
        assert config.max_concurrent_requests == 20

    def test_from_dict_with_targets(self):
        """Test creating config with targets from dictionary."""
        data = {
            "cloud_url": "https://api.example.com",
            "channel": "test",
            "token": "token",
            "default_target": {
                "url": "http://localhost:8000/default",
                "method": "POST",
            },
            "targets": {
                "webhook-1": {
                    "url": "http://localhost:8000/w1",
                    "method": "PUT",
                },
                "webhook-2": {
                    "url": "http://localhost:8001/w2",
                },
            },
        }

        config = ConnectorConfig.from_dict(data)

        assert config.default_target is not None
        assert config.default_target.url == "http://localhost:8000/default"
        assert len(config.targets) == 2
        assert config.targets["webhook-1"].method == "PUT"

    def test_validate_valid_config(self):
        """Test validation of valid config."""
        config = ConnectorConfig(
            cloud_url="https://webhooks.example.com",
            channel="my-channel",
            token="secret",
            default_target=TargetConfig(url="http://localhost:8000"),
        )

        errors = config.validate()
        assert len(errors) == 0

    def test_validate_missing_required(self):
        """Test validation catches missing required fields."""
        config = ConnectorConfig()

        errors = config.validate()

        assert "cloud_url is required" in errors
        assert "channel is required" in errors
        assert "token is required" in errors

    def test_validate_invalid_protocol(self):
        """Test validation catches invalid protocol."""
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="t",
            protocol="invalid",
            default_target=TargetConfig(url="http://localhost"),
        )

        errors = config.validate()
        assert any("protocol" in e for e in errors)

    def test_validate_no_targets(self):
        """Test validation requires at least one target."""
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="t",
        )

        errors = config.validate()
        assert any("target" in e.lower() for e in errors)

    def test_get_target_default(self):
        """Test getting default target."""
        config = ConnectorConfig(
            default_target=TargetConfig(url="http://localhost:8000/default"),
        )

        target = config.get_target("unknown-webhook")
        assert target is not None
        assert target.url == "http://localhost:8000/default"

    def test_get_target_specific(self):
        """Test getting specific target for webhook."""
        config = ConnectorConfig(
            default_target=TargetConfig(url="http://localhost:8000/default"),
            targets={
                "webhook-1": TargetConfig(url="http://localhost:8001/specific"),
            },
        )

        default_target = config.get_target("other-webhook")
        specific_target = config.get_target("webhook-1")

        assert default_target.url == "http://localhost:8000/default"
        assert specific_target.url == "http://localhost:8001/specific"

    def test_get_stream_url_websocket(self):
        """Test generating WebSocket stream URL."""
        config = ConnectorConfig(
            cloud_url="https://webhooks.example.com",
            channel="my-channel",
            protocol="websocket",
        )

        url = config.get_stream_url()
        assert url == "wss://webhooks.example.com/connect/stream/my-channel"

    def test_get_stream_url_websocket_http(self):
        """Test generating WebSocket stream URL from HTTP."""
        config = ConnectorConfig(
            cloud_url="http://localhost:8080",
            channel="test",
            protocol="websocket",
        )

        url = config.get_stream_url()
        assert url == "ws://localhost:8080/connect/stream/test"

    def test_get_stream_url_sse(self):
        """Test generating SSE stream URL."""
        config = ConnectorConfig(
            cloud_url="https://webhooks.example.com",
            channel="my-channel",
            protocol="sse",
        )

        url = config.get_stream_url()
        assert url == "https://webhooks.example.com/connect/stream/my-channel/sse"

    def test_get_stream_url_long_poll(self):
        """Test generating long-poll stream URL."""
        config = ConnectorConfig(
            cloud_url="https://webhooks.example.com",
            channel="my-channel",
            protocol="long_poll",
        )

        url = config.get_stream_url()
        assert url == "https://webhooks.example.com/connect/stream/my-channel/poll"

    def test_get_stream_url_long_poll_http(self):
        """Test generating long-poll stream URL from HTTP."""
        config = ConnectorConfig(
            cloud_url="http://localhost:8080",
            channel="test",
            protocol="long_poll",
        )

        url = config.get_stream_url()
        assert url == "http://localhost:8080/connect/stream/test/poll"

    def test_get_stream_url_invalid_protocol_raises(self):
        """Test that invalid protocol raises ValueError."""
        config = ConnectorConfig(
            cloud_url="https://webhooks.example.com",
            channel="my-channel",
        )
        # Manually set invalid protocol to bypass validation
        config.protocol = "invalid"

        with pytest.raises(ValueError, match="Unknown protocol"):
            config.get_stream_url()

    def test_validate_channel_path_traversal(self):
        """Channel names with path traversal characters must be rejected."""
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="../../admin/reload-config",
            token="t",
            default_target=TargetConfig(url="http://localhost"),
        )
        errors = config.validate()
        assert any("channel" in e for e in errors)

    def test_validate_channel_valid_chars(self):
        """Channel names with alphanumeric, hyphens, underscores are valid."""
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="my-channel_01",
            token="t",
            default_target=TargetConfig(url="http://localhost"),
        )
        errors = config.validate()
        assert not any("channel" in e for e in errors)

    def test_validate_long_poll_protocol(self):
        """Test validation accepts long_poll protocol."""
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="t",
            protocol="long_poll",
            default_target=TargetConfig(url="http://localhost"),
        )

        errors = config.validate()
        assert not any("protocol" in e for e in errors)

    def test_to_dict_excludes_sensitive(self):
        """Test that to_dict excludes sensitive data."""
        config = ConnectorConfig(
            cloud_url="https://example.com",
            channel="ch",
            token="secret-token",
        )

        data = config.to_dict()

        assert "cloud_url" in data
        assert "channel" in data
        assert "token" not in data  # Token should be excluded


class TestConnectorConfigEnv:
    """Tests for environment variable configuration."""

    def test_from_env(self, monkeypatch):
        """Test loading config from environment variables."""
        monkeypatch.setenv("CONNECTOR_CLOUD_URL", "https://env.example.com")
        monkeypatch.setenv("CONNECTOR_CHANNEL", "env-channel")
        monkeypatch.setenv("CONNECTOR_TOKEN", "env-token")
        monkeypatch.setenv("CONNECTOR_PROTOCOL", "sse")
        monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "DEBUG")

        config = ConnectorConfig.from_env()

        assert config.cloud_url == "https://env.example.com"
        assert config.channel == "env-channel"
        assert config.token == "env-token"
        assert config.protocol == "sse"
        assert config.log_level == "DEBUG"

    def test_from_env_with_target(self, monkeypatch):
        """Test loading target from environment."""
        monkeypatch.setenv("CONNECTOR_TARGET_URL", "http://localhost:9000/webhook")
        monkeypatch.setenv("CONNECTOR_TARGET_METHOD", "PUT")
        monkeypatch.setenv("CONNECTOR_TARGET_TIMEOUT", "60")

        config = ConnectorConfig.from_env()

        assert config.default_target is not None
        assert config.default_target.url == "http://localhost:9000/webhook"
        assert config.default_target.method == "PUT"
        assert config.default_target.timeout_seconds == 60.0

    def test_from_env_numeric_values(self, monkeypatch):
        """Test loading numeric values from environment."""
        monkeypatch.setenv("CONNECTOR_RECONNECT_DELAY", "2.5")
        monkeypatch.setenv("CONNECTOR_MAX_RECONNECT_DELAY", "120")
        monkeypatch.setenv("CONNECTOR_MAX_CONCURRENT_REQUESTS", "50")

        config = ConnectorConfig.from_env()

        assert config.reconnect_delay == 2.5
        assert config.max_reconnect_delay == 120.0
        assert config.max_concurrent_requests == 50

    def test_from_env_verify_ssl(self, monkeypatch):
        """Test loading verify_ssl from environment."""
        monkeypatch.setenv("CONNECTOR_VERIFY_SSL", "false")

        config = ConnectorConfig.from_env()
        assert config.verify_ssl is False

        monkeypatch.setenv("CONNECTOR_VERIFY_SSL", "true")
        config = ConnectorConfig.from_env()
        assert config.verify_ssl is True


class TestConnectorConfigLoad:
    """Tests for config loading with precedence."""

    def test_load_with_env_override(self, monkeypatch, tmp_path):
        """Test that environment variables override file config."""
        # Create config file
        config_file = tmp_path / "connector.json"
        config_file.write_text(
            """
        {
            "cloud_url": "https://file.example.com",
            "channel": "file-channel",
            "token": "file-token",
            "protocol": "websocket"
        }
        """
        )

        # Set environment override
        monkeypatch.setenv("CONNECTOR_CHANNEL", "env-channel")

        config = ConnectorConfig.load(str(config_file))

        # File values should be used except for overridden
        assert config.cloud_url == "https://file.example.com"
        assert config.channel == "env-channel"  # Overridden by env
        assert config.token == "file-token"

    def test_load_env_override_matching_default(self, monkeypatch, tmp_path):
        """Env var set to the class default value should still override file config."""
        config_file = tmp_path / "connector.json"
        config_file.write_text(
            json.dumps(
                {
                    "cloud_url": "https://file.example.com",
                    "channel": "ch",
                    "token": "tok",
                    "reconnect_delay": 5.0,
                }
            )
        )

        # 1.0 is the class default -- old code would silently ignore this
        monkeypatch.setenv("CONNECTOR_RECONNECT_DELAY", "1.0")

        config = ConnectorConfig.load(str(config_file))

        assert config.reconnect_delay == 1.0  # env must win, not file's 5.0


try:
    import aiohttp  # noqa: F401
    from src.connector.stream_client import SSEClient

    _has_aiohttp = True
except ImportError:
    _has_aiohttp = False


def _make_sse_client(on_message=None):
    """Create an SSEClient with minimal config for testing."""
    config = ConnectorConfig(
        cloud_url="https://example.com",
        channel="test",
        token="tok",
        protocol="sse",
        default_target=TargetConfig(url="http://localhost:8000"),
    )
    if on_message is None:
        on_message = AsyncMock()
    return SSEClient(config=config, on_message=on_message)


def _mock_response(raw_bytes: bytes):
    """Create a mock aiohttp.ClientResponse whose content yields raw_bytes."""

    async def _iter_any():
        yield raw_bytes

    response = MagicMock()
    response.content.iter_any = _iter_any
    return response


@pytest.mark.asyncio
@pytest.mark.skipif(not _has_aiohttp, reason="aiohttp not installed")
class TestSSEParserLoop:
    """Tests for SSEClient._sse_loop parser."""

    async def test_single_line_data(self):
        """Single data: line should be delivered as-is."""
        received = []

        async def capture(msg):
            received.append(msg)

        client = _make_sse_client(on_message=capture)
        payload = json.dumps({"id": "1", "payload": "hello"})
        raw = f"event: webhook\ndata: {payload}\n\n".encode()

        await client._sse_loop(_mock_response(raw))

        assert len(received) == 1
        assert received[0]["id"] == "1"
        assert received[0]["payload"] == "hello"

    async def test_multi_line_data(self):
        """Multiple data: lines must be concatenated with newline separators."""
        received = []

        async def capture(msg):
            received.append(msg)

        client = _make_sse_client(on_message=capture)
        # Simulate pretty-printed JSON split across data lines
        raw = (
            'event: webhook\n'
            'data: {"id": "123",\n'
            'data:  "payload": "large"}\n'
            '\n'
        ).encode()

        await client._sse_loop(_mock_response(raw))

        assert len(received) == 1
        assert received[0]["id"] == "123"
        assert received[0]["payload"] == "large"

    async def test_multiple_events_in_sequence(self):
        """Multiple events separated by blank lines should each be delivered."""
        received = []

        async def capture(msg):
            received.append(msg)

        client = _make_sse_client(on_message=capture)
        e1 = json.dumps({"id": "1"})
        e2 = json.dumps({"id": "2"})
        raw = (
            f"event: webhook\ndata: {e1}\n\n"
            f"event: webhook\ndata: {e2}\n\n"
        ).encode()

        await client._sse_loop(_mock_response(raw))

        assert len(received) == 2
        assert received[0]["id"] == "1"
        assert received[1]["id"] == "2"

    async def test_heartbeat_event(self):
        """Heartbeat events should update last_heartbeat, not invoke on_message."""
        on_message = AsyncMock()
        client = _make_sse_client(on_message=on_message)
        assert client.last_heartbeat is None

        raw = b"event: heartbeat\ndata: ping\n\n"
        await client._sse_loop(_mock_response(raw))

        assert client.last_heartbeat is not None
        on_message.assert_not_called()

    async def test_connected_event(self):
        """Connected events should set connection_id, not invoke on_message."""
        on_message = AsyncMock()
        client = _make_sse_client(on_message=on_message)

        raw = b'event: connected\ndata: {"connection_id": "abc-123"}\n\n'
        await client._sse_loop(_mock_response(raw))

        assert client.connection_id == "abc-123"
        on_message.assert_not_called()


class TestBatchProcessorSharedSession:
    """Tests that BatchProcessor reuses a single MessageProcessor per target group."""

    @pytest.mark.asyncio
    async def test_process_batch_creates_one_processor_per_target_group(self):
        """_process_batch should create one MessageProcessor per target group, not per message."""
        from unittest.mock import patch

        config = ConnectorConfig(
            cloud_url="https://webhooks.example.com",
            channel="ch",
            token="tok",
            targets={
                "default": TargetConfig(url="http://localhost:8000/webhook"),
            },
        )
        ack = AsyncMock()
        nack = AsyncMock()

        from src.connector.processor import BatchProcessor

        bp = BatchProcessor(config, ack, nack)

        batch = [
            {"webhook_id": "default", "message_id": "m1", "payload": "a"},
            {"webhook_id": "default", "message_id": "m2", "payload": "b"},
            {"webhook_id": "default", "message_id": "m3", "payload": "c"},
        ]

        with patch(
            "src.connector.processor.MessageProcessor"
        ) as MockMP:
            mock_instance = AsyncMock()
            MockMP.return_value = mock_instance

            await bp._process_batch(batch)

            # Only one MessageProcessor created for the single target group
            assert MockMP.call_count == 1
            # start/stop called exactly once
            mock_instance.start.assert_awaited_once()
            mock_instance.stop.assert_awaited_once()
            # process called once per message
            assert mock_instance.process.await_count == 3
