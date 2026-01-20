"""
Unit tests for Webhook Connect Local Connector.
"""

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
