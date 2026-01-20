"""
Unit tests for Webhook Connect models.
"""

import pytest
from datetime import datetime, timedelta, timezone
from src.webhook_connect.models import (
    WebhookMessage,
    ChannelConfig,
    ConnectorConnection,
    ChannelStats,
    ConnectionProtocol,
    ConnectionState,
    AckStatus,
    MessageState,
)


class TestWebhookMessage:
    """Tests for WebhookMessage model."""

    def test_create_message(self):
        """Test creating a WebhookMessage."""
        msg = WebhookMessage(
            channel="test-channel",
            webhook_id="test-webhook",
            payload={"key": "value"},
            headers={"Content-Type": "application/json"},
        )

        assert msg.channel == "test-channel"
        assert msg.webhook_id == "test-webhook"
        assert msg.payload == {"key": "value"}
        assert msg.state == MessageState.PENDING
        assert msg.message_id.startswith("msg_")
        assert msg.delivery_count == 0

    def test_message_id_generation(self):
        """Test that message IDs are unique."""
        msg1 = WebhookMessage(channel="c", webhook_id="w", payload={})
        msg2 = WebhookMessage(channel="c", webhook_id="w", payload={})

        assert msg1.message_id != msg2.message_id

    def test_message_expiration(self):
        """Test message expiration check."""
        # Create message with past expiration
        msg = WebhookMessage(
            channel="c",
            webhook_id="w",
            payload={},
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert msg.is_expired() is True

        # Create message with future expiration
        msg2 = WebhookMessage(
            channel="c",
            webhook_id="w",
            payload={},
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert msg2.is_expired() is False

    def test_to_wire_format(self):
        """Test message wire format serialization."""
        msg = WebhookMessage(
            channel="test",
            webhook_id="webhook-1",
            payload={"data": "test"},
            headers={"X-Test": "value"},
        )

        wire = msg.to_wire_format()

        assert wire["type"] == "webhook"
        assert wire["message_id"] == msg.message_id
        # Data is flat in wire format for connector compatibility
        assert wire["webhook_id"] == "webhook-1"
        assert wire["payload"] == {"data": "test"}
        assert wire["headers"] == {"X-Test": "value"}

    def test_to_envelope(self):
        """Test message envelope serialization."""
        msg = WebhookMessage(
            channel="test",
            webhook_id="webhook-1",
            payload={"data": "test"},
        )

        envelope = msg.to_envelope()

        assert "message_id" in envelope
        assert "channel" in envelope
        assert "webhook_id" in envelope
        assert "payload" in envelope
        assert "timestamp" in envelope  # received_at is serialized as timestamp

    def test_from_envelope(self):
        """Test message deserialization from envelope."""
        original = WebhookMessage(
            channel="test",
            webhook_id="webhook-1",
            payload={"data": "test"},
            headers={"X-Test": "value"},
            metadata={"source": "test"},
        )

        envelope = original.to_envelope()
        restored = WebhookMessage.from_envelope(envelope)

        assert restored.message_id == original.message_id
        assert restored.channel == original.channel
        assert restored.webhook_id == original.webhook_id
        assert restored.payload == original.payload
        assert restored.headers == original.headers


class TestChannelConfig:
    """Tests for ChannelConfig model."""

    def test_create_config(self):
        """Test creating a ChannelConfig."""
        config = ChannelConfig(
            name="test-channel",
            webhook_id="webhook-1",
            channel_token="secret-token",
        )

        assert config.name == "test-channel"
        assert config.webhook_id == "webhook-1"
        assert config.channel_token == "secret-token"
        assert config.max_queue_size == 10000
        assert config.max_connections == 10

    def test_token_validation(self):
        """Test token validation."""
        config = ChannelConfig(
            name="test",
            webhook_id="w",
            channel_token="valid-token",
        )

        assert config.validate_token("valid-token") is True
        assert config.validate_token("invalid-token") is False
        assert config.validate_token("") is False
        assert config.validate_token(None) is False

    def test_old_token_validation(self):
        """Test old token validation during rotation."""
        config = ChannelConfig(
            name="test",
            webhook_id="w",
            channel_token="new-token",
            old_token="old-token",
            old_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        # Both tokens should be valid
        assert config.validate_token("new-token") is True
        assert config.validate_token("old-token") is True

    def test_expired_old_token(self):
        """Test that expired old tokens are rejected."""
        config = ChannelConfig(
            name="test",
            webhook_id="w",
            channel_token="new-token",
            old_token="old-token",
            old_token_expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )

        assert config.validate_token("new-token") is True
        assert config.validate_token("old-token") is False

    def test_to_dict(self):
        """Test config serialization."""
        config = ChannelConfig(
            name="test",
            webhook_id="w",
            channel_token="token",
            max_queue_size=5000,
        )

        data = config.to_dict()

        assert data["name"] == "test"
        assert data["webhook_id"] == "w"
        assert data["max_queue_size"] == 5000
        # Token should not be in dict (sensitive)
        assert "channel_token" not in data


class TestConnectorConnection:
    """Tests for ConnectorConnection model."""

    def test_create_connection(self):
        """Test creating a connection."""
        conn = ConnectorConnection(
            connection_id="conn-1",
            connector_id="connector-1",
            channel="test-channel",
            protocol=ConnectionProtocol.WEBSOCKET,
        )

        assert conn.connection_id == "conn-1"
        assert conn.connector_id == "connector-1"
        assert conn.channel == "test-channel"
        assert conn.protocol == ConnectionProtocol.WEBSOCKET
        assert conn.state == ConnectionState.CONNECTING  # Default is CONNECTING
        assert conn.messages_received == 0

    def test_in_flight_tracking(self):
        """Test in-flight message tracking."""
        conn = ConnectorConnection(
            connection_id="conn-1",
            connector_id="c-1",
            channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )

        conn.in_flight_messages.add("msg-1")
        conn.in_flight_messages.add("msg-2")

        assert "msg-1" in conn.in_flight_messages
        assert "msg-2" in conn.in_flight_messages
        assert len(conn.in_flight_messages) == 2

        conn.in_flight_messages.discard("msg-1")
        assert len(conn.in_flight_messages) == 1

    def test_to_dict(self):
        """Test connection serialization."""
        conn = ConnectorConnection(
            connection_id="conn-1",
            connector_id="c-1",
            channel="ch",
            protocol=ConnectionProtocol.WEBSOCKET,
            remote_ip="127.0.0.1",
        )

        data = conn.to_dict()

        assert data["connection_id"] == "conn-1"
        assert data["connector_id"] == "c-1"
        assert data["channel"] == "ch"
        assert data["protocol"] == "websocket"


class TestChannelStats:
    """Tests for ChannelStats model."""

    def test_create_stats(self):
        """Test creating channel stats."""
        stats = ChannelStats(
            channel="test",
            messages_queued=100,
            messages_delivered=50,
            connected_clients=2,
        )

        assert stats.channel == "test"
        assert stats.messages_queued == 100
        assert stats.messages_delivered == 50
        assert stats.connected_clients == 2

    def test_to_dict(self):
        """Test stats serialization."""
        stats = ChannelStats(
            channel="test",
            messages_queued=100,
            messages_in_flight=10,
            messages_delivered=50,
            messages_expired=5,
            messages_dead_lettered=2,
            connected_clients=3,
        )

        data = stats.to_dict()

        assert data["channel"] == "test"
        assert data["messages_queued"] == 100
        assert data["messages_in_flight"] == 10
        # Check actual fields in the model
        assert data["messages_delivered"] == 50


class TestEnums:
    """Tests for enum values."""

    def test_connection_protocol(self):
        """Test ConnectionProtocol enum."""
        assert ConnectionProtocol.WEBSOCKET.value == "websocket"
        assert ConnectionProtocol.SSE.value == "sse"

    def test_connection_state(self):
        """Test ConnectionState enum."""
        assert ConnectionState.CONNECTED.value == "connected"
        assert ConnectionState.DISCONNECTED.value == "disconnected"

    def test_ack_status(self):
        """Test AckStatus enum."""
        assert AckStatus.ACK.value == "ack"
        assert AckStatus.NACK_RETRY.value == "nack_retry"
        assert AckStatus.NACK_REJECT.value == "nack_reject"

    def test_message_state(self):
        """Test MessageState enum."""
        assert MessageState.PENDING.value == "pending"
        assert MessageState.DELIVERED.value == "delivered"
        assert MessageState.DEAD_LETTERED.value == "dead_lettered"
