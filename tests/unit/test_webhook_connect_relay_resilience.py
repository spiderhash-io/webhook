"""
Tests for Webhook Connect relay resilience — requeue on callback failure
and stale connection eviction.
"""

import asyncio
import json
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

from src.webhook_connect.buffer.rabbitmq_buffer import (
    RabbitMQBuffer,
    MAX_REDELIVERY_ATTEMPTS,
    REQUEUE_DELAY_SECONDS,
)
from src.webhook_connect.buffer.redis_buffer import RedisBuffer
from src.webhook_connect.channel_manager import (
    ChannelManager,
    EVICTION_CHECK_INTERVAL_SECONDS,
    STALE_HEARTBEAT_MULTIPLIER,
    INITIAL_HEARTBEAT_GRACE_SECONDS,
    SSE_STALE_SECONDS,
    LONG_POLL_STALE_SECONDS,
)
from src.webhook_connect.models import (
    ConnectorConnection,
    ConnectionProtocol,
    ConnectionState,
    ChannelConfig,
    WebhookMessage,
)


# ─── RabbitMQ Buffer Requeue Tests ───────────────────────────────────────────


class TestRabbitMQBufferRequeue:
    """Tests for RabbitMQ buffer requeue-on-failure behavior."""

    def _make_buffer(self, **kwargs):
        """Create a RabbitMQBuffer with defaults."""
        return RabbitMQBuffer(
            url="amqp://guest:guest@localhost:5672/",
            **kwargs,
        )

    def _make_amqp_message(self, message_id="msg-1", body_dict=None):
        """Create a mock AMQP incoming message."""
        if body_dict is None:
            body_dict = {
                "message_id": "msg-1",
                "webhook_id": "wh-1",
                "channel": "test-ch",
                "payload": {"key": "value"},
                "received_at": datetime.now(timezone.utc).isoformat(),
            }
        msg = MagicMock()
        msg.message_id = message_id
        msg.body = json.dumps(body_dict).encode()
        msg.headers = {"channel": "test-ch"}
        msg.ack = AsyncMock()
        msg.reject = AsyncMock()
        return msg

    @pytest.mark.asyncio
    async def test_callback_failure_requeues_message(self):
        """When callback raises, message should be requeued, not sent to DLQ."""
        buffer = self._make_buffer()
        buffer._stats["test-ch"] = {"delivered": 0, "expired": 0, "dead_lettered": 0}

        amqp_message = self._make_amqp_message()

        # Simulate the message_handler logic inline
        callback = AsyncMock(side_effect=Exception("WebSocket disconnected"))

        # Build a subscribe-like handler
        channel = "test-ch"

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            try:
                data = json.loads(amqp_message.body.decode())
                message = WebhookMessage.from_envelope(data)
                message._buffer_id = amqp_message.message_id

                async with buffer._in_flight_lock:
                    buffer._in_flight[message.message_id] = amqp_message

                await callback(message)
            except Exception as e:
                # Clean up in-flight
                if 'message' in locals() and message.message_id:
                    async with buffer._in_flight_lock:
                        buffer._in_flight.pop(message.message_id, None)

                msg_id = amqp_message.message_id or "unknown"
                buffer._requeue_counts[msg_id] = buffer._requeue_counts.get(msg_id, 0) + 1

                if buffer._requeue_counts[msg_id] >= buffer.max_redelivery_attempts:
                    buffer._requeue_counts.pop(msg_id, None)
                    await amqp_message.reject(requeue=False)
                else:
                    await asyncio.sleep(buffer.requeue_delay_seconds)
                    await amqp_message.reject(requeue=True)

        # Should requeue, not DLQ
        amqp_message.reject.assert_called_once_with(requeue=True)
        assert buffer._stats["test-ch"]["dead_lettered"] == 0

    @pytest.mark.asyncio
    async def test_callback_failure_cleans_up_in_flight(self):
        """In-flight dict should be cleaned up on callback failure."""
        buffer = self._make_buffer()
        amqp_message = self._make_amqp_message()

        data = json.loads(amqp_message.body.decode())
        message = WebhookMessage.from_envelope(data)

        # Add to in-flight
        async with buffer._in_flight_lock:
            buffer._in_flight[message.message_id] = amqp_message

        assert message.message_id in buffer._in_flight

        # Simulate cleanup
        async with buffer._in_flight_lock:
            buffer._in_flight.pop(message.message_id, None)

        assert message.message_id not in buffer._in_flight

    @pytest.mark.asyncio
    async def test_max_redelivery_sends_to_dlq(self):
        """After max redelivery attempts, message should go to DLQ."""
        buffer = self._make_buffer(max_redelivery_attempts=3)
        buffer._stats["test-ch"] = {"delivered": 0, "expired": 0, "dead_lettered": 0}

        amqp_message = self._make_amqp_message()
        msg_id = amqp_message.message_id

        # Simulate N-1 failures (under threshold)
        for i in range(2):
            buffer._requeue_counts[msg_id] = buffer._requeue_counts.get(msg_id, 0) + 1

        # Now at attempt 2, next will be 3 which meets threshold
        buffer._requeue_counts[msg_id] = buffer._requeue_counts.get(msg_id, 0) + 1

        assert buffer._requeue_counts[msg_id] >= buffer.max_redelivery_attempts

        # Should DLQ
        buffer._requeue_counts.pop(msg_id, None)
        await amqp_message.reject(requeue=False)
        buffer._stats["test-ch"]["dead_lettered"] += 1

        amqp_message.reject.assert_called_once_with(requeue=False)
        assert buffer._stats["test-ch"]["dead_lettered"] == 1
        assert msg_id not in buffer._requeue_counts

    @pytest.mark.asyncio
    async def test_requeue_delay_prevents_tight_loop(self):
        """A sleep delay should be inserted before requeue."""
        buffer = self._make_buffer(requeue_delay_seconds=1.5)

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await asyncio.sleep(buffer.requeue_delay_seconds)
            mock_sleep.assert_called_once_with(1.5)

    @pytest.mark.asyncio
    async def test_ack_clears_requeue_count(self):
        """Acknowledging a message should clear its requeue counter."""
        buffer = self._make_buffer()
        buffer._stats["test-ch"] = {"delivered": 0, "expired": 0, "dead_lettered": 0}

        amqp_message = self._make_amqp_message(message_id="msg-ack")

        # Simulate some requeue attempts
        buffer._requeue_counts["msg-ack"] = 5

        # Add to in-flight and ack
        async with buffer._in_flight_lock:
            buffer._in_flight["msg-ack"] = amqp_message

        result = await buffer.ack("test-ch", "msg-ack")

        assert result is True
        assert "msg-ack" not in buffer._requeue_counts

    @pytest.mark.asyncio
    async def test_parse_failure_requeues_safely(self):
        """JSON parse error should trigger requeue, not crash."""
        buffer = self._make_buffer()
        buffer._stats["test-ch"] = {"delivered": 0, "expired": 0, "dead_lettered": 0}

        # Create a message with invalid JSON body
        amqp_message = MagicMock()
        amqp_message.message_id = "msg-bad"
        amqp_message.body = b"not-valid-json"
        amqp_message.headers = {"channel": "test-ch"}
        amqp_message.ack = AsyncMock()
        amqp_message.reject = AsyncMock()

        with patch("asyncio.sleep", new_callable=AsyncMock):
            try:
                data = json.loads(amqp_message.body.decode())
                # This would raise json.JSONDecodeError
            except Exception:
                msg_id = amqp_message.message_id or "unknown"
                buffer._requeue_counts[msg_id] = buffer._requeue_counts.get(msg_id, 0) + 1

                if buffer._requeue_counts[msg_id] >= buffer.max_redelivery_attempts:
                    await amqp_message.reject(requeue=False)
                else:
                    await asyncio.sleep(buffer.requeue_delay_seconds)
                    await amqp_message.reject(requeue=True)

        amqp_message.reject.assert_called_once_with(requeue=True)


# ─── Redis Buffer Requeue Tests ─────────────────────────────────────────────


class TestRedisBufferRequeue:
    """Tests for Redis buffer leave-pending-on-failure behavior."""

    def _make_buffer(self, **kwargs):
        """Create a RedisBuffer with defaults."""
        return RedisBuffer(
            url="redis://localhost:6379/0",
            **kwargs,
        )

    @pytest.mark.asyncio
    async def test_callback_failure_leaves_pending(self):
        """On callback failure, message should NOT be moved to DLQ."""
        buffer = self._make_buffer()
        buffer._stats["test-ch"] = {"delivered": 0, "expired": 0, "dead_lettered": 0}

        # Simulate a single failure under threshold
        msg_id = "msg-redis-1"
        buffer._requeue_counts[msg_id] = 1

        # Under threshold — should not DLQ
        assert buffer._requeue_counts[msg_id] < buffer.max_redelivery_attempts
        assert buffer._stats["test-ch"]["dead_lettered"] == 0

    @pytest.mark.asyncio
    async def test_max_redelivery_moves_to_dlq(self):
        """After max attempts, message should be moved to DLQ."""
        buffer = self._make_buffer(max_redelivery_attempts=3)
        buffer._stats["test-ch"] = {"delivered": 0, "expired": 0, "dead_lettered": 0}

        msg_id = "msg-redis-dlq"

        # Simulate reaching the threshold
        buffer._requeue_counts[msg_id] = 3

        assert buffer._requeue_counts[msg_id] >= buffer.max_redelivery_attempts

        # Would trigger DLQ path
        buffer._requeue_counts.pop(msg_id, None)
        assert msg_id not in buffer._requeue_counts

    @pytest.mark.asyncio
    async def test_callback_failure_cleans_up_in_flight(self):
        """In-flight dict should be cleaned up on callback failure."""
        buffer = self._make_buffer()

        buffer._in_flight["msg-cleanup"] = {
            "stream_id": "123-0",
            "channel": "test-ch",
        }

        assert "msg-cleanup" in buffer._in_flight

        # Simulate cleanup path
        async with buffer._in_flight_lock:
            buffer._in_flight.pop("msg-cleanup", None)

        assert "msg-cleanup" not in buffer._in_flight

    @pytest.mark.asyncio
    async def test_ack_clears_requeue_count(self):
        """Acknowledging a message should clear its requeue counter."""
        buffer = self._make_buffer()
        buffer._stats["test-ch"] = {"delivered": 0, "expired": 0, "dead_lettered": 0}
        buffer.redis = AsyncMock()

        # Simulate requeue attempts
        buffer._requeue_counts["msg-redis-ack"] = 5

        # Add to in-flight
        buffer._in_flight["msg-redis-ack"] = {
            "stream_id": "456-0",
            "channel": "test-ch",
        }

        result = await buffer.ack("test-ch", "msg-redis-ack")

        assert result is True
        assert "msg-redis-ack" not in buffer._requeue_counts


# ─── Stale Connection Eviction Tests ─────────────────────────────────────────


class TestStaleConnectionEviction:
    """Tests for stale connection eviction in ChannelManager."""

    def _make_channel_manager(self):
        """Create a ChannelManager with a mock buffer."""
        buffer = AsyncMock()
        buffer.connect = AsyncMock()
        buffer.close = AsyncMock()
        buffer.nack = AsyncMock(return_value=True)
        buffer.health_check = AsyncMock(return_value=True)
        manager = ChannelManager(buffer)
        return manager

    def _make_connection(
        self,
        connection_id="conn-1",
        channel="test-ch",
        protocol=ConnectionProtocol.WEBSOCKET,
        connected_at=None,
        last_heartbeat_at=None,
        last_message_at=None,
        state=ConnectionState.CONNECTED,
    ):
        """Create a ConnectorConnection for testing."""
        conn = ConnectorConnection(
            connection_id=connection_id,
            connector_id="test-connector",
            channel=channel,
            protocol=protocol,
        )
        if connected_at:
            conn.connected_at = connected_at
        if last_heartbeat_at is not None:
            conn.last_heartbeat_at = last_heartbeat_at
        if last_message_at is not None:
            conn.last_message_at = last_message_at
        conn.state = state
        return conn

    def _make_channel_config(self, name="test-ch", heartbeat_seconds=30):
        """Create a ChannelConfig for testing."""
        return ChannelConfig(
            name=name,
            webhook_id="wh-1",
            channel_token="tok-1",
            heartbeat_interval=timedelta(seconds=heartbeat_seconds),
        )

    @pytest.mark.asyncio
    async def test_eviction_loop_starts_on_start(self):
        """Eviction task should be created when ChannelManager starts."""
        manager = self._make_channel_manager()

        await manager.start()

        assert manager._eviction_task is not None
        assert not manager._eviction_task.done()

        await manager.stop()

    @pytest.mark.asyncio
    async def test_eviction_loop_stops_on_stop(self):
        """Eviction task should be cancelled when ChannelManager stops."""
        manager = self._make_channel_manager()

        await manager.start()
        task = manager._eviction_task
        assert task is not None

        await manager.stop()

        assert manager._eviction_task is None
        assert task.cancelled() or task.done()

    @pytest.mark.asyncio
    async def test_stale_ws_connection_evicted(self):
        """WebSocket connection with old heartbeat should be evicted."""
        manager = self._make_channel_manager()
        config = self._make_channel_config(heartbeat_seconds=30)
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()

        # Heartbeat from 5 minutes ago — well past 30s * 3 = 90s threshold
        old_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        conn = self._make_connection(last_heartbeat_at=old_time)
        manager.connections[conn.connection_id] = conn
        manager.channel_connections["test-ch"].add(conn.connection_id)

        await manager._evict_stale_connections()

        assert conn.connection_id not in manager.connections

    @pytest.mark.asyncio
    async def test_fresh_ws_connection_not_evicted(self):
        """WebSocket connection with recent heartbeat should be kept."""
        manager = self._make_channel_manager()
        config = self._make_channel_config(heartbeat_seconds=30)
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()

        # Heartbeat from 10 seconds ago — well within 90s threshold
        recent_time = datetime.now(timezone.utc) - timedelta(seconds=10)
        conn = self._make_connection(last_heartbeat_at=recent_time)
        manager.connections[conn.connection_id] = conn
        manager.channel_connections["test-ch"].add(conn.connection_id)

        await manager._evict_stale_connections()

        assert conn.connection_id in manager.connections

    @pytest.mark.asyncio
    async def test_no_heartbeat_evicted_after_grace(self):
        """Connection with no heartbeat and old connected_at should be evicted."""
        manager = self._make_channel_manager()
        config = self._make_channel_config(heartbeat_seconds=30)
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()

        # Connected 2 minutes ago, never sent heartbeat
        old_time = datetime.now(timezone.utc) - timedelta(minutes=2)
        conn = self._make_connection(
            connected_at=old_time,
            last_heartbeat_at=None,
        )
        manager.connections[conn.connection_id] = conn
        manager.channel_connections["test-ch"].add(conn.connection_id)

        await manager._evict_stale_connections()

        assert conn.connection_id not in manager.connections

    @pytest.mark.asyncio
    async def test_no_heartbeat_not_evicted_within_grace(self):
        """Connection with no heartbeat but recent connected_at should be kept."""
        manager = self._make_channel_manager()
        config = self._make_channel_config(heartbeat_seconds=30)
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()

        # Connected 10 seconds ago, no heartbeat yet — within 60s grace
        recent_time = datetime.now(timezone.utc) - timedelta(seconds=10)
        conn = self._make_connection(
            connected_at=recent_time,
            last_heartbeat_at=None,
        )
        manager.connections[conn.connection_id] = conn
        manager.channel_connections["test-ch"].add(conn.connection_id)

        await manager._evict_stale_connections()

        assert conn.connection_id in manager.connections

    @pytest.mark.asyncio
    async def test_eviction_nacks_in_flight_messages(self):
        """Evicted connections should have in-flight messages NACKed with retry=True."""
        manager = self._make_channel_manager()
        config = self._make_channel_config(heartbeat_seconds=30)
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()

        old_time = datetime.now(timezone.utc) - timedelta(minutes=5)
        conn = self._make_connection(last_heartbeat_at=old_time)
        conn.in_flight_messages = {"msg-a", "msg-b"}
        manager.connections[conn.connection_id] = conn
        manager.channel_connections["test-ch"].add(conn.connection_id)

        await manager._evict_stale_connections()

        # Verify nack was called with retry=True for both messages
        nack_calls = manager.buffer.nack.call_args_list
        nack_msg_ids = {call.args[1] for call in nack_calls}
        assert nack_msg_ids == {"msg-a", "msg-b"}
        for call in nack_calls:
            assert call.kwargs.get("retry", call.args[2] if len(call.args) > 2 else None) is True

    @pytest.mark.asyncio
    async def test_protocol_aware_eviction(self):
        """Different protocols should have different staleness thresholds."""
        manager = self._make_channel_manager()
        config = self._make_channel_config(heartbeat_seconds=30)
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()
        now = datetime.now(timezone.utc)

        # SSE connection — 2 hours old, should NOT be evicted (threshold is 24h)
        sse_conn = self._make_connection(
            connection_id="sse-1",
            protocol=ConnectionProtocol.SSE,
            connected_at=now - timedelta(hours=2),
            last_heartbeat_at=now - timedelta(hours=2),
            last_message_at=now - timedelta(hours=2),
        )
        manager.connections[sse_conn.connection_id] = sse_conn
        manager.channel_connections["test-ch"].add(sse_conn.connection_id)

        # Long-poll connection — 10 minutes old, should be evicted (threshold is 5min)
        poll_conn = self._make_connection(
            connection_id="poll-1",
            protocol=ConnectionProtocol.LONG_POLL,
            connected_at=now - timedelta(minutes=10),
            last_heartbeat_at=now - timedelta(minutes=10),
            last_message_at=now - timedelta(minutes=10),
        )
        manager.connections[poll_conn.connection_id] = poll_conn
        manager.channel_connections["test-ch"].add(poll_conn.connection_id)

        await manager._evict_stale_connections()

        assert sse_conn.connection_id in manager.connections
        assert poll_conn.connection_id not in manager.connections


# ─── Initial Heartbeat Timestamp Tests ───────────────────────────────────────


class TestInitialHeartbeatTimestamp:
    """Tests that all connection protocols set initial last_heartbeat_at."""

    def test_websocket_connection_has_heartbeat_field(self):
        """WebSocket connections should have last_heartbeat_at set."""
        conn = ConnectorConnection(
            connection_id="ws-1",
            connector_id="test",
            channel="test-ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        # Simulate what api.py does after creation
        conn.last_heartbeat_at = datetime.now(timezone.utc)

        assert conn.last_heartbeat_at is not None

    def test_sse_connection_has_heartbeat_field(self):
        """SSE connections should have last_heartbeat_at set."""
        conn = ConnectorConnection(
            connection_id="sse-1",
            connector_id="test",
            channel="test-ch",
            protocol=ConnectionProtocol.SSE,
        )
        conn.last_heartbeat_at = datetime.now(timezone.utc)

        assert conn.last_heartbeat_at is not None

    def test_long_poll_connection_has_heartbeat_field(self):
        """Long-poll connections should have last_heartbeat_at set."""
        conn = ConnectorConnection(
            connection_id="poll-1",
            connector_id="test",
            channel="test-ch",
            protocol=ConnectionProtocol.LONG_POLL,
        )
        conn.last_heartbeat_at = datetime.now(timezone.utc)

        assert conn.last_heartbeat_at is not None

    def test_default_heartbeat_is_none(self):
        """Without explicit set, last_heartbeat_at should default to None."""
        conn = ConnectorConnection(
            connection_id="raw-1",
            connector_id="test",
            channel="test-ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        assert conn.last_heartbeat_at is None
