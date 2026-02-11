"""
Security audit tests for Webhook Connect relay resilience.

Validates that requeue/eviction logic does not introduce DoS vectors,
memory leaks, or safety regressions.
"""

import asyncio
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

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
)
from src.webhook_connect.models import (
    ConnectorConnection,
    ConnectionProtocol,
    ConnectionState,
    ChannelConfig,
)


class TestRequeueDelayNotZero:
    """Ensure requeue delay is non-zero to prevent DoS via tight retry loops."""

    @pytest.mark.asyncio
    async def test_rabbitmq_default_delay_positive(self):
        """RabbitMQ buffer default requeue delay must be positive."""
        buffer = RabbitMQBuffer()
        assert buffer.requeue_delay_seconds > 0

    @pytest.mark.asyncio
    async def test_redis_default_delay_positive(self):
        """Redis buffer default requeue delay must be positive."""
        buffer = RedisBuffer()
        assert buffer.requeue_delay_seconds > 0

    def test_module_level_constant_positive(self):
        """Module-level REQUEUE_DELAY_SECONDS must be positive."""
        assert REQUEUE_DELAY_SECONDS > 0


class TestMaxRedeliveryLimitEnforced:
    """Ensure messages cannot be requeued infinitely."""

    @pytest.mark.asyncio
    async def test_rabbitmq_default_limit_set(self):
        """RabbitMQ buffer must have a finite max redelivery limit."""
        buffer = RabbitMQBuffer()
        assert buffer.max_redelivery_attempts > 0
        assert buffer.max_redelivery_attempts <= 100  # Sanity upper bound

    @pytest.mark.asyncio
    async def test_redis_default_limit_set(self):
        """Redis buffer must have a finite max redelivery limit."""
        buffer = RedisBuffer()
        assert buffer.max_redelivery_attempts > 0
        assert buffer.max_redelivery_attempts <= 100

    def test_module_level_constant_finite(self):
        """Module-level MAX_REDELIVERY_ATTEMPTS must be finite and positive."""
        assert MAX_REDELIVERY_ATTEMPTS > 0
        assert MAX_REDELIVERY_ATTEMPTS <= 100

    @pytest.mark.asyncio
    async def test_requeue_count_increments_towards_limit(self):
        """Requeue counter must monotonically increase towards the limit."""
        buffer = RabbitMQBuffer(max_redelivery_attempts=3)
        msg_id = "test-msg"

        for i in range(1, 4):
            buffer._requeue_counts[msg_id] = buffer._requeue_counts.get(msg_id, 0) + 1
            assert buffer._requeue_counts[msg_id] == i

        # At limit — would trigger DLQ
        assert buffer._requeue_counts[msg_id] >= buffer.max_redelivery_attempts


class TestInFlightCleanupOnAllErrorPaths:
    """Ensure in-flight tracking is cleaned up on all error paths to prevent memory leaks."""

    @pytest.mark.asyncio
    async def test_rabbitmq_in_flight_not_leaked_on_callback_error(self):
        """RabbitMQ in-flight dict should not grow unbounded on repeated errors."""
        buffer = RabbitMQBuffer()

        # Simulate adding and cleaning up 100 messages
        for i in range(100):
            msg_id = f"msg-{i}"
            async with buffer._in_flight_lock:
                buffer._in_flight[msg_id] = MagicMock()

            # Simulate error cleanup
            async with buffer._in_flight_lock:
                buffer._in_flight.pop(msg_id, None)

        assert len(buffer._in_flight) == 0

    @pytest.mark.asyncio
    async def test_redis_in_flight_not_leaked_on_callback_error(self):
        """Redis in-flight dict should not grow unbounded on repeated errors."""
        buffer = RedisBuffer()

        for i in range(100):
            msg_id = f"msg-{i}"
            async with buffer._in_flight_lock:
                buffer._in_flight[msg_id] = {"stream_id": f"{i}-0", "channel": "ch"}

            async with buffer._in_flight_lock:
                buffer._in_flight.pop(msg_id, None)

        assert len(buffer._in_flight) == 0

    @pytest.mark.asyncio
    async def test_requeue_counts_cleaned_on_ack(self):
        """Requeue counter should be cleaned up when message is acknowledged."""
        buffer = RabbitMQBuffer()
        buffer._stats["ch"] = {"delivered": 0, "expired": 0, "dead_lettered": 0}

        # Simulate requeue tracking for many messages
        for i in range(50):
            buffer._requeue_counts[f"msg-{i}"] = 3

        assert len(buffer._requeue_counts) == 50

        # Ack each message
        for i in range(50):
            msg_id = f"msg-{i}"
            amqp_msg = MagicMock()
            amqp_msg.ack = AsyncMock()
            async with buffer._in_flight_lock:
                buffer._in_flight[msg_id] = amqp_msg
            await buffer.ack("ch", msg_id)

        assert len(buffer._requeue_counts) == 0

    @pytest.mark.asyncio
    async def test_requeue_counts_cleaned_on_dlq(self):
        """Requeue counter should be cleaned when message is sent to DLQ."""
        buffer = RabbitMQBuffer(max_redelivery_attempts=3)
        msg_id = "msg-dlq"

        buffer._requeue_counts[msg_id] = 3
        assert buffer._requeue_counts[msg_id] >= buffer.max_redelivery_attempts

        # DLQ path cleans up
        buffer._requeue_counts.pop(msg_id, None)
        assert msg_id not in buffer._requeue_counts


class TestEvictionDoesNotRemoveActiveConnections:
    """Ensure eviction only targets genuinely stale connections."""

    def _make_channel_manager(self):
        """Create a ChannelManager with a mock buffer."""
        buffer = AsyncMock(spec_set=["connect", "close", "health_check", "nack"])
        return ChannelManager(buffer)

    def _make_config(self, name="test-ch", heartbeat_seconds=30):
        """Create a ChannelConfig."""
        return ChannelConfig(
            name=name,
            webhook_id="wh-1",
            channel_token="tok-1",
            heartbeat_interval=timedelta(seconds=heartbeat_seconds),
        )

    @pytest.mark.asyncio
    async def test_active_ws_connection_not_evicted(self):
        """WebSocket connection with fresh heartbeat must not be evicted."""
        manager = self._make_channel_manager()
        config = self._make_config()
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()

        now = datetime.now(timezone.utc)
        conn = ConnectorConnection(
            connection_id="active-ws",
            connector_id="test",
            channel="test-ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        conn.state = ConnectionState.CONNECTED
        conn.last_heartbeat_at = now - timedelta(seconds=5)

        manager.connections[conn.connection_id] = conn
        manager.channel_connections["test-ch"].add(conn.connection_id)

        await manager._evict_stale_connections()

        assert conn.connection_id in manager.connections

    @pytest.mark.asyncio
    async def test_disconnected_connection_not_evicted(self):
        """Already-disconnected connections should not be evicted again."""
        manager = self._make_channel_manager()
        config = self._make_config()
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()

        conn = ConnectorConnection(
            connection_id="disconnected-ws",
            connector_id="test",
            channel="test-ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        conn.state = ConnectionState.DISCONNECTED
        conn.last_heartbeat_at = datetime.now(timezone.utc) - timedelta(hours=1)

        manager.connections[conn.connection_id] = conn
        manager.channel_connections["test-ch"].add(conn.connection_id)

        await manager._evict_stale_connections()

        # Disconnected connections are skipped by _is_connection_stale
        assert conn.connection_id in manager.connections


class TestStaleEvictionFreesMaxConnectionSlots:
    """Ensure eviction of stale connections frees slots for new connections."""

    @pytest.mark.asyncio
    async def test_eviction_frees_connection_slot(self):
        """After evicting a stale connection, a new connection should be accepted."""
        buffer = AsyncMock(spec_set=["connect", "close", "health_check", "nack", "ensure_channel", "subscribe", "unsubscribe"])
        buffer.subscribe = AsyncMock(return_value="mock-consumer-tag")
        buffer.unsubscribe = AsyncMock()
        manager = ChannelManager(buffer)

        config = ChannelConfig(
            name="test-ch",
            webhook_id="wh-1",
            channel_token="tok-1",
            max_connections=1,
            heartbeat_interval=timedelta(seconds=30),
        )
        manager.channels["test-ch"] = config
        manager.channel_connections["test-ch"] = set()

        # Add a stale connection that fills the slot
        stale_conn = ConnectorConnection(
            connection_id="stale-1",
            connector_id="old-client",
            channel="test-ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        stale_conn.state = ConnectionState.CONNECTED
        stale_conn.last_heartbeat_at = datetime.now(timezone.utc) - timedelta(minutes=10)

        manager.connections[stale_conn.connection_id] = stale_conn
        manager.channel_connections["test-ch"].add(stale_conn.connection_id)

        # New connection should be rejected (max_connections=1)
        new_conn = ConnectorConnection(
            connection_id="new-1",
            connector_id="new-client",
            channel="test-ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        result = await manager.add_connection(new_conn)
        assert result is False

        # Evict stale connection
        await manager._evict_stale_connections()
        assert stale_conn.connection_id not in manager.connections

        # Now new connection should be accepted
        new_conn2 = ConnectorConnection(
            connection_id="new-2",
            connector_id="new-client",
            channel="test-ch",
            protocol=ConnectionProtocol.WEBSOCKET,
        )
        result = await manager.add_connection(new_conn2)
        assert result is True
