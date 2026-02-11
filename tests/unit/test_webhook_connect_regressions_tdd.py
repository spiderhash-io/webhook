"""
TDD regression tests for webhook_connect integration issues.

These tests are intentionally written against expected behavior and should
fail on commit 40b1797 before fixes are applied.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.websockets import WebSocketState

from src.webhook_connect.api import websocket_stream, set_channel_manager
from src.webhook_connect.buffer.redis_buffer import RedisBuffer
from src.webhook_connect.channel_manager import ChannelManager
from src.webhook_connect.models import ChannelConfig, ConnectionProtocol, ConnectorConnection, WebhookMessage


@pytest.mark.asyncio
async def test_publish_enforces_queue_limit_for_specific_webhook_queue():
    """Publish should check queue depth for the target webhook queue, not channel aggregate placeholder."""
    buffer = AsyncMock()
    buffer.ensure_channel = AsyncMock()
    buffer.get_queue_depth = AsyncMock(return_value=1)
    buffer.push = AsyncMock(return_value=True)

    manager = ChannelManager(buffer)
    await manager.register_channel(
        name="relay.user-1",
        webhook_id="wh-1",
        token="tok-1",
        ttl=timedelta(hours=1),
        max_queue_size=1,
    )

    msg = WebhookMessage(channel="relay.user-1", webhook_id="wh-1", payload={"x": 1})

    accepted = await manager.publish("relay.user-1", msg)

    assert accepted is False
    buffer.get_queue_depth.assert_awaited_once_with("relay.user-1", webhook_id="wh-1")


@pytest.mark.asyncio
async def test_add_connection_starts_single_consumer_under_concurrency():
    """Concurrent first clients must not start more than one buffer consumer for the same channel."""
    buffer = AsyncMock()

    call_counter = 0

    async def delayed_subscribe(*args, **kwargs):
        nonlocal call_counter
        call_counter += 1
        # Keep first subscribe in-flight long enough for second add_connection path.
        await asyncio.sleep(0.05)
        return f"tag-{call_counter}"

    buffer.subscribe = AsyncMock(side_effect=delayed_subscribe)

    manager = ChannelManager(buffer)
    manager.channels["relay.user-1"] = ChannelConfig(
        name="relay.user-1",
        webhook_id="wh-1",
        channel_token="tok-1",
    )
    manager.channel_connections["relay.user-1"] = set()
    manager._channel_webhook_ids["relay.user-1"] = {"wh-1"}

    conn1 = ConnectorConnection(
        connection_id="c1",
        connector_id="client-1",
        channel="relay.user-1",
        protocol=ConnectionProtocol.WEBSOCKET,
    )
    conn2 = ConnectorConnection(
        connection_id="c2",
        connector_id="client-2",
        channel="relay.user-1",
        protocol=ConnectionProtocol.WEBSOCKET,
    )

    r1, r2 = await asyncio.gather(manager.add_connection(conn1), manager.add_connection(conn2))

    assert r1 is True and r2 is True
    assert buffer.subscribe.await_count == 1


class _FakeWebSocket:
    def __init__(self):
        self.headers = {
            "authorization": "Bearer tok-1",
            "x-connector-id": "connector-1",
            "user-agent": "pytest",
        }
        self.query_params = {}
        self.client = SimpleNamespace(host="127.0.0.1")
        self.client_state = WebSocketState.CONNECTED
        self.closed = False
        self.close_code = None

    async def accept(self):
        return None

    async def close(self, code=None, reason=None):
        self.closed = True
        self.close_code = code

    async def send_json(self, data):
        return None

    async def receive_json(self):
        await asyncio.sleep(0)
        return {}


@pytest.mark.asyncio
async def test_websocket_rejected_connection_does_not_leak_send_fn():
    """If add_connection rejects, API must clean up pre-registered send callback."""
    buffer = AsyncMock()
    manager = ChannelManager(buffer)
    manager.channels["relay.user-1"] = ChannelConfig(
        name="relay.user-1",
        webhook_id="wh-1",
        channel_token="tok-1",
    )
    manager.channel_connections["relay.user-1"] = set()
    manager.add_connection = AsyncMock(return_value=False)

    ws = _FakeWebSocket()
    set_channel_manager(manager)
    try:
        await websocket_stream(ws, "relay.user-1")
    finally:
        set_channel_manager(None)

    assert ws.closed is True
    assert ws.close_code == 4003
    assert manager._connection_send_fns == {}


@pytest.mark.asyncio
async def test_redis_failed_delivery_is_retried_then_dead_lettered():
    """Redis consumer should retry failed delivery and eventually DLQ after retry limit."""
    buffer = RedisBuffer(max_redelivery_attempts=2, requeue_delay_seconds=0.001)
    buffer.redis = AsyncMock()
    buffer._discover_streams = AsyncMock(return_value=["wc:stream:relay.user-1:wh-1"])
    buffer._move_to_dlq = AsyncMock()

    envelope = {
        "message_id": "msg-1",
        "channel": "relay.user-1",
        "webhook_id": "wh-1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": {"x": 1},
        "headers": {},
        "metadata": {},
        "sequence": 1,
        "delivery_count": 0,
        "state": "pending",
    }

    first_batch = [
        (
            b"wc:stream:relay.user-1:wh-1",
            [
                (
                    b"1-0",
                    {
                        b"message_id": b"msg-1",
                        b"data": json.dumps(envelope).encode(),
                    },
                )
            ],
        )
    ]

    read_calls = 0

    async def xreadgroup_side_effect(*args, **kwargs):
        nonlocal read_calls
        read_calls += 1
        if read_calls == 1:
            return first_batch
        await asyncio.sleep(0.005)
        return []

    buffer.redis.xgroup_create = AsyncMock(return_value=True)
    buffer.redis.xreadgroup = AsyncMock(side_effect=xreadgroup_side_effect)

    callback = AsyncMock(side_effect=RuntimeError("connector disconnected"))

    tag = await buffer.subscribe("relay.user-1", callback)
    await asyncio.sleep(0.08)
    await buffer.unsubscribe(tag)

    assert callback.await_count >= 2
    buffer._move_to_dlq.assert_awaited_once()
