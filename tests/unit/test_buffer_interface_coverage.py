"""
Unit tests for MessageBufferInterface (buffer/interface.py).

Covers:
- ABC methods raise NotImplementedError when not overridden
- Concrete default methods: subscribe_webhook, health_check, get_webhook_queue_depths
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.webhook_connect.buffer.interface import MessageBufferInterface
from src.webhook_connect.models import WebhookMessage, ChannelStats


class ConcreteBuffer(MessageBufferInterface):
    """Minimal concrete subclass to test abstract interface defaults."""

    async def connect(self):
        pass

    async def close(self):
        pass

    async def push(self, channel, message):
        return True

    async def subscribe(self, channel, callback, prefetch=10, webhook_ids=None):
        return "tag"

    async def unsubscribe(self, consumer_tag):
        pass

    async def ack(self, channel, message_id):
        return True

    async def nack(self, channel, message_id, retry=True):
        return True

    async def get_queue_depth(self, channel, webhook_id=None):
        return 5

    async def get_in_flight_count(self, channel):
        return 0

    async def get_stats(self, channel):
        return ChannelStats(channel=channel)

    async def cleanup_expired(self, channel):
        return 0

    async def ensure_channel(self, channel, ttl_seconds=86400, webhook_id=None):
        pass

    async def delete_channel(self, channel, webhook_ids=None):
        return True

    async def get_dead_letters(self, channel, limit=100):
        return []


class TestMessageBufferInterfaceDefaults:
    """Tests for concrete default methods on the ABC."""

    @pytest.mark.asyncio
    async def test_subscribe_webhook_returns_none_by_default(self):
        """Default subscribe_webhook returns None (no-op)."""
        buf = ConcreteBuffer()
        result = await buf.subscribe_webhook("ch", "wh-1")
        assert result is None

    @pytest.mark.asyncio
    async def test_subscribe_webhook_with_callback_returns_none(self):
        """Default subscribe_webhook ignores callback and returns None."""
        buf = ConcreteBuffer()
        cb = AsyncMock()
        result = await buf.subscribe_webhook("ch", "wh-1", callback=cb)
        assert result is None

    @pytest.mark.asyncio
    async def test_health_check_delegates_to_get_queue_depth(self):
        """Default health_check calls get_queue_depth with __health_check__."""
        buf = ConcreteBuffer()
        result = await buf.health_check()
        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_returns_false_on_exception(self):
        """health_check returns False when get_queue_depth raises."""
        buf = ConcreteBuffer()
        buf.get_queue_depth = AsyncMock(side_effect=Exception("connection lost"))
        result = await buf.health_check()
        assert result is False

    @pytest.mark.asyncio
    async def test_get_webhook_queue_depths_iterates_webhook_ids(self):
        """get_webhook_queue_depths returns depth for each webhook_id."""
        buf = ConcreteBuffer()
        depths = await buf.get_webhook_queue_depths("ch", ["wh-1", "wh-2", "wh-3"])
        assert depths == {"wh-1": 5, "wh-2": 5, "wh-3": 5}

    @pytest.mark.asyncio
    async def test_get_webhook_queue_depths_empty_list(self):
        """get_webhook_queue_depths returns empty dict for empty list."""
        buf = ConcreteBuffer()
        depths = await buf.get_webhook_queue_depths("ch", [])
        assert depths == {}


class TestABCEnforcement:
    """Verify that abstract methods cannot be instantiated without implementation."""

    def test_cannot_instantiate_abstract_class(self):
        """MessageBufferInterface cannot be instantiated directly."""
        with pytest.raises(TypeError):
            MessageBufferInterface()

    def test_missing_method_raises_type_error(self):
        """Subclass missing abstract method raises TypeError on instantiation."""

        class IncompleteBuffer(MessageBufferInterface):
            pass

        with pytest.raises(TypeError):
            IncompleteBuffer()
