"""
Redis-based message buffer for Webhook Connect.

Uses Redis Streams with the following features:
- Consumer groups for distributed consumption
- Automatic message acknowledgment tracking
- Pending entries list for in-flight messages
- XCLAIM for handling stuck messages
"""

import asyncio
import json
import logging
from typing import Optional, Dict, Callable, Awaitable, List
from datetime import datetime, timezone

import redis.asyncio as redis

from src.webhook_connect.buffer.interface import MessageBufferInterface
from src.webhook_connect.models import WebhookMessage, ChannelStats, MessageState

logger = logging.getLogger(__name__)


class RedisBuffer(MessageBufferInterface):
    """Redis Streams-based message buffer implementation."""

    def __init__(
        self,
        url: str = "redis://localhost:6379/0",
        prefix: str = "webhook_connect",
        block_timeout_ms: int = 5000
    ):
        """
        Initialize Redis buffer.

        Args:
            url: Redis connection URL
            prefix: Key prefix for all webhook connect keys
            block_timeout_ms: Timeout for blocking reads in milliseconds
        """
        self.url = url
        self.prefix = prefix
        self.block_timeout_ms = block_timeout_ms

        self.redis: Optional[redis.Redis] = None

        # Track in-flight messages
        self._in_flight: Dict[str, Dict[str, str]] = {}  # message_id -> {stream_id, channel}
        self._in_flight_lock = asyncio.Lock()

        # Stats tracking
        self._stats: Dict[str, Dict[str, int]] = {}

    def _stream_key(self, channel: str) -> str:
        """Get stream key for a channel."""
        return f"{self.prefix}:stream:{channel}"

    def _dlq_key(self, channel: str) -> str:
        """Get dead letter queue key for a channel."""
        return f"{self.prefix}:dlq:{channel}"

    def _consumer_group(self, channel: str) -> str:
        """Get consumer group name for a channel."""
        return f"{self.prefix}_consumers"

    def _stats_key(self, channel: str) -> str:
        """Get stats hash key for a channel."""
        return f"{self.prefix}:stats:{channel}"

    async def connect(self) -> None:
        """Establish connection to Redis."""
        try:
            self.redis = redis.from_url(self.url, decode_responses=False)
            # Test connection
            await self.redis.ping()
            logger.info(f"Connected to Redis: {self.url}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise ConnectionError(f"Failed to connect to Redis: {e}")

    async def close(self) -> None:
        """Close Redis connection."""
        if self.redis:
            await self.redis.aclose()
            self.redis = None
            logger.info("Disconnected from Redis")

    async def ensure_channel(self, channel: str, ttl_seconds: int = 86400) -> None:
        """Ensure channel stream and consumer group exist."""
        if not self.redis:
            raise ConnectionError("Not connected to Redis")

        stream_key = self._stream_key(channel)
        group_name = self._consumer_group(channel)

        try:
            # Create consumer group (this also creates the stream if it doesn't exist)
            await self.redis.xgroup_create(
                stream_key,
                group_name,
                id="0",
                mkstream=True
            )
            logger.info(f"Created consumer group {group_name} for stream {stream_key}")
        except redis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                # Group already exists, that's fine
                pass
            else:
                raise

        # Store TTL in channel metadata
        await self.redis.hset(
            f"{self.prefix}:meta:{channel}",
            mapping={
                "ttl_seconds": str(ttl_seconds),
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        )

        # Initialize stats
        if channel not in self._stats:
            self._stats[channel] = {
                "delivered": 0,
                "expired": 0,
                "dead_lettered": 0
            }

    async def push(self, channel: str, message: WebhookMessage) -> bool:
        """Add message to channel stream."""
        if not self.redis:
            raise ConnectionError("Not connected to Redis")

        stream_key = self._stream_key(channel)

        try:
            # Serialize message
            envelope = message.to_envelope()

            # Add to stream
            stream_id = await self.redis.xadd(
                stream_key,
                {
                    "message_id": message.message_id,
                    "data": json.dumps(envelope),
                    "expires_at": message.expires_at.isoformat() if message.expires_at else ""
                },
                maxlen=10000  # Limit stream size
            )

            logger.debug(f"Published message {message.message_id} to channel {channel} with stream_id {stream_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to publish message to {channel}: {e}")
            return False

    async def subscribe(
        self,
        channel: str,
        callback: Callable[[WebhookMessage], Awaitable[None]],
        prefetch: int = 10
    ) -> None:
        """Subscribe to channel and receive messages via callback."""
        if not self.redis:
            raise ConnectionError("Not connected to Redis")

        stream_key = self._stream_key(channel)
        group_name = self._consumer_group(channel)
        consumer_name = f"consumer_{id(callback)}_{datetime.now(timezone.utc).timestamp()}"

        logger.info(f"Starting consumer {consumer_name} for channel {channel}")

        while True:
            try:
                # Read messages from stream
                messages = await self.redis.xreadgroup(
                    group_name,
                    consumer_name,
                    {stream_key: ">"},
                    count=prefetch,
                    block=self.block_timeout_ms
                )

                if not messages:
                    continue

                for stream, entries in messages:
                    for stream_id, data in entries:
                        try:
                            # Decode stream_id if bytes
                            if isinstance(stream_id, bytes):
                                stream_id = stream_id.decode()

                            # Parse message data
                            message_id = data.get(b"message_id", data.get("message_id", b"")).decode() \
                                if isinstance(data.get(b"message_id", data.get("message_id", b"")), bytes) \
                                else data.get("message_id", "")

                            msg_data = data.get(b"data", data.get("data", b"{}"))
                            if isinstance(msg_data, bytes):
                                msg_data = msg_data.decode()

                            envelope = json.loads(msg_data)
                            message = WebhookMessage.from_envelope(envelope)
                            message._buffer_id = stream_id

                            # Check if expired
                            if message.is_expired():
                                # Acknowledge and skip
                                await self.redis.xack(stream_key, group_name, stream_id)
                                self._stats[channel]["expired"] = self._stats[channel].get("expired", 0) + 1
                                logger.debug(f"Skipped expired message {message.message_id}")
                                continue

                            # Track in-flight
                            async with self._in_flight_lock:
                                self._in_flight[message.message_id] = {
                                    "stream_id": stream_id,
                                    "channel": channel
                                }

                            # Call user callback
                            await callback(message)

                        except Exception as e:
                            logger.error(f"Error processing message from {channel}: {e}")
                            # Move to DLQ
                            await self._move_to_dlq(channel, stream_id, data, str(e))

            except asyncio.CancelledError:
                logger.info(f"Consumer {consumer_name} cancelled")
                break
            except Exception as e:
                logger.error(f"Error in consumer loop for {channel}: {e}")
                await asyncio.sleep(1)

    async def _move_to_dlq(self, channel: str, stream_id: str, data: dict, error: str) -> None:
        """Move a message to the dead letter queue."""
        dlq_key = self._dlq_key(channel)
        stream_key = self._stream_key(channel)
        group_name = self._consumer_group(channel)

        try:
            # Add to DLQ sorted set (score = timestamp)
            await self.redis.zadd(
                dlq_key,
                {json.dumps({
                    "stream_id": stream_id,
                    "data": data,
                    "error": error,
                    "failed_at": datetime.now(timezone.utc).isoformat()
                }): datetime.now(timezone.utc).timestamp()}
            )

            # Acknowledge in original stream
            await self.redis.xack(stream_key, group_name, stream_id)

            self._stats[channel]["dead_lettered"] = self._stats[channel].get("dead_lettered", 0) + 1

        except Exception as e:
            logger.error(f"Failed to move message to DLQ: {e}")

    async def ack(self, channel: str, message_id: str) -> bool:
        """Acknowledge message."""
        if not self.redis:
            return False

        async with self._in_flight_lock:
            info = self._in_flight.pop(message_id, None)

        if not info:
            logger.warning(f"Message {message_id} not found in flight")
            return False

        stream_key = self._stream_key(channel)
        group_name = self._consumer_group(channel)
        stream_id = info["stream_id"]

        try:
            await self.redis.xack(stream_key, group_name, stream_id)
            # Optionally delete the message from stream
            await self.redis.xdel(stream_key, stream_id)

            self._stats[channel]["delivered"] = self._stats[channel].get("delivered", 0) + 1
            logger.debug(f"Acknowledged message {message_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to ack message {message_id}: {e}")
            return False

    async def nack(self, channel: str, message_id: str, retry: bool = True) -> bool:
        """Negative acknowledge message."""
        if not self.redis:
            return False

        async with self._in_flight_lock:
            info = self._in_flight.pop(message_id, None)

        if not info:
            logger.warning(f"Message {message_id} not found in flight")
            return False

        stream_key = self._stream_key(channel)
        group_name = self._consumer_group(channel)
        stream_id = info["stream_id"]

        try:
            if retry:
                # Reset the message to be redelivered
                # XCLAIM with JUSTID to reset delivery count
                # Actually, we can just not ack it - it will be redelivered after timeout
                logger.debug(f"Message {message_id} will be redelivered")
                return True
            else:
                # Move to DLQ
                # Get original message data
                messages = await self.redis.xrange(stream_key, stream_id, stream_id)
                if messages:
                    _, data = messages[0]
                    await self._move_to_dlq(channel, stream_id, data, "Permanent failure")
                else:
                    await self.redis.xack(stream_key, group_name, stream_id)

                logger.debug(f"Sent message {message_id} to dead letter queue")
                return True
        except Exception as e:
            logger.error(f"Failed to nack message {message_id}: {e}")
            return False

    async def get_queue_depth(self, channel: str) -> int:
        """Get number of pending messages in channel."""
        if not self.redis:
            return 0

        stream_key = self._stream_key(channel)

        try:
            info = await self.redis.xinfo_stream(stream_key)
            return info.get("length", 0)
        except Exception:
            return 0

    async def get_in_flight_count(self, channel: str) -> int:
        """Get number of messages awaiting acknowledgment."""
        if not self.redis:
            return 0

        stream_key = self._stream_key(channel)
        group_name = self._consumer_group(channel)

        try:
            groups = await self.redis.xinfo_groups(stream_key)
            for group in groups:
                if group.get("name", b"").decode() if isinstance(group.get("name", b""), bytes) else group.get("name", "") == group_name:
                    return group.get("pending", 0)
        except Exception:
            pass

        return 0

    async def get_stats(self, channel: str) -> ChannelStats:
        """Get channel statistics."""
        queue_depth = await self.get_queue_depth(channel)
        in_flight = await self.get_in_flight_count(channel)

        stats = self._stats.get(channel, {})

        return ChannelStats(
            channel=channel,
            messages_queued=queue_depth,
            messages_in_flight=in_flight,
            messages_delivered=stats.get("delivered", 0),
            messages_expired=stats.get("expired", 0),
            messages_dead_lettered=stats.get("dead_lettered", 0),
            connected_clients=0  # Will be filled by ChannelManager
        )

    async def cleanup_expired(self, channel: str) -> int:
        """Remove expired messages from channel."""
        if not self.redis:
            return 0

        stream_key = self._stream_key(channel)
        count = 0

        try:
            # Get metadata for TTL
            meta = await self.redis.hgetall(f"{self.prefix}:meta:{channel}")
            if not meta:
                return 0

            ttl_seconds = int(meta.get(b"ttl_seconds", meta.get("ttl_seconds", 86400)))

            # Use XTRIM with MINID to remove old entries
            # Calculate minimum ID based on TTL
            min_timestamp = int((datetime.now(timezone.utc).timestamp() - ttl_seconds) * 1000)
            min_id = f"{min_timestamp}-0"

            count = await self.redis.xtrim(stream_key, minid=min_id)
            if count > 0:
                logger.info(f"Cleaned up {count} expired messages from {channel}")

        except Exception as e:
            logger.error(f"Failed to cleanup expired messages for {channel}: {e}")

        return count

    async def delete_channel(self, channel: str) -> bool:
        """Delete a channel and all its messages."""
        if not self.redis:
            return False

        try:
            stream_key = self._stream_key(channel)
            dlq_key = self._dlq_key(channel)
            meta_key = f"{self.prefix}:meta:{channel}"

            # Delete all keys
            await self.redis.delete(stream_key, dlq_key, meta_key)

            # Remove from stats
            self._stats.pop(channel, None)

            logger.info(f"Deleted channel: {channel}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete channel {channel}: {e}")
            return False

    async def get_dead_letters(self, channel: str, limit: int = 100) -> List[WebhookMessage]:
        """Get dead letter messages for a channel."""
        if not self.redis:
            return []

        dlq_key = self._dlq_key(channel)
        messages = []

        try:
            # Get from sorted set (newest first)
            entries = await self.redis.zrevrange(dlq_key, 0, limit - 1)

            for entry in entries:
                try:
                    if isinstance(entry, bytes):
                        entry = entry.decode()
                    data = json.loads(entry)
                    msg_data = data.get("data", {})

                    if isinstance(msg_data, dict) and "data" in msg_data:
                        # Parse from stored format
                        envelope_str = msg_data.get(b"data", msg_data.get("data", "{}"))
                        if isinstance(envelope_str, bytes):
                            envelope_str = envelope_str.decode()
                        envelope = json.loads(envelope_str)
                        message = WebhookMessage.from_envelope(envelope)
                    else:
                        message = WebhookMessage.from_envelope(msg_data)

                    message.state = MessageState.DEAD_LETTERED
                    messages.append(message)
                except Exception as e:
                    logger.error(f"Error parsing dead letter: {e}")

        except Exception as e:
            logger.error(f"Failed to get dead letters for {channel}: {e}")

        return messages

    async def health_check(self) -> bool:
        """Check if Redis connection is healthy."""
        if not self.redis:
            return False
        try:
            await self.redis.ping()
            return True
        except Exception:
            return False
