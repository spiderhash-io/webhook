"""
RabbitMQ-based message buffer for Webhook Connect.

Uses RabbitMQ queues with the following features:
- Durable queues for message persistence
- Dead letter exchange for failed messages
- Message TTL support
- Consumer acknowledgment mode
"""

import asyncio
import json
import logging
from typing import Optional, Dict, Callable, Awaitable, List
from datetime import datetime

import aio_pika
from aio_pika import connect_robust, Message, DeliveryMode, ExchangeType
from aio_pika.abc import AbstractIncomingMessage

from src.webhook_connect.buffer.interface import MessageBufferInterface
from src.webhook_connect.models import WebhookMessage, ChannelStats, MessageState

logger = logging.getLogger(__name__)


class RabbitMQBuffer(MessageBufferInterface):
    """RabbitMQ-based message buffer implementation."""

    def __init__(
        self,
        url: str = "amqp://guest:guest@localhost:5672/",
        exchange_name: str = "webhook_connect",
        prefetch_count: int = 100,
    ):
        """
        Initialize RabbitMQ buffer.

        Args:
            url: AMQP connection URL
            exchange_name: Name of the exchange for webhook connect
            prefetch_count: Number of messages to prefetch per consumer
        """
        self.url = url
        self.exchange_name = exchange_name
        self.prefetch_count = prefetch_count

        self.connection: Optional[aio_pika.RobustConnection] = None
        self.channel: Optional[aio_pika.Channel] = None
        self.exchange: Optional[aio_pika.Exchange] = None
        self.dlx_exchange: Optional[aio_pika.Exchange] = None

        # Track in-flight messages for ack/nack
        self._in_flight: Dict[str, AbstractIncomingMessage] = {}
        self._in_flight_lock = asyncio.Lock()

        # Stats tracking
        self._stats: Dict[str, Dict[str, int]] = {}

    def _queue_name(self, channel: str) -> str:
        """Get queue name for a channel."""
        return f"webhook_connect.{channel}"

    def _dlq_name(self, channel: str) -> str:
        """Get dead letter queue name for a channel."""
        return f"webhook_connect.{channel}.dlq"

    def _routing_key(self, channel: str) -> str:
        """Get routing key for a channel."""
        return f"channel.{channel}"

    async def connect(self) -> None:
        """Establish connection to RabbitMQ."""
        try:
            self.connection = await connect_robust(self.url)
            self.channel = await self.connection.channel()
            await self.channel.set_qos(prefetch_count=self.prefetch_count)

            # Create main exchange for webhook messages
            self.exchange = await self.channel.declare_exchange(
                self.exchange_name, ExchangeType.DIRECT, durable=True
            )

            # Create dead letter exchange
            self.dlx_exchange = await self.channel.declare_exchange(
                f"{self.exchange_name}.dlx", ExchangeType.DIRECT, durable=True
            )

            logger.info(f"Connected to RabbitMQ: {self.url}")

        except Exception as e:
            logger.error(f"Failed to connect to RabbitMQ: {e}")
            raise ConnectionError(f"Failed to connect to RabbitMQ: {e}")

    async def close(self) -> None:
        """Close RabbitMQ connection."""
        if self.connection:
            await self.connection.close()
            self.connection = None
            self.channel = None
            self.exchange = None
            logger.info("Disconnected from RabbitMQ")

    async def ensure_channel(self, channel: str, ttl_seconds: int = 86400) -> None:
        """Ensure channel queue exists with proper configuration."""
        if not self.channel:
            raise ConnectionError("Not connected to RabbitMQ")

        queue_name = self._queue_name(channel)
        dlq_name = self._dlq_name(channel)
        routing_key = self._routing_key(channel)

        # Create dead letter queue first
        dlq = await self.channel.declare_queue(
            dlq_name, durable=True, arguments={"x-queue-type": "classic"}
        )
        await dlq.bind(self.dlx_exchange, routing_key=routing_key)

        # Create main queue with DLX configuration
        queue = await self.channel.declare_queue(
            queue_name,
            durable=True,
            arguments={
                "x-dead-letter-exchange": f"{self.exchange_name}.dlx",
                "x-dead-letter-routing-key": routing_key,
                "x-message-ttl": ttl_seconds * 1000,  # Convert to milliseconds
                "x-queue-type": "classic",
            },
        )
        await queue.bind(self.exchange, routing_key=routing_key)

        # Initialize stats for this channel
        if channel not in self._stats:
            self._stats[channel] = {"delivered": 0, "expired": 0, "dead_lettered": 0}

        logger.info(f"Ensured channel queue: {queue_name} with TTL {ttl_seconds}s")

    async def push(self, channel: str, message: WebhookMessage) -> bool:
        """Add message to channel queue."""
        if not self.exchange:
            raise ConnectionError("Not connected to RabbitMQ")

        try:
            # Serialize message to JSON
            body = json.dumps(message.to_envelope()).encode()

            # Create AMQP message
            amqp_message = Message(
                body=body,
                message_id=message.message_id,
                timestamp=message.received_at,
                delivery_mode=DeliveryMode.PERSISTENT,
                headers={"channel": channel, "webhook_id": message.webhook_id},
            )

            # Publish to exchange
            routing_key = self._routing_key(channel)
            await self.exchange.publish(amqp_message, routing_key=routing_key)

            logger.debug(f"Published message {message.message_id} to channel {channel}")
            return True

        except Exception as e:
            logger.error(f"Failed to publish message to {channel}: {e}")
            return False

    async def subscribe(
        self,
        channel: str,
        callback: Callable[[WebhookMessage], Awaitable[None]],
        prefetch: int = 10,
    ) -> None:
        """Subscribe to channel and receive messages via callback."""
        if not self.channel:
            raise ConnectionError("Not connected to RabbitMQ")

        queue_name = self._queue_name(channel)

        # Get queue reference
        queue = await self.channel.get_queue(queue_name)

        async def message_handler(amqp_message: AbstractIncomingMessage):
            """Handle incoming AMQP message."""
            try:
                # Parse message
                data = json.loads(amqp_message.body.decode())
                message = WebhookMessage.from_envelope(data)
                message._buffer_id = amqp_message.message_id

                # Track in-flight
                async with self._in_flight_lock:
                    self._in_flight[message.message_id] = amqp_message

                # Call user callback
                await callback(message)

            except Exception as e:
                logger.error(f"Error processing message from {channel}: {e}")
                # Reject message, send to DLQ
                await amqp_message.reject(requeue=False)

        # Start consuming
        await queue.consume(message_handler)
        logger.info(f"Subscribed to channel: {channel}")

        # Keep running until cancelled
        while True:
            await asyncio.sleep(1)

    async def ack(self, channel: str, message_id: str) -> bool:
        """Acknowledge message."""
        async with self._in_flight_lock:
            amqp_message = self._in_flight.pop(message_id, None)

        if not amqp_message:
            logger.warning(f"Message {message_id} not found in flight")
            return False

        try:
            await amqp_message.ack()
            if channel in self._stats:
                self._stats[channel]["delivered"] += 1
            logger.debug(f"Acknowledged message {message_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to ack message {message_id}: {e}")
            return False

    async def nack(self, channel: str, message_id: str, retry: bool = True) -> bool:
        """Negative acknowledge message."""
        async with self._in_flight_lock:
            amqp_message = self._in_flight.pop(message_id, None)

        if not amqp_message:
            logger.warning(f"Message {message_id} not found in flight")
            return False

        try:
            if retry:
                # Requeue for retry
                await amqp_message.reject(requeue=True)
                logger.debug(f"Requeued message {message_id} for retry")
            else:
                # Send to dead letter queue
                await amqp_message.reject(requeue=False)
                if channel in self._stats:
                    self._stats[channel]["dead_lettered"] += 1
                logger.debug(f"Sent message {message_id} to dead letter queue")
            return True
        except Exception as e:
            logger.error(f"Failed to nack message {message_id}: {e}")
            return False

    async def get_queue_depth(self, channel: str) -> int:
        """Get number of pending messages in channel."""
        if not self.channel:
            return 0

        try:
            queue_name = self._queue_name(channel)
            queue = await self.channel.get_queue(queue_name, ensure=False)
            if queue:
                declaration = await queue.declare(passive=True)
                return declaration.message_count
        except Exception:
            pass
        return 0

    async def get_in_flight_count(self, channel: str) -> int:
        """Get number of messages awaiting acknowledgment."""
        async with self._in_flight_lock:
            # Count messages for this channel
            count = sum(
                1
                for msg in self._in_flight.values()
                if msg.headers and msg.headers.get("channel") == channel
            )
        return count

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
            connected_clients=0,  # Will be filled by ChannelManager
        )

    async def cleanup_expired(self, channel: str) -> int:
        """Remove expired messages from channel."""
        # RabbitMQ handles TTL automatically via x-message-ttl
        # This method is mainly for manual cleanup if needed
        return 0

    async def delete_channel(self, channel: str) -> bool:
        """Delete a channel and all its messages."""
        if not self.channel:
            return False

        try:
            queue_name = self._queue_name(channel)
            dlq_name = self._dlq_name(channel)

            # Delete queues
            await self.channel.queue_delete(queue_name)
            await self.channel.queue_delete(dlq_name)

            # Remove from stats
            self._stats.pop(channel, None)

            logger.info(f"Deleted channel: {channel}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete channel {channel}: {e}")
            return False

    async def get_dead_letters(
        self, channel: str, limit: int = 100
    ) -> List[WebhookMessage]:
        """Get dead letter messages for a channel."""
        if not self.channel:
            return []

        messages = []
        dlq_name = self._dlq_name(channel)

        try:
            queue = await self.channel.get_queue(dlq_name, ensure=False)
            if not queue:
                return []

            # Get messages without consuming (peek)
            count = 0
            async with queue.iterator() as queue_iter:
                async for amqp_message in queue_iter:
                    try:
                        data = json.loads(amqp_message.body.decode())
                        message = WebhookMessage.from_envelope(data)
                        message.state = MessageState.DEAD_LETTERED
                        messages.append(message)

                        # Requeue message (we're just peeking)
                        await amqp_message.reject(requeue=True)

                        count += 1
                        if count >= limit:
                            break
                    except Exception as e:
                        logger.error(f"Error reading dead letter: {e}")
                        await amqp_message.reject(requeue=True)

        except Exception as e:
            logger.error(f"Failed to get dead letters for {channel}: {e}")

        return messages

    async def health_check(self) -> bool:
        """Check if RabbitMQ connection is healthy."""
        if not self.connection or self.connection.is_closed:
            return False
        return True
