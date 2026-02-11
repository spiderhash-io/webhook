"""
Abstract interface for message buffer backends.

The message buffer provides temporary storage for webhook messages between
the Cloud Receiver and Local Connectors. It supports:
- Push: Add messages to the buffer
- Subscribe: Stream messages to consumers
- Ack/Nack: Acknowledge or reject message processing
- TTL: Automatic message expiration
- Dead letter: Store permanently failed messages
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, AsyncIterator, Callable, Awaitable
from contextlib import asynccontextmanager

from src.webhook_connect.models import WebhookMessage, ChannelStats


class MessageBufferInterface(ABC):
    """Abstract interface for message buffer backends."""

    @abstractmethod
    async def connect(self) -> None:
        """
        Establish connection to the buffer backend.

        Raises:
            ConnectionError: If connection fails
        """
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close connection to the buffer backend."""
        pass

    @abstractmethod
    async def push(self, channel: str, message: WebhookMessage) -> bool:
        """
        Add message to channel queue.

        Args:
            channel: Channel name
            message: Webhook message to queue

        Returns:
            True if message was queued, False if queue is full

        Raises:
            ConnectionError: If not connected to backend
        """
        pass

    @abstractmethod
    async def subscribe(
        self,
        channel: str,
        callback: Callable[[WebhookMessage], Awaitable[None]],
        prefetch: int = 10,
        webhook_ids: List[str] = None,
    ) -> Optional[str]:
        """
        Subscribe to channel and receive messages via callback.

        Returns a consumer tag (or equivalent identifier) that can be
        passed to ``unsubscribe()`` to cancel the consumer.

        Failure contract:
            When the callback raises an exception (e.g. dead WebSocket),
            the message is requeued for redelivery rather than immediately
            sent to the dead letter queue. After ``max_redelivery_attempts``
            consecutive failures for the same message, the message is moved
            to the DLQ. A small delay (``requeue_delay_seconds``) is inserted
            between requeue attempts to prevent tight retry loops.

        Args:
            channel: Channel name
            callback: Async function to call with each message
            prefetch: Number of messages to prefetch
            webhook_ids: List of webhook IDs whose queues to consume from.
                         If None, backend discovers queues automatically.

        Returns:
            Consumer tag for cancellation, or None on failure

        Raises:
            ConnectionError: If not connected to backend
        """
        pass

    async def subscribe_webhook(
        self,
        channel: str,
        webhook_id: str,
        callback: Callable[[WebhookMessage], Awaitable[None]] = None,
    ) -> Optional[str]:
        """
        Add a consumer for a single webhook queue on an already-subscribed channel.

        Used when a new webhook registers while a connector is already connected.

        Args:
            channel: Channel name
            webhook_id: Webhook ID to start consuming
            callback: Async callback (uses stored callback if None)

        Returns:
            Consumer tag, or None on failure
        """
        return None  # Default no-op; RabbitMQ buffer overrides

    @abstractmethod
    async def unsubscribe(self, consumer_tag: str) -> None:
        """
        Cancel a consumer by tag. Messages stop being delivered.

        Args:
            consumer_tag: Tag returned by ``subscribe()``
        """
        pass

    @abstractmethod
    async def ack(self, channel: str, message_id: str) -> bool:
        """
        Acknowledge message, removing it from queue.

        Args:
            channel: Channel name
            message_id: Message ID to acknowledge

        Returns:
            True if acknowledged, False if message not found
        """
        pass

    @abstractmethod
    async def nack(self, channel: str, message_id: str, retry: bool = True) -> bool:
        """
        Negative acknowledge message.

        Args:
            channel: Channel name
            message_id: Message ID
            retry: If True, return to queue for retry. If False, send to dead letter.

        Returns:
            True if processed, False if message not found
        """
        pass

    @abstractmethod
    async def get_queue_depth(self, channel: str, webhook_id: str = None) -> int:
        """
        Get number of pending messages in channel.

        Args:
            channel: Channel name
            webhook_id: If provided, returns count for a specific webhook queue

        Returns:
            Number of messages waiting to be delivered
        """
        pass

    async def get_webhook_queue_depths(
        self, channel: str, webhook_ids: List[str]
    ) -> Dict[str, int]:
        """
        Get pending message counts for each webhook in a channel.

        Args:
            channel: Channel name
            webhook_ids: List of webhook IDs to query

        Returns:
            Dict mapping webhook_id to pending message count
        """
        depths: Dict[str, int] = {}
        for webhook_id in webhook_ids:
            depths[webhook_id] = await self.get_queue_depth(channel, webhook_id)
        return depths

    @abstractmethod
    async def get_in_flight_count(self, channel: str) -> int:
        """
        Get number of messages awaiting acknowledgment.

        Args:
            channel: Channel name

        Returns:
            Number of messages delivered but not yet acknowledged
        """
        pass

    @abstractmethod
    async def get_stats(self, channel: str) -> ChannelStats:
        """
        Get channel statistics.

        Args:
            channel: Channel name

        Returns:
            ChannelStats object with current statistics
        """
        pass

    @abstractmethod
    async def cleanup_expired(self, channel: str) -> int:
        """
        Remove expired messages from channel.

        Args:
            channel: Channel name

        Returns:
            Number of messages removed
        """
        pass

    @abstractmethod
    async def ensure_channel(
        self, channel: str, ttl_seconds: int = 86400, webhook_id: str = None
    ) -> None:
        """
        Ensure channel exists with proper configuration.

        If ``webhook_id`` is provided, creates a per-webhook queue
        bound to the channel exchange. Otherwise, creates a channel-level
        queue (legacy behavior).

        Args:
            channel: Channel name
            ttl_seconds: Message TTL in seconds
            webhook_id: Optional webhook ID for per-webhook queue creation
        """
        pass

    @abstractmethod
    async def delete_channel(
        self, channel: str, webhook_ids: List[str] = None
    ) -> bool:
        """
        Delete a channel and all its messages.

        Args:
            channel: Channel name
            webhook_ids: If provided, deletes per-webhook queues for these IDs

        Returns:
            True if deleted, False if not found
        """
        pass

    @abstractmethod
    async def get_dead_letters(
        self, channel: str, limit: int = 100
    ) -> List[WebhookMessage]:
        """
        Get dead letter messages for a channel.

        Args:
            channel: Channel name
            limit: Maximum number of messages to return

        Returns:
            List of dead letter messages
        """
        pass

    async def health_check(self) -> bool:
        """
        Check if buffer backend is healthy.

        Returns:
            True if healthy, False otherwise
        """
        try:
            # Try to get queue depth for a test channel
            await self.get_queue_depth("__health_check__")
            return True
        except Exception:
            return False
