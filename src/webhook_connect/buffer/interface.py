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
from typing import List, Optional, AsyncIterator, Callable, Awaitable
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
        prefetch: int = 10
    ) -> None:
        """
        Subscribe to channel and receive messages via callback.

        This is a blocking call that runs until cancelled.

        Args:
            channel: Channel name
            callback: Async function to call with each message
            prefetch: Number of messages to prefetch

        Raises:
            ConnectionError: If not connected to backend
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
    async def get_queue_depth(self, channel: str) -> int:
        """
        Get number of pending messages in channel.

        Args:
            channel: Channel name

        Returns:
            Number of messages waiting to be delivered
        """
        pass

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
    async def ensure_channel(self, channel: str, ttl_seconds: int = 86400) -> None:
        """
        Ensure channel exists with proper configuration.

        Creates queue/stream if it doesn't exist.

        Args:
            channel: Channel name
            ttl_seconds: Message TTL in seconds
        """
        pass

    @abstractmethod
    async def delete_channel(self, channel: str) -> bool:
        """
        Delete a channel and all its messages.

        Args:
            channel: Channel name

        Returns:
            True if deleted, False if not found
        """
        pass

    @abstractmethod
    async def get_dead_letters(self, channel: str, limit: int = 100) -> List[WebhookMessage]:
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
