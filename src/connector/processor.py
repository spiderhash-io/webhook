"""
Message Processor for Local Connector.

Handles processing of received webhook messages:
- Delivery to local targets
- Retry logic
- Acknowledgment handling
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Callable, Awaitable, Set
from dataclasses import dataclass, field

import aiohttp

from src.connector.config import ConnectorConfig, TargetConfig

logger = logging.getLogger(__name__)


@dataclass
class ProcessingResult:
    """Result of processing a message."""

    success: bool
    message_id: str
    webhook_id: str
    target_url: Optional[str] = None
    status_code: Optional[int] = None
    error: Optional[str] = None
    attempts: int = 1
    duration_ms: float = 0.0


@dataclass
class InFlightMessage:
    """Tracks a message being processed."""

    message_id: str
    webhook_id: str
    data: Dict[str, Any]
    received_at: datetime
    target: TargetConfig
    attempts: int = 0
    task: Optional[asyncio.Task] = None


class MessageProcessor:
    """
    Processes webhook messages and delivers them to local targets.

    Features:
    - Concurrent processing with configurable limit
    - Automatic retry with exponential backoff
    - Timeout handling
    - ACK/NACK callbacks
    """

    def __init__(
        self,
        config: ConnectorConfig,
        ack_callback: Callable[[str], Awaitable[bool]],
        nack_callback: Callable[[str, bool], Awaitable[bool]],
    ):
        """
        Initialize message processor.

        Args:
            config: Connector configuration
            ack_callback: Callback to send ACK (message_id)
            nack_callback: Callback to send NACK (message_id, retry)
        """
        self.config = config
        self.ack_callback = ack_callback
        self.nack_callback = nack_callback

        self._in_flight: Dict[str, InFlightMessage] = {}
        self._semaphore = asyncio.Semaphore(config.max_concurrent_requests)
        self._session: Optional[aiohttp.ClientSession] = None
        self._stats = ProcessingStats()
        self._running = False

    async def start(self) -> None:
        """Start the processor."""
        if self._running:
            return

        self._session = aiohttp.ClientSession()
        self._running = True
        logger.info("Message processor started")

    async def stop(self) -> None:
        """Stop the processor and cleanup."""
        self._running = False

        # Cancel all in-flight tasks
        for msg_info in list(self._in_flight.values()):
            if msg_info.task and not msg_info.task.done():
                msg_info.task.cancel()
                try:
                    await msg_info.task
                except asyncio.CancelledError:
                    pass

        # Close session
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

        logger.info("Message processor stopped")

    async def process(self, message: Dict[str, Any]) -> None:
        """
        Process a received webhook message.

        Args:
            message: The webhook message data from stream
        """
        if not self._running:
            logger.warning("Processor not running, ignoring message")
            return

        message_id = message.get("message_id")
        webhook_id = message.get("webhook_id")
        payload = message.get("payload")
        headers = message.get("headers", {})

        if not message_id:
            logger.error("Message missing message_id")
            return

        if not webhook_id:
            logger.error(f"Message {message_id} missing webhook_id")
            await self.nack_callback(message_id, False)
            return

        # Get target for this webhook
        target = self.config.get_target(webhook_id)
        if not target:
            logger.error(f"No target configured for webhook_id: {webhook_id}")
            await self.nack_callback(message_id, False)
            return

        # Track in-flight
        msg_info = InFlightMessage(
            message_id=message_id,
            webhook_id=webhook_id,
            data={"payload": payload, "headers": headers},
            received_at=datetime.now(timezone.utc),
            target=target,
        )
        self._in_flight[message_id] = msg_info

        # Start processing task
        msg_info.task = asyncio.create_task(self._process_with_retry(msg_info))

    async def _process_with_retry(self, msg_info: InFlightMessage) -> None:
        """Process message with retry logic."""
        try:
            async with self._semaphore:
                result = await self._deliver_with_retry(msg_info)

            if result.success:
                # Send ACK
                await self.ack_callback(msg_info.message_id)
                self._stats.messages_delivered += 1
                logger.debug(
                    f"Delivered {msg_info.message_id} to {result.target_url} "
                    f"(status={result.status_code}, attempts={result.attempts})"
                )
            else:
                # Send NACK
                retry = (
                    msg_info.target.retry_enabled
                    and result.attempts < msg_info.target.retry_max_attempts
                )
                await self.nack_callback(msg_info.message_id, retry)
                self._stats.messages_failed += 1
                logger.error(
                    f"Failed to deliver {msg_info.message_id}: {result.error} "
                    f"(attempts={result.attempts}, retry={retry})"
                )

        except asyncio.CancelledError:
            logger.info(f"Processing cancelled for {msg_info.message_id}")
            raise
        except Exception as e:
            logger.error(f"Error processing {msg_info.message_id}: {e}")
            await self.nack_callback(msg_info.message_id, True)
            self._stats.messages_failed += 1
        finally:
            self._in_flight.pop(msg_info.message_id, None)

    async def _deliver_with_retry(self, msg_info: InFlightMessage) -> ProcessingResult:
        """Deliver message with retry logic."""
        target = msg_info.target
        delay = target.retry_delay_seconds
        last_error = None
        last_status = None

        for attempt in range(1, target.retry_max_attempts + 1):
            msg_info.attempts = attempt

            try:
                start_time = datetime.now(timezone.utc)
                status_code = await self._deliver(msg_info)
                duration = (
                    datetime.now(timezone.utc) - start_time
                ).total_seconds() * 1000

                if 200 <= status_code < 300:
                    return ProcessingResult(
                        success=True,
                        message_id=msg_info.message_id,
                        webhook_id=msg_info.webhook_id,
                        target_url=target.url,
                        status_code=status_code,
                        attempts=attempt,
                        duration_ms=duration,
                    )

                # Non-success status
                last_status = status_code
                last_error = f"HTTP {status_code}"

                # Don't retry on 4xx errors (client errors)
                if 400 <= status_code < 500:
                    logger.warning(f"Client error {status_code}, not retrying")
                    break

            except asyncio.TimeoutError:
                last_error = "Request timeout"
                logger.warning(f"Attempt {attempt} timeout for {msg_info.message_id}")

            except aiohttp.ClientError as e:
                last_error = str(e)
                logger.warning(
                    f"Attempt {attempt} failed for {msg_info.message_id}: {e}"
                )

            except Exception as e:
                last_error = str(e)
                logger.error(f"Unexpected error on attempt {attempt}: {e}")

            # Wait before retry (unless last attempt)
            if attempt < target.retry_max_attempts and target.retry_enabled:
                logger.debug(f"Waiting {delay:.1f}s before retry")
                await asyncio.sleep(delay)
                delay = min(delay * target.retry_backoff_multiplier, 60.0)

        return ProcessingResult(
            success=False,
            message_id=msg_info.message_id,
            webhook_id=msg_info.webhook_id,
            target_url=target.url,
            status_code=last_status,
            error=last_error,
            attempts=msg_info.attempts,
        )

    async def _deliver(self, msg_info: InFlightMessage) -> int:
        """Deliver a single message to target."""
        target = msg_info.target
        payload = msg_info.data.get("payload")
        original_headers = msg_info.data.get("headers", {})

        # Build request headers
        headers = dict(target.headers)  # Start with target-configured headers

        # Add original webhook headers (with prefix to avoid conflicts)
        for key, value in original_headers.items():
            headers[f"X-Original-{key}"] = value

        # Set content type
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"

        # Add tracking headers
        headers["X-Webhook-Message-ID"] = msg_info.message_id
        headers["X-Webhook-ID"] = msg_info.webhook_id
        headers["X-Webhook-Attempt"] = str(msg_info.attempts)

        # Serialize payload
        if isinstance(payload, (dict, list)):
            body = json.dumps(payload)
        elif isinstance(payload, str):
            body = payload
        else:
            body = str(payload)

        # Make request
        timeout = aiohttp.ClientTimeout(total=target.timeout_seconds)

        async with self._session.request(
            method=target.method,
            url=target.url,
            headers=headers,
            data=body,
            timeout=timeout,
            ssl=self.config.verify_ssl,
        ) as response:
            return response.status

    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return {
            "messages_delivered": self._stats.messages_delivered,
            "messages_failed": self._stats.messages_failed,
            "in_flight_count": len(self._in_flight),
            "running": self._running,
        }

    @property
    def in_flight_count(self) -> int:
        """Number of messages currently being processed."""
        return len(self._in_flight)


@dataclass
class ProcessingStats:
    """Statistics for message processing."""

    messages_delivered: int = 0
    messages_failed: int = 0
    messages_retried: int = 0
    total_delivery_time_ms: float = 0.0


class BatchProcessor:
    """
    Processes messages in batches for improved efficiency.

    Use this when the target supports batch requests.
    """

    def __init__(
        self,
        config: ConnectorConfig,
        ack_callback: Callable[[str], Awaitable[bool]],
        nack_callback: Callable[[str, bool], Awaitable[bool]],
        batch_size: int = 10,
        batch_timeout: float = 1.0,
    ):
        """
        Initialize batch processor.

        Args:
            config: Connector configuration
            ack_callback: Callback to send ACK
            nack_callback: Callback to send NACK
            batch_size: Maximum messages per batch
            batch_timeout: Maximum time to wait for batch
        """
        self.config = config
        self.ack_callback = ack_callback
        self.nack_callback = nack_callback
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout

        self._queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        self._batch_task: Optional[asyncio.Task] = None
        self._session: Optional[aiohttp.ClientSession] = None

    async def start(self) -> None:
        """Start the batch processor."""
        if self._running:
            return

        self._session = aiohttp.ClientSession()
        self._running = True
        self._batch_task = asyncio.create_task(self._batch_loop())
        logger.info("Batch processor started")

    async def stop(self) -> None:
        """Stop the batch processor."""
        self._running = False

        if self._batch_task:
            self._batch_task.cancel()
            try:
                await self._batch_task
            except asyncio.CancelledError:
                pass

        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

        logger.info("Batch processor stopped")

    async def process(self, message: Dict[str, Any]) -> None:
        """Add message to batch queue."""
        await self._queue.put(message)

    async def _batch_loop(self) -> None:
        """Main batch processing loop."""
        while self._running:
            try:
                batch = []

                # Wait for first message
                try:
                    msg = await asyncio.wait_for(
                        self._queue.get(), timeout=self.batch_timeout
                    )
                    batch.append(msg)
                except asyncio.TimeoutError:
                    continue

                # Collect more messages up to batch size
                deadline = asyncio.get_event_loop().time() + self.batch_timeout
                while len(batch) < self.batch_size:
                    remaining = deadline - asyncio.get_event_loop().time()
                    if remaining <= 0:
                        break

                    try:
                        msg = await asyncio.wait_for(
                            self._queue.get(), timeout=remaining
                        )
                        batch.append(msg)
                    except asyncio.TimeoutError:
                        break

                # Process batch
                if batch:
                    await self._process_batch(batch)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in batch loop: {e}")
                await asyncio.sleep(1)

    async def _process_batch(self, batch: list) -> None:
        """Process a batch of messages."""
        # Group by target
        by_target: Dict[str, list] = {}
        for msg in batch:
            webhook_id = msg.get("webhook_id", "default")
            if webhook_id not in by_target:
                by_target[webhook_id] = []
            by_target[webhook_id].append(msg)

        # Process each target group
        for webhook_id, messages in by_target.items():
            target = self.config.get_target(webhook_id)
            if not target:
                # NACK all messages
                for msg in messages:
                    await self.nack_callback(msg.get("message_id"), False)
                continue

            # TODO: Implement batch delivery
            # For now, just process individually
            for msg in messages:
                processor = MessageProcessor(
                    self.config, self.ack_callback, self.nack_callback
                )
                await processor.start()
                try:
                    await processor.process(msg)
                finally:
                    await processor.stop()
