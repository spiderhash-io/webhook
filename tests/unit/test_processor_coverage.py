"""
Coverage tests for src/connector/processor.py.

Targets the ~93 missed lines covering:
- MessageProcessor: start/stop, process, deliver with retry, error handling
- BatchProcessor: start/stop, batch loop, process_batch
- ProcessingResult and InFlightMessage dataclasses
- Delivery with various HTTP status codes, timeouts, client errors
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, AsyncMock, patch, MagicMock, PropertyMock
from datetime import datetime, timezone

from src.connector.config import ConnectorConfig, TargetConfig
from src.connector.processor import (
    MessageProcessor,
    BatchProcessor,
    ProcessingResult,
    InFlightMessage,
    ProcessingStats,
)


# --- Fixtures ---


@pytest.fixture
def target_config():
    """Create a TargetConfig for testing."""
    return TargetConfig(
        url="http://local-target.example.com/webhook",
        method="POST",
        headers={"X-Custom": "value"},
        timeout_seconds=5.0,
        retry_enabled=True,
        retry_max_attempts=3,
        retry_delay_seconds=0.01,  # Very small for testing
        retry_backoff_multiplier=1.5,
    )


@pytest.fixture
def connector_config(target_config):
    """Create a ConnectorConfig for testing."""
    config = MagicMock(spec=ConnectorConfig)
    config.max_concurrent_requests = 5
    config.verify_ssl = True
    config.get_target.return_value = target_config
    return config


@pytest.fixture
def ack_callback():
    """Create an async ACK callback."""
    return AsyncMock(return_value=True)


@pytest.fixture
def nack_callback():
    """Create an async NACK callback."""
    return AsyncMock(return_value=True)


@pytest.fixture
async def processor(connector_config, ack_callback, nack_callback):
    """Create a MessageProcessor instance."""
    return MessageProcessor(connector_config, ack_callback, nack_callback)


@pytest.fixture
def sample_message():
    """Create a sample webhook message."""
    return {
        "message_id": "msg-123",
        "webhook_id": "test-webhook",
        "payload": {"key": "value"},
        "headers": {"Content-Type": "application/json"},
    }


# ============================================================================
# MessageProcessor tests
# ============================================================================


class TestMessageProcessorStartStop:
    """Test MessageProcessor start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_creates_session(self, processor):
        """Test that start creates an aiohttp session."""
        await processor.start()
        assert processor._running is True
        assert processor._session is not None
        await processor.stop()

    @pytest.mark.asyncio
    async def test_start_idempotent(self, processor):
        """Test that start is idempotent (calling twice doesn't create new session)."""
        await processor.start()
        first_session = processor._session
        await processor.start()
        assert processor._session is first_session
        await processor.stop()

    @pytest.mark.asyncio
    async def test_stop_closes_session(self, processor):
        """Test that stop closes the session."""
        await processor.start()
        await processor.stop()
        assert processor._running is False
        assert processor._session is None

    @pytest.mark.asyncio
    async def test_stop_cancels_in_flight_tasks(self, processor, sample_message):
        """Test that stop cancels in-flight tasks."""
        await processor.start()

        # Create a real asyncio task that will block
        async def long_running():
            await asyncio.sleep(100)

        real_task = asyncio.create_task(long_running())

        msg_info = InFlightMessage(
            message_id="msg-cancel",
            webhook_id="test",
            data={"payload": {}, "headers": {}},
            received_at=datetime.now(timezone.utc),
            target=MagicMock(),
            task=real_task,
        )
        processor._in_flight["msg-cancel"] = msg_info

        await processor.stop()

        assert real_task.cancelled()


class TestMessageProcessorProcess:
    """Test MessageProcessor.process method."""

    @pytest.mark.asyncio
    async def test_process_when_not_running(self, processor, sample_message):
        """Test that process ignores messages when not running."""
        await processor.process(sample_message)
        # Should not add to in_flight
        assert len(processor._in_flight) == 0

    @pytest.mark.asyncio
    async def test_process_missing_message_id(self, processor):
        """Test that process rejects messages without message_id."""
        await processor.start()
        message = {"webhook_id": "test", "payload": {}}
        await processor.process(message)
        assert len(processor._in_flight) == 0
        await processor.stop()

    @pytest.mark.asyncio
    async def test_process_missing_webhook_id(self, processor, nack_callback):
        """Test that process NACKs messages without webhook_id."""
        await processor.start()
        message = {"message_id": "msg-123", "payload": {}}
        await processor.process(message)
        # Wait for processing
        await asyncio.sleep(0.05)
        nack_callback.assert_called_with("msg-123", False)
        await processor.stop()

    @pytest.mark.asyncio
    async def test_process_no_target_configured(
        self, connector_config, ack_callback, nack_callback
    ):
        """Test that process NACKs when no target is configured."""
        connector_config.get_target.return_value = None
        proc = MessageProcessor(connector_config, ack_callback, nack_callback)
        await proc.start()
        message = {
            "message_id": "msg-123",
            "webhook_id": "unknown-wh",
            "payload": {},
        }
        await proc.process(message)
        await asyncio.sleep(0.05)
        nack_callback.assert_called_with("msg-123", False)
        await proc.stop()


class TestMessageProcessorDelivery:
    """Test MessageProcessor delivery with various HTTP status codes."""

    @pytest.mark.asyncio
    async def test_deliver_success_200(self, processor, sample_message, ack_callback):
        """Test successful delivery with 200 status."""
        await processor.start()

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        with patch.object(
            processor._session, "request", return_value=mock_response
        ):
            await processor.process(sample_message)
            await asyncio.sleep(0.1)

        ack_callback.assert_called_with("msg-123")
        assert processor._stats.messages_delivered == 1
        await processor.stop()

    @pytest.mark.asyncio
    async def test_deliver_client_error_400(
        self, processor, sample_message, nack_callback
    ):
        """Test delivery failure with 400 client error (no retry)."""
        await processor.start()

        mock_response = MagicMock()
        mock_response.status = 400
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        with patch.object(
            processor._session, "request", return_value=mock_response
        ):
            await processor.process(sample_message)
            await asyncio.sleep(0.1)

        nack_callback.assert_called_with("msg-123", False)
        assert processor._stats.messages_failed == 1
        await processor.stop()

    @pytest.mark.asyncio
    async def test_deliver_server_error_500_retries(
        self, processor, sample_message, nack_callback
    ):
        """Test delivery with 500 server error triggers retries and eventually NACKs with retry=True."""
        await processor.start()

        mock_response = MagicMock()
        mock_response.status = 500
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        with patch.object(
            processor._session, "request", return_value=mock_response
        ):
            await processor.process(sample_message)
            await asyncio.sleep(0.5)  # Wait for retries

        # Should NACK with retry=True for server errors
        nack_callback.assert_called_with("msg-123", True)
        assert processor._stats.messages_failed == 1
        await processor.stop()

    @pytest.mark.asyncio
    async def test_deliver_timeout_retries(
        self, processor, sample_message, nack_callback
    ):
        """Test delivery with timeout triggers retries."""
        await processor.start()

        with patch.object(
            processor._session,
            "request",
            side_effect=asyncio.TimeoutError(),
        ):
            await processor.process(sample_message)
            await asyncio.sleep(0.5)

        nack_callback.assert_called_with("msg-123", True)
        await processor.stop()

    @pytest.mark.asyncio
    async def test_deliver_client_error_retries(
        self, processor, sample_message, nack_callback
    ):
        """Test delivery with aiohttp ClientError triggers retries."""
        import aiohttp

        await processor.start()

        with patch.object(
            processor._session,
            "request",
            side_effect=aiohttp.ClientError("Connection failed"),
        ):
            await processor.process(sample_message)
            await asyncio.sleep(0.5)

        nack_callback.assert_called_with("msg-123", True)
        await processor.stop()

    @pytest.mark.asyncio
    async def test_deliver_unexpected_exception(
        self, processor, sample_message, nack_callback
    ):
        """Test delivery with unexpected exception triggers NACK with retry."""
        await processor.start()

        with patch.object(
            processor._session,
            "request",
            side_effect=RuntimeError("Unexpected error"),
        ):
            await processor.process(sample_message)
            await asyncio.sleep(0.5)

        nack_callback.assert_called_with("msg-123", True)
        await processor.stop()


class TestMessageProcessorPayloadSerialization:
    """Test payload serialization in _deliver."""

    @pytest.mark.asyncio
    async def test_deliver_dict_payload(self, processor, ack_callback):
        """Test delivery with dict payload (serialized to JSON)."""
        await processor.start()

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        with patch.object(
            processor._session, "request", return_value=mock_response
        ) as mock_req:
            await processor.process(
                {
                    "message_id": "msg-dict",
                    "webhook_id": "test",
                    "payload": {"nested": "data"},
                    "headers": {},
                }
            )
            await asyncio.sleep(0.1)

        ack_callback.assert_called_with("msg-dict")
        await processor.stop()

    @pytest.mark.asyncio
    async def test_deliver_string_payload(self, processor, ack_callback):
        """Test delivery with string payload."""
        await processor.start()

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        with patch.object(
            processor._session, "request", return_value=mock_response
        ):
            await processor.process(
                {
                    "message_id": "msg-str",
                    "webhook_id": "test",
                    "payload": "raw string data",
                    "headers": {},
                }
            )
            await asyncio.sleep(0.1)

        ack_callback.assert_called_with("msg-str")
        await processor.stop()

    @pytest.mark.asyncio
    async def test_deliver_non_dict_non_str_payload(self, processor, ack_callback):
        """Test delivery with non-dict, non-string payload (e.g., int)."""
        await processor.start()

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        with patch.object(
            processor._session, "request", return_value=mock_response
        ):
            await processor.process(
                {
                    "message_id": "msg-int",
                    "webhook_id": "test",
                    "payload": 42,
                    "headers": {},
                }
            )
            await asyncio.sleep(0.1)

        ack_callback.assert_called_with("msg-int")
        await processor.stop()

    @pytest.mark.asyncio
    async def test_deliver_list_payload(self, processor, ack_callback):
        """Test delivery with list payload (serialized to JSON)."""
        await processor.start()

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        with patch.object(
            processor._session, "request", return_value=mock_response
        ):
            await processor.process(
                {
                    "message_id": "msg-list",
                    "webhook_id": "test",
                    "payload": [1, 2, 3],
                    "headers": {},
                }
            )
            await asyncio.sleep(0.1)

        ack_callback.assert_called_with("msg-list")
        await processor.stop()


class TestMessageProcessorStats:
    """Test MessageProcessor statistics."""

    @pytest.mark.asyncio
    async def test_get_stats(self, processor):
        """Test get_stats returns correct format."""
        stats = processor.get_stats()
        assert "messages_delivered" in stats
        assert "messages_failed" in stats
        assert "in_flight_count" in stats
        assert "running" in stats

    @pytest.mark.asyncio
    async def test_in_flight_count(self, processor):
        """Test in_flight_count property."""
        assert processor.in_flight_count == 0


class TestProcessWithRetryExceptionPaths:
    """Test _process_with_retry exception handling."""

    @pytest.mark.asyncio
    async def test_process_with_retry_general_exception(
        self, connector_config, ack_callback, nack_callback
    ):
        """Test _process_with_retry handles general exceptions."""
        proc = MessageProcessor(connector_config, ack_callback, nack_callback)
        await proc.start()

        # Mock _deliver_with_retry to raise an exception
        msg_info = InFlightMessage(
            message_id="msg-err",
            webhook_id="test",
            data={"payload": {}, "headers": {}},
            received_at=datetime.now(timezone.utc),
            target=connector_config.get_target("test"),
        )
        proc._in_flight["msg-err"] = msg_info

        with patch.object(
            proc, "_deliver_with_retry", side_effect=RuntimeError("Unexpected")
        ):
            await proc._process_with_retry(msg_info)

        nack_callback.assert_called_with("msg-err", True)
        assert proc._stats.messages_failed == 1
        assert "msg-err" not in proc._in_flight
        await proc.stop()


# ============================================================================
# BatchProcessor tests
# ============================================================================


class TestBatchProcessor:
    """Test BatchProcessor lifecycle and processing."""

    @pytest.fixture
    async def batch_processor(self, connector_config, ack_callback, nack_callback):
        """Create a BatchProcessor instance."""
        return BatchProcessor(
            connector_config,
            ack_callback,
            nack_callback,
            batch_size=3,
            batch_timeout=0.1,
        )

    @pytest.mark.asyncio
    async def test_batch_start_stop(self, batch_processor):
        """Test batch processor start and stop lifecycle."""
        await batch_processor.start()
        assert batch_processor._running is True
        assert batch_processor._batch_task is not None
        await batch_processor.stop()
        assert batch_processor._running is False
        assert batch_processor._session is None

    @pytest.mark.asyncio
    async def test_batch_start_idempotent(self, batch_processor):
        """Test batch processor start is idempotent."""
        await batch_processor.start()
        first_task = batch_processor._batch_task
        await batch_processor.start()
        assert batch_processor._batch_task is first_task
        await batch_processor.stop()

    @pytest.mark.asyncio
    async def test_batch_process_adds_to_queue(self, batch_processor):
        """Test batch process adds messages to queue."""
        await batch_processor.start()
        message = {
            "message_id": "msg-1",
            "webhook_id": "test",
            "payload": {},
        }
        await batch_processor.process(message)
        assert not batch_processor._queue.empty()
        await batch_processor.stop()

    @pytest.mark.asyncio
    async def test_batch_process_no_target(
        self, connector_config, ack_callback, nack_callback
    ):
        """Test batch process NACKs messages with no matching target."""
        connector_config.get_target.return_value = None
        bp = BatchProcessor(
            connector_config,
            ack_callback,
            nack_callback,
            batch_size=2,
            batch_timeout=0.1,
        )
        await bp.start()

        msg1 = {"message_id": "msg-1", "webhook_id": "unknown", "payload": {}}
        msg2 = {"message_id": "msg-2", "webhook_id": "unknown", "payload": {}}
        await bp.process(msg1)
        await bp.process(msg2)

        # Wait for batch processing
        await asyncio.sleep(0.5)

        nack_callback.assert_any_call("msg-1", False)
        nack_callback.assert_any_call("msg-2", False)
        await bp.stop()


# ============================================================================
# Dataclass tests
# ============================================================================


class TestDataclasses:
    """Test dataclass defaults and initialization."""

    def test_processing_result_defaults(self):
        """Test ProcessingResult with defaults."""
        result = ProcessingResult(
            success=True, message_id="msg-1", webhook_id="wh-1"
        )
        assert result.target_url is None
        assert result.status_code is None
        assert result.error is None
        assert result.attempts == 1
        assert result.duration_ms == 0.0

    def test_processing_result_full(self):
        """Test ProcessingResult with all fields."""
        result = ProcessingResult(
            success=False,
            message_id="msg-1",
            webhook_id="wh-1",
            target_url="http://target.example.com",
            status_code=500,
            error="Server error",
            attempts=3,
            duration_ms=150.5,
        )
        assert result.status_code == 500
        assert result.duration_ms == 150.5

    def test_in_flight_message_defaults(self):
        """Test InFlightMessage with defaults."""
        msg = InFlightMessage(
            message_id="msg-1",
            webhook_id="wh-1",
            data={},
            received_at=datetime.now(timezone.utc),
            target=MagicMock(),
        )
        assert msg.attempts == 0
        assert msg.task is None

    def test_processing_stats_defaults(self):
        """Test ProcessingStats defaults."""
        stats = ProcessingStats()
        assert stats.messages_delivered == 0
        assert stats.messages_failed == 0
