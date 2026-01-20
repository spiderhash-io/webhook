"""
Integration tests for retry handler with real services.

These tests verify retry mechanisms, exponential backoff, and error classification.
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, patch
from src.retry_handler import (
    RetryHandler,
    DEFAULT_RETRYABLE_ERRORS,
    DEFAULT_NON_RETRYABLE_ERRORS,
)


@pytest.mark.integration
class TestRetryHandlerIntegration:
    """Integration tests for retry handler."""

    @pytest.fixture
    def retry_handler(self):
        """Create a retry handler instance."""
        return RetryHandler()

    @pytest.mark.asyncio
    async def test_retry_handler_success_immediate(self, retry_handler):
        """Test that retry handler succeeds on first attempt."""
        call_count = 0

        async def success_function():
            nonlocal call_count
            call_count += 1
            return "success"

        retry_config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": 0.1,
            "max_delay": 1.0,
            "backoff_multiplier": 2.0,
        }

        success, error = await retry_handler.execute_with_retry(
            success_function, retry_config=retry_config
        )

        assert success is True
        assert error is None
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_handler_success_after_retry(self, retry_handler):
        """Test that retry handler succeeds after retries."""
        call_count = 0

        async def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Connection failed")
            return "success"

        retry_config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": 0.1,
            "max_delay": 1.0,
            "backoff_multiplier": 2.0,
        }

        start_time = time.time()
        success, error = await retry_handler.execute_with_retry(
            flaky_function, retry_config=retry_config
        )
        elapsed = time.time() - start_time

        assert success is True
        assert error is None
        assert call_count == 3
        # Should have waited for backoff delays (at least 0.1 + 0.2 = 0.3 seconds)
        assert elapsed >= 0.3

    @pytest.mark.asyncio
    async def test_retry_handler_all_attempts_fail(self, retry_handler):
        """Test that retry handler fails after all attempts."""
        call_count = 0

        async def failing_function():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Connection failed")

        retry_config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": 0.1,
            "max_delay": 1.0,
            "backoff_multiplier": 2.0,
        }

        success, error = await retry_handler.execute_with_retry(
            failing_function, retry_config=retry_config
        )

        assert success is False
        assert error is not None
        assert isinstance(error, ConnectionError)
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_retry_handler_non_retryable_error(self, retry_handler):
        """Test that non-retryable errors fail immediately."""
        call_count = 0

        async def validation_error_function():
            nonlocal call_count
            call_count += 1
            raise ValueError("Invalid input")

        retry_config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": 0.1,
            "max_delay": 1.0,
            "backoff_multiplier": 2.0,
        }

        success, error = await retry_handler.execute_with_retry(
            validation_error_function, retry_config=retry_config
        )

        assert success is False
        assert error is not None
        assert isinstance(error, ValueError)
        # Should not retry non-retryable errors
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_handler_exponential_backoff(self, retry_handler):
        """Test that exponential backoff delays increase correctly."""
        call_times = []

        async def flaky_function():
            call_times.append(time.time())
            if len(call_times) < 4:
                raise ConnectionError("Connection failed")
            return "success"

        retry_config = {
            "enabled": True,
            "max_attempts": 4,
            "initial_delay": 0.1,
            "max_delay": 1.0,
            "backoff_multiplier": 2.0,
        }

        await retry_handler.execute_with_retry(
            flaky_function, retry_config=retry_config
        )

        # Check that delays increase exponentially
        assert len(call_times) == 4
        delay1 = call_times[1] - call_times[0]
        delay2 = call_times[2] - call_times[1]
        delay3 = call_times[3] - call_times[2]

        # Delays should be approximately 0.1, 0.2, 0.4 (with some tolerance)
        assert 0.05 <= delay1 <= 0.2
        assert 0.15 <= delay2 <= 0.3
        assert 0.35 <= delay3 <= 0.5

    @pytest.mark.asyncio
    async def test_retry_handler_max_delay_cap(self, retry_handler):
        """Test that backoff delays are capped at max_delay."""
        call_times = []

        async def flaky_function():
            call_times.append(time.time())
            if len(call_times) < 3:
                raise ConnectionError("Connection failed")
            return "success"

        retry_config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": 0.1,  # Small initial delay
            "max_delay": 0.2,  # Small max delay (should cap)
            "backoff_multiplier": 2.0,
        }

        await retry_handler.execute_with_retry(
            flaky_function, retry_config=retry_config
        )

        # Check that delays are capped
        assert len(call_times) == 3
        delay1 = call_times[1] - call_times[0]
        delay2 = call_times[2] - call_times[1]

        # Both delays should be capped at max_delay (0.2)
        assert delay1 <= 0.3  # Allow some tolerance
        assert delay2 <= 0.3

    @pytest.mark.asyncio
    async def test_retry_handler_error_classification(self, retry_handler):
        """Test that error classification works correctly."""
        # Test retryable errors
        retryable_errors = [
            ConnectionError("Connection failed"),
            ConnectionRefusedError("Connection refused"),
            TimeoutError("Timeout"),
            OSError("OS error"),
            IOError("IO error"),
        ]

        for error in retryable_errors:
            is_retryable = retry_handler._is_retryable_error(
                error, DEFAULT_RETRYABLE_ERRORS, DEFAULT_NON_RETRYABLE_ERRORS
            )
            assert is_retryable is True, f"{type(error).__name__} should be retryable"

        # Test non-retryable errors
        non_retryable_errors = [
            ValueError("Invalid value"),
            KeyError("Missing key"),
            TypeError("Type error"),
        ]

        for error in non_retryable_errors:
            is_retryable = retry_handler._is_retryable_error(
                error, DEFAULT_RETRYABLE_ERRORS, DEFAULT_NON_RETRYABLE_ERRORS
            )
            assert (
                is_retryable is False
            ), f"{type(error).__name__} should not be retryable"

    @pytest.mark.asyncio
    async def test_retry_handler_custom_retryable_errors(self, retry_handler):
        """Test that custom retryable error lists work."""
        call_count = 0

        async def custom_error_function():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("Custom retryable error")
            return "success"

        retry_config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": 0.1,
            "max_delay": 1.0,
            "backoff_multiplier": 2.0,
            "retryable_errors": ["ValueError"],  # Make ValueError retryable
            "non_retryable_errors": [],
        }

        success, error = await retry_handler.execute_with_retry(
            custom_error_function, retry_config=retry_config
        )

        assert success is True
        assert call_count == 2  # Should have retried

    @pytest.mark.asyncio
    async def test_retry_handler_disabled(self, retry_handler):
        """Test that retry handler doesn't retry when disabled."""
        call_count = 0

        async def failing_function():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Connection failed")

        retry_config = {
            "enabled": False,  # Disabled
            "max_attempts": 3,
            "initial_delay": 0.1,
            "max_delay": 1.0,
            "backoff_multiplier": 2.0,
        }

        success, error = await retry_handler.execute_with_retry(
            failing_function, retry_config=retry_config
        )

        assert success is False
        assert error is not None
        assert call_count == 1  # Should not retry when disabled

    @pytest.mark.asyncio
    async def test_retry_handler_no_config(self, retry_handler):
        """Test that retry handler works without config."""
        call_count = 0

        async def failing_function():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Connection failed")

        # No retry config provided
        success, error = await retry_handler.execute_with_retry(
            failing_function, retry_config=None
        )

        assert success is False
        assert error is not None
        assert call_count == 1  # Should not retry without config
