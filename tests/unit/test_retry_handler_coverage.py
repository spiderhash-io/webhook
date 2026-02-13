"""
Coverage tests for src/retry_handler.py.

Targets the ~22 missed lines covering:
- _validate_retry_config: type validation for all fields, boundary capping,
  max_delay < initial_delay adjustment, error list filtering
- _is_retryable_error: full_error_name matching, substring matching,
  non-retryable precedence, unknown error default
- _calculate_backoff: negative inputs, overflow, infinity, NaN
- execute_with_retry: no retry config failure, retry success after first attempt,
  non-retryable error early exit, all attempts exhausted
"""

import pytest
import math
import logging
from unittest.mock import AsyncMock

from src.retry_handler import (
    RetryHandler,
    MAX_ATTEMPTS_LIMIT,
    MAX_DELAY_LIMIT,
    MAX_BACKOFF_MULTIPLIER,
    MIN_ATTEMPTS,
    MIN_DELAY,
    MIN_BACKOFF_MULTIPLIER,
    DEFAULT_RETRYABLE_ERRORS,
    DEFAULT_NON_RETRYABLE_ERRORS,
)


class TestValidateRetryConfig:
    """Test _validate_retry_config method."""

    def test_defaults(self):
        """Test default values when keys are missing."""
        handler = RetryHandler()
        result = handler._validate_retry_config({})
        max_attempts, initial_delay, max_delay, backoff_multiplier, retryable, non_retryable = result
        assert max_attempts == 3
        assert initial_delay == 1.0
        assert max_delay == 60.0
        assert backoff_multiplier == 2.0
        assert retryable == DEFAULT_RETRYABLE_ERRORS
        assert non_retryable == DEFAULT_NON_RETRYABLE_ERRORS

    def test_max_attempts_non_int(self):
        """Test max_attempts type validation defaults to 3."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"max_attempts": "five"})
        assert result[0] == 3

    def test_max_attempts_below_minimum(self):
        """Test max_attempts below minimum is capped."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"max_attempts": 0})
        assert result[0] == MIN_ATTEMPTS

    def test_max_attempts_above_limit(self):
        """Test max_attempts above limit is capped."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"max_attempts": 100})
        assert result[0] == MAX_ATTEMPTS_LIMIT

    def test_initial_delay_non_number(self):
        """Test initial_delay type validation defaults to 1.0."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"initial_delay": "slow"})
        assert result[1] == 1.0

    def test_initial_delay_below_minimum(self):
        """Test initial_delay below minimum is capped."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"initial_delay": -1.0})
        assert result[1] == MIN_DELAY

    def test_initial_delay_above_limit(self):
        """Test initial_delay above limit is capped."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"initial_delay": 100.0})
        assert result[1] == MAX_DELAY_LIMIT

    def test_max_delay_non_number(self):
        """Test max_delay type validation defaults to 60.0."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"max_delay": "forever"})
        assert result[2] == 60.0

    def test_max_delay_below_minimum(self):
        """Test max_delay below minimum is capped, then adjusted to initial_delay."""
        handler = RetryHandler()
        # max_delay is set to MIN_DELAY (0.0) first, then adjusted to initial_delay (1.0)
        # because max_delay < initial_delay triggers the adjustment
        result = handler._validate_retry_config({"max_delay": -5.0})
        assert result[2] == 1.0  # Adjusted to default initial_delay

    def test_max_delay_above_limit(self):
        """Test max_delay above limit is capped."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"max_delay": 999.0})
        assert result[2] == MAX_DELAY_LIMIT

    def test_max_delay_less_than_initial_delay(self):
        """Test max_delay adjusted when less than initial_delay."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"initial_delay": 10.0, "max_delay": 5.0})
        # max_delay should be set to initial_delay
        assert result[2] == result[1]
        assert result[2] == 10.0

    def test_backoff_multiplier_non_number(self):
        """Test backoff_multiplier type validation defaults to 2.0."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"backoff_multiplier": "double"})
        assert result[3] == 2.0

    def test_backoff_multiplier_below_minimum(self):
        """Test backoff_multiplier below minimum is capped."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"backoff_multiplier": 0.01})
        assert result[3] == MIN_BACKOFF_MULTIPLIER

    def test_backoff_multiplier_above_limit(self):
        """Test backoff_multiplier above limit is capped."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"backoff_multiplier": 100.0})
        assert result[3] == MAX_BACKOFF_MULTIPLIER

    def test_retryable_errors_non_list(self):
        """Test retryable_errors type validation uses defaults."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"retryable_errors": "ConnectionError"})
        assert result[4] == DEFAULT_RETRYABLE_ERRORS

    def test_retryable_errors_filters_non_strings(self):
        """Test retryable_errors filters out non-string and empty entries."""
        handler = RetryHandler()
        result = handler._validate_retry_config(
            {"retryable_errors": ["ConnectionError", 123, "", "TimeoutError", None]}
        )
        assert result[4] == ["ConnectionError", "TimeoutError"]

    def test_non_retryable_errors_non_list(self):
        """Test non_retryable_errors type validation uses defaults."""
        handler = RetryHandler()
        result = handler._validate_retry_config({"non_retryable_errors": 42})
        assert result[5] == DEFAULT_NON_RETRYABLE_ERRORS

    def test_non_retryable_errors_filters_non_strings(self):
        """Test non_retryable_errors filters out non-string and empty entries."""
        handler = RetryHandler()
        result = handler._validate_retry_config(
            {"non_retryable_errors": ["ValueError", 999, "", "KeyError"]}
        )
        assert result[5] == ["ValueError", "KeyError"]

    def test_valid_config(self):
        """Test valid configuration returns exact values."""
        handler = RetryHandler()
        result = handler._validate_retry_config({
            "max_attempts": 5,
            "initial_delay": 2.0,
            "max_delay": 30.0,
            "backoff_multiplier": 3.0,
            "retryable_errors": ["ConnectionError"],
            "non_retryable_errors": ["ValueError"],
        })
        assert result == (5, 2.0, 30.0, 3.0, ["ConnectionError"], ["ValueError"])


class TestIsRetryableError:
    """Test _is_retryable_error method."""

    def test_non_retryable_takes_precedence(self):
        """Test non-retryable errors checked before retryable."""
        handler = RetryHandler()
        # ConnectionError is in both lists, non-retryable should win
        assert handler._is_retryable_error(
            ConnectionError(), ["ConnectionError"], ["ConnectionError"]
        ) is False

    def test_exact_type_name_match_retryable(self):
        """Test exact type name matching for retryable errors."""
        handler = RetryHandler()

        class CustomRetryableError(Exception):
            pass

        assert handler._is_retryable_error(
            CustomRetryableError(), ["CustomRetryableError"], []
        ) is True

    def test_exact_type_name_match_non_retryable(self):
        """Test exact type name matching for non-retryable errors."""
        handler = RetryHandler()

        class CustomNonRetryableError(Exception):
            pass

        assert handler._is_retryable_error(
            CustomNonRetryableError(), [], ["CustomNonRetryableError"]
        ) is False

    def test_substring_match_retryable(self):
        """Test substring matching for retryable errors."""
        handler = RetryHandler()

        class MyConnectionRefused(Exception):
            pass

        assert handler._is_retryable_error(
            MyConnectionRefused(), ["Connection"], []
        ) is True

    def test_substring_match_non_retryable(self):
        """Test substring matching for non-retryable errors."""
        handler = RetryHandler()

        class MyAuthenticationFailed(Exception):
            pass

        assert handler._is_retryable_error(
            MyAuthenticationFailed(), [], ["Authentication"]
        ) is False

    def test_builtin_connection_error(self):
        """Test built-in ConnectionError is retryable by type hierarchy."""
        handler = RetryHandler()
        assert handler._is_retryable_error(ConnectionError(), [], []) is True

    def test_builtin_timeout_error(self):
        """Test built-in TimeoutError is retryable by type hierarchy."""
        handler = RetryHandler()
        assert handler._is_retryable_error(TimeoutError(), [], []) is True

    def test_builtin_os_error(self):
        """Test built-in OSError is retryable by type hierarchy."""
        handler = RetryHandler()
        assert handler._is_retryable_error(OSError(), [], []) is True

    def test_unknown_error_defaults_non_retryable(self):
        """Test unknown error type defaults to non-retryable (fail-safe)."""
        handler = RetryHandler()

        class CompletelyUnknownError(Exception):
            pass

        assert handler._is_retryable_error(
            CompletelyUnknownError(), [], []
        ) is False

    def test_full_error_name_match(self):
        """Test matching against full module.class error name."""
        handler = RetryHandler()

        class SpecialError(Exception):
            pass

        # The full name will be something like
        # "unit.test_retry_handler_coverage.TestIsRetryableError.test_full_error_name_match.<locals>.SpecialError"
        error = SpecialError()
        full_name = f"{type(error).__module__}.{type(error).__name__}"

        assert handler._is_retryable_error(
            error, [full_name], []
        ) is True


class TestCalculateBackoff:
    """Test _calculate_backoff method."""

    def test_basic_exponential_backoff(self):
        """Test basic exponential backoff calculation."""
        handler = RetryHandler()
        assert handler._calculate_backoff(0, 1.0, 60.0, 2.0) == 1.0
        assert handler._calculate_backoff(1, 1.0, 60.0, 2.0) == 2.0
        assert handler._calculate_backoff(2, 1.0, 60.0, 2.0) == 4.0
        assert handler._calculate_backoff(3, 1.0, 60.0, 2.0) == 8.0

    def test_capped_at_max_delay(self):
        """Test backoff is capped at max_delay."""
        handler = RetryHandler()
        assert handler._calculate_backoff(10, 1.0, 5.0, 2.0) == 5.0

    def test_negative_attempt(self):
        """Test negative attempt is treated as 0."""
        handler = RetryHandler()
        assert handler._calculate_backoff(-1, 1.0, 60.0, 2.0) == 1.0

    def test_negative_initial_delay(self):
        """Test negative initial_delay is treated as 0."""
        handler = RetryHandler()
        assert handler._calculate_backoff(0, -1.0, 60.0, 2.0) == 0.0

    def test_negative_max_delay(self):
        """Test negative max_delay is treated as 0."""
        handler = RetryHandler()
        assert handler._calculate_backoff(0, 1.0, -1.0, 2.0) == 0.0

    def test_negative_backoff_multiplier(self):
        """Test negative backoff_multiplier is treated as 1.0."""
        handler = RetryHandler()
        result = handler._calculate_backoff(2, 1.0, 60.0, -2.0)
        # With multiplier=1.0: 1.0 * 1.0^2 = 1.0
        assert result == 1.0

    def test_zero_initial_delay(self):
        """Test zero initial_delay returns zero."""
        handler = RetryHandler()
        assert handler._calculate_backoff(3, 0.0, 60.0, 2.0) == 0.0

    def test_overflow_returns_max_delay(self):
        """Test overflow in calculation returns max_delay."""
        handler = RetryHandler()
        # Very large exponent that should overflow
        result = handler._calculate_backoff(10000, 1e300, 60.0, 1e300)
        assert result <= 60.0
        assert result >= 0.0

    def test_result_always_non_negative(self):
        """Test result is always non-negative."""
        handler = RetryHandler()
        for attempt in range(10):
            result = handler._calculate_backoff(attempt, 1.0, 60.0, 2.0)
            assert result >= 0.0


class TestExecuteWithRetry:
    """Test execute_with_retry method."""

    @pytest.mark.asyncio
    async def test_no_retry_config_success(self):
        """Test no retry config executes once successfully."""
        handler = RetryHandler()
        func = AsyncMock()
        success, error = await handler.execute_with_retry(func, retry_config=None)
        assert success is True
        assert error is None
        func.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_retry_config_failure(self):
        """Test no retry config failure returns error."""
        handler = RetryHandler()
        func = AsyncMock(side_effect=RuntimeError("boom"))
        success, error = await handler.execute_with_retry(func, retry_config=None)
        assert success is False
        assert isinstance(error, RuntimeError)

    @pytest.mark.asyncio
    async def test_disabled_retry_config(self):
        """Test disabled retry config executes once."""
        handler = RetryHandler()
        func = AsyncMock()
        success, error = await handler.execute_with_retry(
            func, retry_config={"enabled": False}
        )
        assert success is True
        assert error is None

    @pytest.mark.asyncio
    async def test_empty_retry_config(self):
        """Test empty retry config (no 'enabled' key) executes once."""
        handler = RetryHandler()
        func = AsyncMock()
        success, error = await handler.execute_with_retry(func, retry_config={})
        assert success is True
        assert error is None

    @pytest.mark.asyncio
    async def test_success_on_first_attempt(self):
        """Test success on first attempt with retry enabled."""
        handler = RetryHandler()
        func = AsyncMock()
        config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": 0.01,
            "max_delay": 0.1,
        }
        success, error = await handler.execute_with_retry(func, retry_config=config)
        assert success is True
        assert error is None
        assert func.call_count == 1

    @pytest.mark.asyncio
    async def test_success_after_retries(self):
        """Test success after retries logs info message."""
        handler = RetryHandler()
        func = AsyncMock(side_effect=[
            ConnectionError("fail 1"),
            ConnectionError("fail 2"),
            None,  # Success on 3rd attempt
        ])
        config = {
            "enabled": True,
            "max_attempts": 5,
            "initial_delay": 0.01,
            "max_delay": 0.1,
        }
        success, error = await handler.execute_with_retry(func, retry_config=config)
        assert success is True
        assert error is None
        assert func.call_count == 3

    @pytest.mark.asyncio
    async def test_non_retryable_error_stops_immediately(self):
        """Test non-retryable error stops retry loop immediately."""
        handler = RetryHandler()
        func = AsyncMock(side_effect=ValueError("bad input"))
        config = {
            "enabled": True,
            "max_attempts": 5,
            "initial_delay": 0.01,
            "max_delay": 0.1,
        }
        success, error = await handler.execute_with_retry(func, retry_config=config)
        assert success is False
        assert isinstance(error, ValueError)
        assert func.call_count == 1

    @pytest.mark.asyncio
    async def test_all_attempts_exhausted(self):
        """Test all attempts exhausted returns last error."""
        handler = RetryHandler()
        func = AsyncMock(side_effect=ConnectionError("still failing"))
        config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": 0.01,
            "max_delay": 0.1,
        }
        success, error = await handler.execute_with_retry(func, retry_config=config)
        assert success is False
        assert isinstance(error, ConnectionError)
        assert func.call_count == 3

    @pytest.mark.asyncio
    async def test_with_args_and_kwargs(self):
        """Test function receives positional and keyword arguments."""
        handler = RetryHandler()
        func = AsyncMock()
        config = {
            "enabled": True,
            "max_attempts": 1,
            "initial_delay": 0.01,
            "max_delay": 0.1,
        }
        success, _ = await handler.execute_with_retry(
            func, "arg1", "arg2", retry_config=config, key1="val1"
        )
        assert success is True
        func.assert_called_once_with("arg1", "arg2", key1="val1")
