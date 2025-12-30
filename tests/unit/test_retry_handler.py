"""
Tests for retry handler functionality.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from src.retry_handler import RetryHandler, retry_handler


@pytest.mark.asyncio
async def test_retry_handler_no_config():
    """Test retry handler with no retry configuration."""
    handler = RetryHandler()
    
    # Mock successful function
    mock_func = AsyncMock(return_value=None)
    
    success, error = await handler.execute_with_retry(mock_func, retry_config=None)
    
    assert success is True
    assert error is None
    assert mock_func.call_count == 1


@pytest.mark.asyncio
async def test_retry_handler_disabled():
    """Test retry handler with retry disabled."""
    handler = RetryHandler()
    
    # Mock successful function
    mock_func = AsyncMock(return_value=None)
    
    retry_config = {"enabled": False}
    success, error = await handler.execute_with_retry(mock_func, retry_config=retry_config)
    
    assert success is True
    assert error is None
    assert mock_func.call_count == 1


@pytest.mark.asyncio
async def test_retry_handler_success_immediate():
    """Test retry handler with immediate success."""
    handler = RetryHandler()
    
    mock_func = AsyncMock(return_value=None)
    
    retry_config = {
        "enabled": True,
        "max_attempts": 3,
        "initial_delay": 0.1,
        "max_delay": 1.0,
        "backoff_multiplier": 2.0
    }
    
    success, error = await handler.execute_with_retry(mock_func, retry_config=retry_config)
    
    assert success is True
    assert error is None
    assert mock_func.call_count == 1


@pytest.mark.asyncio
async def test_retry_handler_success_after_retry():
    """Test retry handler with success after retry."""
    handler = RetryHandler()
    
    # Mock function that fails twice then succeeds
    mock_func = AsyncMock(side_effect=[
        ConnectionError("Connection failed"),
        ConnectionError("Connection failed"),
        None  # Success on third attempt
    ])
    
    retry_config = {
        "enabled": True,
        "max_attempts": 3,
        "initial_delay": 0.1,
        "max_delay": 1.0,
        "backoff_multiplier": 2.0
    }
    
    success, error = await handler.execute_with_retry(mock_func, retry_config=retry_config)
    
    assert success is True
    assert error is None
    assert mock_func.call_count == 3


@pytest.mark.asyncio
async def test_retry_handler_all_attempts_fail():
    """Test retry handler when all attempts fail."""
    handler = RetryHandler()
    
    # Mock function that always fails
    mock_func = AsyncMock(side_effect=ConnectionError("Connection failed"))
    
    retry_config = {
        "enabled": True,
        "max_attempts": 3,
        "initial_delay": 0.1,
        "max_delay": 1.0,
        "backoff_multiplier": 2.0
    }
    
    success, error = await handler.execute_with_retry(mock_func, retry_config=retry_config)
    
    assert success is False
    assert error is not None
    assert isinstance(error, ConnectionError)
    assert mock_func.call_count == 3


@pytest.mark.asyncio
async def test_retry_handler_non_retryable_error():
    """Test retry handler with non-retryable error."""
    handler = RetryHandler()
    
    # Mock function that raises non-retryable error
    mock_func = AsyncMock(side_effect=ValueError("Invalid value"))
    
    retry_config = {
        "enabled": True,
        "max_attempts": 3,
        "initial_delay": 0.1,
        "max_delay": 1.0,
        "backoff_multiplier": 2.0
    }
    
    success, error = await handler.execute_with_retry(mock_func, retry_config=retry_config)
    
    assert success is False
    assert error is not None
    assert isinstance(error, ValueError)
    # Should not retry for non-retryable errors
    assert mock_func.call_count == 1


@pytest.mark.asyncio
async def test_retry_handler_backoff_calculation():
    """Test backoff delay calculation."""
    handler = RetryHandler()
    
    # Test exponential backoff
    delay1 = handler._calculate_backoff(0, 1.0, 10.0, 2.0)
    delay2 = handler._calculate_backoff(1, 1.0, 10.0, 2.0)
    delay3 = handler._calculate_backoff(2, 1.0, 10.0, 2.0)
    
    assert delay1 == 1.0  # 1.0 * 2^0
    assert delay2 == 2.0  # 1.0 * 2^1
    assert delay3 == 4.0  # 1.0 * 2^2
    
    # Test max delay cap
    delay4 = handler._calculate_backoff(5, 1.0, 10.0, 2.0)
    assert delay4 == 10.0  # Capped at max_delay


@pytest.mark.asyncio
async def test_retry_handler_error_classification():
    """Test error classification logic."""
    handler = RetryHandler()
    
    # Retryable errors
    assert handler._is_retryable_error(ConnectionError(), [], []) is True
    assert handler._is_retryable_error(TimeoutError(), [], []) is True
    assert handler._is_retryable_error(OSError(), [], []) is True
    
    # Non-retryable errors
    assert handler._is_retryable_error(ValueError(), [], ["ValueError"]) is False
    assert handler._is_retryable_error(KeyError(), [], ["KeyError"]) is False
    
    # Custom retryable error
    class CustomConnectionError(Exception):
        pass
    
    assert handler._is_retryable_error(
        CustomConnectionError(),
        ["CustomConnectionError"],
        []
    ) is True


@pytest.mark.asyncio
async def test_retry_handler_global_instance():
    """Test global retry handler instance."""
    assert retry_handler is not None
    assert isinstance(retry_handler, RetryHandler)
    
    mock_func = AsyncMock(return_value=None)
    success, error = await retry_handler.execute_with_retry(mock_func, retry_config=None)
    
    assert success is True
    assert error is None

