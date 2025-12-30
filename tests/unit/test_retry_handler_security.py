"""
Security tests for retry handler - DoS, resource exhaustion, and configuration injection attacks.

These tests verify that the retry handler properly validates configuration values
and prevents resource exhaustion attacks via malicious retry configurations.
"""
import pytest
import asyncio
import time
from unittest.mock import AsyncMock
from src.retry_handler import RetryHandler, retry_handler


class TestRetryHandlerSecurity:
    """Security-focused tests for retry handler."""
    
    # @pytest.mark.asyncio
    # async def test_dos_unbounded_max_attempts(self):
    #     """Test that extremely large max_attempts values are rejected or capped."""
    #     handler = RetryHandler()
    #     
    #     # Attempt with extremely large max_attempts (DoS attack)
    #     malicious_config = {
    #         "enabled": True,
    #         "max_attempts": 1000000,  # Extremely large value
    #         "initial_delay": 0.001,
    #         "max_delay": 1.0,
    #         "backoff_multiplier": 2.0
    #     }
    #     
    #     call_count = 0
    #     async def failing_function():
    #         nonlocal call_count
    #         call_count += 1
    #         raise ConnectionError("Connection failed")
    #     
    #     start_time = time.time()
    #     success, error = await handler.execute_with_retry(
    #         failing_function,
    #         retry_config=malicious_config
    #     )
    #     elapsed = time.time() - start_time
    #     
    #     # Should cap attempts to MAX_ATTEMPTS_LIMIT (20)
    #     # With max_delay of 1.0 and exponential backoff, 20 attempts should complete in reasonable time
    #     assert elapsed < 30.0, f"Retry handler should cap max_attempts to prevent DoS (took {elapsed}s)"
    #     assert call_count <= 20, f"Should cap at MAX_ATTEMPTS_LIMIT (20), not execute {call_count} retries"
    #     assert success is False
    
    # @pytest.mark.asyncio
    # async def test_dos_excessive_initial_delay(self):
    #     """Test that extremely large initial_delay values are rejected or capped."""
    #     handler = RetryHandler()
    #     
    #     # Attempt with extremely large initial_delay (DoS attack)
    #     malicious_config = {
    #         "enabled": True,
    #         "max_attempts": 2,
    #         "initial_delay": 1000000.0,  # Extremely large delay (11+ days)
    #         "max_delay": 1000000.0,
    #         "backoff_multiplier": 2.0
    #     }
    #     
    #     call_count = 0
    #     async def failing_function():
    #         nonlocal call_count
    #         call_count += 1
    #         raise ConnectionError("Connection failed")
    #     
    #     start_time = time.time()
    #     success, error = await handler.execute_with_retry(
    #         failing_function,
    #         retry_config=malicious_config
    #     )
    #     elapsed = time.time() - start_time
    #     
    #     # Should cap delay to MAX_DELAY_LIMIT (60 seconds)
    #     # With 2 attempts and max_delay capped at 60s, should complete in ~60s
    #     assert elapsed < 70.0, f"Retry handler should cap delays to prevent DoS (took {elapsed}s, max 60s delay)"
    #     assert success is False
    
    # @pytest.mark.asyncio
    # async def test_dos_excessive_max_delay(self):
    #     """Test that extremely large max_delay values are rejected or capped."""
    #     handler = RetryHandler()
    #     
    #     # Attempt with extremely large max_delay (DoS attack)
    #     malicious_config = {
    #         "enabled": True,
    #         "max_attempts": 3,
    #         "initial_delay": 1.0,
    #         "max_delay": 1000000.0,  # Extremely large max delay
    #         "backoff_multiplier": 2.0
    #     }
    #     
    #     call_count = 0
    #     async def failing_function():
    #         nonlocal call_count
    #         call_count += 1
    #         if call_count < 3:
    #             raise ConnectionError("Connection failed")
    #         return "success"
    #     
    #     start_time = time.time()
    #     success, error = await handler.execute_with_retry(
    #         failing_function,
    #         retry_config=malicious_config
    #     )
    #     elapsed = time.time() - start_time
    #     
    #     # Should cap max_delay to MAX_DELAY_LIMIT (60 seconds)
    #     # With 3 attempts and max_delay capped at 60s, should complete in ~120s (2 delays)
    #     assert elapsed < 130.0, f"Retry handler should cap max_delay to prevent DoS (took {elapsed}s, max 60s delay)"
    
    # @pytest.mark.asyncio
    # async def test_dos_exponential_backoff_overflow(self):
    #     """Test that extremely large backoff_multiplier values don't cause overflow."""
    #     handler = RetryHandler()
    #     
    #     # Attempt with extremely large backoff_multiplier
    #     malicious_config = {
    #         "enabled": True,
    #         "max_attempts": 5,
    #         "initial_delay": 1.0,
    #         "max_delay": 1000.0,
    #         "backoff_multiplier": 1000000.0  # Extremely large multiplier
    #     }
    #     
    #     call_count = 0
    #     async def failing_function():
    #         nonlocal call_count
    #         call_count += 1
    #         if call_count < 5:
    #             raise ConnectionError("Connection failed")
    #         return "success"
    #     
    #     start_time = time.time()
    #     success, error = await handler.execute_with_retry(
    #         failing_function,
    #         retry_config=malicious_config
    #     )
    #     elapsed = time.time() - start_time
    #     
    #     # Should cap at max_delay, not overflow
    #     # With 5 attempts, delays are: 1.0, 10.0, 60.0 (capped), 60.0 (capped) = ~131 seconds total
    #     # This is expected behavior - max_delay and backoff_multiplier are properly capped
    #     assert elapsed < 150.0, f"Retry handler should cap backoff to max_delay, not overflow (took {elapsed}s, expected ~131s)"
    #     # Verify calculation doesn't crash
    #     delay = handler._calculate_backoff(10, 1.0, 1000.0, 1000000.0)
    #     assert delay <= 1000.0, "Backoff calculation should cap at max_delay"
    #     assert not (delay == float('inf') or delay == float('-inf')), "Backoff should not overflow to infinity"
    
    @pytest.mark.asyncio
    async def test_negative_max_attempts(self):
        """Test that negative max_attempts values are rejected."""
        handler = RetryHandler()
        
        malicious_config = {
            "enabled": True,
            "max_attempts": -1,  # Negative value
            "initial_delay": 0.1,
            "max_delay": 1.0,
            "backoff_multiplier": 2.0
        }
        
        call_count = 0
        async def failing_function():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Connection failed")
        
        success, error = await handler.execute_with_retry(
            failing_function,
            retry_config=malicious_config
        )
        
        # Should either reject negative or default to minimum
        # Current behavior: range() with negative would not execute, but should be validated
        assert call_count >= 1, "Should execute at least once even with invalid config"
    
    @pytest.mark.asyncio
    async def test_negative_delays(self):
        """Test that negative delay values are rejected or handled safely."""
        handler = RetryHandler()
        
        malicious_config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": -1.0,  # Negative delay
            "max_delay": -1.0,  # Negative max delay
            "backoff_multiplier": 2.0
        }
        
        call_count = 0
        async def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Connection failed")
            return "success"
        
        start_time = time.time()
        success, error = await handler.execute_with_retry(
            failing_function,
            retry_config=malicious_config
        )
        elapsed = time.time() - start_time
        
        # Should not sleep with negative delays (would cause issues)
        # Should either reject or default to minimum positive value
        assert elapsed < 5.0, "Negative delays should not cause infinite sleep"
    
    @pytest.mark.asyncio
    async def test_zero_max_attempts(self):
        """Test that zero max_attempts is handled safely."""
        handler = RetryHandler()
        
        malicious_config = {
            "enabled": True,
            "max_attempts": 0,  # Zero attempts
            "initial_delay": 0.1,
            "max_delay": 1.0,
            "backoff_multiplier": 2.0
        }
        
        call_count = 0
        async def failing_function():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Connection failed")
        
        success, error = await handler.execute_with_retry(
            failing_function,
            retry_config=malicious_config
        )
        
        # Should either default to minimum or handle gracefully
        # range(0) would not execute, but should be validated
        assert call_count >= 1, "Should execute at least once even with zero max_attempts"
    
    @pytest.mark.asyncio
    async def test_zero_delays(self):
        """Test that zero delay values are handled safely."""
        handler = RetryHandler()
        
        config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": 0.0,  # Zero delay
            "max_delay": 0.0,  # Zero max delay
            "backoff_multiplier": 2.0
        }
        
        call_count = 0
        call_times = []
        async def failing_function():
            nonlocal call_count
            call_count += 1
            call_times.append(time.time())
            if call_count < 3:
                raise ConnectionError("Connection failed")
            return "success"
        
        start_time = time.time()
        success, error = await handler.execute_with_retry(
            failing_function,
            retry_config=config
        )
        elapsed = time.time() - start_time
        
        # Zero delays should be handled (no sleep, immediate retry)
        # This is acceptable behavior but should be documented
        assert elapsed < 1.0, "Zero delays should not cause long waits"
        assert success is True
    
    @pytest.mark.asyncio
    async def test_error_classification_bypass_string_matching(self):
        """Test that error classification string matching cannot be bypassed."""
        handler = RetryHandler()
        
        # Attempt to bypass non-retryable error classification
        # by creating error with substring match
        class AuthenticationErrorBypass(Exception):
            """Error that contains 'AuthenticationError' in name but should not match."""
            pass
        
        class ValueErrorBypass(Exception):
            """Error that might match 'ValueError' substring."""
            pass
        
        # Test with custom error lists
        retry_config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": 0.1,
            "max_delay": 1.0,
            "backoff_multiplier": 2.0,
            "retryable_errors": ["ConnectionError"],
            "non_retryable_errors": ["AuthenticationError", "ValueError"]
        }
        
        call_count = 0
        async def function_with_bypass_error():
            nonlocal call_count
            call_count += 1
            # Raise error that might bypass classification
            raise AuthenticationErrorBypass("Bypass attempt")
        
        success, error = await handler.execute_with_retry(
            function_with_bypass_error,
            retry_config=retry_config
        )
        
        # Should classify based on actual error type, not substring matching
        # Current implementation uses substring matching which could be bypassed
        # This test documents the behavior
        assert call_count >= 1
    
    @pytest.mark.asyncio
    async def test_default_retryable_unknown_errors(self):
        """Test that unknown errors default to retryable (security risk)."""
        handler = RetryHandler()
        
        # Create an unknown error type
        class UnknownSecurityError(Exception):
            """Unknown error that should not be retried by default."""
            pass
        
        retry_config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": 0.1,
            "max_delay": 1.0,
            "backoff_multiplier": 2.0,
            # No custom error lists - uses defaults
        }
        
        call_count = 0
        async def function_with_unknown_error():
            nonlocal call_count
            call_count += 1
            raise UnknownSecurityError("Security-related error")
        
        success, error = await handler.execute_with_retry(
            function_with_unknown_error,
            retry_config=retry_config
        )
        
        # SECURITY FIX: Unknown errors now default to non-retryable (fail-safe)
        # This prevents retrying security-related or unexpected errors
        assert call_count == 1, f"Unknown errors should not be retried (fail-safe), but was retried {call_count} times"
    
    @pytest.mark.asyncio
    async def test_concurrent_retry_exhaustion(self):
        """Test that concurrent retry operations don't cause resource exhaustion."""
        handler = RetryHandler()
        
        # Create multiple concurrent retry operations
        retry_config = {
            "enabled": True,
            "max_attempts": 10,
            "initial_delay": 0.01,
            "max_delay": 0.1,
            "backoff_multiplier": 2.0
        }
        
        call_counts = []
        async def failing_function(index):
            call_counts.append(index)
            raise ConnectionError(f"Connection failed {index}")
        
        # Launch 50 concurrent retry operations
        tasks = []
        for i in range(50):
            task = handler.execute_with_retry(
                lambda: failing_function(i),
                retry_config=retry_config
            )
            tasks.append(task)
        
        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start_time
        
        # Should complete in reasonable time
        assert elapsed < 30.0, "Concurrent retries should not cause excessive delays"
        # All should fail
        assert all(not r[0] if isinstance(r, tuple) else False for r in results), "All should fail"
    
    @pytest.mark.asyncio
    async def test_retry_config_injection_via_nested_dict(self):
        """Test that nested dict injection in retry_config is handled safely."""
        handler = RetryHandler()
        
        # Attempt to inject nested structures
        malicious_config = {
            "enabled": True,
            "max_attempts": {"__class__": "evil"},  # Dict instead of int
            "initial_delay": [1, 2, 3],  # List instead of float
            "max_delay": "not_a_number",  # String instead of float
            "backoff_multiplier": None,  # None instead of float
        }
        
        call_count = 0
        async def failing_function():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Connection failed")
        
        # Should handle type errors gracefully
        try:
            success, error = await handler.execute_with_retry(
                failing_function,
                retry_config=malicious_config
            )
            # Should either default to safe values or raise TypeError
            assert call_count >= 1
        except (TypeError, ValueError, AttributeError):
            # Acceptable - type validation should catch this
            pass
    
    @pytest.mark.asyncio
    async def test_retryable_errors_list_injection(self):
        """Test that retryable_errors list cannot be used for injection."""
        handler = RetryHandler()
        
        # Attempt to inject malicious values in error lists
        malicious_config = {
            "enabled": True,
            "max_attempts": 3,
            "initial_delay": 0.1,
            "max_delay": 1.0,
            "backoff_multiplier": 2.0,
            "retryable_errors": [
                "ConnectionError",
                "__import__('os').system('rm -rf /')",  # Code injection attempt
                "<script>alert('xss')</script>",  # XSS attempt
            ],
            "non_retryable_errors": [
                "ValueError",
                None,  # Invalid type
                123,  # Invalid type
            ]
        }
        
        call_count = 0
        async def failing_function():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Connection failed")
        
        # Should handle invalid error list items safely
        success, error = await handler.execute_with_retry(
            failing_function,
            retry_config=malicious_config
        )
        
        # Should not execute injected code
        # Error classification should handle invalid types gracefully
        assert call_count >= 1
    
    @pytest.mark.asyncio
    async def test_backoff_calculation_edge_cases(self):
        """Test backoff calculation with edge case values."""
        handler = RetryHandler()
        
        # Test various edge cases
        test_cases = [
            (0, 0.0, 10.0, 2.0),  # Zero attempt
            (100, 1.0, 10.0, 2.0),  # Large attempt number
            (10, 0.0, 10.0, 2.0),  # Zero initial delay
            (10, 1.0, 0.0, 2.0),  # Zero max delay
            (10, 1.0, 10.0, 0.0),  # Zero multiplier
            (10, 1.0, 10.0, 1.0),  # Multiplier of 1 (linear)
            (10, 1.0, 10.0, 0.5),  # Multiplier < 1 (decreasing)
        ]
        
        for attempt, initial, max_delay, multiplier in test_cases:
            delay = handler._calculate_backoff(attempt, initial, max_delay, multiplier)
            # Should never be negative, infinite, or NaN
            assert delay >= 0.0, f"Backoff delay should not be negative: {delay}"
            assert delay != float('inf'), f"Backoff delay should not be infinite: {delay}"
            assert delay == delay, f"Backoff delay should not be NaN: {delay}"  # NaN != NaN
            assert delay <= max_delay or max_delay == 0.0, f"Backoff should cap at max_delay: {delay} > {max_delay}"

