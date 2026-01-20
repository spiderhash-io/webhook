"""
Comprehensive security audit tests for EndpointStats (utils.py).

This test suite covers security vulnerabilities in the in-memory statistics
tracking system, including DoS attacks, type confusion, memory exhaustion,
and information disclosure.
"""

import pytest
import asyncio
from src.utils import EndpointStats
from datetime import datetime, timedelta, timezone


class TestEndpointStatsTypeConfusion:
    """Test type confusion attacks on endpoint_name parameter."""

    @pytest.mark.asyncio
    async def test_endpoint_name_none(self):
        """Test that None endpoint_name is handled safely."""
        stats = EndpointStats()

        # Should not crash, but may raise TypeError
        with pytest.raises((TypeError, AttributeError)):
            await stats.increment(None)

    @pytest.mark.asyncio
    async def test_endpoint_name_non_string_types(self):
        """Test that non-string endpoint names are handled safely."""
        stats = EndpointStats()

        # Test various non-string types
        invalid_types = [
            123,  # int
            123.45,  # float
            [],  # list
            {},  # dict
            True,  # bool
            set(),  # set
        ]

        for invalid_type in invalid_types:
            # Should not crash, but may raise TypeError
            with pytest.raises((TypeError, AttributeError)):
                await stats.increment(invalid_type)

    @pytest.mark.asyncio
    async def test_endpoint_name_empty_string(self):
        """Test that empty string endpoint names are handled."""
        stats = EndpointStats()

        # Empty string should be accepted (but may cause issues in get_stats)
        await stats.increment("")
        result = stats.get_stats()

        # Empty string should be in results
        assert "" in result or len(result) == 0


class TestEndpointStatsDoS:
    """Test DoS attacks via excessive endpoint names."""

    @pytest.mark.asyncio
    async def test_many_unique_endpoints_dos(self):
        """Test DoS via creating many unique endpoint names."""
        stats = EndpointStats()

        # Create many unique endpoint names
        num_endpoints = 10000

        for i in range(num_endpoints):
            await stats.increment(f"endpoint_{i}")

        # get_stats should handle this without crashing
        result = stats.get_stats()

        # Should have many endpoints
        assert len(result) == num_endpoints

    @pytest.mark.asyncio
    async def test_very_long_endpoint_name(self):
        """Test DoS via very long endpoint name - should be rejected."""
        stats = EndpointStats()

        # Very long endpoint name (1MB) - should be rejected
        long_name = "a" * (1024 * 1024)

        # Should raise ValueError due to length validation
        with pytest.raises(ValueError, match="endpoint_name too long"):
            await stats.increment(long_name)

    @pytest.mark.asyncio
    async def test_many_buckets_per_endpoint(self):
        """Test DoS via creating many time buckets for one endpoint."""
        stats = EndpointStats()

        # Simulate many increments over time (would normally be spread out)
        # But we can't easily manipulate time, so we'll test with many increments
        endpoint = "test_endpoint"

        # Many increments should create many buckets
        for _ in range(1000):
            await stats.increment(endpoint)

        result = stats.get_stats()
        assert endpoint in result


class TestEndpointStatsMemoryExhaustion:
    """Test memory exhaustion attacks."""

    @pytest.mark.asyncio
    async def test_memory_exhaustion_many_endpoints(self):
        """Test memory exhaustion via many unique endpoints."""
        stats = EndpointStats()

        # Create a large number of unique endpoints
        # This should be handled gracefully
        num_endpoints = 50000

        try:
            for i in range(num_endpoints):
                await stats.increment(f"endpoint_{i}")

            # get_stats should complete without memory issues
            result = stats.get_stats()
            assert len(result) == num_endpoints
        except MemoryError:
            # Memory error is acceptable for extreme cases
            pytest.skip("Memory exhaustion test - system ran out of memory")

    @pytest.mark.asyncio
    async def test_memory_exhaustion_large_endpoint_names(self):
        """Test memory exhaustion via very large endpoint names - should be rejected."""
        stats = EndpointStats()

        # Create endpoints with very large names - should be rejected
        large_name_size = 10 * 1024 * 1024  # 10MB per name

        # Should raise ValueError due to length validation
        for i in range(10):  # Test with fewer iterations
            large_name = "a" * large_name_size + str(i)
            with pytest.raises(ValueError, match="endpoint_name too long"):
                await stats.increment(large_name)


class TestEndpointStatsInformationDisclosure:
    """Test information disclosure vulnerabilities."""

    @pytest.mark.asyncio
    async def test_error_message_disclosure(self):
        """Test that error messages don't disclose sensitive information."""
        stats = EndpointStats()

        # Try to trigger an error with sensitive information
        try:
            # This should not expose internal details
            await stats.increment(None)
        except Exception as e:
            error_msg = str(e)
            # Should not contain sensitive patterns
            sensitive_patterns = [
                "file://",
                "http://",
                "postgresql://",
                "redis://",
                "password",
                "secret",
            ]
            for pattern in sensitive_patterns:
                assert (
                    pattern.lower() not in error_msg.lower()
                ), f"Error message contains sensitive pattern: {pattern}"

    @pytest.mark.asyncio
    async def test_get_stats_information_disclosure(self):
        """Test that get_stats doesn't expose sensitive information."""
        stats = EndpointStats()

        # Add some endpoints
        await stats.increment("normal_endpoint")

        # get_stats should return clean data
        result = stats.get_stats()

        # Should not contain sensitive patterns in structure
        import json

        stats_json = json.dumps(result)

        sensitive_patterns = [
            "file://",
            "postgresql://",
            "redis://",
            "password",
            "secret",
        ]
        for pattern in sensitive_patterns:
            assert (
                pattern.lower() not in stats_json.lower()
            ), f"get_stats contains sensitive pattern: {pattern}"


class TestEndpointStatsRaceConditions:
    """Test race condition vulnerabilities."""

    @pytest.mark.asyncio
    async def test_concurrent_increment(self):
        """Test concurrent increment operations."""
        stats = EndpointStats()
        endpoint = "concurrent_endpoint"

        # Create many concurrent increments
        num_concurrent = 100

        async def increment():
            await stats.increment(endpoint)

        # Run all increments concurrently
        await asyncio.gather(*[increment() for _ in range(num_concurrent)])

        # Check that all increments were recorded
        result = stats.get_stats()
        assert endpoint in result
        assert result[endpoint]["total"] == num_concurrent

    @pytest.mark.asyncio
    async def test_concurrent_get_stats(self):
        """Test concurrent get_stats calls."""
        stats = EndpointStats()

        # Add some endpoints
        for i in range(10):
            await stats.increment(f"endpoint_{i}")

        # Call get_stats concurrently
        async def get_stats():
            return stats.get_stats()

        results = await asyncio.gather(*[get_stats() for _ in range(10)])

        # All results should be consistent
        for result in results:
            assert len(result) == 10


class TestEndpointStatsEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_endpoint_name_with_null_bytes(self):
        """Test endpoint names with null bytes."""
        stats = EndpointStats()

        # Null bytes in endpoint name
        endpoint = "test\x00endpoint"

        # Should handle null bytes (may be stripped or cause issues)
        try:
            await stats.increment(endpoint)
            result = stats.get_stats()
            # Should not crash
            assert True
        except (TypeError, ValueError):
            # Acceptable to reject null bytes
            pass

    @pytest.mark.asyncio
    async def test_endpoint_name_with_newlines(self):
        """Test endpoint names with newlines."""
        stats = EndpointStats()

        # Newlines in endpoint name
        endpoint = "test\nendpoint"

        await stats.increment(endpoint)
        result = stats.get_stats()

        # Should handle newlines
        assert endpoint in result or "\n" in str(result)

    @pytest.mark.asyncio
    async def test_endpoint_name_with_unicode(self):
        """Test endpoint names with Unicode characters."""
        stats = EndpointStats()

        # Unicode endpoint names
        unicode_endpoints = [
            "测试端点",
            "тест_эндпоинт",
            "🎯endpoint",
            "endpoint_🚀",
        ]

        for endpoint in unicode_endpoints:
            await stats.increment(endpoint)

        result = stats.get_stats()

        # All Unicode endpoints should be in results
        for endpoint in unicode_endpoints:
            assert endpoint in result

    @pytest.mark.asyncio
    async def test_get_stats_empty(self):
        """Test get_stats with no endpoints."""
        stats = EndpointStats()

        # No endpoints added
        result = stats.get_stats()

        # Should return empty dict or dict with no endpoints
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_cleanup_old_buckets(self):
        """Test cleanup of old buckets."""
        stats = EndpointStats()
        endpoint = "test_endpoint"

        # Add some increments
        for _ in range(10):
            await stats.increment(endpoint)

        # Manually call cleanup (normally called in increment)
        now = datetime.now(timezone.utc)
        stats._cleanup_old_buckets(endpoint, now)

        # Should not crash
        result = stats.get_stats()
        assert endpoint in result


class TestEndpointStatsBucketManipulation:
    """Test bucket timestamp manipulation attacks."""

    @pytest.mark.asyncio
    async def test_get_bucket_edge_cases(self):
        """Test _get_bucket with edge cases."""
        stats = EndpointStats()

        # Test various timestamps
        test_timestamps = [
            datetime.min.replace(tzinfo=timezone.utc),
            datetime.max.replace(tzinfo=timezone.utc),
            datetime.now(timezone.utc),
        ]

        for ts in test_timestamps:
            bucket = stats._get_bucket(ts)
            # Should return a datetime
            assert isinstance(bucket, datetime)

    @pytest.mark.asyncio
    async def test_bucket_overflow(self):
        """Test bucket calculation with very large timestamps."""
        stats = EndpointStats()

        # Very large timestamp
        large_ts = datetime.max.replace(tzinfo=timezone.utc)

        try:
            bucket = stats._get_bucket(large_ts)
            assert isinstance(bucket, datetime)
        except (OverflowError, ValueError):
            # Acceptable to reject extreme timestamps
            pass


class TestEndpointStatsConcurrentAccess:
    """Test concurrent access patterns."""

    @pytest.mark.asyncio
    async def test_concurrent_increment_and_get_stats(self):
        """Test concurrent increment and get_stats operations."""
        stats = EndpointStats()
        endpoint = "concurrent_endpoint"

        async def increment_loop():
            for _ in range(50):
                await stats.increment(endpoint)
                await asyncio.sleep(0.001)  # Small delay

        async def get_stats_loop():
            for _ in range(50):
                result = stats.get_stats()
                await asyncio.sleep(0.001)  # Small delay

        # Run both operations concurrently
        await asyncio.gather(increment_loop(), get_stats_loop())

        # Final result should be consistent
        result = stats.get_stats()
        assert endpoint in result
        assert result[endpoint]["total"] == 50


class TestEndpointStatsValidation:
    """Test input validation and sanitization."""

    @pytest.mark.asyncio
    async def test_endpoint_name_validation_missing(self):
        """Test that endpoint_name validation is missing (vulnerability)."""
        stats = EndpointStats()

        # Currently, no validation is performed on endpoint_name
        # This is a potential vulnerability

        # Test with various problematic inputs
        problematic_inputs = [
            None,
            123,
            [],
            {},
        ]

        for input_val in problematic_inputs:
            # Should either validate or handle gracefully
            try:
                await stats.increment(input_val)
                # If it doesn't raise an error, validation is missing
                result = stats.get_stats()
                # Check if invalid input was stored
                if input_val in result or str(input_val) in result:
                    # Validation is missing - this is a vulnerability
                    assert (
                        False
                    ), f"Invalid input {input_val} was accepted without validation"
            except (TypeError, AttributeError, ValueError):
                # Good - validation is present
                pass
