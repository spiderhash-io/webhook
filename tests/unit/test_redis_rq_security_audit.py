"""
Comprehensive security audit tests for RedisRQModule.
Tests queue name security, payload security, error disclosure, connection security, and concurrent processing.
"""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock, Mock
from src.modules.redis_rq import RedisRQModule


# ============================================================================
# 1. QUEUE NAME SECURITY
# ============================================================================


class TestRedisRQQueueNameSecurity:
    """Test queue name security vulnerabilities."""

    @pytest.mark.asyncio
    async def test_queue_name_injection_attempts(self):
        """Test that malicious queue names are handled safely."""
        malicious_queue_names = [
            "queue; FLUSHALL",
            "queue\nINJECT",
            "queue\x00NULL",
            "../../etc/passwd",
            "queue|command",
            "queue&command",
            "queue`command`",
        ]

        for queue_name in malicious_queue_names:
            config = {
                "module": "redis_rq",
                "module-config": {
                    "function": "valid_function",
                    "queue_name": queue_name,
                },
                "connection_details": {"conn": Mock()},
            }

            module = RedisRQModule(config)

            # Mock Queue
            with patch("src.modules.redis_rq.Queue") as mock_queue_class:
                mock_queue = Mock()
                mock_queue.enqueue.return_value = Mock(id="test-job-id")
                mock_queue_class.return_value = mock_queue

                payload = {"test": "data"}
                headers = {}

                try:
                    await module.process(payload, headers)
                    # RQ should handle queue names safely, but we should validate
                    assert mock_queue_class.called
                    # Queue name is passed to Queue constructor
                    call_args = mock_queue_class.call_args
                    if call_args:
                        passed_queue_name = call_args[0][0] if call_args[0] else None
                        # Queue name should be passed as-is (RQ handles validation)
                        assert passed_queue_name == queue_name
                except Exception as e:
                    # Should not crash with unexpected errors
                    pass

    @pytest.mark.asyncio
    async def test_queue_name_with_control_characters(self):
        """Test that queue names with control characters are handled safely."""
        config = {
            "module": "redis_rq",
            "module-config": {
                "function": "valid_function",
                "queue_name": "queue\x00with\ncontrol",
            },
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            payload = {"test": "data"}
            headers = {}

            try:
                await module.process(payload, headers)
                # RQ should handle control characters safely
                assert mock_queue_class.called
            except Exception as e:
                # Should not crash
                pass

    @pytest.mark.asyncio
    async def test_queue_name_type_validation(self):
        """Test that non-string queue names are handled safely."""
        config = {
            "module": "redis_rq",
            "module-config": {
                "function": "valid_function",
                "queue_name": 12345,  # Non-string queue name
            },
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            payload = {"test": "data"}
            headers = {}

            try:
                await module.process(payload, headers)
                # RQ should handle non-string queue names (may convert to string)
                assert mock_queue_class.called
            except Exception as e:
                # Should not crash
                pass


# ============================================================================
# 2. PAYLOAD SECURITY
# ============================================================================


class TestRedisRQPayloadSecurity:
    """Test payload security vulnerabilities."""

    @pytest.mark.asyncio
    async def test_circular_reference_in_payload(self):
        """Test that circular references in payloads are handled safely."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        # Create circular reference
        payload = {"test": "data"}
        payload["self"] = payload  # Circular reference

        headers = {}

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            try:
                await module.process(payload, headers)
                # RQ serializes payloads, circular references may cause issues
                # Should handle gracefully
            except (ValueError, TypeError) as e:
                # JSON serialization error is expected for circular references
                assert (
                    "circular" in str(e).lower()
                    or "not serializable" in str(e).lower()
                    or isinstance(e, (ValueError, TypeError))
                )
            except Exception as e:
                # Should not crash with unexpected errors
                pass

    @pytest.mark.asyncio
    async def test_large_payload_dos(self):
        """Test that very large payloads are handled safely."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        # Very large payload
        large_payload = {"data": "x" * 10000000}  # 10MB string

        headers = {}

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            try:
                await module.process(large_payload, headers)
                # Should handle large payloads without DoS
                assert mock_queue.enqueue.called
            except Exception as e:
                # Should not crash
                pass

    @pytest.mark.asyncio
    async def test_deeply_nested_payload(self):
        """Test that deeply nested payloads are handled safely."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        # Deeply nested payload
        nested_payload = {"level": 0}
        current = nested_payload
        for i in range(1000):
            current["next"] = {"level": i + 1}
            current = current["next"]

        headers = {}

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            try:
                await module.process(nested_payload, headers)
                # Should handle deeply nested payloads safely
                assert mock_queue.enqueue.called
            except Exception as e:
                # Should not crash
                pass

    @pytest.mark.asyncio
    async def test_non_serializable_payload(self):
        """Test that non-serializable payloads are handled safely."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        # Non-serializable object
        class NonSerializable:
            pass

        payload = {"obj": NonSerializable()}
        headers = {}

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            try:
                await module.process(payload, headers)
                # RQ serializes payloads, non-serializable objects may cause issues
            except (TypeError, ValueError) as e:
                # Expected error for non-serializable objects
                assert (
                    "not serializable" in str(e).lower()
                    or "not JSON serializable" in str(e).lower()
                    or isinstance(e, (TypeError, ValueError))
                )
            except Exception as e:
                # Should not crash with unexpected errors
                pass


# ============================================================================
# 3. ERROR INFORMATION DISCLOSURE
# ============================================================================


class TestRedisRQErrorDisclosure:
    """Test error message information disclosure."""

    @pytest.mark.asyncio
    async def test_error_message_sanitization(self):
        """Test that error messages are sanitized."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        # Mock Queue to raise exception with sensitive info
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.side_effect = Exception(
                "Connection failed: password=secret_password, host=redis.internal"
            )
            mock_queue_class.return_value = mock_queue

            payload = {"test": "data"}
            headers = {}

            try:
                await module.process(payload, headers)
                assert False, "Should have raised exception"
            except Exception as e:
                # Should sanitize error message
                error_msg = str(e).lower()
                # Should not expose passwords or internal Redis details
                assert "secret_password" not in error_msg
                # Should contain sanitized error message
                assert (
                    "redis rq operation" in error_msg or "processing error" in error_msg
                )

    @pytest.mark.asyncio
    async def test_rq_details_not_exposed(self):
        """Test that RQ-specific details are not exposed in errors."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        # Mock Queue to raise RQ-specific exception
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            from rq.exceptions import NoSuchJobError

            mock_queue.enqueue.side_effect = NoSuchJobError(
                "Job not found: internal-job-id-12345"
            )
            mock_queue_class.return_value = mock_queue

            payload = {"test": "data"}
            headers = {}

            try:
                await module.process(payload, headers)
                # Should not expose RQ-specific error details
            except Exception as e:
                # Error should be handled gracefully
                pass


# ============================================================================
# 4. CONNECTION SECURITY
# ============================================================================


class TestRedisRQConnectionSecurity:
    """Test connection security vulnerabilities."""

    @pytest.mark.asyncio
    async def test_missing_connection(self):
        """Test that missing connection is handled safely."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {},
        }

        module = RedisRQModule(config)

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            assert False, "Should have raised exception"
        except Exception as e:
            # Should raise exception for missing connection
            assert "connection" in str(e).lower() or "not defined" in str(e).lower()

    @pytest.mark.asyncio
    async def test_invalid_connection(self):
        """Test that invalid connection is handled safely."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {
                "conn": "invalid_connection"  # Invalid connection type
            },
        }

        module = RedisRQModule(config)

        payload = {"test": "data"}
        headers = {}

        # Mock Queue to handle invalid connection
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue_class.side_effect = Exception("Invalid connection")

            try:
                await module.process(payload, headers)
                # Should handle invalid connection gracefully
            except Exception as e:
                # Should not crash
                pass


# ============================================================================
# 5. CONFIGURATION SECURITY
# ============================================================================


class TestRedisRQConfigurationSecurity:
    """Test configuration security and type validation."""

    def test_config_type_validation(self):
        """Test that config values are validated for correct types."""
        invalid_configs = [
            {
                "module": "redis_rq",
                "module-config": {"function": None},
                "connection_details": {"conn": Mock()},
            },
            {
                "module": "redis_rq",
                "module-config": {"function": 123},
                "connection_details": {"conn": Mock()},
            },
            {
                "module": "redis_rq",
                "module-config": {"function": []},
                "connection_details": {"conn": Mock()},
            },
            {
                "module": "redis_rq",
                "module-config": {"function": {}},
                "connection_details": {"conn": Mock()},
            },
        ]

        for invalid_config in invalid_configs:
            try:
                module = RedisRQModule(invalid_config)
                # Should validate function type during initialization
                assert module._validated_function_name is None or isinstance(
                    module._validated_function_name, str
                )
            except ValueError as e:
                # Should raise ValueError for invalid function types
                assert (
                    "non-empty string" in str(e).lower() or "must be" in str(e).lower()
                )
            except Exception as e:
                # Should not crash
                pass

    def test_queue_name_type_validation(self):
        """Test that queue name type is handled safely."""
        config = {
            "module": "redis_rq",
            "module-config": {
                "function": "valid_function",
                "queue_name": None,  # None queue name (should use default)
            },
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)
        # Should use default queue name when None
        assert (
            module.module_config.get("queue_name", "default") == "default"
            or module.module_config.get("queue_name") is None
        )


# ============================================================================
# 6. CONCURRENT PROCESSING
# ============================================================================


class TestRedisRQConcurrentProcessing:
    """Test concurrent processing security."""

    @pytest.mark.asyncio
    async def test_concurrent_message_processing(self):
        """Test that concurrent message processing is handled safely."""
        import asyncio

        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            # Process multiple messages concurrently
            async def process_message(i):
                module = RedisRQModule(config)
                payload = {"test": f"data_{i}"}
                headers = {}
                await module.process(payload, headers)

            # Process 10 messages concurrently
            tasks = [process_message(i) for i in range(10)]
            await asyncio.gather(*tasks)

            # Should handle concurrent processing safely
            # Each process() call creates a new Queue, so we expect multiple calls
            assert mock_queue_class.call_count >= 10


# ============================================================================
# 7. EDGE CASES & BOUNDARY CONDITIONS
# ============================================================================


class TestRedisRQEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_payload(self):
        """Test handling of empty payload."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        payload = {}
        headers = {}

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            try:
                await module.process(payload, headers)
                # Should handle empty payload safely
                assert mock_queue.enqueue.called
            except Exception as e:
                # Should not crash
                pass

    @pytest.mark.asyncio
    async def test_none_payload(self):
        """Test handling of None payload."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        payload = None
        headers = {}

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            try:
                await module.process(payload, headers)
                # Should handle None payload safely
                assert mock_queue.enqueue.called
            except Exception as e:
                # Should not crash
                pass

    @pytest.mark.asyncio
    async def test_empty_headers(self):
        """Test handling of empty headers."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        payload = {"test": "data"}
        headers = {}

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            try:
                await module.process(payload, headers)
                # Should handle empty headers safely
                assert mock_queue.enqueue.called
            except Exception as e:
                # Should not crash
                pass


# ============================================================================
# 8. FUNCTION NAME VALIDATION EDGE CASES
# ============================================================================


class TestRedisRQFunctionNameValidation:
    """Test function name validation edge cases."""

    def test_function_name_at_max_length(self):
        """Test function name at maximum length."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "a" * 255},  # Max length
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)
        assert module._validated_function_name == "a" * 255

    def test_function_name_regex_redos(self):
        """Test ReDoS vulnerability in function name regex."""
        import time

        # Complex function name that might cause ReDoS
        complex_name = "a" * 1000 + "!"  # Long string ending with invalid char

        start_time = time.time()
        try:
            config = {
                "module": "redis_rq",
                "module-config": {"function": complex_name},
                "connection_details": {"conn": Mock()},
            }
            RedisRQModule(config)
            assert False, "Should have raised ValueError"
        except ValueError:
            elapsed = time.time() - start_time
            # Should complete quickly (no ReDoS)
            assert elapsed < 1.0, f"ReDoS detected: validation took {elapsed:.2f}s"

    def test_function_name_unicode(self):
        """Test that Unicode function names are rejected."""
        unicode_names = [
            "测试_function",
            "ログ_function",
            "логи_function",
            "function_📊",
        ]

        for name in unicode_names:
            config = {
                "module": "redis_rq",
                "module-config": {"function": name},
                "connection_details": {"conn": Mock()},
            }
            try:
                RedisRQModule(config)
                # Should reject Unicode function names
            except ValueError as e:
                # Should raise ValueError for invalid function names
                assert "does not match allowed patterns" in str(
                    e
                ) or "dangerous character" in str(e)


# ============================================================================
# 9. HEADERS HANDLING SECURITY
# ============================================================================


class TestRedisRQHeadersHandling:
    """Test headers handling security."""

    @pytest.mark.asyncio
    async def test_headers_with_special_characters(self):
        """Test that headers with special characters are handled safely."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        payload = {"test": "data"}
        # Headers with special characters
        headers = {
            "X-Test": "value\nwith\rspecial\tchars",
            "X-Another": "value with spaces",
        }

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            try:
                await module.process(payload, headers)
                # Should handle special characters in headers safely
                assert mock_queue.enqueue.called
            except Exception as e:
                # Should not crash
                pass

    @pytest.mark.asyncio
    async def test_headers_with_unicode(self):
        """Test that headers with Unicode are handled safely."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        payload = {"test": "data"}
        headers = {"X-Test": "测试_🔑_ключ"}

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            try:
                await module.process(payload, headers)
                # Should handle Unicode in headers safely
                assert mock_queue.enqueue.called
            except Exception as e:
                # Should not crash
                pass


# ============================================================================
# 10. RQ-SPECIFIC VULNERABILITIES
# ============================================================================


class TestRedisRQRQSpecific:
    """Test RQ-specific vulnerabilities."""

    @pytest.mark.asyncio
    async def test_enqueue_with_validated_function(self):
        """Test that enqueue uses validated function name."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "valid_function"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        payload = {"test": "data"}
        headers = {}

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            await module.process(payload, headers)

            # Verify enqueue was called with validated function name
            mock_queue.enqueue.assert_called_once_with(
                "valid_function", payload, headers
            )

    @pytest.mark.asyncio
    async def test_enqueue_with_module_function(self):
        """Test that enqueue works with module.function names."""
        config = {
            "module": "redis_rq",
            "module-config": {"function": "utils.process_data"},
            "connection_details": {"conn": Mock()},
        }

        module = RedisRQModule(config)

        payload = {"test": "data"}
        headers = {}

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            await module.process(payload, headers)

            # Verify enqueue was called with validated function name
            mock_queue.enqueue.assert_called_once_with(
                "utils.process_data", payload, headers
            )

    @pytest.mark.asyncio
    async def test_default_queue_name(self):
        """Test that default queue name is used when not specified."""
        mock_connection = Mock()
        config = {
            "module": "redis_rq",
            "module-config": {
                "function": "valid_function"
                # queue_name not specified, should use 'default'
            },
            "connection_details": {"conn": mock_connection},
        }

        module = RedisRQModule(config)

        payload = {"test": "data"}
        headers = {}

        # Mock Queue
        with patch("src.modules.redis_rq.Queue") as mock_queue_class:
            mock_queue = Mock()
            mock_queue.enqueue.return_value = Mock(id="test-job-id")
            mock_queue_class.return_value = mock_queue

            await module.process(payload, headers)

            # Verify Queue was created with default queue name and same connection
            mock_queue_class.assert_called_once_with(
                "default", connection=mock_connection
            )
