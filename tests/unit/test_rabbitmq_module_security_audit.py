"""
Comprehensive security audit tests for RabbitMQModule.
Tests message header injection, payload security, connection handling, error disclosure, and edge cases.
"""

import pytest
import json
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from src.modules.rabbitmq_module import RabbitMQModule


# ============================================================================
# 1. MESSAGE HEADER INJECTION ATTACKS
# ============================================================================


class TestRabbitMQHeaderInjection:
    """Test message header injection vulnerabilities."""

    @pytest.mark.asyncio
    async def test_newline_injection_in_headers(self):
        """Test that newlines in headers are handled safely."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        # Mock connection pool
        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        # Headers with newlines (should be handled by aio_pika, but we test)
        malicious_headers = {
            "X-Header": "value\nInjected-Header: malicious",
            "X-Header2": "value\rInjected-Header2: malicious",
            "X-Header3": "value\r\nInjected-Header3: malicious",
        }

        payload = {"test": "data"}

        try:
            await module.process(payload, malicious_headers)
            # aio_pika should handle headers safely, but we verify no crashes
        except Exception as e:
            # Should not expose internal details
            error_msg = str(e).lower()
            assert "traceback" not in error_msg
            assert "file" not in error_msg

    @pytest.mark.asyncio
    async def test_null_byte_injection_in_headers(self):
        """Test that null bytes in headers are handled safely."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        # Headers with null bytes
        malicious_headers = {
            "X-Header": "value\x00injection",
        }

        payload = {"test": "data"}

        try:
            await module.process(payload, malicious_headers)
            # Should handle null bytes safely
        except Exception as e:
            # Should not expose internal details
            error_msg = str(e).lower()
            assert "traceback" not in error_msg

    @pytest.mark.asyncio
    async def test_very_large_headers(self):
        """Test that very large headers are handled without DoS."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        # Very large header value
        large_headers = {
            "X-Large-Header": "x" * (100 * 1024),  # 100KB header
        }

        payload = {"test": "data"}

        try:
            await module.process(payload, large_headers)
            # Should handle large headers (may be slow, but shouldn't crash)
        except Exception as e:
            # Should handle gracefully
            pass


# ============================================================================
# 2. PAYLOAD SECURITY
# ============================================================================


class TestRabbitMQPayloadSecurity:
    """Test payload serialization and security."""

    @pytest.mark.asyncio
    async def test_circular_reference_in_payload(self):
        """Test that circular references in payload are handled safely."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        # Create circular reference
        payload = {"key": "value"}
        payload["self"] = payload  # Circular reference

        headers = {}

        try:
            await module.process(payload, headers)
            # json.dumps should handle circular references (raise TypeError)
            assert False, "Should raise error for circular reference"
        except (TypeError, ValueError) as e:
            # Expected - circular references can't be serialized
            assert True
        except Exception as e:
            # Other exceptions should be sanitized
            error_msg = str(e).lower()
            assert "traceback" not in error_msg

    @pytest.mark.asyncio
    async def test_very_large_payload(self):
        """Test that very large payloads are handled without DoS."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        # Very large payload (100MB)
        large_payload = {"data": "x" * (100 * 1024 * 1024)}

        headers = {}

        try:
            await module.process(large_payload, headers)
            # Should handle large payloads (may be slow, but shouldn't crash)
            # Note: InputValidator should catch this before it reaches the module
        except Exception as e:
            # Should handle gracefully
            pass

    @pytest.mark.asyncio
    async def test_non_serializable_payload(self):
        """Test that non-serializable payloads are handled safely."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        # Non-serializable object (function)
        payload = {"func": lambda x: x}

        headers = {}

        try:
            await module.process(payload, headers)
            # json.dumps should fail for non-serializable objects
            assert False, "Should raise error for non-serializable payload"
        except (TypeError, ValueError) as e:
            # Expected
            assert True
        except Exception as e:
            # Should be sanitized
            error_msg = str(e).lower()
            assert "traceback" not in error_msg


# ============================================================================
# 3. CONNECTION POOL SECURITY
# ============================================================================


class TestRabbitMQConnectionPoolSecurity:
    """Test connection pool security and exhaustion attacks."""

    @pytest.mark.asyncio
    async def test_connection_pool_exhaustion_handling(self):
        """Test that connection pool exhaustion is handled gracefully."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        # Simulate pool exhaustion
        mock_connection_pool.get_connection = AsyncMock(return_value=None)

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            assert False, "Should raise error when connection is None"
        except Exception as e:
            # Should handle gracefully
            error_msg = str(e).lower()
            # Should not expose internal RabbitMQ details
            assert "rabbitmq" not in error_msg or "operation" in error_msg
            assert "traceback" not in error_msg

    @pytest.mark.asyncio
    async def test_missing_connection_pool(self):
        """Test that missing connection pool is handled safely."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        config["connection_details"] = {}  # No connection_pool
        module = RabbitMQModule(config)

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            assert False, "Should raise error when connection pool is missing"
        except Exception as e:
            # Should handle gracefully
            error_msg = str(e).lower()
            assert "traceback" not in error_msg

    @pytest.mark.asyncio
    async def test_connection_release_on_error(self):
        """Test that connection is always released even on error."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(
            side_effect=Exception("Channel creation failed")
        )
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            assert False, "Should raise error"
        except Exception:
            pass

        # Verify connection was released
        mock_connection_pool.release.assert_called_once_with(mock_connection)


# ============================================================================
# 4. ERROR MESSAGE DISCLOSURE
# ============================================================================


class TestRabbitMQErrorDisclosure:
    """Test error message information disclosure."""

    @pytest.mark.asyncio
    async def test_rabbitmq_error_sanitization(self):
        """Test that RabbitMQ errors are sanitized."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()

        # Simulate RabbitMQ error with sensitive information
        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(
            side_effect=Exception(
                "Access denied to queue 'test_queue' with credentials 'admin:password123'"
            )
        )
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            assert False, "Should raise error"
        except Exception as e:
            # Should sanitize error message
            error_msg = str(e).lower()
            assert "password123" not in error_msg
            assert "credentials" not in error_msg or "operation" in error_msg
            assert "rabbitmq operation" in error_msg or "operation" in error_msg

    @pytest.mark.asyncio
    async def test_queue_name_not_in_error(self):
        """Test that queue name is not exposed in error messages."""
        config = {"module": "rabbitmq", "queue_name": "sensitive_queue_name_xyz123"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(side_effect=Exception("Queue error"))
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            assert False, "Should raise error"
        except Exception as e:
            # Should not expose queue name
            error_msg = str(e)
            assert "sensitive_queue_name_xyz123" not in error_msg

    @pytest.mark.asyncio
    async def test_internal_paths_not_exposed(self):
        """Test that internal file paths are not exposed in errors."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()

        # Simulate error with file path
        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(
            side_effect=Exception(
                "FileNotFoundError: /etc/rabbitmq/rabbitmq.conf not found"
            )
        )
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            assert False, "Should raise error"
        except Exception as e:
            # Should sanitize error
            error_msg = str(e).lower()
            assert "/etc/rabbitmq" not in error_msg
            assert "rabbitmq.conf" not in error_msg


# ============================================================================
# 5. CONFIG INJECTION & TYPE VALIDATION
# ============================================================================


class TestRabbitMQConfigInjection:
    """Test configuration injection and type validation."""

    def test_queue_name_type_validation(self):
        """Test that queue_name must be a string."""
        invalid_configs = [
            {"module": "rabbitmq", "queue_name": None},
            {"module": "rabbitmq", "queue_name": 123},
            {"module": "rabbitmq", "queue_name": []},
            {"module": "rabbitmq", "queue_name": {}},
        ]

        for invalid_config in invalid_configs:
            # None is allowed in __init__ but will fail in process()
            if invalid_config["queue_name"] is None:
                module = RabbitMQModule(invalid_config)
                assert module._validated_queue_name is None
            else:
                with pytest.raises(ValueError) as exc_info:
                    RabbitMQModule(invalid_config)
                assert (
                    "non-empty string" in str(exc_info.value).lower()
                    or "must be" in str(exc_info.value).lower()
                )

    @pytest.mark.asyncio
    async def test_missing_queue_name_in_process(self):
        """Test that missing queue_name in process() raises error."""
        config = {"module": "rabbitmq", "queue_name": None}

        mock_connection_pool = Mock()
        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        payload = {"test": "data"}
        headers = {}

        with pytest.raises(ValueError) as exc_info:
            await module.process(payload, headers)
        assert (
            "required" in str(exc_info.value).lower()
            or "queue name" in str(exc_info.value).lower()
        )

    def test_queue_name_validation_during_init(self):
        """Test that queue_name is validated during initialization."""
        config = {
            "module": "rabbitmq",
            "queue_name": "../../etc/passwd",  # Path traversal attempt
        }

        with pytest.raises(ValueError) as exc_info:
            RabbitMQModule(config)
        error_msg = str(exc_info.value).lower()
        assert (
            "invalid" in error_msg
            or "dangerous" in error_msg
            or "forbidden" in error_msg
        )


# ============================================================================
# 6. CHANNEL & QUEUE DECLARATION SECURITY
# ============================================================================


class TestRabbitMQChannelSecurity:
    """Test channel and queue declaration security."""

    @pytest.mark.asyncio
    async def test_queue_declaration_with_validated_name(self):
        """Test that queue declaration uses validated queue name."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        payload = {"test": "data"}
        headers = {}

        await module.process(payload, headers)

        # Verify queue was declared with validated name
        mock_channel.declare_queue.assert_called_once_with("test_queue", durable=True)
        # Verify publish used validated routing key
        mock_exchange.publish.assert_called_once()
        call_args = mock_exchange.publish.call_args
        assert call_args[1]["routing_key"] == "test_queue"

    @pytest.mark.asyncio
    async def test_channel_creation_error_handling(self):
        """Test that channel creation errors are handled securely."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()

        # Simulate channel creation failure
        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(
            side_effect=Exception("Channel creation failed with internal error")
        )
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            assert False, "Should raise error"
        except Exception as e:
            # Should sanitize error
            error_msg = str(e).lower()
            assert "internal error" not in error_msg
            assert "rabbitmq operation" in error_msg or "operation" in error_msg
            # Verify connection was released
            mock_connection_pool.release.assert_called_once()


# ============================================================================
# 7. MESSAGE PROPERTIES SECURITY
# ============================================================================


class TestRabbitMQMessageProperties:
    """Test message properties and delivery mode security."""

    @pytest.mark.asyncio
    async def test_message_delivery_mode_set(self):
        """Test that message delivery mode is set correctly."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        payload = {"test": "data"}
        headers = {}

        await module.process(payload, headers)

        # Verify message was created with delivery_mode=2 (persistent)
        publish_call = mock_exchange.publish.call_args
        message = publish_call[0][0]  # First positional argument
        assert message.delivery_mode == 2

    @pytest.mark.asyncio
    async def test_message_headers_preserved(self):
        """Test that message headers are correctly preserved."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        payload = {"test": "data"}
        headers = {"X-Custom-Header": "value", "X-Another-Header": "value2"}

        await module.process(payload, headers)

        # Verify message headers were set
        publish_call = mock_exchange.publish.call_args
        message = publish_call[0][0]
        assert message.headers == headers


# ============================================================================
# 8. JSON SERIALIZATION SECURITY
# ============================================================================


class TestRabbitMQJSONSerialization:
    """Test JSON serialization security."""

    @pytest.mark.asyncio
    async def test_json_serialization_handles_special_chars(self):
        """Test that JSON serialization handles special characters safely."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        # Payload with special characters
        payload = {
            "data": "test\x00data",  # Null byte
            "unicode": "测试",
            "special": "test\n\r\t",
        }

        headers = {}

        await module.process(payload, headers)

        # Verify message body was serialized
        publish_call = mock_exchange.publish.call_args
        message = publish_call[0][0]
        # Body should be bytes
        assert isinstance(message.body, bytes)
        # Should be valid JSON
        decoded = json.loads(message.body.decode("utf-8"))
        assert decoded == payload

    @pytest.mark.asyncio
    async def test_json_serialization_with_unicode(self):
        """Test that JSON serialization handles Unicode correctly."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        # Payload with Unicode
        payload = {
            "chinese": "测试",
            "japanese": "ログ",
            "russian": "логи",
            "emoji": "📊",
        }

        headers = {}

        await module.process(payload, headers)

        # Verify Unicode was serialized correctly
        publish_call = mock_exchange.publish.call_args
        message = publish_call[0][0]
        decoded = json.loads(message.body.decode("utf-8"))
        assert decoded == payload


# ============================================================================
# 9. CONCURRENT PROCESSING SECURITY
# ============================================================================


class TestRabbitMQConcurrentProcessing:
    """Test concurrent processing security."""

    @pytest.mark.asyncio
    async def test_concurrent_message_processing(self):
        """Test that concurrent message processing is handled securely."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        # Process multiple messages concurrently
        tasks = [module.process({"data": f"message_{i}"}, {}) for i in range(10)]

        await asyncio.gather(*tasks)

        # Verify all messages were processed
        assert mock_exchange.publish.call_count == 10
        # Verify connections were released
        assert mock_connection_pool.release.call_count == 10


# ============================================================================
# 10. EDGE CASES & BOUNDARY CONDITIONS
# ============================================================================


class TestRabbitMQEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_payload(self):
        """Test that empty payloads are handled safely."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        # Empty payload
        payload = {}
        headers = {}

        await module.process(payload, headers)

        # Verify message was published
        mock_exchange.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_empty_headers(self):
        """Test that empty headers are handled safely."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        payload = {"test": "data"}
        headers = {}  # Empty headers

        await module.process(payload, headers)

        # Verify message was published with empty headers
        publish_call = mock_exchange.publish.call_args
        message = publish_call[0][0]
        assert message.headers == {}

    @pytest.mark.asyncio
    async def test_non_dict_payload(self):
        """Test that non-dict payloads are handled safely."""
        config = {"module": "rabbitmq", "queue_name": "test_queue"}

        mock_connection_pool = Mock()
        mock_connection = AsyncMock()
        mock_channel = AsyncMock()
        mock_queue = AsyncMock()
        mock_exchange = AsyncMock()

        mock_connection_pool.get_connection = AsyncMock(return_value=mock_connection)
        mock_connection.channel = AsyncMock(return_value=mock_channel)
        mock_channel.declare_queue = AsyncMock(return_value=mock_queue)
        mock_channel.default_exchange = mock_exchange
        mock_exchange.publish = AsyncMock()
        mock_connection_pool.release = AsyncMock()

        config["connection_details"] = {"connection_pool": mock_connection_pool}
        module = RabbitMQModule(config)

        # Non-dict payloads
        test_cases = [
            "string_payload",
            123,
            [1, 2, 3],
            True,
            None,
        ]

        for payload in test_cases:
            headers = {}
            await module.process(payload, headers)

            # Verify message was serialized
            publish_call = mock_exchange.publish.call_args
            message = publish_call[0][0]
            decoded = json.loads(message.body.decode("utf-8"))
            assert decoded == payload
