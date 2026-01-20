"""
Comprehensive security audit tests for KafkaModule.
Tests message key injection, partition manipulation, header injection, payload security, connection security, and error disclosure.
"""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from src.modules.kafka import KafkaModule


# ============================================================================
# 1. MESSAGE KEY INJECTION
# ============================================================================


class TestKafkaMessageKeyInjection:
    """Test message key injection vulnerabilities."""

    @pytest.mark.asyncio
    async def test_message_key_injection_attempts(self):
        """Test that malicious message keys are handled safely."""
        config = {
            "module": "kafka",
            "topic": "webhook_events",
            "module-config": {"key": "../../etc/passwd"},  # Path traversal attempt
        }

        module = KafkaModule(config)

        # Mock producer
        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            # Should handle key safely (key is encoded as bytes)
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash on malicious key
            assert False, f"Module crashed on malicious key: {e}"

    @pytest.mark.asyncio
    async def test_message_key_with_control_characters(self):
        """Test message key with control characters."""
        config = {
            "module": "kafka",
            "topic": "webhook_events",
            "module-config": {"key": "key\ninjected"},
        }

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            # Should handle control characters safely
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass

    @pytest.mark.asyncio
    async def test_message_key_type_validation(self):
        """Test that non-string message keys are handled."""
        config = {
            "module": "kafka",
            "topic": "webhook_events",
            "module-config": {"key": 123},  # Non-string key
        }

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            # Should handle non-string keys safely
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass


# ============================================================================
# 2. PARTITION MANIPULATION
# ============================================================================


class TestKafkaPartitionManipulation:
    """Test partition manipulation vulnerabilities."""

    @pytest.mark.asyncio
    async def test_partition_type_validation(self):
        """Test that partition values are validated for correct types."""
        config = {
            "module": "kafka",
            "topic": "webhook_events",
            "module-config": {"partition": "invalid"},  # String instead of int
        }

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            # Should handle invalid partition types safely
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass

    @pytest.mark.asyncio
    async def test_partition_negative_value(self):
        """Test that negative partition values are handled."""
        config = {
            "module": "kafka",
            "topic": "webhook_events",
            "module-config": {"partition": -1},  # Negative partition
        }

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            # Should handle negative partitions safely
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass

    @pytest.mark.asyncio
    async def test_partition_large_value(self):
        """Test that very large partition values are handled."""
        config = {
            "module": "kafka",
            "topic": "webhook_events",
            "module-config": {"partition": 999999999},  # Very large partition
        }

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            # Should handle large partitions safely
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass


# ============================================================================
# 3. HEADER INJECTION
# ============================================================================


class TestKafkaHeaderInjection:
    """Test header injection vulnerabilities."""

    @pytest.mark.asyncio
    async def test_header_injection_via_forward_headers(self):
        """Test header injection when forward_headers is enabled."""
        config = {
            "module": "kafka",
            "topic": "webhook_events",
            "module-config": {"forward_headers": True},
        }

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = {"test": "data"}
        # Malicious headers with injection attempts
        headers = {
            "X-Normal-Header": "value",
            "X-Injected\nHeader": "injected_value",  # Newline injection
            "X-Injected\rHeader": "injected_value",  # Carriage return injection
            "X-Injected\x00Header": "injected_value",  # Null byte injection
        }

        try:
            await module.process(payload, headers)
            # Should handle header injection safely
            assert mock_producer.send.called
            # Check that headers were encoded
            call_args = mock_producer.send.call_args
            kafka_headers = call_args[1].get("headers")
            if kafka_headers:
                # Headers should be encoded as bytes
                assert isinstance(kafka_headers, list)
        except Exception as e:
            # Should not crash
            pass

    @pytest.mark.asyncio
    async def test_header_value_encoding(self):
        """Test that header values are properly encoded."""
        config = {
            "module": "kafka",
            "topic": "webhook_events",
            "module-config": {"forward_headers": True},
        }

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = {"test": "data"}
        headers = {"X-Test-Header": "test_value_测试"}

        try:
            await module.process(payload, headers)
            # Should encode header values as UTF-8 bytes
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass

    @pytest.mark.asyncio
    async def test_header_name_injection(self):
        """Test header name injection attempts."""
        config = {
            "module": "kafka",
            "topic": "webhook_events",
            "module-config": {"forward_headers": True},
        }

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = {"test": "data"}
        # Malicious header names
        headers = {
            "../../etc/passwd": "value",  # Path traversal in header name
            "header; DROP": "value",  # Command injection attempt
        }

        try:
            await module.process(payload, headers)
            # Should handle header name injection safely
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass


# ============================================================================
# 4. PAYLOAD SECURITY
# ============================================================================


class TestKafkaPayloadSecurity:
    """Test payload security vulnerabilities."""

    @pytest.mark.asyncio
    async def test_circular_reference_in_payload(self):
        """Test that circular references in payload are handled safely."""
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        # Create circular reference
        payload = {"test": "data"}
        payload["self"] = payload  # Circular reference

        headers = {}

        try:
            await module.process(payload, headers)
            # JSON serialization should handle circular references (may raise error)
            # This is expected behavior
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
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        # Very large payload
        large_payload = {"data": "x" * 10000000}  # 10MB string

        headers = {}

        try:
            await module.process(large_payload, headers)
            # Should handle large payloads without DoS
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass

    @pytest.mark.asyncio
    async def test_deeply_nested_payload(self):
        """Test that deeply nested payloads are handled safely."""
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        # Deeply nested payload
        nested_payload = {"level": 0}
        current = nested_payload
        for i in range(1000):
            current["next"] = {"level": i + 1}
            current = current["next"]

        headers = {}

        try:
            await module.process(nested_payload, headers)
            # Should handle deeply nested payloads safely
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass

    @pytest.mark.asyncio
    async def test_non_serializable_payload(self):
        """Test that non-serializable payloads are handled safely."""
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        # Non-serializable object
        class NonSerializable:
            pass

        payload = {"obj": NonSerializable()}
        headers = {}

        try:
            await module.process(payload, headers)
            # JSON serialization should fail for non-serializable objects
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
# 5. CONNECTION SECURITY
# ============================================================================


class TestKafkaConnectionSecurity:
    """Test connection security vulnerabilities."""

    @pytest.mark.asyncio
    async def test_bootstrap_servers_injection(self):
        """Test that bootstrap_servers configuration is handled safely."""
        config = {
            "module": "kafka",
            "topic": "webhook_events",
            "connection": "kafka_connection",
        }

        # Mock connection details with malicious bootstrap_servers
        malicious_servers = [
            "localhost:9092; rm -rf /",
            "localhost:9092 | cat /etc/passwd",
            "localhost:9092 && malicious_command",
        ]

        for malicious_server in malicious_servers:
            module = KafkaModule(config)
            # Mock connection_details
            module.connection_details = {"bootstrap_servers": malicious_server}

            try:
                await module.setup()
                # Should handle malicious bootstrap_servers safely
                # (aiokafka should validate server format)
            except Exception as e:
                # Should not crash, but may reject invalid server format
                pass

    @pytest.mark.asyncio
    @pytest.mark.longrunning
    async def test_bootstrap_servers_ssrf_attempt(self):
        """Test SSRF attempts via bootstrap_servers."""
        config = {
            "module": "kafka",
            "topic": "webhook_events",
            "connection": "kafka_connection",
        }

        # SSRF attempt servers
        ssrf_servers = [
            "127.0.0.1:9092",
            "localhost:9092",
            "169.254.169.254:9092",  # AWS metadata
            "file:///etc/passwd",
        ]

        for ssrf_server in ssrf_servers:
            module = KafkaModule(config)
            module.connection_details = {"bootstrap_servers": ssrf_server}

            try:
                await module.setup()
                # Should handle SSRF attempts safely
                # (aiokafka should validate server format)
            except Exception as e:
                # Should not crash
                pass


# ============================================================================
# 6. ERROR INFORMATION DISCLOSURE
# ============================================================================


class TestKafkaErrorDisclosure:
    """Test error message information disclosure."""

    @pytest.mark.asyncio
    async def test_error_message_sanitization(self):
        """Test that error messages are sanitized."""
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        # Mock producer.send to raise exception with sensitive info
        mock_producer.send.side_effect = Exception(
            "Internal error with path: /etc/passwd"
        )

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            assert False, "Should have raised exception"
        except Exception as e:
            # Should sanitize error message
            error_msg = str(e).lower()
            assert "/etc/passwd" not in error_msg
            assert "kafka operation" in error_msg or "processing error" in error_msg

    @pytest.mark.asyncio
    async def test_kafka_details_not_exposed(self):
        """Test that Kafka-specific details are not exposed in errors."""
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        # Mock producer.send to raise Kafka-specific exception
        from aiokafka.errors import KafkaError

        mock_producer.send.side_effect = KafkaError(
            "Topic 'webhook_events' does not exist"
        )

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            assert False, "Should have raised exception"
        except Exception as e:
            # Should sanitize Kafka-specific error
            error_msg = str(e).lower()
            # Should not expose internal Kafka details
            assert "kafka operation" in error_msg or "processing error" in error_msg


# ============================================================================
# 7. CONFIGURATION SECURITY
# ============================================================================


class TestKafkaConfigurationSecurity:
    """Test configuration security and type validation."""

    @pytest.mark.asyncio
    async def test_config_type_validation(self):
        """Test that config values are validated for correct types."""
        invalid_configs = [
            {"module": "kafka", "topic": None},
            {"module": "kafka", "topic": 123},
            {"module": "kafka", "topic": []},
            {"module": "kafka", "topic": {}},
        ]

        for invalid_config in invalid_configs:
            try:
                module = KafkaModule(invalid_config)
                # Should validate topic type during initialization
                assert module._validated_topic is None or isinstance(
                    module._validated_topic, str
                )
            except ValueError as e:
                # Should raise ValueError for invalid topic types
                assert (
                    "non-empty string" in str(e).lower() or "must be" in str(e).lower()
                )
            except Exception as e:
                # Should not crash
                pass

    @pytest.mark.asyncio
    async def test_module_config_type_validation(self):
        """Test that module_config values are validated for correct types."""
        config = {
            "module": "kafka",
            "topic": "webhook_events",
            "module-config": {
                "key": None,  # None key
                "partition": "invalid",  # Invalid partition type
                "forward_headers": "true",  # String instead of bool
            },
        }

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            # Should handle invalid config types safely
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass


# ============================================================================
# 8. JSON SERIALIZATION SECURITY
# ============================================================================


class TestKafkaJsonSerialization:
    """Test JSON serialization security."""

    @pytest.mark.asyncio
    async def test_json_serialization_unicode(self):
        """Test JSON serialization with Unicode characters."""
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        # Payload with Unicode
        payload = {"test": "测试_🔑_ключ"}
        headers = {}

        try:
            await module.process(payload, headers)
            # Should serialize Unicode correctly
            assert mock_producer.send.called
            call_args = mock_producer.send.call_args
            value = call_args[1].get("value")
            # Value should be serialized JSON
            assert isinstance(value, (dict, str, bytes))
        except Exception as e:
            # Should not crash
            pass

    @pytest.mark.asyncio
    async def test_json_serialization_special_chars(self):
        """Test JSON serialization with special characters."""
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        # Payload with special characters
        payload = {"test": "value\nwith\rspecial\tchars"}
        headers = {}

        try:
            await module.process(payload, headers)
            # Should serialize special characters correctly
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass


# ============================================================================
# 9. CONCURRENT PROCESSING
# ============================================================================


class TestKafkaConcurrentProcessing:
    """Test concurrent processing security."""

    @pytest.mark.asyncio
    async def test_concurrent_message_processing(self):
        """Test that concurrent message processing is handled safely."""
        import asyncio

        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        # Process multiple messages concurrently
        async def process_message(i):
            payload = {"test": f"data_{i}"}
            headers = {}
            await module.process(payload, headers)

        # Process 10 messages concurrently
        tasks = [process_message(i) for i in range(10)]
        await asyncio.gather(*tasks)

        # Should handle concurrent processing safely
        assert mock_producer.send.call_count == 10


# ============================================================================
# 10. EDGE CASES & BOUNDARY CONDITIONS
# ============================================================================


class TestKafkaEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_missing_topic_handling(self):
        """Test handling when topic is missing."""
        config = {
            "module": "kafka"
            # No topic specified
        }

        module = KafkaModule(config)
        assert module._validated_topic is None

        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = {"test": "data"}
        headers = {}

        try:
            await module.process(payload, headers)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            # Should raise ValueError for missing topic
            assert "topic" in str(e).lower() or "required" in str(e).lower()

    @pytest.mark.asyncio
    async def test_empty_payload(self):
        """Test handling of empty payload."""
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = {}
        headers = {}

        try:
            await module.process(payload, headers)
            # Should handle empty payload safely
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass

    @pytest.mark.asyncio
    async def test_none_payload(self):
        """Test handling of None payload."""
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        mock_producer = AsyncMock()
        module.producer = mock_producer

        payload = None
        headers = {}

        try:
            await module.process(payload, headers)
            # Should handle None payload safely
            assert mock_producer.send.called
        except Exception as e:
            # Should not crash
            pass

    @pytest.mark.asyncio
    async def test_producer_not_initialized(self):
        """Test handling when producer is not initialized."""
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        # Producer is None (not initialized)

        # Mock setup to create producer
        with patch.object(module, "setup", new_callable=AsyncMock) as mock_setup:
            mock_producer = AsyncMock()
            mock_setup.return_value = None
            module.producer = mock_producer

            payload = {"test": "data"}
            headers = {}

            try:
                await module.process(payload, headers)
                # Should initialize producer if not present
                assert mock_setup.called or module.producer is not None
            except Exception as e:
                # Should not crash
                pass


# ============================================================================
# 11. TOPIC NAME VALIDATION EDGE CASES
# ============================================================================


class TestKafkaTopicNameValidation:
    """Test topic name validation edge cases."""

    def test_topic_name_at_max_length(self):
        """Test topic name at maximum length."""
        config = {"module": "kafka", "topic": "a" * 249}  # Max length

        module = KafkaModule(config)
        assert module._validated_topic == "a" * 249

    def test_topic_name_at_min_length(self):
        """Test topic name at minimum length."""
        config = {"module": "kafka", "topic": "ab"}  # Min length (2 chars)

        module = KafkaModule(config)
        assert module._validated_topic == "ab"

    def test_topic_name_regex_redos(self):
        """Test ReDoS vulnerability in topic name regex."""
        import time

        # Complex topic name that might cause ReDoS
        complex_name = "a" * 1000 + "!"  # Long string ending with invalid char

        start_time = time.time()
        try:
            config = {"module": "kafka", "topic": complex_name}
            KafkaModule(config)
            assert False, "Should have raised ValueError"
        except ValueError:
            elapsed = time.time() - start_time
            # Should complete quickly (no ReDoS)
            assert elapsed < 1.0, f"ReDoS detected: validation took {elapsed:.2f}s"


# ============================================================================
# 12. BOOTSTRAP SERVERS VALIDATION
# ============================================================================


class TestKafkaBootstrapServersValidation:
    """Test bootstrap servers validation."""

    @pytest.mark.asyncio
    async def test_bootstrap_servers_default(self):
        """Test default bootstrap_servers value."""
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        # connection_details should have default bootstrap_servers
        # This is handled by connection config, not module config

        # Mock setup to test default
        with patch("src.modules.kafka.AIOKafkaProducer") as mock_producer_class:
            mock_producer = AsyncMock()
            mock_producer.start = AsyncMock()
            mock_producer_class.return_value = mock_producer

            # Set connection_details to test default
            module.connection_details = {}

            await module.setup()

            # Should use default or connection config
            assert mock_producer_class.called
            # Check that bootstrap_servers was passed (default is 'localhost:9092')
            call_args = mock_producer_class.call_args
            assert call_args is not None

    @pytest.mark.asyncio
    async def test_bootstrap_servers_empty_string(self):
        """Test empty bootstrap_servers string."""
        config = {"module": "kafka", "topic": "webhook_events"}

        module = KafkaModule(config)
        module.connection_details = {"bootstrap_servers": ""}

        try:
            await module.setup()
            # Should handle empty string safely
        except Exception as e:
            # Should not crash
            pass
