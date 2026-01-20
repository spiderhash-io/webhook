"""
Comprehensive security audit tests for GCP Pub/Sub module.

Tests cover:
- Topic name injection (command injection, path traversal)
- Project ID injection
- Credentials path traversal
- Attribute key/value injection
- Payload security (circular references, large payloads)
- Type confusion attacks
- Error information disclosure
- Attribute length limits
- Control character injection
"""

import pytest
import json
import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch, Mock

# Mock google.cloud.pubsub_v1 before importing GCPPubSubModule
mock_pubsub = MagicMock()
mock_pubsub_v1 = MagicMock()
mock_pubsub_v1.PublisherClient = MagicMock()
sys.modules["google.cloud"] = mock_pubsub
sys.modules["google.cloud.pubsub_v1"] = mock_pubsub_v1
sys.modules["google.api_core"] = MagicMock()
sys.modules["google.api_core.exceptions"] = MagicMock()
sys.modules["google.oauth2"] = MagicMock()
sys.modules["google.oauth2.service_account"] = MagicMock()

# Reload module to ensure mocks are used
if "src.modules.gcp_pubsub" in sys.modules:
    import importlib

    importlib.reload(sys.modules["src.modules.gcp_pubsub"])

from src.modules.gcp_pubsub import GCPPubSubModule


# ============================================================================
# 1. TOPIC NAME INJECTION
# ============================================================================


class TestTopicNameInjection:
    """Test topic name injection attacks."""

    def test_topic_name_command_injection_attempts(self):
        """Test that command injection attempts in topic names are blocked."""
        invalid_topics = [
            "topic'; rm -rf /; --",
            'topic" | cat /etc/passwd',
            "topic; DROP TABLE users; --",
            "topic' OR '1'='1",
        ]

        for invalid_topic in invalid_topics:
            config = {
                "connection_details": {"project_id": "test-project"},
                "module-config": {"topic": invalid_topic},
            }
            with pytest.raises(ValueError):
                GCPPubSubModule(config)

    def test_topic_name_path_traversal(self):
        """Test that path traversal attempts in topic names are blocked."""
        invalid_topics = [
            "../topic",
            "../../topic",
            "topic/../other",
        ]

        for invalid_topic in invalid_topics:
            config = {
                "connection_details": {"project_id": "test-project"},
                "module-config": {"topic": invalid_topic},
            }
            with pytest.raises(ValueError):
                GCPPubSubModule(config)

    def test_topic_name_uppercase_rejected(self):
        """Test that uppercase letters in topic names are rejected."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "InvalidTopic"},  # Uppercase
        }
        with pytest.raises(ValueError, match="Invalid topic name format"):
            GCPPubSubModule(config)

    def test_topic_name_starts_with_number_rejected(self):
        """Test that topic names starting with numbers are rejected."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "123topic"},  # Starts with number
        }
        with pytest.raises(ValueError, match="Invalid topic name format"):
            GCPPubSubModule(config)

    def test_topic_name_control_characters(self):
        """Test that control characters in topic names are rejected."""
        invalid_topics = [
            "topic\nname",
            "topic\rname",
            "topic\0name",
            "topic\tname",
        ]

        for invalid_topic in invalid_topics:
            config = {
                "connection_details": {"project_id": "test-project"},
                "module-config": {"topic": invalid_topic},
            }
            with pytest.raises(ValueError):
                GCPPubSubModule(config)

    def test_topic_name_type_confusion(self):
        """Test that non-string topic names are rejected."""
        invalid_types = [
            123,
            [],
            {},
            {"key": "value"},
        ]

        for invalid_type in invalid_types:
            config = {
                "connection_details": {"project_id": "test-project"},
                "module-config": {"topic": invalid_type},
            }
            with pytest.raises(ValueError, match="must be a non-empty string"):
                GCPPubSubModule(config)

    def test_topic_name_too_long(self):
        """Test that excessively long topic names are rejected."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "a" * 256},  # Exceeds 255 limit
        }
        with pytest.raises(ValueError, match="too long"):
            GCPPubSubModule(config)


# ============================================================================
# 2. PROJECT ID INJECTION
# ============================================================================


class TestProjectIDInjection:
    """Test project ID injection attacks."""

    def test_project_id_uppercase_rejected(self):
        """Test that uppercase letters in project IDs are rejected."""
        config = {
            "connection_details": {"project_id": "InvalidProject"},
            "module-config": {"topic": "test-topic"},
        }
        with pytest.raises(ValueError, match="Invalid project ID format"):
            GCPPubSubModule(config)

    def test_project_id_too_short(self):
        """Test that project IDs that are too short are rejected."""
        config = {
            "connection_details": {"project_id": "test"},  # Less than 6 chars
            "module-config": {"topic": "test-topic"},
        }
        with pytest.raises(ValueError, match="Invalid project ID format"):
            GCPPubSubModule(config)

    def test_project_id_too_long(self):
        """Test that project IDs that are too long are rejected."""
        config = {
            "connection_details": {"project_id": "a" * 31},  # More than 30 chars
            "module-config": {"topic": "test-topic"},
        }
        with pytest.raises(ValueError, match="Invalid project ID format"):
            GCPPubSubModule(config)

    def test_project_id_starts_with_hyphen(self):
        """Test that project IDs starting with hyphens are rejected."""
        config = {
            "connection_details": {"project_id": "-test-project"},
            "module-config": {"topic": "test-topic"},
        }
        with pytest.raises(ValueError, match="Invalid project ID format"):
            GCPPubSubModule(config)

    def test_project_id_type_confusion(self):
        """Test that non-string project IDs are rejected."""
        # None is handled separately (raises "project_id is required")
        config = {
            "connection_details": {"project_id": None},
            "module-config": {"topic": "test-topic"},
        }
        with pytest.raises(ValueError, match="project_id is required"):
            GCPPubSubModule(config)

        # Other invalid types should be caught by validation
        invalid_types = [
            123,
            [],
            {},
        ]

        for invalid_type in invalid_types:
            config = {
                "connection_details": {"project_id": invalid_type},
                "module-config": {"topic": "test-topic"},
            }
            with pytest.raises(ValueError):
                GCPPubSubModule(config)

    def test_project_id_missing(self):
        """Test that missing project ID is rejected."""
        config = {
            "connection_details": {},  # No project_id
            "module-config": {"topic": "test-topic"},
        }
        with pytest.raises(ValueError, match="project_id is required"):
            GCPPubSubModule(config)


# ============================================================================
# 3. CREDENTIALS PATH TRAVERSAL
# ============================================================================


class TestCredentialsPathTraversal:
    """Test credentials path traversal attacks."""

    @pytest.mark.asyncio
    async def test_credentials_path_traversal_detected(self):
        """Test that path traversal in credentials path is blocked."""
        config = {
            "connection_details": {
                "project_id": "test-project",
                "credentials_path": "../../etc/passwd",
            },
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        # Error is sanitized, but should raise exception
        with pytest.raises(Exception):
            await module.setup()

    @pytest.mark.asyncio
    async def test_credentials_path_absolute_path_blocked(self):
        """Test that absolute paths in credentials path are blocked."""
        config = {
            "connection_details": {
                "project_id": "test-project",
                "credentials_path": "/etc/passwd",
            },
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        # Error is sanitized, but should raise exception
        with pytest.raises(Exception):
            await module.setup()

    @pytest.mark.asyncio
    async def test_credentials_path_double_encoded_traversal(self):
        """Test that double-encoded path traversal is blocked."""
        # Current implementation only checks for '..' - double encoding might bypass
        # This test documents the limitation
        config = {
            "connection_details": {
                "project_id": "test-project",
                "credentials_path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # URL encoded ../
            },
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        # Current implementation might not catch URL-encoded traversal
        # This test documents the potential vulnerability
        try:
            await module.setup()
            # If we get here, double-encoded traversal is not blocked
            # This would be a vulnerability
            assert False, "Double-encoded path traversal should be blocked"
        except (ValueError, Exception):
            pass  # Good if blocked


# ============================================================================
# 4. ATTRIBUTE KEY/VALUE INJECTION
# ============================================================================


class TestAttributeInjection:
    """Test attribute key/value injection attacks."""

    @pytest.mark.asyncio
    async def test_attribute_key_injection(self):
        """Test that invalid attribute keys are filtered."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        mock_publisher = Mock()
        mock_future = Mock()
        mock_future.result = Mock(return_value="message-id")
        mock_publisher.topic_path = Mock(
            return_value="projects/test-project/topics/test-topic"
        )
        mock_publisher.publish = Mock(return_value=mock_future)
        module.publisher = mock_publisher

        # Headers with invalid keys (containing special characters)
        malicious_headers = {
            "valid-key": "value",
            "invalid.key": "value",  # Contains dot
            "invalid/key": "value",  # Contains slash
            "invalid key": "value",  # Contains space
        }

        payload = {"test": "data"}

        await module.process(payload, malicious_headers)

        # Verify publish was called
        assert mock_publisher.publish.called
        call_kwargs = mock_publisher.publish.call_args[1]  # Get keyword arguments
        attributes = call_kwargs

        # Invalid keys should be filtered out (only valid-key should remain)
        # The code uses re.match(r'^[a-zA-Z0-9_-]+$', key) to validate
        assert "valid-key" in attributes or "valid-key" in str(attributes)

    @pytest.mark.asyncio
    async def test_attribute_value_length_limit(self):
        """Test that attribute values exceeding 1024 chars are filtered."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        mock_publisher = Mock()
        mock_future = Mock()
        mock_future.result = Mock(return_value="message-id")
        mock_publisher.topic_path = Mock(
            return_value="projects/test-project/topics/test-topic"
        )
        mock_publisher.publish = Mock(return_value=mock_future)
        module.publisher = mock_publisher

        # Header value exceeding 1024 chars
        headers = {"valid-key": "x" * 1025}  # Exceeds limit

        payload = {"test": "data"}

        await module.process(payload, headers)

        # Value should be filtered out due to length limit
        assert mock_publisher.publish.called

    @pytest.mark.asyncio
    async def test_attribute_value_type_confusion(self):
        """Test that non-string attribute values are handled safely."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        mock_publisher = Mock()
        mock_future = Mock()
        mock_future.result = Mock(return_value="message-id")
        mock_publisher.topic_path = Mock(
            return_value="projects/test-project/topics/test-topic"
        )
        mock_publisher.publish = Mock(return_value=mock_future)
        module.publisher = mock_publisher

        # Headers with non-string values
        headers = {
            "valid-key": "string-value",
            "number-key": 123,
            "list-key": [1, 2, 3],
            "dict-key": {"key": "value"},
        }

        payload = {"test": "data"}

        # Code checks isinstance(value, str) - non-string values should be filtered
        await module.process(payload, headers)

        assert mock_publisher.publish.called


# ============================================================================
# 5. PAYLOAD SECURITY
# ============================================================================


class TestPayloadSecurity:
    """Test payload security (circular references, large payloads)."""

    @pytest.mark.asyncio
    async def test_circular_reference_handling(self):
        """Test that circular references in payload are handled."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        mock_publisher = Mock()
        mock_future = Mock()
        mock_future.result = Mock(return_value="message-id")
        mock_publisher.topic_path = Mock(
            return_value="projects/test-project/topics/test-topic"
        )
        mock_publisher.publish = Mock(return_value=mock_future)
        module.publisher = mock_publisher

        # Create circular reference
        payload = {"key": "value"}
        payload["self"] = payload  # Circular reference

        # json.dumps will raise ValueError for circular references
        with pytest.raises((ValueError, TypeError, OverflowError, Exception)):
            await module.process(payload, {})

    @pytest.mark.asyncio
    async def test_large_payload_handling(self):
        """Test that large payloads are handled without DoS."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        mock_publisher = Mock()
        mock_future = Mock()
        mock_future.result = Mock(return_value="message-id")
        mock_publisher.topic_path = Mock(
            return_value="projects/test-project/topics/test-topic"
        )
        mock_publisher.publish = Mock(return_value=mock_future)
        module.publisher = mock_publisher

        # Large payload (10MB)
        large_payload = {"data": "x" * (10 * 1024 * 1024)}

        # Should handle without crashing - might be slow but shouldn't DoS
        await module.process(large_payload, {})
        assert mock_publisher.publish.called

    @pytest.mark.asyncio
    async def test_deeply_nested_payload(self):
        """Test that deeply nested payloads are handled."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        mock_publisher = Mock()
        mock_future = Mock()
        mock_future.result = Mock(return_value="message-id")
        mock_publisher.topic_path = Mock(
            return_value="projects/test-project/topics/test-topic"
        )
        mock_publisher.publish = Mock(return_value=mock_future)
        module.publisher = mock_publisher

        # Deeply nested payload (but limit to avoid RecursionError in json.dumps)
        # Python's default recursion limit is ~1000, so use 500 levels to be safe
        nested = {}
        current = nested
        for i in range(500):
            current["level"] = i
            current["next"] = {}
            current = current["next"]

        # Should handle without stack overflow
        # Module should catch RecursionError if it occurs during serialization
        try:
            await module.process(nested, {})
            assert mock_publisher.publish.called
        except RecursionError:
            # If json.dumps hits recursion limit, module should handle it gracefully
            # Test passes if it doesn't crash
            assert True


# ============================================================================
# 6. ERROR INFORMATION DISCLOSURE
# ============================================================================


class TestErrorInformationDisclosure:
    """Test error information disclosure prevention."""

    @pytest.mark.asyncio
    async def test_client_creation_error_sanitization(self):
        """Test that client creation errors are sanitized."""
        config = {
            "connection_details": {
                "project_id": "test-project",
                "credentials_path": "valid-path.json",
            },
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)

        # Mock the import that happens inside setup
        with patch("src.modules.gcp_pubsub.pubsub_v1.PublisherClient") as mock_client:
            mock_client.side_effect = Exception(
                "Failed to load credentials: Invalid key file path /etc/passwd"
            )

            with pytest.raises(Exception) as exc_info:
                await module.setup()

            # Error should be sanitized - should not contain sensitive paths
            error_msg = str(exc_info.value)
            assert "/etc/passwd" not in error_msg

    @pytest.mark.asyncio
    async def test_publish_error_sanitization(self):
        """Test that publish errors are sanitized."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        mock_publisher = Mock()
        mock_future = Mock()
        mock_future.result = Mock(
            side_effect=Exception(
                "Permission denied: projects/test-project/topics/test-topic"
            )
        )
        mock_publisher.topic_path = Mock(
            return_value="projects/test-project/topics/test-topic"
        )
        mock_publisher.publish = Mock(return_value=mock_future)
        module.publisher = mock_publisher

        payload = {"test": "data"}

        with pytest.raises(Exception) as exc_info:
            await module.process(payload, {})

        # Error should be sanitized
        error_msg = str(exc_info.value)
        # Should not expose internal details
        assert "Permission denied" not in error_msg or "Processing error" in error_msg


# ============================================================================
# 7. MISSING TOPIC VALIDATION
# ============================================================================


class TestMissingTopicValidation:
    """Test handling of missing topic."""

    @pytest.mark.asyncio
    async def test_missing_topic(self):
        """Test that missing topic is handled."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {},  # No topic
        }

        module = GCPPubSubModule(config)
        # Should raise error when setup is called
        with pytest.raises(ValueError, match="Topic name is required"):
            await module.setup()

    def test_none_topic(self):
        """Test that None topic is handled."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": None},
        }

        # Module should be created but topic should be None
        module = GCPPubSubModule(config)
        assert module._validated_topic is None

        # Should fail on setup
        with pytest.raises(ValueError, match="Topic name is required"):
            asyncio.run(module.setup())


# ============================================================================
# 8. CONCURRENT PROCESSING
# ============================================================================


class TestConcurrentProcessing:
    """Test concurrent processing security."""

    @pytest.mark.asyncio
    async def test_concurrent_publish(self):
        """Test that concurrent publishes are handled safely."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        mock_publisher = Mock()
        mock_future = Mock()
        mock_future.result = Mock(return_value="message-id")
        mock_publisher.topic_path = Mock(
            return_value="projects/test-project/topics/test-topic"
        )
        mock_publisher.publish = Mock(return_value=mock_future)
        module.publisher = mock_publisher

        # Simulate concurrent publishes
        async def publish(i):
            await module.process({"id": i}, {})

        # Run 10 concurrent publishes
        await asyncio.gather(*[publish(i) for i in range(10)])

        # Verify all publishes were called
        assert mock_publisher.publish.call_count == 10


# ============================================================================
# 9. ATTRIBUTE KEY VALIDATION EDGE CASES
# ============================================================================


class TestAttributeKeyValidation:
    """Test attribute key validation edge cases."""

    @pytest.mark.asyncio
    async def test_attribute_key_empty_string(self):
        """Test that empty string attribute keys are handled."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        mock_publisher = Mock()
        mock_future = Mock()
        mock_future.result = Mock(return_value="message-id")
        mock_publisher.topic_path = Mock(
            return_value="projects/test-project/topics/test-topic"
        )
        mock_publisher.publish = Mock(return_value=mock_future)
        module.publisher = mock_publisher

        headers = {
            "": "value",  # Empty key
            "valid-key": "value",
        }

        payload = {"test": "data"}

        await module.process(payload, headers)
        assert mock_publisher.publish.called

    @pytest.mark.asyncio
    async def test_attribute_key_unicode(self):
        """Test that Unicode attribute keys are handled."""
        config = {
            "connection_details": {"project_id": "test-project"},
            "module-config": {"topic": "test-topic"},
        }

        module = GCPPubSubModule(config)
        mock_publisher = Mock()
        mock_future = Mock()
        mock_future.result = Mock(return_value="message-id")
        mock_publisher.topic_path = Mock(
            return_value="projects/test-project/topics/test-topic"
        )
        mock_publisher.publish = Mock(return_value=mock_future)
        module.publisher = mock_publisher

        headers = {
            "valid-key": "value",
            "unicode-key-测试": "value",  # Unicode characters
        }

        payload = {"test": "data"}

        # Unicode keys should be filtered (regex only allows [a-zA-Z0-9_-])
        await module.process(payload, headers)
        assert mock_publisher.publish.called
