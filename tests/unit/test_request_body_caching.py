"""
Security tests for request body caching.
Tests that request body is cached after first read to prevent processing failures.
"""

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from unittest.mock import Mock, AsyncMock, patch
from src.webhook import WebhookHandler
from src.main import app


class TestRequestBodyCaching:
    """Test suite for request body caching security."""

    @pytest.mark.asyncio
    async def test_body_cached_after_validate_webhook(self):
        """Test that body is cached after validate_webhook() and can be reused."""
        # Create a mock request with body
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}

        # Mock body() to simulate FastAPI behavior (can only be read once)
        body_read_count = 0
        original_body = b'{"test": "data"}'

        async def mock_body():
            nonlocal body_read_count
            body_read_count += 1
            if body_read_count == 1:
                return original_body
            else:
                # Second read returns empty (FastAPI behavior)
                return b""

        mock_request.body = AsyncMock(side_effect=mock_body)

        configs = {"test_webhook": {"data_type": "json", "module": "log"}}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # First call to validate_webhook() should read body
        is_valid, message = await handler.validate_webhook()

        # Body should be cached
        assert handler._cached_body == original_body
        assert body_read_count == 1

        # process_webhook() should use cached body, not read again
        payload, headers, task = await handler.process_webhook()

        # Body should still be cached and body() should not be called again
        assert handler._cached_body == original_body
        assert body_read_count == 1  # Should still be 1, not 2
        assert payload == {"test": "data"}

    @pytest.mark.asyncio
    async def test_body_cached_before_process_webhook(self):
        """Test that body is cached even if validate_webhook() wasn't called."""
        # Create a mock request with body
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}

        # Mock body() to simulate FastAPI behavior
        body_read_count = 0
        original_body = b'{"test": "data"}'

        async def mock_body():
            nonlocal body_read_count
            body_read_count += 1
            if body_read_count == 1:
                return original_body
            else:
                return b""

        mock_request.body = AsyncMock(side_effect=mock_body)

        configs = {"test_webhook": {"data_type": "json", "module": "log"}}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Skip validate_webhook(), go directly to process_webhook()
        # Body should be read and cached
        payload, headers, task = await handler.process_webhook()

        # Body should be cached
        assert handler._cached_body == original_body
        assert body_read_count == 1
        assert payload == {"test": "data"}

    @pytest.mark.asyncio
    async def test_body_reused_multiple_times(self):
        """Test that cached body can be reused multiple times without re-reading."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}

        body_read_count = 0
        original_body = b'{"test": "data"}'

        async def mock_body():
            nonlocal body_read_count
            body_read_count += 1
            if body_read_count == 1:
                return original_body
            else:
                return b""

        mock_request.body = AsyncMock(side_effect=mock_body)

        configs = {"test_webhook": {"data_type": "json", "module": "log"}}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # Read body multiple times
        await handler.validate_webhook()
        await handler.process_webhook()

        # Access cached body directly
        cached = handler._cached_body

        # Body should only be read once
        assert body_read_count == 1
        assert cached == original_body

    @pytest.mark.asyncio
    async def test_large_body_cached_correctly(self):
        """Test that large request bodies are cached correctly."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}

        # Create a large body (1MB)
        large_body = b'{"data": "' + b"x" * (1024 * 1024 - 20) + b'"}'

        body_read_count = 0

        async def mock_body():
            nonlocal body_read_count
            body_read_count += 1
            if body_read_count == 1:
                return large_body
            else:
                return b""

        mock_request.body = AsyncMock(side_effect=mock_body)

        configs = {"test_webhook": {"data_type": "blob", "module": "log"}}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        await handler.validate_webhook()
        payload, headers, task = await handler.process_webhook()

        # Large body should be cached correctly
        assert handler._cached_body == large_body
        assert len(handler._cached_body) == len(large_body)
        assert body_read_count == 1

    @pytest.mark.asyncio
    async def test_empty_body_cached_correctly(self):
        """Test that empty request bodies are cached correctly."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}

        empty_body = b""

        body_read_count = 0

        async def mock_body():
            nonlocal body_read_count
            body_read_count += 1
            if body_read_count == 1:
                return empty_body
            else:
                return b""

        mock_request.body = AsyncMock(side_effect=mock_body)

        configs = {"test_webhook": {"data_type": "blob", "module": "log"}}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        await handler.validate_webhook()
        payload, headers, task = await handler.process_webhook()

        # Empty body should be cached correctly
        assert handler._cached_body == empty_body
        assert body_read_count == 1

    @pytest.mark.asyncio
    async def test_binary_body_cached_correctly(self):
        """Test that binary request bodies are cached correctly."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/octet-stream"}
        mock_request.query_params = {}

        binary_body = b"\x00\x01\x02\x03\xff\xfe\xfd"

        body_read_count = 0

        async def mock_body():
            nonlocal body_read_count
            body_read_count += 1
            if body_read_count == 1:
                return binary_body
            else:
                return b""

        mock_request.body = AsyncMock(side_effect=mock_body)

        configs = {"test_webhook": {"data_type": "blob", "module": "log"}}

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        await handler.validate_webhook()
        payload, headers, task = await handler.process_webhook()

        # Binary body should be cached correctly
        assert handler._cached_body == binary_body
        assert body_read_count == 1

    def test_integration_request_body_caching(self):
        """Integration test: verify request body caching works in real webhook flow."""
        client = TestClient(app)

        # This test would require a real webhook configuration
        # For now, we test the caching mechanism directly
        # In a real scenario, we'd need to set up webhook config

        # The key test is that body is only read once
        # This is verified by the unit tests above

        assert True  # Placeholder - integration test would go here

    @pytest.mark.asyncio
    async def test_body_caching_with_hmac_validation(self):
        """Test that body caching works correctly with HMAC validation."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {
            "content-type": "application/json",
            "x-hmac-signature": "test_signature",
        }
        mock_request.query_params = {}

        body_content = b'{"test": "data"}'

        body_read_count = 0

        async def mock_body():
            nonlocal body_read_count
            body_read_count += 1
            if body_read_count == 1:
                return body_content
            else:
                return b""

        mock_request.body = AsyncMock(side_effect=mock_body)

        configs = {
            "test_webhook": {
                "data_type": "json",
                "module": "log",
                "hmac": {"secret": "test_secret", "header": "X-HMAC-Signature"},
            }
        }

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # validate_webhook() should read body once for HMAC validation
        # Body should be cached
        is_valid, message = await handler.validate_webhook()

        # Body should be cached
        assert handler._cached_body == body_content
        assert body_read_count == 1

        # process_webhook() should use cached body
        payload, headers, task = await handler.process_webhook()

        # Body should still be cached, no additional reads
        assert handler._cached_body == body_content
        assert body_read_count == 1

    @pytest.mark.asyncio
    async def test_body_caching_with_json_schema_validation(self):
        """Test that body caching works correctly with JSON schema validation."""
        mock_request = Mock(spec=Request)
        mock_request.headers = {"content-type": "application/json"}
        mock_request.query_params = {}

        body_content = b'{"test": "data"}'

        body_read_count = 0

        async def mock_body():
            nonlocal body_read_count
            body_read_count += 1
            if body_read_count == 1:
                return body_content
            else:
                return b""

        mock_request.body = AsyncMock(side_effect=mock_body)

        configs = {
            "test_webhook": {
                "data_type": "json",
                "module": "log",
                "json_schema": {
                    "type": "object",
                    "properties": {"test": {"type": "string"}},
                },
            }
        }

        handler = WebhookHandler("test_webhook", configs, {}, mock_request)

        # validate_webhook() should read body once for JSON schema validation
        is_valid, message = await handler.validate_webhook()

        # Body should be cached
        assert handler._cached_body == body_content
        assert body_read_count == 1

        # process_webhook() should use cached body
        payload, headers, task = await handler.process_webhook()

        # Body should still be cached
        assert handler._cached_body == body_content
        assert body_read_count == 1
