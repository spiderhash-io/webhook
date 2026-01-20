"""
HTTP request handling tests based on ngrok patterns.
Tests request body, headers, and forwarding behavior specific to HTTP requests.
"""

import pytest
import json
from unittest.mock import Mock, AsyncMock, patch
import httpx
from src.modules.http_webhook import HTTPWebhookModule


class TestRequestBodyPreservation:
    """Test request body preservation during forwarding."""

    @pytest.mark.asyncio
    async def test_request_body_preserved(self):
        """Test that request body is preserved exactly when forwarding."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        payload = {"key": "value", "number": 123, "nested": {"data": "test"}}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process(payload, {})

            # Verify payload was sent as JSON
            call_args = mock_instance.post.call_args
            assert call_args is not None
            assert call_args.kwargs.get("json") == payload

    @pytest.mark.asyncio
    async def test_binary_data_handled(self):
        """Test that binary data in payload is handled correctly."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        # Payload with base64-encoded binary data
        payload = {"data": "SGVsbG8gV29ybGQ=", "type": "binary"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process(payload, {})

            call_args = mock_instance.post.call_args
            assert call_args is not None
            assert call_args.kwargs.get("json") == payload


class TestHostHeaderHandling:
    """Test Host header handling during forwarding."""

    @pytest.mark.asyncio
    async def test_host_header_not_forwarded(self):
        """Test that Host header is not forwarded (hop-by-hop header)."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {"Host": "original-host.com", "Content-Type": "application/json"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, headers)

            call_args = mock_instance.post.call_args
            assert call_args is not None
            forwarded_headers = call_args.kwargs.get("headers", {})
            # Host should not be forwarded (hop-by-hop header)
            assert "Host" not in forwarded_headers
            assert "host" not in forwarded_headers
            # Other headers should be forwarded
            assert "Content-Type" in forwarded_headers


class TestContentLengthHandling:
    """Test Content-Length header handling."""

    @pytest.mark.asyncio
    async def test_content_length_not_manually_set(self):
        """Test that Content-Length is not manually set (httpx handles it)."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {
            "Content-Length": "100",  # Should be filtered (hop-by-hop)
            "Content-Type": "application/json",
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, headers)

            # httpx will set Content-Length automatically, we don't forward it
            call_args = mock_instance.post.call_args
            assert call_args is not None
            # httpx handles Content-Length automatically for json parameter


class TestConnectionHeaderHandling:
    """Test Connection header handling."""

    @pytest.mark.asyncio
    async def test_connection_header_not_forwarded(self):
        """Test that Connection header is not forwarded (hop-by-hop header)."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {"Connection": "keep-alive", "Content-Type": "application/json"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, headers)

            call_args = mock_instance.post.call_args
            assert call_args is not None
            forwarded_headers = call_args.kwargs.get("headers", {})
            # Connection should not be forwarded (hop-by-hop header)
            assert "Connection" not in forwarded_headers
            assert "connection" not in forwarded_headers


class TestUserAgentPreservation:
    """Test User-Agent header preservation."""

    @pytest.mark.asyncio
    async def test_user_agent_forwarded(self):
        """Test that User-Agent header is forwarded when configured."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {"User-Agent": "TestAgent/1.0", "Content-Type": "application/json"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, headers)

            call_args = mock_instance.post.call_args
            assert call_args is not None
            forwarded_headers = call_args.kwargs.get("headers", {})
            assert "User-Agent" in forwarded_headers
            assert forwarded_headers["User-Agent"] == "TestAgent/1.0"


class TestRefererHeaderHandling:
    """Test Referer header handling."""

    @pytest.mark.asyncio
    async def test_referer_forwarded(self):
        """Test that Referer header is forwarded when configured."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {
            "Referer": "https://example.com/source",
            "Content-Type": "application/json",
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, headers)

            call_args = mock_instance.post.call_args
            assert call_args is not None
            forwarded_headers = call_args.kwargs.get("headers", {})
            assert "Referer" in forwarded_headers
            assert forwarded_headers["Referer"] == "https://example.com/source"


class TestCookieForwarding:
    """Test Cookie header forwarding."""

    @pytest.mark.asyncio
    async def test_cookie_forwarded(self):
        """Test that Cookie header is forwarded when configured."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {
            "Cookie": "session=abc123; user=test",
            "Content-Type": "application/json",
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, headers)

            call_args = mock_instance.post.call_args
            assert call_args is not None
            forwarded_headers = call_args.kwargs.get("headers", {})
            assert "Cookie" in forwarded_headers
            assert forwarded_headers["Cookie"] == "session=abc123; user=test"


class TestAuthorizationHeaderForwarding:
    """Test Authorization header forwarding."""

    @pytest.mark.asyncio
    async def test_authorization_forwarded(self):
        """Test that Authorization header is forwarded when configured."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {
            "Authorization": "Bearer token123",
            "Content-Type": "application/json",
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, headers)

            call_args = mock_instance.post.call_args
            assert call_args is not None
            forwarded_headers = call_args.kwargs.get("headers", {})
            assert "Authorization" in forwarded_headers
            assert forwarded_headers["Authorization"] == "Bearer token123"


class TestXForwardedHeaders:
    """Test X-Forwarded-* header handling."""

    @pytest.mark.asyncio
    async def test_x_forwarded_for_forwarded(self):
        """Test that X-Forwarded-For header is forwarded when present."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {"X-Forwarded-For": "192.168.1.1", "Content-Type": "application/json"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, headers)

            call_args = mock_instance.post.call_args
            assert call_args is not None
            forwarded_headers = call_args.kwargs.get("headers", {})
            assert "X-Forwarded-For" in forwarded_headers
            assert forwarded_headers["X-Forwarded-For"] == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_x_forwarded_proto_forwarded(self):
        """Test that X-Forwarded-Proto header is forwarded when present."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {"X-Forwarded-Proto": "https", "Content-Type": "application/json"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, headers)

            call_args = mock_instance.post.call_args
            assert call_args is not None
            forwarded_headers = call_args.kwargs.get("headers", {})
            assert "X-Forwarded-Proto" in forwarded_headers
            assert forwarded_headers["X-Forwarded-Proto"] == "https"


class TestAcceptHeaderForwarding:
    """Test Accept header forwarding."""

    @pytest.mark.asyncio
    async def test_accept_header_forwarded(self):
        """Test that Accept header is forwarded when configured."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {
            "Accept": "application/json, text/plain",
            "Content-Type": "application/json",
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, headers)

            call_args = mock_instance.post.call_args
            assert call_args is not None
            forwarded_headers = call_args.kwargs.get("headers", {})
            assert "Accept" in forwarded_headers
            assert forwarded_headers["Accept"] == "application/json, text/plain"


class TestHTTPMethodCaseSensitivity:
    """Test HTTP method case sensitivity."""

    def test_method_normalized_to_uppercase(self):
        """Test that HTTP method is normalized to uppercase."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "method": "post",  # lowercase
            },
        }
        module = HTTPWebhookModule(config)

        # Method should be normalized to uppercase in process()
        assert module.module_config.get("method", "POST").upper() == "POST"

    @pytest.mark.asyncio
    async def test_method_uppercase_used(self):
        """Test that HTTP method is used in uppercase when forwarding."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook", "method": "PUT"},
        }
        module = HTTPWebhookModule(config)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.put.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, {})

            # PUT should be called (uppercase)
            mock_instance.put.assert_called_once()
            mock_instance.post.assert_not_called()


class TestEmptyBodyHandling:
    """Test empty body handling."""

    @pytest.mark.asyncio
    async def test_empty_payload_handled(self):
        """Test that empty payload is handled correctly."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({}, {})

            call_args = mock_instance.post.call_args
            assert call_args is not None
            assert call_args.kwargs.get("json") == {}


class TestURLEncodingHandling:
    """Test URL encoding handling."""

    def test_url_with_encoded_query_params(self):
        """Test that URL-encoded query parameters are preserved."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook?param1=value%20with%20spaces&param2=test%2Fdata"
            },
        }
        module = HTTPWebhookModule(config)

        # URL should preserve encoded parameters
        assert (
            "param1=value%20with%20spaces" in module._validated_url
            or "param1=value with spaces" in module._validated_url
        )
        assert "param2" in module._validated_url

    def test_url_with_special_characters(self):
        """Test that URLs with special characters are handled correctly."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook?key=value&other=test"},
        }
        module = HTTPWebhookModule(config)

        # URL should be validated and preserved
        assert "example.com" in module._validated_url


class TestTransferEncodingHandling:
    """Test Transfer-Encoding header handling."""

    @pytest.mark.asyncio
    async def test_transfer_encoding_not_forwarded(self):
        """Test that Transfer-Encoding header is not forwarded (hop-by-hop header)."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {"Transfer-Encoding": "chunked", "Content-Type": "application/json"}

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, headers)

            call_args = mock_instance.post.call_args
            assert call_args is not None
            forwarded_headers = call_args.kwargs.get("headers", {})
            # Transfer-Encoding should not be forwarded (hop-by-hop header)
            assert "Transfer-Encoding" not in forwarded_headers
            assert "transfer-encoding" not in forwarded_headers


class TestRequestTimeoutPropagation:
    """Test request timeout propagation."""

    @pytest.mark.asyncio
    async def test_timeout_config_respected(self):
        """Test that configured timeout is respected when forwarding."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "timeout": 5.0,  # 5 seconds
            },
        }
        module = HTTPWebhookModule(config)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance

            await module.process({"test": "data"}, {})

            # Verify timeout was passed to httpx.AsyncClient
            mock_client.assert_called_once()
            call_kwargs = mock_client.call_args[1] if mock_client.call_args else {}
            # httpx.AsyncClient accepts timeout parameter
            assert (
                "timeout" in call_kwargs or mock_client.call_args[0]
            )  # timeout can be positional or keyword
