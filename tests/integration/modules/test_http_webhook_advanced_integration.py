"""
Integration tests for HTTP webhook module advanced features.

These tests verify SSRF prevention, retry logic, and request customization.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, patch
from tests.integration.test_config import API_BASE_URL
from src.modules.http_webhook import HTTPWebhookModule


@pytest.mark.integration
class TestHTTPWebhookAdvancedIntegration:
    """Integration tests for HTTP webhook advanced features."""

    @pytest.mark.asyncio
    async def test_ssrf_prevention_localhost_blocked(self):
        """Test that SSRF prevention blocks localhost access."""
        from src.modules.http_webhook import HTTPWebhookModule

        # Attempt to use localhost URLs (should be blocked)
        localhost_urls = [
            "http://localhost:8080/webhook",
            "http://127.0.0.1:8080/webhook",
            "http://0.0.0.0:8080/webhook",
            "http://[::1]:8080/webhook",
        ]

        for url in localhost_urls:
            config = {"module": "http_webhook", "module-config": {"url": url}}
            with pytest.raises(ValueError, match="localhost|not allowed|security"):
                HTTPWebhookModule(config)

    @pytest.mark.asyncio
    async def test_ssrf_prevention_private_ip_blocked(self):
        """Test that SSRF prevention blocks private IP ranges."""
        from src.modules.http_webhook import HTTPWebhookModule

        # Attempt to use private IPs (should be blocked)
        private_ip_urls = [
            "http://192.168.1.1:8080/webhook",
            "http://10.0.0.1:8080/webhook",
            "http://172.16.0.1:8080/webhook",
        ]

        for url in private_ip_urls:
            config = {"module": "http_webhook", "module-config": {"url": url}}
            with pytest.raises(ValueError, match="private|not allowed|security"):
                HTTPWebhookModule(config)

    @pytest.mark.asyncio
    async def test_ssrf_prevention_metadata_endpoint_blocked(self):
        """Test that SSRF prevention blocks cloud metadata endpoints."""
        from src.modules.http_webhook import HTTPWebhookModule

        # Attempt to use metadata endpoints (should be blocked)
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data",
            "http://metadata.google.internal/computeMetadata/v1",
        ]

        for url in metadata_urls:
            config = {"module": "http_webhook", "module-config": {"url": url}}
            with pytest.raises(ValueError, match="metadata|not allowed|security"):
                HTTPWebhookModule(config)

    @pytest.mark.asyncio
    async def test_ssrf_prevention_whitelist_allowed(self):
        """Test that whitelisted URLs are allowed."""
        from src.modules.http_webhook import HTTPWebhookModule

        # Whitelist a URL (for testing purposes)
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "allowed_hosts": ["example.com", "localhost"],  # Whitelist
            },
        }

        # Should succeed if URL is whitelisted
        module = HTTPWebhookModule(config)
        assert module._validated_url == "http://example.com/webhook"

    @pytest.mark.asyncio
    async def test_custom_headers(self):
        """Test that custom headers can be added to requests."""
        from src.modules.http_webhook import HTTPWebhookModule

        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "headers": {
                    "X-Custom-Header": "custom_value",
                    "X-API-Key": "api_key_123",
                },
            },
        }

        module = HTTPWebhookModule(config)

        # Mock httpx client
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            await module.process({"test": "data"}, {"Authorization": "Bearer token"})

            # Verify custom headers were included
            call_args = mock_client.return_value.__aenter__.return_value.post.call_args
            assert call_args is not None
            headers = call_args[1].get("headers", {})
            assert "X-Custom-Header" in headers
            assert headers["X-Custom-Header"] == "custom_value"
            assert headers["X-API-Key"] == "api_key_123"

    @pytest.mark.asyncio
    async def test_forward_headers_configuration(self):
        """Test that headers can be forwarded or filtered."""
        from src.modules.http_webhook import HTTPWebhookModule

        # Test with forward_headers=True
        config_forward = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }

        module_forward = HTTPWebhookModule(config_forward)

        # Mock httpx client
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            test_headers = {"Authorization": "Bearer token", "X-Custom": "value"}
            await module_forward.process({"test": "data"}, test_headers)

            # Verify headers were forwarded (excluding hop-by-hop headers)
            call_args = mock_client.return_value.__aenter__.return_value.post.call_args
            headers = call_args[1].get("headers", {})
            assert "Authorization" in headers or "X-Custom" in headers

        # Test with forward_headers=False
        config_no_forward = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": False,
            },
        }

        module_no_forward = HTTPWebhookModule(config_no_forward)

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            await module_no_forward.process({"test": "data"}, test_headers)

            # Verify original headers were not forwarded
            call_args = mock_client.return_value.__aenter__.return_value.post.call_args
            headers = call_args[1].get("headers", {})
            # Should not contain original headers (only custom ones if any)
            assert "Authorization" not in headers or "X-Custom" not in headers

    @pytest.mark.asyncio
    async def test_custom_method(self):
        """Test that custom HTTP methods can be used."""
        from src.modules.http_webhook import HTTPWebhookModule

        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook", "method": "PUT"},
        }

        module = HTTPWebhookModule(config)

        # Mock httpx client
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.put = AsyncMock(
                return_value=mock_response
            )

            await module.process({"test": "data"}, {})

            # Verify PUT method was used
            assert mock_client.return_value.__aenter__.return_value.put.called

    @pytest.mark.asyncio
    async def test_timeout_configuration(self):
        """Test that custom timeouts can be configured."""
        from src.modules.http_webhook import HTTPWebhookModule

        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook", "timeout": 60},
        }

        module = HTTPWebhookModule(config)

        # Mock httpx client
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            await module.process({"test": "data"}, {})

            # Verify timeout was passed to httpx client
            call_args = mock_client.call_args
            assert call_args is not None
            assert call_args[1].get("timeout") == 60

    @pytest.mark.asyncio
    async def test_header_sanitization(self):
        """Test that headers are sanitized to prevent injection."""
        from src.modules.http_webhook import HTTPWebhookModule

        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }

        module = HTTPWebhookModule(config)

        # Test with dangerous header values
        dangerous_headers = {
            "X-Injection": "value\r\nInjected-Header: malicious",
            "X-Null": "value\x00null",
        }

        # Headers should be sanitized
        sanitized = module._sanitize_headers(dangerous_headers)

        # Verify dangerous characters are removed or escaped
        for key, value in sanitized.items():
            assert "\r" not in value
            assert "\n" not in value
            assert "\x00" not in value
