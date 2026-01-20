"""
Security tests for HTTP webhook module header injection prevention.
Tests header validation and sanitization to prevent HTTP header injection attacks.
"""

import pytest
from src.modules.http_webhook import HTTPWebhookModule


class TestHTTPHeaderInjection:
    """Test suite for HTTP header injection prevention."""

    def test_valid_headers_accepted(self):
        """Test that valid headers are accepted."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {
            "Content-Type": "application/json",
            "X-Custom-Header": "value",
            "Authorization": "Bearer token123",
            "User-Agent": "TestAgent/1.0",
        }

        sanitized = module._sanitize_headers(headers)
        assert len(sanitized) == len(headers)
        assert sanitized["Content-Type"] == "application/json"
        assert sanitized["X-Custom-Header"] == "value"

    def test_newline_injection_rejected(self):
        """Test that newlines in header values are rejected."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {"X-Injected": "value\nX-Injected-Header: malicious"}

        with pytest.raises(ValueError) as exc_info:
            module._sanitize_header_value(headers["X-Injected"])
        assert "forbidden character" in str(exc_info.value).lower()
        assert "injection" in str(exc_info.value).lower()

    def test_carriage_return_injection_rejected(self):
        """Test that carriage returns in header values are rejected."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {"X-Injected": "value\rX-Injected-Header: malicious"}

        with pytest.raises(ValueError) as exc_info:
            module._sanitize_header_value(headers["X-Injected"])
        assert "forbidden character" in str(exc_info.value).lower()

    def test_null_byte_injection_rejected(self):
        """Test that null bytes in header values are rejected."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {"X-Injected": "value\x00malicious"}

        with pytest.raises(ValueError) as exc_info:
            module._sanitize_header_value(headers["X-Injected"])
        assert "forbidden character" in str(exc_info.value).lower()

    def test_multiple_injection_attempts(self):
        """Test various header injection patterns."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        injection_patterns = [
            "value\nX-Injected: malicious",
            "value\rX-Injected: malicious",
            "value\r\nX-Injected: malicious",
            "value\n\nX-Injected: malicious",
            "value\x00X-Injected: malicious",
            "\nX-Injected: malicious",
            "\rX-Injected: malicious",
        ]

        for pattern in injection_patterns:
            with pytest.raises(ValueError):
                module._sanitize_header_value(pattern)

    def test_header_name_validation(self):
        """Test that invalid header names are rejected."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        invalid_names = [
            "Header\nName",  # Newline in name
            "Header\rName",  # Carriage return in name
            "Header Name",  # Space in name
            "Header:Name",  # Colon in name
            "Header/Name",  # Slash in name
            "",  # Empty name
        ]

        for name in invalid_names:
            assert not module._validate_header_name(
                name
            ), f"Should reject invalid header name: {repr(name)}"

    def test_valid_header_names(self):
        """Test that valid header names are accepted."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        valid_names = [
            "Content-Type",
            "X-Custom-Header",
            "Authorization",
            "X-API-Key",
            "X-Forwarded-For",
            "X-Request-ID",
            "User-Agent",
            "Accept",
            "X_Underscore_Header",
            "X.Header.With.Dots",
            "X123Numeric",
        ]

        for name in valid_names:
            assert module._validate_header_name(
                name
            ), f"Should accept valid header name: {name}"

    def test_hop_by_hop_headers_filtered(self):
        """Test that hop-by-hop headers are filtered out before sanitization."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {
            "Host": "example.com",
            "Connection": "keep-alive",
            "Keep-Alive": "timeout=5",
            "Transfer-Encoding": "chunked",
            "Content-Type": "application/json",
            "X-Custom": "value",
        }

        # Simulate the filtering that happens in process() method
        skip_headers = {
            "host",
            "connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "proxy-connection",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
        }
        filtered_headers = {
            k: v for k, v in headers.items() if k.lower() not in skip_headers
        }

        # Then sanitize
        sanitized = module._sanitize_headers(filtered_headers)

        # Hop-by-hop headers should not be in sanitized output
        assert "Host" not in sanitized
        assert "Connection" not in sanitized
        assert "Keep-Alive" not in sanitized
        assert "Transfer-Encoding" not in sanitized
        # Valid headers should be present
        assert "Content-Type" in sanitized
        assert "X-Custom" in sanitized

    def test_header_whitelist_enforcement(self):
        """Test that header whitelist is enforced when configured."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
                "allowed_headers": ["Content-Type", "Authorization", "X-API-Key"],
            },
        }
        module = HTTPWebhookModule(config)

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer token",
            "X-API-Key": "key123",
            "X-Malicious": "should be filtered",
            "User-Agent": "should be filtered",
        }

        sanitized = module._sanitize_headers(headers)
        assert "Content-Type" in sanitized
        assert "Authorization" in sanitized
        assert "X-API-Key" in sanitized
        assert "X-Malicious" not in sanitized
        assert "User-Agent" not in sanitized

    def test_header_whitelist_case_insensitive(self):
        """Test that header whitelist is case-insensitive."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
                "allowed_headers": ["content-type", "AUTHORIZATION"],
            },
        }
        module = HTTPWebhookModule(config)

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer token",
            "X-Other": "should be filtered",
        }

        sanitized = module._sanitize_headers(headers)
        assert "Content-Type" in sanitized
        assert "Authorization" in sanitized
        assert "X-Other" not in sanitized

    def test_header_value_length_limit(self):
        """Test that very long header values are rejected."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        long_value = "a" * 9000  # Exceeds 8192 limit

        with pytest.raises(ValueError) as exc_info:
            module._sanitize_header_value(long_value)
        assert "too long" in str(exc_info.value).lower()

    def test_header_name_length_limit(self):
        """Test that very long header names are rejected."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        long_name = "X-" + "a" * 250  # Exceeds 200 limit

        assert not module._validate_header_name(long_name)

    def test_header_value_whitespace_trimmed(self):
        """Test that header values are trimmed of leading/trailing whitespace."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        value = "  value with spaces  "
        sanitized = module._sanitize_header_value(value)
        assert sanitized == "value with spaces"

    def test_header_value_preserves_internal_whitespace(self):
        """Test that internal whitespace in header values is preserved."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        value = "Bearer token with spaces"
        sanitized = module._sanitize_header_value(value)
        assert sanitized == "Bearer token with spaces"

    def test_custom_headers_sanitized(self):
        """Test that custom headers from config are also sanitized."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
                "headers": {"X-Custom": "valid value", "X-Invalid": "value\ninjected"},
            },
        }
        module = HTTPWebhookModule(config)

        # Custom headers with injection should be filtered out
        headers = {}
        custom_headers = config["module-config"]["headers"]
        sanitized_custom = module._sanitize_headers(custom_headers)

        assert "X-Custom" in sanitized_custom
        assert (
            "X-Invalid" not in sanitized_custom
        )  # Should be filtered due to injection attempt

    def test_request_smuggling_prevention(self):
        """Test prevention of HTTP request smuggling via header injection."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        # Common request smuggling patterns
        smuggling_patterns = [
            "value\r\nContent-Length: 0\r\n\r\nSMUGGLED",
            "value\nContent-Length: 0\n\nSMUGGLED",
            "value\rTransfer-Encoding: chunked\r\rSMUGGLED",
        ]

        for pattern in smuggling_patterns:
            with pytest.raises(ValueError):
                module._sanitize_header_value(pattern)

    def test_cache_poisoning_prevention(self):
        """Test prevention of cache poisoning via header injection."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        # Cache poisoning patterns
        poisoning_patterns = [
            "value\nCache-Control: no-cache",
            "value\rX-Cache-Key: malicious",
            "value\nX-Forwarded-Host: evil.com",
        ]

        for pattern in poisoning_patterns:
            with pytest.raises(ValueError):
                module._sanitize_header_value(pattern)

    def test_invalid_headers_skipped_not_crashed(self):
        """Test that invalid headers are skipped rather than crashing."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        headers = {
            "Valid-Header": "valid value",
            "Invalid\nHeader": "value",  # Invalid name
            "Another-Valid": "value\ninjected",  # Invalid value
            "Final-Valid": "another valid value",
        }

        # Should not raise, but should filter out invalid headers
        sanitized = module._sanitize_headers(headers)
        assert "Valid-Header" in sanitized
        assert "Invalid\nHeader" not in sanitized
        assert "Another-Valid" not in sanitized  # Filtered due to injection
        assert "Final-Valid" in sanitized

    def test_unicode_in_header_values(self):
        """Test that Unicode characters in header values are handled."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "forward_headers": True,
            },
        }
        module = HTTPWebhookModule(config)

        # Unicode should be allowed (but may need encoding in actual HTTP)
        value = "Bearer token_测试_123"
        sanitized = module._sanitize_header_value(value)
        assert sanitized == "Bearer token_测试_123"

        # But newlines in Unicode should still be rejected
        with pytest.raises(ValueError):
            module._sanitize_header_value("value\n测试")
