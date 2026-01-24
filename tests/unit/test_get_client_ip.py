"""
Tests for the get_client_ip utility function.

Tests cover:
- Direct connection IP extraction
- Trusted proxy X-Forwarded-For handling
- Trusted proxy X-Real-IP handling
- IP spoofing prevention (untrusted proxy)
- Header injection prevention
- Edge cases (missing client, empty headers)
"""

import pytest
from unittest.mock import MagicMock
from src.utils import get_client_ip


class TestGetClientIPDirect:
    """Test direct connection IP extraction."""

    def test_direct_connection_returns_client_host(self):
        """Test that direct connections return request.client.host."""
        request = MagicMock()
        request.client.host = "192.168.1.100"
        request.headers = {}

        client_ip, is_from_proxy = get_client_ip(request)

        assert client_ip == "192.168.1.100"
        assert is_from_proxy is False

    def test_direct_connection_ignores_x_forwarded_for(self):
        """Test that X-Forwarded-For is ignored without trusted proxies."""
        request = MagicMock()
        request.client.host = "192.168.1.100"
        request.headers = {"x-forwarded-for": "10.0.0.1"}

        client_ip, is_from_proxy = get_client_ip(request)

        assert client_ip == "192.168.1.100"
        assert is_from_proxy is False

    def test_direct_connection_ignores_x_real_ip(self):
        """Test that X-Real-IP is ignored without trusted proxies."""
        request = MagicMock()
        request.client.host = "192.168.1.100"
        request.headers = {"x-real-ip": "10.0.0.1"}

        client_ip, is_from_proxy = get_client_ip(request)

        assert client_ip == "192.168.1.100"
        assert is_from_proxy is False


class TestGetClientIPTrustedProxy:
    """Test trusted proxy handling."""

    def test_trusted_proxy_uses_x_forwarded_for(self):
        """Test that X-Forwarded-For is used when from trusted proxy."""
        request = MagicMock()
        request.client.host = "10.0.0.1"  # Trusted proxy IP
        request.headers = {"x-forwarded-for": "203.0.113.50"}

        client_ip, is_from_proxy = get_client_ip(request, trusted_proxies=["10.0.0.1"])

        assert client_ip == "203.0.113.50"
        assert is_from_proxy is True

    def test_trusted_proxy_uses_first_x_forwarded_for_ip(self):
        """Test that first IP in X-Forwarded-For chain is used."""
        request = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {"x-forwarded-for": "203.0.113.50, 10.0.0.2, 10.0.0.1"}

        client_ip, is_from_proxy = get_client_ip(request, trusted_proxies=["10.0.0.1"])

        assert client_ip == "203.0.113.50"
        assert is_from_proxy is True

    def test_trusted_proxy_uses_x_real_ip_when_no_x_forwarded_for(self):
        """Test that X-Real-IP is used when X-Forwarded-For is missing."""
        request = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {"x-real-ip": "203.0.113.50"}

        client_ip, is_from_proxy = get_client_ip(request, trusted_proxies=["10.0.0.1"])

        assert client_ip == "203.0.113.50"
        assert is_from_proxy is True

    def test_trusted_proxy_prefers_x_forwarded_for_over_x_real_ip(self):
        """Test that X-Forwarded-For takes priority over X-Real-IP."""
        request = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {
            "x-forwarded-for": "203.0.113.50",
            "x-real-ip": "198.51.100.1",
        }

        client_ip, is_from_proxy = get_client_ip(request, trusted_proxies=["10.0.0.1"])

        assert client_ip == "203.0.113.50"
        assert is_from_proxy is True

    def test_multiple_trusted_proxies(self):
        """Test with multiple trusted proxy IPs configured."""
        request = MagicMock()
        request.client.host = "10.0.0.2"  # Second trusted proxy
        request.headers = {"x-forwarded-for": "203.0.113.50"}

        client_ip, is_from_proxy = get_client_ip(
            request, trusted_proxies=["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        )

        assert client_ip == "203.0.113.50"
        assert is_from_proxy is True


class TestGetClientIPSpoofingPrevention:
    """Test IP spoofing prevention."""

    def test_untrusted_source_ignores_x_forwarded_for(self):
        """Test that X-Forwarded-For from untrusted source is ignored."""
        request = MagicMock()
        request.client.host = "192.168.1.100"  # Not in trusted proxies
        request.headers = {"x-forwarded-for": "10.0.0.1"}

        # Attacker tries to spoof IP via X-Forwarded-For
        client_ip, is_from_proxy = get_client_ip(
            request, trusted_proxies=["10.0.0.1"]  # Only 10.0.0.1 is trusted
        )

        # Should return actual client IP, not spoofed one
        assert client_ip == "192.168.1.100"
        assert is_from_proxy is False

    def test_untrusted_source_ignores_x_real_ip(self):
        """Test that X-Real-IP from untrusted source is ignored."""
        request = MagicMock()
        request.client.host = "192.168.1.100"
        request.headers = {"x-real-ip": "10.0.0.1"}

        client_ip, is_from_proxy = get_client_ip(
            request, trusted_proxies=["10.0.0.1"]
        )

        assert client_ip == "192.168.1.100"
        assert is_from_proxy is False


class TestGetClientIPHeaderInjection:
    """Test header injection prevention."""

    def test_newline_injection_in_x_forwarded_for(self):
        """Test that newlines are stripped from X-Forwarded-For."""
        request = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {"x-forwarded-for": "203.0.113.50\nX-Injected: value"}

        client_ip, is_from_proxy = get_client_ip(request, trusted_proxies=["10.0.0.1"])

        assert "\n" not in client_ip
        assert client_ip == "203.0.113.50X-Injected: value"

    def test_carriage_return_injection_in_x_forwarded_for(self):
        """Test that carriage returns are stripped from X-Forwarded-For."""
        request = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {"x-forwarded-for": "203.0.113.50\rX-Injected: value"}

        client_ip, is_from_proxy = get_client_ip(request, trusted_proxies=["10.0.0.1"])

        assert "\r" not in client_ip

    def test_null_byte_injection_in_x_forwarded_for(self):
        """Test that null bytes are stripped from X-Forwarded-For."""
        request = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {"x-forwarded-for": "203.0.113.50\x00evil"}

        client_ip, is_from_proxy = get_client_ip(request, trusted_proxies=["10.0.0.1"])

        assert "\x00" not in client_ip

    def test_injection_in_x_real_ip(self):
        """Test that injection characters are stripped from X-Real-IP."""
        request = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {"x-real-ip": "203.0.113.50\n\r\x00"}

        client_ip, is_from_proxy = get_client_ip(request, trusted_proxies=["10.0.0.1"])

        assert "\n" not in client_ip
        assert "\r" not in client_ip
        assert "\x00" not in client_ip


class TestGetClientIPEdgeCases:
    """Test edge cases."""

    def test_missing_client_returns_unknown(self):
        """Test that missing client returns 'unknown'."""
        request = MagicMock()
        request.client = None
        request.headers = {}

        client_ip, is_from_proxy = get_client_ip(request)

        assert client_ip == "unknown"
        assert is_from_proxy is False

    def test_empty_client_host_returns_unknown(self):
        """Test that empty client.host returns 'unknown'."""
        request = MagicMock()
        request.client.host = ""
        request.headers = {}

        client_ip, is_from_proxy = get_client_ip(request)

        assert client_ip == "unknown"
        assert is_from_proxy is False

    def test_whitespace_only_client_host_returns_unknown(self):
        """Test that whitespace-only client.host returns 'unknown'."""
        request = MagicMock()
        request.client.host = "   "
        request.headers = {}

        client_ip, is_from_proxy = get_client_ip(request)

        assert client_ip == "unknown"
        assert is_from_proxy is False

    def test_empty_x_forwarded_for_uses_client_host(self):
        """Test that empty X-Forwarded-For falls back to client.host."""
        request = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {"x-forwarded-for": ""}

        client_ip, is_from_proxy = get_client_ip(request, trusted_proxies=["10.0.0.1"])

        assert client_ip == "10.0.0.1"
        assert is_from_proxy is False

    def test_empty_trusted_proxies_list(self):
        """Test with empty trusted proxies list."""
        request = MagicMock()
        request.client.host = "192.168.1.100"
        request.headers = {"x-forwarded-for": "10.0.0.1"}

        client_ip, is_from_proxy = get_client_ip(request, trusted_proxies=[])

        assert client_ip == "192.168.1.100"
        assert is_from_proxy is False

    def test_case_insensitive_headers(self):
        """Test that header lookup is case-insensitive."""
        request = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {"X-Forwarded-For": "203.0.113.50"}

        client_ip, is_from_proxy = get_client_ip(request, trusted_proxies=["10.0.0.1"])

        assert client_ip == "203.0.113.50"
        assert is_from_proxy is True


class TestGetClientIPEnvironmentVariable:
    """Test TRUSTED_PROXY_IPS environment variable handling."""

    def test_reads_trusted_proxies_from_env(self, monkeypatch):
        """Test that trusted proxies are read from environment variable."""
        monkeypatch.setenv("TRUSTED_PROXY_IPS", "10.0.0.1,10.0.0.2")

        request = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {"x-forwarded-for": "203.0.113.50"}

        client_ip, is_from_proxy = get_client_ip(request)

        assert client_ip == "203.0.113.50"
        assert is_from_proxy is True

    def test_env_variable_with_whitespace(self, monkeypatch):
        """Test that whitespace in env variable is handled."""
        monkeypatch.setenv("TRUSTED_PROXY_IPS", "  10.0.0.1 , 10.0.0.2  ")

        request = MagicMock()
        request.client.host = "10.0.0.1"
        request.headers = {"x-forwarded-for": "203.0.113.50"}

        client_ip, is_from_proxy = get_client_ip(request)

        assert client_ip == "203.0.113.50"
        assert is_from_proxy is True

    def test_empty_env_variable(self, monkeypatch):
        """Test with empty environment variable."""
        monkeypatch.setenv("TRUSTED_PROXY_IPS", "")

        request = MagicMock()
        request.client.host = "192.168.1.100"
        request.headers = {"x-forwarded-for": "10.0.0.1"}

        client_ip, is_from_proxy = get_client_ip(request)

        assert client_ip == "192.168.1.100"
        assert is_from_proxy is False

    def test_parameter_overrides_env_variable(self, monkeypatch):
        """Test that trusted_proxies parameter overrides env variable."""
        monkeypatch.setenv("TRUSTED_PROXY_IPS", "10.0.0.1")

        request = MagicMock()
        request.client.host = "10.0.0.2"  # Different from env
        request.headers = {"x-forwarded-for": "203.0.113.50"}

        # Use different trusted proxy than env
        client_ip, is_from_proxy = get_client_ip(
            request, trusted_proxies=["10.0.0.2"]
        )

        assert client_ip == "203.0.113.50"
        assert is_from_proxy is True
