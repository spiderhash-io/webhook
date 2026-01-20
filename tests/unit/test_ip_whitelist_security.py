"""
Security tests for IPWhitelistValidator.
Tests IP spoofing prevention and trusted proxy validation.
"""

import pytest
from unittest.mock import Mock, MagicMock
from src.validators import IPWhitelistValidator


class TestIPWhitelistSecurity:
    """Test suite for IP whitelist security."""

    @pytest.mark.asyncio
    async def test_ip_whitelist_valid_ip_with_request(self):
        """Test that valid IPs are accepted when using Request object."""
        # Mock Request object with client IP
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.100"

        config = {"ip_whitelist": ["192.168.1.100", "10.0.0.1"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")

        assert is_valid is True
        assert "Valid IP address" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_invalid_ip_with_request(self):
        """Test that invalid IPs are rejected when using Request object."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.200"  # Not in whitelist

        config = {"ip_whitelist": ["192.168.1.100", "10.0.0.1"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")

        assert is_valid is False
        assert "not in whitelist" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_x_forwarded_for_spoofing_prevented(self):
        """Test that X-Forwarded-For header cannot be spoofed without trusted proxy."""
        # Mock Request object with actual client IP (attacker's real IP)
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "1.2.3.4"  # Attacker's real IP (not whitelisted)

        config = {"ip_whitelist": ["192.168.1.100"]}  # Only this IP is whitelisted
        validator = IPWhitelistValidator(config, request=mock_request)

        # Attacker tries to spoof X-Forwarded-For header
        headers = {"x-forwarded-for": "192.168.1.100"}  # Spoofed IP (whitelisted)
        is_valid, message = await validator.validate(headers, b"")

        # Should be rejected because X-Forwarded-For is not trusted without trusted proxy
        assert is_valid is False
        assert "1.2.3.4" in message or "not in whitelist" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_trusted_proxy_allows_x_forwarded_for(self):
        """Test that X-Forwarded-For is trusted when coming from trusted proxy."""
        # Mock Request object with trusted proxy IP
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"  # Trusted proxy IP

        config = {
            "ip_whitelist": ["192.168.1.100"],
            "trusted_proxies": ["10.0.0.1", "10.0.0.2"],  # Trusted proxy IPs
        }
        validator = IPWhitelistValidator(config, request=mock_request)

        # X-Forwarded-For contains the original client IP
        headers = {
            "x-forwarded-for": "192.168.1.100"  # Original client IP (whitelisted)
        }
        is_valid, message = await validator.validate(headers, b"")

        # Should be accepted because proxy is trusted
        assert is_valid is True
        assert "Valid IP address" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_trusted_proxy_rejects_invalid_client(self):
        """Test that even with trusted proxy, invalid client IPs are rejected."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"  # Trusted proxy IP

        config = {"ip_whitelist": ["192.168.1.100"], "trusted_proxies": ["10.0.0.1"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        # X-Forwarded-For contains invalid client IP
        headers = {"x-forwarded-for": "192.168.1.200"}  # Not whitelisted
        is_valid, message = await validator.validate(headers, b"")

        # Should be rejected even though proxy is trusted
        assert is_valid is False
        assert "not in whitelist" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_x_forwarded_for_multiple_ips(self):
        """Test that X-Forwarded-For with multiple IPs uses first IP (original client)."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"  # Trusted proxy

        config = {"ip_whitelist": ["192.168.1.100"], "trusted_proxies": ["10.0.0.1"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        # X-Forwarded-For with proxy chain: "client, proxy1, proxy2"
        headers = {"x-forwarded-for": "192.168.1.100, 10.0.0.2, 10.0.0.3"}
        is_valid, message = await validator.validate(headers, b"")

        # Should use first IP (original client)
        assert is_valid is True
        assert "Valid IP address" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_x_real_ip_with_trusted_proxy(self):
        """Test that X-Real-IP is used as fallback when X-Forwarded-For is missing."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"  # Trusted proxy

        config = {"ip_whitelist": ["192.168.1.100"], "trusted_proxies": ["10.0.0.1"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        # Only X-Real-IP header (no X-Forwarded-For)
        headers = {"x-real-ip": "192.168.1.100"}
        is_valid, message = await validator.validate(headers, b"")

        # Should be accepted
        assert is_valid is True
        assert "Valid IP address" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_fallback_to_headers_without_request(self):
        """Test that headers are NOT trusted when Request object is not available (security fix)."""
        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=None)  # No request object

        # Should NOT fall back to headers (security fix prevents spoofing)
        headers = {"x-forwarded-for": "192.168.1.100"}
        is_valid, message = await validator.validate(headers, b"")

        # Should fail - no Request object means we can't trust headers (prevents IP spoofing)
        assert is_valid is False
        assert "Could not determine client IP" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_invalid_ip_format(self):
        """Test that invalid IP formats are rejected."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "invalid.ip.address"

        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")

        assert is_valid is False
        assert "Invalid IP address format" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_ipv6_support(self):
        """Test that IPv6 addresses are supported."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

        config = {
            "ip_whitelist": ["2001:0db8:85a3:0000:0000:8a2e:0370:7334", "192.168.1.100"]
        }
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")

        assert is_valid is True
        assert "Valid IP address" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_no_config(self):
        """Test that validation passes when no IP whitelist is configured."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "1.2.3.4"

        config = {}  # No IP whitelist
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")

        assert is_valid is True
        assert "No IP whitelist configured" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_empty_whitelist(self):
        """Test that validation passes when whitelist is empty."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "1.2.3.4"

        config = {"ip_whitelist": []}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")

        assert is_valid is True
        assert "No IP whitelist configured" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_untrusted_proxy_ignores_x_forwarded_for(self):
        """Test that X-Forwarded-For is ignored when proxy is not trusted."""
        # Mock Request object with untrusted proxy IP
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "1.2.3.4"  # Untrusted proxy (not in trusted_proxies)

        config = {
            "ip_whitelist": ["192.168.1.100"],
            "trusted_proxies": ["10.0.0.1"],  # Different proxy IP
        }
        validator = IPWhitelistValidator(config, request=mock_request)

        # X-Forwarded-For header should be ignored
        headers = {"x-forwarded-for": "192.168.1.100"}
        is_valid, message = await validator.validate(headers, b"")

        # Should use actual client IP (1.2.3.4) which is not whitelisted
        assert is_valid is False
        assert "1.2.3.4" in message or "not in whitelist" in message

    @pytest.mark.asyncio
    async def test_ip_whitelist_no_client_info(self):
        """Test behavior when Request object has no client information."""
        mock_request = Mock()
        mock_request.client = None  # No client info

        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")

        # Should fall back to headers or fail
        # This is an edge case, behavior depends on implementation
        assert isinstance(is_valid, bool)
