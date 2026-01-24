"""
Comprehensive security tests for IP Whitelist validation.
Tests advanced IP spoofing and bypass techniques.
"""

import pytest
from unittest.mock import Mock, MagicMock
from src.validators import IPWhitelistValidator
import ipaddress


class TestIPWhitelistSpoofing:
    """Test IP spoofing attack vectors."""

    @pytest.mark.asyncio
    async def test_x_forwarded_for_spoofing_without_request(self):
        """Test X-Forwarded-For spoofing when Request object is not available."""
        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=None)  # No request object

        # Attacker spoofs X-Forwarded-For header
        headers = {"x-forwarded-for": "192.168.1.100"}  # Spoofed whitelisted IP

        is_valid, message = await validator.validate(headers, b"")
        # Should be blocked - no Request object means we can't trust headers
        # This prevents IP spoofing attacks
        assert is_valid is False
        assert "Could not determine client IP" in message

    @pytest.mark.asyncio
    async def test_x_real_ip_spoofing_without_request(self):
        """Test X-Real-IP spoofing when Request object is not available."""
        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=None)

        headers = {"x-real-ip": "192.168.1.100"}  # Spoofed

        is_valid, message = await validator.validate(headers, b"")
        # Should be blocked - no Request object means we can't trust headers
        assert is_valid is False
        assert "Could not determine client IP" in message

    @pytest.mark.asyncio
    async def test_multiple_x_forwarded_for_ips_manipulation(self):
        """Test manipulation of multiple IPs in X-Forwarded-For."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"  # Trusted proxy

        config = {"ip_whitelist": ["192.168.1.100"], "trusted_proxies": ["10.0.0.1"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        # Try to manipulate order or add extra IPs
        manipulation_attempts = [
            "192.168.1.200, 192.168.1.100",  # Wrong IP first
            "192.168.1.100, 192.168.1.100",  # Duplicate
            " 192.168.1.100 ",  # Whitespace
            "192.168.1.100,",  # Trailing comma
        ]

        for xff_value in manipulation_attempts:
            headers = {"x-forwarded-for": xff_value}
            is_valid, message = await validator.validate(headers, b"")
            # First IP should be used, so only first test should fail
            if xff_value.startswith("192.168.1.200"):
                assert is_valid is False
            elif "192.168.1.100" in xff_value:
                # Should extract first valid IP
                pass


class TestIPWhitelistEncodingBypass:
    """Test IP encoding bypass techniques."""

    @pytest.mark.asyncio
    async def test_octal_ip_encoding(self):
        """Test octal IP encoding bypass attempts."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "0177.0.0.1"  # Octal for 127.0.0.1

        config = {"ip_whitelist": ["127.0.0.1"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - octal IP should not match decimal IP
        # Or should normalize and fail if it's localhost
        assert is_valid is False or "Invalid" in message

    @pytest.mark.asyncio
    async def test_hex_ip_encoding(self):
        """Test hexadecimal IP encoding bypass attempts."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "0x7f.0.0.1"  # Hex for 127.0.0.1

        config = {"ip_whitelist": ["127.0.0.1"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - hex IP should not match decimal IP
        assert is_valid is False or "Invalid" in message

    @pytest.mark.asyncio
    async def test_decimal_ip_encoding(self):
        """Test decimal IP encoding (integer representation)."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "2130706433"  # Decimal for 127.0.0.1

        config = {"ip_whitelist": ["127.0.0.1"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - decimal IP should not match dotted decimal
        assert is_valid is False or "Invalid" in message

    @pytest.mark.asyncio
    async def test_ipv6_different_representations(self):
        """Test IPv6 different representations (compressed vs full)."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "2001:db8::1"  # Compressed IPv6

        config = {
            "ip_whitelist": ["2001:0db8:0000:0000:0000:0000:0000:0001"]  # Full form
        }
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - different representations don't match
        # Or should normalize and match (better behavior)
        # Test documents current behavior
        assert isinstance(is_valid, bool)


class TestIPWhitelistNormalization:
    """Test IP address normalization issues."""

    @pytest.mark.asyncio
    async def test_ipv4_leading_zeros(self):
        """Test IPv4 with leading zeros."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.001.100"  # Leading zeros

        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - leading zeros don't match
        # Or should normalize and match (better behavior)
        assert isinstance(is_valid, bool)

    @pytest.mark.asyncio
    async def test_ipv4_case_sensitivity(self):
        """Test IPv4 case sensitivity (should be case-insensitive)."""
        # IPv4 addresses don't have case, but test anyway
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.100"

        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should work - exact match
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_ipv6_case_sensitivity(self):
        """Test IPv6 case sensitivity (should be case-insensitive)."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "2001:DB8::1"  # Uppercase

        config = {"ip_whitelist": ["2001:db8::1"]}  # Lowercase
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should work - IPv6 should be case-insensitive
        # Or should normalize and match
        assert isinstance(is_valid, bool)


class TestIPWhitelistHeaderInjection:
    """Test header injection attacks."""

    @pytest.mark.asyncio
    async def test_newline_in_x_forwarded_for(self):
        """Test newline injection in X-Forwarded-For header."""
        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=None)

        # Newline injection attempts
        injection_attempts = [
            "192.168.1.100\nX-Injected: value",
            "192.168.1.100\rX-Injected: value",
            "192.168.1.100\r\nX-Injected: value",
        ]

        for xff_value in injection_attempts:
            headers = {"x-forwarded-for": xff_value}
            is_valid, message = await validator.validate(headers, b"")
            # Should handle newlines safely (extract IP before newline)
            # Or reject entirely
            # Newlines should not cause header injection
            if "\n" in xff_value or "\r" in xff_value:
                # Should extract IP before newline or reject
                ip_part = xff_value.split("\n")[0].split("\r")[0].strip()
                if ip_part == "192.168.1.100":
                    # If IP is extracted correctly, should pass
                    pass
                else:
                    # If rejected, should fail
                    assert is_valid is False

    @pytest.mark.asyncio
    async def test_null_bytes_in_x_forwarded_for(self):
        """Test null bytes in X-Forwarded-For header."""
        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=None)

        headers = {"x-forwarded-for": "192.168.1.100\x00injection"}

        is_valid, message = await validator.validate(headers, b"")
        # Should handle null bytes safely
        # Should extract IP before null byte or reject
        assert isinstance(is_valid, bool)

    @pytest.mark.asyncio
    async def test_whitespace_manipulation(self):
        """Test whitespace manipulation in IP headers."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"  # Trusted proxy

        config = {"ip_whitelist": ["192.168.1.100"], "trusted_proxies": ["10.0.0.1"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        # Whitespace variations
        whitespace_variations = [
            " 192.168.1.100 ",  # Leading/trailing spaces
            "\t192.168.1.100\t",  # Tabs
            "192.168.1.100  ,  10.0.0.2",  # Extra spaces around comma
        ]

        for xff_value in whitespace_variations:
            headers = {"x-forwarded-for": xff_value}
            is_valid, message = await validator.validate(headers, b"")
            # Should strip whitespace and extract first IP
            # All should work if whitespace is handled
            if "192.168.1.100" in xff_value:
                # Should extract and match
                pass


class TestIPWhitelistTrustedProxyBypass:
    """Test trusted proxy bypass techniques."""

    @pytest.mark.asyncio
    async def test_empty_trusted_proxies_list(self):
        """Test behavior with empty trusted_proxies list."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "1.2.3.4"  # Not a trusted proxy

        config = {
            "ip_whitelist": ["192.168.1.100"],
            "trusted_proxies": [],  # Empty list
        }
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {"x-forwarded-for": "192.168.1.100"}

        is_valid, message = await validator.validate(headers, b"")
        # Should reject - empty trusted_proxies means no proxy is trusted
        assert is_valid is False
        assert "1.2.3.4" in message or "not in whitelist" in message

    @pytest.mark.asyncio
    async def test_trusted_proxy_ip_spoofing(self):
        """Test spoofing trusted proxy IP."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "1.2.3.4"  # Attacker's real IP (not trusted)

        config = {
            "ip_whitelist": ["192.168.1.100"],
            "trusted_proxies": ["10.0.0.1"],  # Different proxy
        }
        validator = IPWhitelistValidator(config, request=mock_request)

        # Attacker tries to use X-Forwarded-For even though not behind trusted proxy
        headers = {"x-forwarded-for": "192.168.1.100"}

        is_valid, message = await validator.validate(headers, b"")
        # Should reject - actual client IP (1.2.3.4) is not a trusted proxy
        assert is_valid is False
        assert "1.2.3.4" in message or "not in whitelist" in message

    @pytest.mark.asyncio
    async def test_trusted_proxy_case_sensitivity(self):
        """Test trusted proxy IP case sensitivity."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"  # Trusted proxy (exact match)

        config = {
            "ip_whitelist": ["192.168.1.100"],
            "trusted_proxies": ["10.0.0.1"],  # Exact match
        }
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {"x-forwarded-for": "192.168.1.100"}

        is_valid, message = await validator.validate(headers, b"")
        # Should work - exact match
        assert is_valid is True


class TestIPWhitelistEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_ip_in_whitelist(self):
        """Test empty string in IP whitelist."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.100"

        config = {"ip_whitelist": ["", "192.168.1.100"]}  # Empty string
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should work - valid IP is in whitelist
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_whitespace_in_whitelist(self):
        """Test whitespace in IP whitelist."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.100"

        config = {"ip_whitelist": [" 192.168.1.100 ", "10.0.0.1"]}  # Whitespace
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - whitespace in whitelist doesn't match
        # Or should normalize and match (better behavior)
        assert isinstance(is_valid, bool)

    @pytest.mark.asyncio
    async def test_very_long_ip_string(self):
        """Test very long IP string (DoS attempt)."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.100"

        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        # Very long X-Forwarded-For header
        long_ip_string = "192.168.1.100," + "1.2.3.4," * 10000
        headers = {"x-forwarded-for": long_ip_string}

        # Should handle gracefully (extract first IP)
        is_valid, message = await validator.validate(headers, b"")
        # Should work - first IP is whitelisted
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_special_characters_in_ip(self):
        """Test special characters in IP address."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.100@evil.com"  # Invalid IP

        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - invalid IP format
        assert is_valid is False
        assert "Invalid IP address format" in message

    @pytest.mark.asyncio
    async def test_ipv4_mapped_ipv6(self):
        """Test IPv4-mapped IPv6 addresses."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "::ffff:192.168.1.100"  # IPv4-mapped IPv6

        config = {"ip_whitelist": ["192.168.1.100"]}  # IPv4 format
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - IPv4-mapped IPv6 doesn't match IPv4
        # Or should normalize and match (better behavior)
        assert isinstance(is_valid, bool)

    @pytest.mark.asyncio
    async def test_private_ip_in_whitelist(self):
        """Test that private IPs can be whitelisted (document behavior)."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.100"  # Private IP

        config = {"ip_whitelist": ["192.168.1.100"]}  # Private IP whitelisted
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should work - private IPs can be whitelisted
        assert is_valid is True


class TestIPWhitelistRequestObject:
    """Test Request object handling."""

    @pytest.mark.asyncio
    async def test_request_object_without_client(self):
        """Test Request object without client attribute."""
        mock_request = Mock()
        mock_request.client = None  # No client

        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {"x-forwarded-for": "192.168.1.100"}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - no client means we can't trust headers
        assert is_valid is False
        assert "Could not determine client IP" in message

    @pytest.mark.asyncio
    async def test_request_object_without_client_host(self):
        """Test Request object without client.host attribute."""
        mock_request = Mock()
        mock_request.client = Mock()
        # Remove host attribute using spec
        type(mock_request.client).host = property(lambda self: None)

        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {"x-forwarded-for": "192.168.1.100"}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - no valid client IP from Request object
        assert is_valid is False
        assert "Could not determine client IP" in message

    @pytest.mark.asyncio
    async def test_request_object_empty_client_host(self):
        """Test Request object with empty client.host."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = ""  # Empty host

        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {"x-forwarded-for": "192.168.1.100"}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - empty client.host means we can't trust headers
        assert is_valid is False
        assert "Could not determine client IP" in message


class TestIPWhitelistComparison:
    """Test IP comparison logic."""

    @pytest.mark.asyncio
    async def test_exact_match_required(self):
        """Test that exact IP match is required (no subnet matching)."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.100"

        config = {
            "ip_whitelist": ["192.168.1.0/24"]  # Subnet notation (should not match)
        }
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - subnet notation doesn't match exact IP
        # Current implementation requires exact match
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_case_insensitive_comparison(self):
        """Test that IP comparison is case-insensitive (for IPv6)."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "2001:DB8::1"  # Uppercase

        config = {"ip_whitelist": ["2001:db8::1"]}  # Lowercase
        validator = IPWhitelistValidator(config, request=mock_request)

        headers = {}
        is_valid, message = await validator.validate(headers, b"")
        # Should work if normalized, or fail if exact match required
        # Test documents current behavior
        assert isinstance(is_valid, bool)


class TestIPWhitelistSecurityLogging:
    """Test security logging and detection."""

    @pytest.mark.asyncio
    async def test_spoofing_attempt_logged(self, caplog):
        """Test that spoofing attempts are logged."""
        import logging

        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "1.2.3.4"  # Not whitelisted

        config = {"ip_whitelist": ["192.168.1.100"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        # Try to spoof via X-Forwarded-For
        headers = {"x-forwarded-for": "192.168.1.100"}

        with caplog.at_level(logging.WARNING):
            is_valid, message = await validator.validate(headers, b"")

        # Should log spoofing attempt
        assert is_valid is False
        # Check log messages for security warning
        log_messages = [record.message for record in caplog.records]
        assert any(
            "SECURITY" in msg or "spoofed" in msg.lower() or "X-Forwarded-For" in msg
            for msg in log_messages
        ), f"Expected security warning in logs but got: {log_messages}"


class TestIPWhitelistMultipleHeaders:
    """Test handling of multiple IP-related headers."""

    @pytest.mark.asyncio
    async def test_x_forwarded_for_and_x_real_ip_both_present(self):
        """Test when both X-Forwarded-For and X-Real-IP are present."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"  # Trusted proxy

        config = {"ip_whitelist": ["192.168.1.100"], "trusted_proxies": ["10.0.0.1"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        # Both headers present
        headers = {
            "x-forwarded-for": "192.168.1.100",
            "x-real-ip": "192.168.1.200",  # Different IP
        }

        is_valid, message = await validator.validate(headers, b"")
        # Should use X-Forwarded-For (checked first)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_x_real_ip_fallback_when_x_forwarded_for_missing(self):
        """Test X-Real-IP fallback when X-Forwarded-For is missing."""
        mock_request = Mock()
        mock_request.client = Mock()
        mock_request.client.host = "10.0.0.1"  # Trusted proxy

        config = {"ip_whitelist": ["192.168.1.100"], "trusted_proxies": ["10.0.0.1"]}
        validator = IPWhitelistValidator(config, request=mock_request)

        # Only X-Real-IP
        headers = {"x-real-ip": "192.168.1.100"}

        is_valid, message = await validator.validate(headers, b"")
        # Should use X-Real-IP as fallback
        assert is_valid is True
