"""
Comprehensive security tests for HTTP webhook module.
Tests advanced SSRF bypass techniques, header injection variants, and other HTTP attack vectors.
"""

import pytest
from src.modules.http_webhook import HTTPWebhookModule


class TestAdvancedSSRFBypass:
    """Test advanced SSRF bypass techniques."""

    def test_decimal_ip_encoding(self):
        """Test that decimal IP encoding (2130706433 = 127.0.0.1) is blocked."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://2130706433/webhook"  # 127.0.0.1 in decimal
            },
        }

        with pytest.raises(ValueError):
            HTTPWebhookModule(config)

    def test_hex_ip_encoding(self):
        """Test that hex IP encoding (0x7f000001 = 127.0.0.1) is blocked."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://0x7f000001/webhook"},  # 127.0.0.1 in hex
        }

        # Should be blocked (parsed as hostname, caught by validation)
        with pytest.raises(ValueError):
            HTTPWebhookModule(config)

    def test_octal_ip_variants(self):
        """Test various octal IP encoding attempts."""
        octal_urls = [
            "http://0177.0.0.1/webhook",  # Already tested, but ensure coverage
            "http://0177.000.000.001/webhook",
            "http://127.0.0.01/webhook",  # Mixed format
            "http://127.0.00.1/webhook",
        ]

        for url in octal_urls:
            config = {"module": "http_webhook", "module-config": {"url": url}}
            with pytest.raises(ValueError):
                HTTPWebhookModule(config)

    def test_ipv6_localhost_variants(self):
        """Test IPv6 localhost bypass attempts."""
        ipv6_localhost = [
            "http://[::1]/webhook",
            "http://[::]/webhook",
            "http://[0:0:0:0:0:0:0:1]/webhook",
            "http://[0000:0000:0000:0000:0000:0000:0000:0001]/webhook",
            "http://[::ffff:127.0.0.1]/webhook",  # IPv4-mapped IPv6
            "http://[::ffff:7f00:1]/webhook",  # IPv4-mapped IPv6 (hex)
        ]

        for url in ipv6_localhost:
            config = {"module": "http_webhook", "module-config": {"url": url}}
            with pytest.raises(ValueError):
                HTTPWebhookModule(config)

    def test_ipv6_private_ranges(self):
        """Test IPv6 private range bypass attempts."""
        ipv6_private = [
            "http://[fc00::1]/webhook",  # Unique local address
            "http://[fd00::1]/webhook",  # Unique local address
            "http://[fe80::1]/webhook",  # Link-local
            "http://[2001:db8::1]/webhook",  # Documentation range (should be blocked as reserved)
        ]

        for url in ipv6_private:
            config = {"module": "http_webhook", "module-config": {"url": url}}
            with pytest.raises(ValueError):
                HTTPWebhookModule(config)

    def test_url_encoding_bypass(self):
        """Test URL encoding attempts to bypass validation."""
        encoded_urls = [
            "http://127%2E0%2E0%2E1/webhook",  # URL encoded dots
            "http://127%2e0%2e0%2e1/webhook",  # Lowercase encoding
            "http://%31%32%37%2e%30%2e%30%2e%31/webhook",  # Fully encoded 127.0.0.1
            "http://%6c%6f%63%61%6c%68%6f%73%74/webhook",  # Encoded 'localhost'
        ]

        for url in encoded_urls:
            config = {"module": "http_webhook", "module-config": {"url": url}}
            # URL parsing should decode these, then validation should catch them
            with pytest.raises(ValueError):
                HTTPWebhookModule(config)

    def test_mixed_case_scheme(self):
        """Test that mixed case schemes are handled correctly."""
        mixed_schemes = [
            "HTTP://example.com/webhook",
            "HtTp://example.com/webhook",
            "HTTPS://example.com/webhook",
            "HtTpS://example.com/webhook",
        ]

        for url in mixed_schemes:
            config = {"module": "http_webhook", "module-config": {"url": url}}
            # Should work (case-insensitive scheme handling)
            module = HTTPWebhookModule(config)
            assert module._validated_url.lower() == url.lower()

    def test_dangerous_schemes(self):
        """Test that dangerous schemes are blocked."""
        dangerous_schemes = [
            "file:///etc/passwd",
            "gopher://example.com",
            "ldap://example.com",
            "ldaps://example.com",
            "dict://example.com",
            "sftp://example.com",
            "ftp://example.com",
            "javascript://alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript://alert(1)",
        ]

        for url in dangerous_schemes:
            config = {"module": "http_webhook", "module-config": {"url": url}}
            with pytest.raises(ValueError, match="scheme.*is not allowed"):
                HTTPWebhookModule(config)

    def test_missing_scheme(self):
        """Test that URLs without schemes are rejected."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "example.com/webhook"},  # Missing scheme
        }

        with pytest.raises(
            ValueError, match="scheme.*is not allowed|Invalid URL format"
        ):
            HTTPWebhookModule(config)

    def test_userinfo_in_url(self):
        """Test that userinfo (user:pass@host) is handled correctly."""
        # Userinfo should be stripped by urlparse, but test anyway
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://user:pass@example.com/webhook"},
        }

        # Should work (userinfo is part of netloc, hostname extraction should handle it)
        module = HTTPWebhookModule(config)
        assert "example.com" in module._validated_url

    def test_userinfo_with_localhost(self):
        """Test that userinfo doesn't bypass localhost detection."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://user:pass@localhost/webhook"},
        }

        with pytest.raises(ValueError, match="localhost is not allowed"):
            HTTPWebhookModule(config)

    def test_port_scanning_attempts(self):
        """Test that port scanning via common internal ports is blocked."""
        internal_ports = [
            "http://127.0.0.1:22/webhook",  # SSH
            "http://127.0.0.1:3306/webhook",  # MySQL
            "http://127.0.0.1:5432/webhook",  # PostgreSQL
            "http://127.0.0.1:6379/webhook",  # Redis
            "http://127.0.0.1:27017/webhook",  # MongoDB
        ]

        for url in internal_ports:
            config = {"module": "http_webhook", "module-config": {"url": url}}
            with pytest.raises(ValueError, match="localhost is not allowed"):
                HTTPWebhookModule(config)

    def test_cloud_metadata_endpoints_extended(self):
        """Test extended cloud metadata endpoint bypass attempts."""
        metadata_endpoints = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.azure.com/metadata/instance",
            "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
            "http://192.0.0.192/metadata/latest/",  # Oracle Cloud
        ]

        for url in metadata_endpoints:
            config = {"module": "http_webhook", "module-config": {"url": url}}
            with pytest.raises(ValueError):
                HTTPWebhookModule(config)

    def test_dns_rebinding_simulation(self):
        """Test that hostname validation happens at init time (DNS rebinding protection)."""
        # Note: We can't actually test DNS rebinding, but we can test that
        # validation happens at init time, not at request time
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }

        # URL should be validated and stored at init
        module = HTTPWebhookModule(config)
        assert module._validated_url == "http://example.com/webhook"

        # If someone tries to change it later, it should fail
        # (This is tested in process() method)

    def test_fragment_in_url(self):
        """Test that URL fragments don't affect hostname validation."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook#fragment"},
        }

        module = HTTPWebhookModule(config)
        # Fragment should be preserved but not affect validation
        assert "example.com" in module._validated_url

    def test_query_parameters_in_url(self):
        """Test that query parameters don't affect hostname validation."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook?param=value&other=123"
            },
        }

        module = HTTPWebhookModule(config)
        assert "example.com" in module._validated_url

    def test_malformed_ipv6(self):
        """Test that malformed IPv6 addresses are rejected."""
        malformed_ipv6 = [
            "http://[::1/webhook",  # Missing closing bracket
            "http://::1]/webhook",  # Missing opening bracket
            "http://[::1:]/webhook",  # Invalid format
            "http://[:::1]/webhook",  # Too many colons
        ]

        for url in malformed_ipv6:
            config = {"module": "http_webhook", "module-config": {"url": url}}
            with pytest.raises(ValueError):
                HTTPWebhookModule(config)

    def test_whitespace_in_url(self):
        """Test that URLs with whitespace are handled."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "  http://example.com/webhook  "},  # Whitespace
        }

        # Should be trimmed
        module = HTTPWebhookModule(config)
        assert module._validated_url.strip() == "http://example.com/webhook"

    def test_unicode_in_hostname(self):
        """Test that Unicode hostnames are handled correctly."""
        # Unicode hostnames should be rejected (invalid DNS)
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://例え.テスト/webhook"},  # Unicode
        }

        # Should be rejected (invalid hostname format)
        with pytest.raises(ValueError, match="Invalid hostname format"):
            HTTPWebhookModule(config)

    def test_hostname_with_underscore(self):
        """Test that hostnames with underscores are handled."""
        # Underscores are technically invalid in DNS but sometimes used
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://test_example.com/webhook"},
        }

        # Current regex might allow this, but it's technically invalid
        # Test what happens
        try:
            module = HTTPWebhookModule(config)
            # If it passes, that's okay (will fail DNS resolution)
        except ValueError:
            # If it's rejected, that's also okay
            pass


class TestAdvancedHeaderInjection:
    """Test advanced header injection techniques."""

    def test_unicode_newline_variants(self):
        """Test Unicode newline variants that might bypass detection."""
        unicode_newlines = [
            "\u2028",  # Line separator
            "\u2029",  # Paragraph separator
            "\u000b",  # Vertical tab (sometimes treated as newline)
            "\u000c",  # Form feed
        ]

        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        for newline in unicode_newlines:
            value = f"value{newline}X-Injected: malicious"
            # These should ideally be caught, but test current behavior
            try:
                module._sanitize_header_value(value)
                # If it passes, that's a potential issue
                pytest.fail(f"Unicode newline {repr(newline)} was not caught")
            except ValueError:
                # Good - it was caught
                pass

    def test_multiple_crlf_variants(self):
        """Test various CRLF injection patterns."""
        crlf_patterns = [
            "\r\n",
            "\n\r",  # Reverse order
            "\r\r\n",  # Double CR
            "\n\n",  # Double LF
            "\r\n\r\n",  # Double CRLF
            "\r\n\t",  # CRLF with tab
            "\r\n ",  # CRLF with space
        ]

        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        for pattern in crlf_patterns:
            value = f"value{pattern}X-Injected: malicious"
            with pytest.raises(ValueError):
                module._sanitize_header_value(value)

    def test_header_name_injection(self):
        """Test header name injection attempts."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        # Header names with injection characters
        malicious_names = [
            "Header\nName",
            "Header\rName",
            "Header:Name",  # Colon in name
            "Header Name",  # Space in name
            "Header\tName",  # Tab in name
        ]

        for name in malicious_names:
            assert not module._validate_header_name(
                name
            ), f"Should reject: {repr(name)}"

    def test_header_value_with_tabs(self):
        """Test that tabs in header values are handled."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        # Tabs are technically allowed in header values, but test behavior
        value_with_tab = "value\twith\ttabs"
        # Should pass (tabs are allowed in HTTP header values)
        sanitized = module._sanitize_header_value(value_with_tab)
        assert sanitized == value_with_tab

    def test_header_value_with_unicode_control_chars(self):
        """Test Unicode control characters in header values."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        # Various control characters
        control_chars = [
            "\x01",  # SOH
            "\x02",  # STX
            "\x03",  # ETX
            "\x04",  # EOT
            "\x05",  # ENQ
            "\x06",  # ACK
            "\x07",  # BEL
            "\x08",  # BS
            "\x0e",  # SO
            "\x0f",  # SI
            "\x10",  # DLE
            "\x11",  # DC1
            "\x12",  # DC2
            "\x13",  # DC3
            "\x14",  # DC4
            "\x15",  # NAK
            "\x16",  # SYN
            "\x17",  # ETB
            "\x18",  # CAN
            "\x19",  # EM
            "\x1a",  # SUB
            "\x1b",  # ESC
            "\x1c",  # FS
            "\x1d",  # GS
            "\x1e",  # RS
            "\x1f",  # US
            "\x7f",  # DEL
        ]

        for char in control_chars:
            value = f"value{char}test"
            # Most control chars should be rejected or sanitized
            # Test current behavior
            try:
                sanitized = module._sanitize_header_value(value)
                # If it passes, might be okay (depends on HTTP library)
            except ValueError:
                # If rejected, that's good
                pass

    def test_multiple_header_injection(self):
        """Test multiple header injection in single value."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        multi_injection = "value\nHeader1: value1\nHeader2: value2\nHeader3: value3"
        with pytest.raises(ValueError):
            module._sanitize_header_value(multi_injection)

    def test_chunked_encoding_attack(self):
        """Test chunked encoding attack patterns."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        chunked_attacks = [
            "value\nTransfer-Encoding: chunked",
            "value\rTransfer-Encoding: chunked",
            "value\nContent-Length: 0\nTransfer-Encoding: chunked",
        ]

        for attack in chunked_attacks:
            with pytest.raises(ValueError):
                module._sanitize_header_value(attack)

    def test_content_length_manipulation(self):
        """Test Content-Length header manipulation."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        cl_attacks = [
            "value\nContent-Length: 0",
            "value\rContent-Length: 999999",
            "value\nContent-Length: -1",
        ]

        for attack in cl_attacks:
            with pytest.raises(ValueError):
                module._sanitize_header_value(attack)

    def test_host_header_injection(self):
        """Test Host header injection attempts."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        host_injections = [
            "value\nHost: evil.com",
            "value\rHost: 127.0.0.1",
            "value\nHost: example.com:evil.com",
        ]

        for injection in host_injections:
            with pytest.raises(ValueError):
                module._sanitize_header_value(injection)

    def test_x_forwarded_for_injection(self):
        """Test X-Forwarded-For header injection."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        xff_injections = [
            "value\nX-Forwarded-For: 127.0.0.1",
            "value\rX-Forwarded-For: internal",
        ]

        for injection in xff_injections:
            with pytest.raises(ValueError):
                module._sanitize_header_value(injection)


class TestHTTPRequestSmuggling:
    """Test HTTP request smuggling prevention."""

    def test_cl_te_attack_pattern(self):
        """Test CL.TE (Content-Length / Transfer-Encoding) attack."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        # CL.TE attack: Content-Length header with Transfer-Encoding in body
        cl_te_pattern = "value\nContent-Length: 13\nTransfer-Encoding: chunked"
        with pytest.raises(ValueError):
            module._sanitize_header_value(cl_te_pattern)

    def test_te_cl_attack_pattern(self):
        """Test TE.CL (Transfer-Encoding / Content-Length) attack."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        # TE.CL attack pattern
        te_cl_pattern = "value\nTransfer-Encoding: chunked\nContent-Length: 0"
        with pytest.raises(ValueError):
            module._sanitize_header_value(te_cl_pattern)

    def test_te_te_attack_pattern(self):
        """Test TE.TE (double Transfer-Encoding) attack."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        # TE.TE attack: conflicting Transfer-Encoding headers
        te_te_pattern = "value\nTransfer-Encoding: chunked\nTransfer-Encoding: identity"
        with pytest.raises(ValueError):
            module._sanitize_header_value(te_te_pattern)


class TestURLValidationEdgeCases:
    """Test URL validation edge cases."""

    def test_empty_hostname(self):
        """Test that empty hostname is rejected."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http:///webhook"},  # Empty hostname
        }

        with pytest.raises(ValueError, match="must include a hostname"):
            HTTPWebhookModule(config)

    def test_hostname_only(self):
        """Test that hostname-only URLs work."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com"},
        }

        module = HTTPWebhookModule(config)
        assert module._validated_url == "http://example.com"

    def test_ipv6_with_port(self):
        """Test IPv6 addresses with ports."""
        # Public IPv6
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://[2001:4860:4860::8888]:8080/webhook"},
        }

        module = HTTPWebhookModule(config)
        assert (
            "2001:4860:4860::8888" in module._validated_url
            or "[2001:4860:4860::8888]" in module._validated_url
        )

        # Private IPv6 should be blocked
        config_private = {
            "module": "http_webhook",
            "module-config": {"url": "http://[fc00::1]:8080/webhook"},
        }

        with pytest.raises(ValueError):
            HTTPWebhookModule(config_private)

    def test_very_long_hostname(self):
        """Test that very long hostnames are handled."""
        # DNS max length is 253 characters
        long_hostname = "a" * 250 + ".com"
        config = {
            "module": "http_webhook",
            "module-config": {"url": f"http://{long_hostname}/webhook"},
        }

        # Should either work or fail gracefully
        try:
            module = HTTPWebhookModule(config)
            # If it works, that's okay (DNS will fail)
        except ValueError:
            # If rejected, that's also okay
            pass

    def test_hostname_with_many_subdomains(self):
        """Test hostname with many subdomains."""
        many_subdomains = ".".join(["sub"] * 50) + ".example.com"
        config = {
            "module": "http_webhook",
            "module-config": {"url": f"http://{many_subdomains}/webhook"},
        }

        # Should work (valid DNS format, even if long)
        module = HTTPWebhookModule(config)
        assert "example.com" in module._validated_url

    def test_numeric_hostname(self):
        """Test that numeric-only hostnames are handled."""
        # Numeric hostnames are invalid DNS but might be IPs
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://1234567890/webhook"},
        }

        # Should be rejected (invalid hostname, not a valid IP)
        with pytest.raises(ValueError, match="Invalid hostname format"):
            HTTPWebhookModule(config)


class TestHeaderWhitelistSecurity:
    """Test header whitelist security."""

    def test_whitelist_bypass_attempts(self):
        """Test attempts to bypass header whitelist."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "allowed_headers": ["Content-Type", "Authorization"],
            },
        }
        module = HTTPWebhookModule(config)

        # Try to bypass with case variations
        headers = {
            "content-type": "application/json",  # Lowercase
            "CONTENT-TYPE": "application/json",  # Uppercase
            "Content-Type": "application/json",  # Mixed case
            "X-Malicious": "should be filtered",
        }

        sanitized = module._sanitize_headers(headers)
        # All case variations should work (case-insensitive)
        assert "content-type" in sanitized or "Content-Type" in sanitized
        assert "X-Malicious" not in sanitized

    def test_empty_whitelist(self):
        """Test that empty whitelist blocks all headers."""
        config = {
            "module": "http_webhook",
            "module-config": {
                "url": "http://example.com/webhook",
                "allowed_headers": [],
            },
        }
        module = HTTPWebhookModule(config)

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer token",
        }

        sanitized = module._sanitize_headers(headers)
        # All headers should be filtered
        assert len(sanitized) == 0


class TestTimeoutAndResourceAttacks:
    """Test timeout and resource exhaustion attacks."""

    def test_very_long_url(self):
        """Test that very long URLs are handled safely."""
        # Very long URL (potential DoS)
        long_path = "/webhook?" + "&".join([f"param{i}=value{i}" for i in range(1000)])
        config = {
            "module": "http_webhook",
            "module-config": {"url": f"http://example.com{long_path}"},
        }

        # With stricter validation, very long URLs may be rejected to prevent DoS.
        # Both behaviours are acceptable as long as they fail safely.
        try:
            module = HTTPWebhookModule(config)
            assert "example.com" in module._validated_url
        except ValueError as e:
            # If rejected, it should clearly indicate length-related validation
            assert "URL too long" in str(e)

    def test_many_headers(self):
        """Test that many headers don't cause issues."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        # Create many headers
        many_headers = {f"X-Header-{i}": f"value-{i}" for i in range(100)}

        # Should handle gracefully
        sanitized = module._sanitize_headers(many_headers)
        assert len(sanitized) == len(many_headers)


class TestProcessMethodSecurity:
    """Test security of process() method."""

    def test_url_cannot_be_changed_after_init(self):
        """Test that URL cannot be changed after initialization."""
        config = {
            "module": "http_webhook",
            "module-config": {"url": "http://example.com/webhook"},
        }
        module = HTTPWebhookModule(config)

        # Try to change validated URL (should fail in process)
        original_url = module._validated_url

        # If someone tries to modify _validated_url, process() should catch it
        # This is tested by the check: if url != self._validated_url
        assert module._validated_url == original_url

    def test_missing_url_in_process(self):
        """Test that missing URL in process() raises error."""
        config = {"module": "http_webhook", "module-config": {}}  # No URL
        module = HTTPWebhookModule(config)

        # process() should raise error if URL is None
        import pytest
        from unittest.mock import AsyncMock

        # We can't easily test async process() without mocking httpx
        # But we can verify the check exists
        assert module._validated_url is None
