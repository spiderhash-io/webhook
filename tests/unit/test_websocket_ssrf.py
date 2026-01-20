"""
Security tests for SSRF prevention in WebSocket webhook module.
Tests that WebSocket URLs are properly validated to prevent Server-Side Request Forgery attacks.
"""

import pytest
from src.modules.websocket import WebSocketModule


class TestWebSocketSSRFPrevention:
    """Test suite for SSRF prevention in WebSocket webhook module."""

    def test_localhost_blocked(self):
        """Test that localhost WebSocket URLs are blocked."""
        config = {
            "module": "websocket",
            "module-config": {"url": "ws://localhost:8080/ws"},
        }

        with pytest.raises(ValueError, match="localhost is not allowed"):
            WebSocketModule(config)

    def test_127_0_0_1_blocked(self):
        """Test that 127.0.0.1 is blocked."""
        config = {
            "module": "websocket",
            "module-config": {"url": "ws://127.0.0.1:8080/ws"},
        }

        with pytest.raises(ValueError, match="localhost is not allowed|loopback"):
            WebSocketModule(config)

    def test_private_ip_ranges_blocked(self):
        """Test that private IP ranges (RFC 1918) are blocked."""
        private_ips = [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "10.10.10.10",
            "172.31.255.255",
            "192.168.255.255",
        ]

        for ip in private_ips:
            config = {
                "module": "websocket",
                "module-config": {"url": f"ws://{ip}:8080/ws"},
            }

            with pytest.raises(ValueError, match="private IP address"):
                WebSocketModule(config)

    def test_link_local_blocked(self):
        """Test that link-local addresses (169.254.0.0/16) are blocked."""
        config = {
            "module": "websocket",
            "module-config": {"url": "ws://169.254.169.254/ws"},
        }

        with pytest.raises(ValueError, match="link-local|private IP address"):
            WebSocketModule(config)

    def test_cloud_metadata_endpoint_blocked(self):
        """Test that cloud metadata endpoints are blocked."""
        metadata_urls = [
            ("ws://169.254.169.254/ws", "link-local|private IP address"),
            ("ws://metadata.google.internal/ws", "metadata service"),
            ("ws://metadata/ws", "metadata service"),
        ]

        for url, pattern in metadata_urls:
            config = {"module": "websocket", "module-config": {"url": url}}

            with pytest.raises(ValueError, match=pattern):
                WebSocketModule(config)

    def test_file_scheme_blocked(self):
        """Test that file:// scheme is blocked."""
        config = {"module": "websocket", "module-config": {"url": "file:///etc/passwd"}}

        with pytest.raises(ValueError, match="scheme.*is not allowed"):
            WebSocketModule(config)

    def test_http_scheme_blocked(self):
        """Test that http:// scheme is blocked (must use ws:// or wss://)."""
        config = {
            "module": "websocket",
            "module-config": {"url": "http://example.com/ws"},
        }

        with pytest.raises(ValueError, match="scheme.*is not allowed"):
            WebSocketModule(config)

    def test_https_scheme_blocked(self):
        """Test that https:// scheme is blocked (must use ws:// or wss://)."""
        config = {
            "module": "websocket",
            "module-config": {"url": "https://example.com/ws"},
        }

        with pytest.raises(ValueError, match="scheme.*is not allowed"):
            WebSocketModule(config)

    def test_wss_allowed(self):
        """Test that wss:// URLs are allowed."""
        config = {
            "module": "websocket",
            "module-config": {"url": "wss://example.com/ws"},
        }

        # Should not raise an exception
        module = WebSocketModule(config)
        assert module._validated_url == "wss://example.com/ws"

    def test_ws_allowed(self):
        """Test that ws:// URLs are allowed."""
        config = {
            "module": "websocket",
            "module-config": {"url": "ws://example.com/ws"},
        }

        # Should not raise an exception
        module = WebSocketModule(config)
        assert module._validated_url == "ws://example.com/ws"

    def test_public_ip_allowed(self):
        """Test that public IP addresses are allowed."""
        config = {"module": "websocket", "module-config": {"url": "ws://8.8.8.8/ws"}}

        # Should not raise an exception
        module = WebSocketModule(config)
        assert module._validated_url == "ws://8.8.8.8/ws"

    def test_whitelist_allows_private_ip(self):
        """Test that whitelist allows private IPs if configured."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://192.168.1.1:8080/ws",
                "allowed_hosts": ["192.168.1.1", "example.com"],
            },
        }

        # Should not raise an exception if whitelisted
        module = WebSocketModule(config)
        assert module._validated_url == "ws://192.168.1.1:8080/ws"

    def test_whitelist_allows_localhost(self):
        """Test that whitelist allows localhost if configured."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://localhost:8080/ws",
                "allowed_hosts": ["localhost"],
            },
        }

        # Should not raise an exception if whitelisted
        module = WebSocketModule(config)
        assert module._validated_url == "ws://localhost:8080/ws"

    def test_whitelist_blocks_non_whitelisted(self):
        """Test that non-whitelisted hosts are blocked even if public."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com/ws",
                "allowed_hosts": ["allowed.com"],
            },
        }

        with pytest.raises(ValueError, match="not in the allowed hosts whitelist"):
            WebSocketModule(config)

    def test_whitelist_case_insensitive(self):
        """Test that whitelist is case-insensitive."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://EXAMPLE.COM/ws",
                "allowed_hosts": ["example.com"],
            },
        }

        # Should not raise an exception (case-insensitive match)
        module = WebSocketModule(config)
        assert module._validated_url == "ws://EXAMPLE.COM/ws"

    def test_loopback_variants_blocked(self):
        """Test that various localhost representations are blocked."""
        localhost_variants = [
            "ws://127.0.0.1/ws",
            "ws://0.0.0.0/ws",
            "ws://::1/ws",
            "wss://[::1]/ws",
        ]

        for url in localhost_variants:
            config = {"module": "websocket", "module-config": {"url": url}}

            with pytest.raises(ValueError):
                WebSocketModule(config)

    def test_multicast_blocked(self):
        """Test that multicast addresses are blocked."""
        config = {"module": "websocket", "module-config": {"url": "ws://224.0.0.1/ws"}}

        with pytest.raises(ValueError, match="multicast"):
            WebSocketModule(config)

    def test_reserved_ip_blocked(self):
        """Test that reserved IP addresses are blocked."""
        config = {"module": "websocket", "module-config": {"url": "ws://0.0.0.0/ws"}}

        with pytest.raises(ValueError, match="localhost|reserved|loopback"):
            WebSocketModule(config)

    def test_empty_url_rejected(self):
        """Test that empty URL is rejected."""
        config = {
            "module": "websocket",
            "module-config": {"url": "   "},  # Whitespace only
        }

        with pytest.raises(ValueError, match="cannot be empty"):
            WebSocketModule(config)

    def test_missing_url_allowed(self):
        """Test that missing URL is allowed (will fail in process())."""
        config = {"module": "websocket", "module-config": {}}

        # Should not raise during init (will fail in process())
        module = WebSocketModule(config)
        assert module._validated_url is None

    def test_invalid_url_format_rejected(self):
        """Test that invalid URL format is rejected."""
        config = {"module": "websocket", "module-config": {"url": "not a valid url"}}

        with pytest.raises(
            ValueError,
            match="scheme.*is not allowed|Invalid hostname|Invalid URL format",
        ):
            WebSocketModule(config)

    def test_url_with_path_allowed(self):
        """Test that URLs with paths are allowed."""
        config = {
            "module": "websocket",
            "module-config": {"url": "wss://example.com/api/v1/ws?param=value"},
        }

        # Should not raise an exception
        module = WebSocketModule(config)
        assert "example.com" in module._validated_url

    def test_url_with_port_allowed(self):
        """Test that URLs with ports are allowed."""
        config = {
            "module": "websocket",
            "module-config": {"url": "ws://example.com:8080/ws"},
        }

        # Should not raise an exception
        module = WebSocketModule(config)
        assert module._validated_url == "ws://example.com:8080/ws"

    def test_public_hostname_allowed(self):
        """Test that public hostnames are allowed."""
        config = {
            "module": "websocket",
            "module-config": {"url": "wss://api.example.com/ws"},
        }

        # Should not raise an exception
        module = WebSocketModule(config)
        assert "example.com" in module._validated_url

    def test_ipv6_public_allowed(self):
        """Test that public IPv6 addresses are allowed."""
        config = {
            "module": "websocket",
            "module-config": {"url": "ws://[2001:4860:4860::8888]/ws"},
        }

        # Should not raise an exception (public IPv6)
        module = WebSocketModule(config)
        assert (
            "2001:4860:4860::8888" in module._validated_url
            or "[2001:4860:4860::8888]" in module._validated_url
        )

    def test_ipv6_private_blocked(self):
        """Test that private IPv6 addresses are blocked."""
        config = {"module": "websocket", "module-config": {"url": "ws://[fc00::1]/ws"}}

        with pytest.raises(ValueError, match="private IP address|Invalid hostname"):
            WebSocketModule(config)
