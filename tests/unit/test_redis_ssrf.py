"""
Security tests for SSRF prevention in Redis connection configuration.
Tests that Redis host and port are properly validated to prevent Server-Side Request Forgery attacks.
"""

import pytest
from src.modules.redis_publish import RedisPublishModule


class TestRedisSSRFPrevention:
    """Test suite for SSRF prevention in Redis connection configuration."""

    def test_localhost_blocked(self):
        """Test that localhost is blocked."""
        config = {
            "module": "redis_publish",
            "redis": {"host": "localhost", "port": 6379, "channel": "test_channel"},
        }

        with pytest.raises(ValueError, match="localhost is not allowed"):
            RedisPublishModule(config)

    def test_127_0_0_1_blocked(self):
        """Test that 127.0.0.1 is blocked."""
        config = {
            "module": "redis_publish",
            "redis": {"host": "127.0.0.1", "port": 6379, "channel": "test_channel"},
        }

        with pytest.raises(ValueError, match="localhost is not allowed|loopback"):
            RedisPublishModule(config)

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
                "module": "redis_publish",
                "redis": {"host": ip, "port": 6379, "channel": "test_channel"},
            }

            with pytest.raises(ValueError, match="private IP address"):
                RedisPublishModule(config)

    def test_link_local_blocked(self):
        """Test that link-local addresses (169.254.0.0/16) are blocked."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "169.254.169.254",
                "port": 6379,
                "channel": "test_channel",
            },
        }

        with pytest.raises(ValueError, match="link-local|private IP address"):
            RedisPublishModule(config)

    def test_cloud_metadata_endpoint_blocked(self):
        """Test that cloud metadata endpoints are blocked."""
        metadata_hosts = [
            ("169.254.169.254", "link-local|private IP address"),
            ("metadata.google.internal", "metadata service"),
            ("metadata", "metadata service"),
        ]

        for host, pattern in metadata_hosts:
            config = {
                "module": "redis_publish",
                "redis": {"host": host, "port": 6379, "channel": "test_channel"},
            }

            with pytest.raises(ValueError, match=pattern):
                RedisPublishModule(config)

    def test_public_ip_allowed(self):
        """Test that public IP addresses are allowed."""
        config = {
            "module": "redis_publish",
            "redis": {"host": "8.8.8.8", "port": 6379, "channel": "test_channel"},
        }

        # Should not raise an exception
        module = RedisPublishModule(config)
        assert module._validated_host == "8.8.8.8"
        assert module._validated_port == 6379

    def test_public_hostname_allowed(self):
        """Test that public hostnames are allowed."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "redis.example.com",
                "port": 6379,
                "channel": "test_channel",
            },
        }

        # Should not raise an exception
        module = RedisPublishModule(config)
        assert module._validated_host == "redis.example.com"

    def test_whitelist_allows_private_ip(self):
        """Test that whitelist allows private IPs if configured."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "192.168.1.1",
                "port": 6379,
                "channel": "test_channel",
                "allowed_hosts": ["192.168.1.1", "redis.internal"],
            },
        }

        # Should not raise an exception if whitelisted
        module = RedisPublishModule(config)
        assert module._validated_host == "192.168.1.1"

    def test_whitelist_allows_localhost(self):
        """Test that whitelist allows localhost if configured."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "localhost",
                "port": 6379,
                "channel": "test_channel",
                "allowed_hosts": ["localhost"],
            },
        }

        # Should not raise an exception if whitelisted
        module = RedisPublishModule(config)
        assert module._validated_host == "localhost"

    def test_whitelist_blocks_non_whitelisted(self):
        """Test that non-whitelisted hosts are blocked even if public."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "redis.example.com",
                "port": 6379,
                "channel": "test_channel",
                "allowed_hosts": ["allowed.redis.com"],
            },
        }

        with pytest.raises(ValueError, match="not in the allowed hosts whitelist"):
            RedisPublishModule(config)

    def test_whitelist_case_insensitive(self):
        """Test that whitelist is case-insensitive."""
        config = {
            "module": "redis_publish",
            "redis": {
                "host": "REDIS.EXAMPLE.COM",
                "port": 6379,
                "channel": "test_channel",
                "allowed_hosts": ["redis.example.com"],
            },
        }

        # Should not raise an exception (case-insensitive match)
        module = RedisPublishModule(config)
        assert module._validated_host == "REDIS.EXAMPLE.COM"

    def test_invalid_port_rejected(self):
        """Test that invalid ports are rejected."""
        invalid_ports = [
            -1,
            0,
            65536,
            70000,
            "invalid",
            "",
        ]

        for port in invalid_ports:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": "redis.example.com",
                    "port": port,
                    "channel": "test_channel",
                },
            }

            with pytest.raises(ValueError, match="port"):
                RedisPublishModule(config)

    def test_valid_port_accepted(self):
        """Test that valid ports are accepted."""
        valid_ports = [
            6379,
            6380,
            1,
            65535,
            "6379",  # String port
            "6380",  # String port
        ]

        for port in valid_ports:
            config = {
                "module": "redis_publish",
                "redis": {
                    "host": "redis.example.com",
                    "port": port,
                    "channel": "test_channel",
                },
            }

            # Should not raise an exception
            module = RedisPublishModule(config)
            assert isinstance(module._validated_port, int)
            assert 1 <= module._validated_port <= 65535

    def test_empty_host_rejected(self):
        """Test that empty host is rejected."""
        config = {
            "module": "redis_publish",
            "redis": {"host": "", "port": 6379, "channel": "test_channel"},
        }

        with pytest.raises(ValueError, match="cannot be empty|non-empty string"):
            RedisPublishModule(config)

    def test_multicast_blocked(self):
        """Test that multicast addresses are blocked."""
        config = {
            "module": "redis_publish",
            "redis": {"host": "224.0.0.1", "port": 6379, "channel": "test_channel"},
        }

        with pytest.raises(ValueError, match="multicast"):
            RedisPublishModule(config)

    def test_reserved_ip_blocked(self):
        """Test that reserved IP addresses are blocked."""
        config = {
            "module": "redis_publish",
            "redis": {"host": "0.0.0.0", "port": 6379, "channel": "test_channel"},
        }

        with pytest.raises(ValueError, match="localhost|reserved|loopback"):
            RedisPublishModule(config)

    def test_invalid_hostname_format_rejected(self):
        """Test that invalid hostname formats are rejected."""
        invalid_hostnames = [
            "redis..example.com",  # Double dots
            "-redis.example.com",  # Starts with hyphen
            "redis.example.com-",  # Ends with hyphen
        ]

        for hostname in invalid_hostnames:
            config = {
                "module": "redis_publish",
                "redis": {"host": hostname, "port": 6379, "channel": "test_channel"},
            }

            with pytest.raises(ValueError, match="Invalid hostname"):
                RedisPublishModule(config)

    def test_default_host_and_port(self):
        """Test that default host and port are validated."""
        # Default host is "localhost" which should be blocked
        config = {
            "module": "redis_publish",
            "redis": {
                "channel": "test_channel"
                # host defaults to "localhost", port defaults to 6379
            },
        }

        with pytest.raises(ValueError, match="localhost is not allowed"):
            RedisPublishModule(config)
