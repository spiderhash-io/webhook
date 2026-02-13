"""
Coverage tests for src/config.py.

Targets the ~20 missed lines covering:
- _validate_connection_host: SSRF prevention, localhost variants, dangerous chars,
  IP parsing (link-local, loopback, multicast, reserved, private), metadata endpoints,
  IPv6 bracketed, hostname format validation
- _validate_connection_port: None, non-integer, out of range
- inject_connection_details: missing type, redis-rq creation, rabbitmq creation,
  unknown type passthrough
"""

import pytest
import os
from unittest.mock import patch, MagicMock, AsyncMock

from src.config import (
    _validate_connection_host,
    _validate_connection_port,
    inject_connection_details,
)


class TestValidateConnectionHost:
    """Test _validate_connection_host function."""

    def test_valid_hostname(self):
        """Test valid hostname passes."""
        result = _validate_connection_host("rabbitmq.example.com", "RabbitMQ")
        assert result == "rabbitmq.example.com"

    def test_empty_host(self):
        """Test empty host is rejected."""
        with pytest.raises(ValueError, match="non-empty string"):
            _validate_connection_host("", "Redis")

    def test_none_host(self):
        """Test None host is rejected."""
        with pytest.raises(ValueError, match="non-empty string"):
            _validate_connection_host(None, "Redis")

    def test_non_string_host(self):
        """Test non-string host is rejected."""
        with pytest.raises(ValueError, match="non-empty string"):
            _validate_connection_host(123, "Redis")

    def test_whitespace_only_host(self):
        """Test whitespace-only host is rejected."""
        with pytest.raises(ValueError, match="cannot be empty"):
            _validate_connection_host("   ", "Redis")

    def test_too_long_host(self):
        """Test host exceeding max length is rejected."""
        with pytest.raises(ValueError, match="too long"):
            _validate_connection_host("a" * 254, "Redis")

    def test_null_byte_host(self):
        """Test host with null bytes is rejected."""
        with pytest.raises(ValueError, match="null bytes"):
            _validate_connection_host("test\x00.com", "Redis")

    def test_localhost_blocked(self):
        """Test localhost is blocked by default."""
        with pytest.raises(ValueError, match="not allowed"):
            _validate_connection_host("localhost", "Redis")

    def test_127_0_0_1_blocked(self):
        """Test 127.0.0.1 is blocked by default."""
        with pytest.raises(ValueError, match="not allowed"):
            _validate_connection_host("127.0.0.1", "Redis")

    def test_0_0_0_0_blocked(self):
        """Test 0.0.0.0 is blocked by default."""
        with pytest.raises(ValueError, match="not allowed"):
            _validate_connection_host("0.0.0.0", "Redis")

    def test_ipv6_localhost_blocked(self):
        """Test ::1 is blocked by default."""
        with pytest.raises(ValueError, match="not allowed"):
            _validate_connection_host("::1", "Redis")

    def test_bracketed_ipv6_localhost_blocked(self):
        """Test [::1] is blocked by default."""
        with pytest.raises(ValueError, match="not allowed"):
            _validate_connection_host("[::1]", "Redis")

    @patch.dict(os.environ, {"ALLOW_LOCALHOST_FOR_TESTS": "true"})
    def test_localhost_allowed_for_tests(self):
        """Test localhost allowed when ALLOW_LOCALHOST_FOR_TESTS=true."""
        # localhost will still fail on loopback IP check since it's treated as hostname
        result = _validate_connection_host("localhost", "Redis")
        assert result == "localhost"

    def test_dangerous_chars_blocked(self):
        """Test dangerous characters in hostname are blocked."""
        dangerous = [";", "|", "&", "$", "`", "(", ")", "{", "}", "<", ">", "?", "*", "!", "\\"]
        for char in dangerous:
            with pytest.raises(ValueError, match="dangerous character"):
                _validate_connection_host(f"test{char}host", "Redis")

    def test_link_local_ip_blocked(self):
        """Test link-local IP addresses are blocked."""
        with pytest.raises(ValueError, match="link-local"):
            _validate_connection_host("169.254.1.1", "Redis")

    def test_loopback_ip_blocked(self):
        """Test loopback IP addresses are blocked."""
        with pytest.raises(ValueError, match="localhost IP"):
            _validate_connection_host("127.0.0.2", "Redis")

    def test_multicast_ip_blocked(self):
        """Test multicast IP addresses are blocked."""
        with pytest.raises(ValueError, match="multicast"):
            _validate_connection_host("224.0.0.1", "Redis")

    def test_reserved_ip_blocked(self):
        """Test reserved IP addresses are blocked."""
        with pytest.raises(ValueError, match="reserved"):
            _validate_connection_host("240.0.0.1", "Redis")

    def test_private_ip_blocked_by_default(self):
        """Test private IP addresses are blocked by default."""
        with pytest.raises(ValueError, match="private IP"):
            _validate_connection_host("10.0.0.1", "Redis")

    @patch.dict(os.environ, {"ALLOW_PRIVATE_IP_CONNECTIONS": "true"})
    def test_private_ip_allowed_when_enabled(self):
        """Test private IP allowed when ALLOW_PRIVATE_IP_CONNECTIONS=true."""
        result = _validate_connection_host("10.0.0.1", "Redis")
        assert result == "10.0.0.1"

    def test_metadata_endpoint_blocked(self):
        """Test metadata.google.internal is blocked."""
        with pytest.raises(ValueError, match="metadata endpoint"):
            _validate_connection_host("metadata.google.internal", "Redis")

    def test_aws_metadata_blocked(self):
        """Test AWS metadata endpoint is blocked."""
        with pytest.raises(ValueError, match="not allowed"):
            _validate_connection_host("169.254.169.254", "Redis")

    def test_azure_metadata_blocked(self):
        """Test Azure metadata endpoint is blocked."""
        with pytest.raises(ValueError, match="metadata endpoint"):
            _validate_connection_host("metadata.azure.com", "Redis")

    def test_invalid_ipv6_bracketed(self):
        """Test invalid bracketed IPv6 address is rejected."""
        with pytest.raises(ValueError, match="IPv6 address format"):
            _validate_connection_host("[not-ipv6]", "Redis")

    def test_invalid_hostname_format(self):
        """Test invalid hostname characters are rejected."""
        with pytest.raises(ValueError, match="hostname format"):
            _validate_connection_host("host@name", "Redis")

    def test_valid_public_ip(self):
        """Test valid public IP address passes."""
        result = _validate_connection_host("8.8.8.8", "Redis")
        assert result == "8.8.8.8"

    def test_hostname_with_dots_and_hyphens(self):
        """Test hostname with dots and hyphens is valid."""
        result = _validate_connection_host("my-host.example.com", "Redis")
        assert result == "my-host.example.com"


class TestValidateConnectionPort:
    """Test _validate_connection_port function."""

    def test_valid_port(self):
        """Test valid port returns integer."""
        assert _validate_connection_port(5672, "RabbitMQ") == 5672

    def test_valid_port_as_string(self):
        """Test valid port as string is converted to int."""
        assert _validate_connection_port("6379", "Redis") == 6379

    def test_none_port(self):
        """Test None port is rejected."""
        with pytest.raises(ValueError, match="must be specified"):
            _validate_connection_port(None, "Redis")

    def test_non_integer_port(self):
        """Test non-integer port is rejected."""
        with pytest.raises(ValueError, match="valid integer"):
            _validate_connection_port("abc", "Redis")

    def test_port_too_low(self):
        """Test port below 1 is rejected."""
        with pytest.raises(ValueError, match="between 1 and 65535"):
            _validate_connection_port(0, "Redis")

    def test_port_too_high(self):
        """Test port above 65535 is rejected."""
        with pytest.raises(ValueError, match="between 1 and 65535"):
            _validate_connection_port(65536, "Redis")

    def test_negative_port(self):
        """Test negative port is rejected."""
        with pytest.raises(ValueError, match="between 1 and 65535"):
            _validate_connection_port(-1, "Redis")

    def test_min_port(self):
        """Test minimum valid port (1)."""
        assert _validate_connection_port(1, "Redis") == 1

    def test_max_port(self):
        """Test maximum valid port (65535)."""
        assert _validate_connection_port(65535, "Redis") == 65535


class TestInjectConnectionDetails:
    """Test inject_connection_details function."""

    @pytest.mark.asyncio
    async def test_no_connections(self):
        """Test with no connection references in webhooks."""
        webhooks = {"hook1": {"module": "log", "data_type": "json"}}
        connections = {}

        result = await inject_connection_details(webhooks, connections)
        assert "connection_details" not in result["hook1"]

    @pytest.mark.asyncio
    async def test_connection_not_found(self):
        """Test webhook references non-existent connection."""
        webhooks = {"hook1": {"module": "redis_rq", "connection": "nonexistent"}}
        connections = {}

        result = await inject_connection_details(webhooks, connections)
        assert "connection_details" not in result["hook1"]

    @pytest.mark.asyncio
    async def test_missing_connection_type(self):
        """Test connection with missing type field."""
        webhooks = {"hook1": {"module": "redis_rq", "connection": "my-redis"}}
        connections = {"my-redis": {"host": "redis.example.com", "port": 6379}}

        with pytest.raises(ValueError, match="missing required 'type' field"):
            await inject_connection_details(webhooks, connections)

    @pytest.mark.asyncio
    async def test_redis_rq_connection(self):
        """Test Redis RQ connection injection."""
        webhooks = {"hook1": {"module": "redis_rq", "connection": "my-redis"}}
        connections = {
            "my-redis": {"type": "redis-rq", "host": "10.0.0.1", "port": 6379, "db": 0}
        }

        with patch.dict(os.environ, {"ALLOW_LOCALHOST_FOR_TESTS": "true", "ALLOW_PRIVATE_IP_CONNECTIONS": "true"}):
            with patch("src.config.Redis") as mock_redis:
                mock_redis.return_value = MagicMock()
                result = await inject_connection_details(webhooks, connections)

        assert "connection_details" in result["hook1"]
        assert result["hook1"]["connection_details"]["type"] == "redis-rq"
        assert "conn" in result["hook1"]["connection_details"]

    @pytest.mark.asyncio
    async def test_rabbitmq_connection(self):
        """Test RabbitMQ connection injection."""
        webhooks = {"hook1": {"module": "rabbitmq", "connection": "my-rmq"}}
        connections = {
            "my-rmq": {
                "type": "rabbitmq",
                "host": "10.0.0.2",
                "port": 5672,
                "user": "guest",
                "pass": "guest",
            }
        }

        mock_pool = MagicMock()
        mock_pool.create_pool = AsyncMock()

        with patch.dict(os.environ, {"ALLOW_LOCALHOST_FOR_TESTS": "true", "ALLOW_PRIVATE_IP_CONNECTIONS": "true"}):
            with patch("src.config.RabbitMQConnectionPool", return_value=mock_pool):
                result = await inject_connection_details(webhooks, connections)

        assert "connection_details" in result["hook1"]
        assert result["hook1"]["connection_details"]["type"] == "rabbitmq"
        assert "connection_pool" in result["hook1"]["connection_details"]
        mock_pool.create_pool.assert_called_once()

    @pytest.mark.asyncio
    async def test_unknown_connection_type_passthrough(self):
        """Test unknown connection type just injects details without pool creation."""
        webhooks = {"hook1": {"module": "custom", "connection": "my-custom"}}
        connections = {
            "my-custom": {"type": "custom-type", "host": "custom.example.com", "port": 9999}
        }

        result = await inject_connection_details(webhooks, connections)
        assert "connection_details" in result["hook1"]
        assert result["hook1"]["connection_details"]["type"] == "custom-type"

    @pytest.mark.asyncio
    async def test_multiple_webhooks_same_connection(self):
        """Test multiple webhooks sharing same connection."""
        webhooks = {
            "hook1": {"module": "log", "connection": "shared"},
            "hook2": {"module": "log", "connection": "shared"},
        }
        connections = {"shared": {"type": "custom", "host": "shared.example.com"}}

        result = await inject_connection_details(webhooks, connections)
        assert "connection_details" in result["hook1"]
        assert "connection_details" in result["hook2"]

    @pytest.mark.asyncio
    async def test_webhook_without_connection_key(self):
        """Test webhook without connection key is left unchanged."""
        webhooks = {"hook1": {"module": "log", "data_type": "json"}}
        connections = {"my-redis": {"type": "redis-rq"}}

        result = await inject_connection_details(webhooks, connections)
        assert "connection_details" not in result["hook1"]
