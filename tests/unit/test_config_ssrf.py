"""
Security tests for SSRF prevention in connection configuration.
Tests that connection host/port validation prevents SSRF attacks.
"""
import pytest
import os
from unittest.mock import Mock, patch, AsyncMock
from src.config import _validate_connection_host, _validate_connection_port, inject_connection_details


class TestConfigSSRFPrevention:
    """Test suite for SSRF prevention in connection configuration."""
    
    def test_private_ip_allowed(self):
        """Test that private IPs are allowed (internal network support)."""
        private_ips = [
            '10.0.0.1',
            '172.16.0.1',
            '192.168.1.1',
            '10.255.255.255',
            '172.31.255.255',
            '192.168.255.255',
        ]
        for ip in private_ips:
            # Private IPs are now allowed to support internal networks.
            # Validation should return the host unchanged.
            result = _validate_connection_host(ip, "Test")
            assert result == ip
    
    def test_localhost_blocked(self):
        """Test that localhost is blocked."""
        # Save original value and ensure localhost is blocked for this test
        # (integration tests may set ALLOW_LOCALHOST_FOR_TESTS=true)
        original_value = os.environ.get("ALLOW_LOCALHOST_FOR_TESTS")
        try:
            # Explicitly set to false to ensure localhost is blocked
            os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = "false"
            
            localhost_variants = [
                'localhost',
                '127.0.0.1',
                '0.0.0.0',
                '::1',
                '[::1]',
            ]
            
            for host in localhost_variants:
                with pytest.raises(ValueError, match=r'localhost|not allowed'):
                    _validate_connection_host(host, "Test")
        finally:
            # Restore original value
            if original_value is None:
                os.environ.pop("ALLOW_LOCALHOST_FOR_TESTS", None)
            else:
                os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = original_value
    
    def test_link_local_blocked(self):
        """Test that link-local addresses are blocked."""
        link_local = '169.254.1.1'
        
        with pytest.raises(ValueError, match=r'link-local|not allowed'):
            _validate_connection_host(link_local, "Test")
    
    def test_metadata_endpoints_blocked(self):
        """Test that metadata endpoints are blocked."""
        metadata_hosts = [
            'metadata.google.internal',
            '169.254.169.254',
            'metadata.azure.com',
            'metadata.cloud.ibm.com',
        ]
        
        for host in metadata_hosts:
            with pytest.raises(ValueError, match=r'metadata endpoint|not allowed'):
                _validate_connection_host(host, "Test")
    
    def test_public_ip_allowed(self):
        """Test that public IPs are allowed."""
        public_ips = [
            '8.8.8.8',
            '1.1.1.1',
            '208.67.222.222',
        ]
        
        for ip in public_ips:
            result = _validate_connection_host(ip, "Test")
            assert result == ip
    
    def test_valid_hostname_allowed(self):
        """Test that valid hostnames are allowed."""
        valid_hostnames = [
            'example.com',
            'api.example.com',
            'redis.example.com',
            'sub-domain.example.com',
        ]
        
        for hostname in valid_hostnames:
            result = _validate_connection_host(hostname, "Test")
            assert result == hostname
    
    def test_dangerous_characters_blocked(self):
        """Test that dangerous characters are blocked."""
        # Note: brackets are allowed for IPv6 addresses, so exclude them
        dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '?', '*', '!', '\\']
        
        for char in dangerous_chars:
            host = f'example{char}com'
            with pytest.raises(ValueError, match=r'dangerous character'):
                _validate_connection_host(host, "Test")
    
    def test_ipv6_brackets_allowed(self):
        """Test that brackets are allowed for IPv6 addresses."""
        # IPv6 addresses in brackets should be allowed (but still blocked if localhost)
        # Test with a public IPv6 (Google's public DNS)
        public_ipv6 = '[2001:4860:4860::8888]'
        # This should be allowed (public IP, not private/localhost)
        result = _validate_connection_host(public_ipv6, "Test")
        assert result == public_ipv6
    
    def test_ipv6_localhost_blocked(self):
        """Test that IPv6 localhost in brackets is blocked."""
        # Save original value and ensure localhost is blocked for this test
        original_value = os.environ.get("ALLOW_LOCALHOST_FOR_TESTS")
        try:
            # Explicitly set to false to ensure localhost is blocked
            os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = "false"
            
            # IPv6 localhost should be blocked even in brackets
            ipv6_localhost = '[::1]'
            with pytest.raises(ValueError, match=r'localhost|not allowed'):
                _validate_connection_host(ipv6_localhost, "Test")
        finally:
            # Restore original value
            if original_value is None:
                os.environ.pop("ALLOW_LOCALHOST_FOR_TESTS", None)
            else:
                os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = original_value
    
    def test_null_byte_blocked(self):
        """Test that null bytes are blocked."""
        host = 'example.com\x00evil'
        
        with pytest.raises(ValueError, match=r'null bytes'):
            _validate_connection_host(host, "Test")
    
    def test_empty_host_rejected(self):
        """Test that empty host is rejected."""
        with pytest.raises(ValueError, match=r'cannot be empty|must be a non-empty string'):
            _validate_connection_host('', "Test")
        
        with pytest.raises(ValueError, match=r'cannot be empty|must be a non-empty string'):
            _validate_connection_host('   ', "Test")
    
    def test_too_long_host_rejected(self):
        """Test that overly long hostnames are rejected."""
        long_host = 'a' * 300
        
        with pytest.raises(ValueError, match=r'too long'):
            _validate_connection_host(long_host, "Test")
    
    def test_valid_port_allowed(self):
        """Test that valid ports are allowed."""
        valid_ports = [1, 80, 443, 6379, 5672, 9000, 65535]
        
        for port in valid_ports:
            result = _validate_connection_port(port, "Test")
            assert result == port
    
    def test_invalid_port_rejected(self):
        """Test that invalid ports are rejected."""
        invalid_ports = [0, -1, 65536, 70000, 'invalid', None]
        
        for port in invalid_ports:
            with pytest.raises(ValueError):
                _validate_connection_port(port, "Test")
    
    def test_port_string_converted(self):
        """Test that port strings are converted to integers."""
        result = _validate_connection_port('6379', "Test")
        assert result == 6379
        assert isinstance(result, int)
    
    @pytest.mark.asyncio
    async def test_redis_rq_connection_validation(self):
        """Test that Redis RQ connections are validated (including private IPs)."""
        webhook_config = {
            "test_webhook": {
                "module": "redis_rq",
                "connection": "redis_test"
            }
        }
        
        connection_config = {
            "redis_test": {
                "type": "redis-rq",
                "host": "10.0.0.1",  # Private IP - now allowed for internal networks
                "port": 6379,
                "db": 0
            }
        }
        # Mock Redis to avoid actual connection
        with patch('src.config.Redis') as mock_redis:
            mock_redis.return_value = Mock()

            result = await inject_connection_details(webhook_config, connection_config)

            # Should succeed and create connection_details even with private IP
            assert "connection_details" in result["test_webhook"]
            mock_redis.assert_called_once_with(
                host="10.0.0.1",
                port=6379,
                db=0
            )
    
    @pytest.mark.asyncio
    async def test_redis_rq_public_ip_allowed(self):
        """Test that Redis RQ connections with public IPs are allowed."""
        webhook_config = {
            "test_webhook": {
                "module": "redis_rq",
                "connection": "redis_test"
            }
        }
        
        connection_config = {
            "redis_test": {
                "type": "redis-rq",
                "host": "8.8.8.8",  # Public IP - should be allowed
                "port": 6379,
                "db": 0
            }
        }
        
        # Mock Redis to avoid actual connection
        with patch('src.config.Redis') as mock_redis:
            mock_redis.return_value = Mock()
            
            result = await inject_connection_details(webhook_config, connection_config)
            
            # Should succeed and create connection
            assert "connection_details" in result["test_webhook"]
            mock_redis.assert_called_once_with(host="8.8.8.8", port=6379, db=0)
    
    @pytest.mark.asyncio
    async def test_rabbitmq_connection_validation(self):
        """Test that RabbitMQ connections are validated."""
        # Save original value and ensure localhost is blocked for this test
        original_value = os.environ.get("ALLOW_LOCALHOST_FOR_TESTS")
        try:
            # Explicitly set to false to ensure localhost is blocked
            os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = "false"
            
            webhook_config = {
                "test_webhook": {
                    "module": "rabbitmq",
                    "connection": "rabbitmq_test"
                }
            }
            
            connection_config = {
                "rabbitmq_test": {
                    "type": "rabbitmq",
                    "host": "127.0.0.1",  # Localhost - should be blocked
                    "port": 5672,
                    "user": "guest",
                    "pass": "guest"
                }
            }
            
            # Should raise ValueError due to localhost
            with pytest.raises(ValueError, match=r'localhost|not allowed'):
                await inject_connection_details(webhook_config, connection_config)
        finally:
            # Restore original value
            if original_value is None:
                os.environ.pop("ALLOW_LOCALHOST_FOR_TESTS", None)
            else:
                os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = original_value
    
    @pytest.mark.asyncio
    async def test_rabbitmq_public_host_allowed(self):
        """Test that RabbitMQ connections with public hosts are allowed."""
        webhook_config = {
            "test_webhook": {
                "module": "rabbitmq",
                "connection": "rabbitmq_test"
            }
        }
        
        connection_config = {
            "rabbitmq_test": {
                "type": "rabbitmq",
                "host": "rabbitmq.example.com",  # Public hostname - should be allowed
                "port": 5672,
                "user": "guest",
                "pass": "guest"
            }
        }
        
        # Mock RabbitMQConnectionPool to avoid actual connection
        with patch('src.config.RabbitMQConnectionPool') as mock_pool_class:
            mock_pool = AsyncMock()
            mock_pool.create_pool = AsyncMock()
            mock_pool_class.return_value = mock_pool
            
            result = await inject_connection_details(webhook_config, connection_config)
            
            # Should succeed and create connection pool
            assert "connection_details" in result["test_webhook"]
            mock_pool.create_pool.assert_called_once_with(
                host="rabbitmq.example.com",
                port=5672,
                login="guest",
                password="guest"
            )
    
    def test_multicast_ip_blocked(self):
        """Test that multicast IPs are blocked."""
        multicast_ip = '224.0.0.1'
        
        with pytest.raises(ValueError, match=r'multicast|not allowed'):
            _validate_connection_host(multicast_ip, "Test")
    
    def test_reserved_ip_blocked(self):
        """Test that reserved IPs are blocked."""
        # Reserved IP range (e.g., 240.0.0.0/4)
        reserved_ip = '240.0.0.1'
        
        with pytest.raises(ValueError, match=r'reserved|not allowed'):
            _validate_connection_host(reserved_ip, "Test")
    
    def test_loopback_ip_blocked(self):
        """Test that loopback IPs are blocked."""
        # Save original value and ensure localhost is blocked for this test
        original_value = os.environ.get("ALLOW_LOCALHOST_FOR_TESTS")
        try:
            # Explicitly set to false to ensure localhost is blocked
            os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = "false"
            
            loopback_ips = ['127.0.0.1', '127.1.1.1', '::1']
            
            for ip in loopback_ips:
                with pytest.raises(ValueError, match=r'loopback|localhost|not allowed'):
                    _validate_connection_host(ip, "Test")
        finally:
            # Restore original value
            if original_value is None:
                os.environ.pop("ALLOW_LOCALHOST_FOR_TESTS", None)
            else:
                os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = original_value

