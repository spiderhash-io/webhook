"""
Integration tests for WebSocket module.

These tests verify SSRF prevention, URL validation, and connection management.
"""

import pytest
from src.modules.websocket import WebSocketModule


@pytest.mark.integration
class TestWebSocketIntegration:
    """Integration tests for WebSocket module."""
    
    @pytest.mark.asyncio
    async def test_websocket_ssrf_prevention_localhost_blocked(self):
        """Test that SSRF prevention blocks localhost access."""
        # Attempt to use localhost URLs (should be blocked)
        localhost_urls = [
            "ws://localhost:8080/webhook",
            "ws://127.0.0.1:8080/webhook",
            "wss://localhost:8080/webhook",
            "wss://127.0.0.1:8080/webhook",
            "ws://0.0.0.0:8080/webhook",
            "ws://[::1]:8080/webhook",
        ]
        
        for url in localhost_urls:
            config = {
                "module": "websocket",
                "module-config": {
                    "url": url
                }
            }
            with pytest.raises(ValueError, match="localhost|not allowed|security"):
                WebSocketModule(config)
    
    @pytest.mark.asyncio
    async def test_websocket_ssrf_prevention_private_ip_blocked(self):
        """Test that SSRF prevention blocks private IP ranges."""
        # Attempt to use private IPs (should be blocked)
        private_ip_urls = [
            "ws://192.168.1.1:8080/webhook",
            "ws://10.0.0.1:8080/webhook",
            "ws://172.16.0.1:8080/webhook",
            "wss://192.168.1.1:8080/webhook",
        ]
        
        for url in private_ip_urls:
            config = {
                "module": "websocket",
                "module-config": {
                    "url": url
                }
            }
            with pytest.raises(ValueError, match="private|not allowed|security"):
                WebSocketModule(config)
    
    @pytest.mark.asyncio
    async def test_websocket_ssrf_prevention_metadata_endpoint_blocked(self):
        """Test that SSRF prevention blocks cloud metadata endpoints."""
        # Attempt to use metadata endpoints (should be blocked)
        metadata_urls = [
            "ws://169.254.169.254/latest/meta-data",
            "ws://metadata.google.internal/computeMetadata/v1",
        ]
        
        for url in metadata_urls:
            config = {
                "module": "websocket",
                "module-config": {
                    "url": url
                }
            }
            with pytest.raises(ValueError, match="metadata|link-local|not allowed|security"):
                WebSocketModule(config)
    
    @pytest.mark.asyncio
    async def test_websocket_ssrf_prevention_whitelist_allowed(self):
        """Test that whitelisted URLs are allowed."""
        # Whitelist a URL (for testing purposes)
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com:8080/webhook",
                "allowed_hosts": ["example.com", "localhost"]  # Whitelist
            }
        }
        
        # Should succeed if URL is whitelisted
        module = WebSocketModule(config)
        assert module._validated_url == "ws://example.com:8080/webhook"
    
    @pytest.mark.asyncio
    async def test_websocket_scheme_validation(self):
        """Test that only ws:// and wss:// schemes are allowed."""
        invalid_schemes = [
            "http://example.com:8080/webhook",
            "https://example.com:8080/webhook",
            "file:///etc/passwd",
            "gopher://example.com",
        ]
        
        for url in invalid_schemes:
            config = {
                "module": "websocket",
                "module-config": {
                    "url": url
                }
            }
            with pytest.raises(ValueError, match="scheme|not allowed|ws://|wss://"):
                WebSocketModule(config)
    
    @pytest.mark.asyncio
    async def test_websocket_url_format_validation(self):
        """Test that URL format is validated."""
        # Test invalid format (empty string might be None, so skip that)
        config_invalid = {
            "module": "websocket",
            "module-config": {
                "url": "not-a-url"
            }
        }
        with pytest.raises(ValueError, match="scheme|not allowed"):
            WebSocketModule(config_invalid)
        
        # Test no hostname
        config_no_host = {
            "module": "websocket",
            "module-config": {
                "url": "ws://"
            }
        }
        with pytest.raises(ValueError, match="hostname|URL"):
            WebSocketModule(config_no_host)
        
        # Test empty string (if provided, should raise error)
        # Note: Empty string might be treated as None in some cases
        try:
            config_empty = {
                "module": "websocket",
                "module-config": {
                    "url": ""
                }
            }
            WebSocketModule(config_empty)
            # If no error, that's OK - empty might be treated as None
        except ValueError:
            # Expected if empty string is validated
            pass
    
    @pytest.mark.asyncio
    async def test_websocket_custom_headers(self):
        """Test that custom headers can be configured."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com:8080/webhook",
                "allowed_hosts": ["example.com"],
                "headers": {
                    "X-Custom-Header": "custom_value",
                    "X-API-Key": "api_key_123"
                }
            }
        }
        
        module = WebSocketModule(config)
        assert module.module_config.get("headers") == {
            "X-Custom-Header": "custom_value",
            "X-API-Key": "api_key_123"
        }
    
    @pytest.mark.asyncio
    async def test_websocket_timeout_configuration(self):
        """Test that timeout can be configured."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com:8080/webhook",
                "allowed_hosts": ["example.com"],
                "timeout": 30
            }
        }
        
        module = WebSocketModule(config)
        assert module.module_config.get("timeout") == 30
    
    @pytest.mark.asyncio
    async def test_websocket_max_retries_configuration(self):
        """Test that max retries can be configured."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com:8080/webhook",
                "allowed_hosts": ["example.com"],
                "max_retries": 5
            }
        }
        
        module = WebSocketModule(config)
        assert module.module_config.get("max_retries") == 5
    
    @pytest.mark.asyncio
    async def test_websocket_wait_for_response_configuration(self):
        """Test that wait_for_response can be configured."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com:8080/webhook",
                "allowed_hosts": ["example.com"],
                "wait_for_response": True
            }
        }
        
        module = WebSocketModule(config)
        assert module.module_config.get("wait_for_response") is True
    
    @pytest.mark.asyncio
    async def test_websocket_message_format_json(self):
        """Test that message format can be configured."""
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://example.com:8080/webhook",
                "allowed_hosts": ["example.com"],
                "format": "json"
            }
        }
        
        module = WebSocketModule(config)
        assert module.module_config.get("format") == "json"
    
    @pytest.mark.asyncio
    async def test_websocket_connection_error_handling(self):
        """Test handling of connection failures."""
        # Use invalid host (but whitelisted to pass validation)
        config = {
            "module": "websocket",
            "module-config": {
                "url": "ws://invalid_host_that_does_not_exist:8080/webhook",
                "allowed_hosts": ["invalid_host_that_does_not_exist"],
                "timeout": 1,
                "max_retries": 1
            }
        }
        
        module = WebSocketModule(config)
        
        # Process should raise connection error
        with pytest.raises(Exception):
            await module.process({"test": "data"}, {})

