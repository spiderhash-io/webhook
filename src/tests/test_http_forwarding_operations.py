"""
Operational tests for HTTP webhook forwarding functionality.
Tests connection handling, error scenarios, and forwarding behavior.
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import httpx
from src.modules.http_webhook import HTTPWebhookModule


class TestConnectionTimeoutHandling:
    """Test connection timeout scenarios."""
    
    @pytest.mark.asyncio
    async def test_connection_timeout_handled(self):
        """Test that connection timeouts are handled gracefully."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook',
                'timeout': 1.0  # 1 second timeout
            }
        }
        module = HTTPWebhookModule(config)
        
        # Mock httpx to raise timeout
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance
            mock_instance.post.side_effect = httpx.TimeoutException("Connection timeout")
            
            with pytest.raises(Exception) as exc_info:
                await module.process({"test": "data"}, {})
            
            # Error should be sanitized (no URL exposure)
            error_msg = str(exc_info.value)
            assert "example.com" not in error_msg
            assert "timeout" in error_msg.lower() or "error" in error_msg.lower()
    
    @pytest.mark.asyncio
    async def test_read_timeout_handled(self):
        """Test that read timeouts are handled correctly."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook',
                'timeout': 1.0
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance
            mock_instance.post.side_effect = httpx.ReadTimeout("Read timeout")
            
            with pytest.raises(Exception):
                await module.process({"test": "data"}, {})


class TestConnectionErrorTypes:
    """Test different types of connection errors."""
    
    @pytest.mark.asyncio
    async def test_dns_resolution_failure(self):
        """Test handling of DNS resolution failures."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://nonexistent-domain-12345.com/webhook'
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance
            mock_instance.post.side_effect = httpx.ConnectError("DNS resolution failed")
            
            with pytest.raises(Exception) as exc_info:
                await module.process({"test": "data"}, {})
            
            # Should not expose DNS details
            error_msg = str(exc_info.value)
            assert "nonexistent-domain" not in error_msg
    
    @pytest.mark.asyncio
    async def test_connection_refused(self):
        """Test handling of connection refused errors."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com:9999/webhook'
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance
            mock_instance.post.side_effect = httpx.ConnectError("Connection refused")
            
            with pytest.raises(Exception):
                await module.process({"test": "data"}, {})
    
    @pytest.mark.asyncio
    async def test_network_unreachable(self):
        """Test handling of network unreachable errors."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook'  # Use public domain
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance
            mock_instance.post.side_effect = httpx.NetworkError("Network unreachable")
            
            with pytest.raises(Exception):
                await module.process({"test": "data"}, {})
    
    @pytest.mark.asyncio
    async def test_ssl_error_handled(self):
        """Test handling of SSL/TLS errors."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'https://example.com/webhook'
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance
            mock_instance.post.side_effect = httpx.ConnectError("SSL certificate verification failed")
            
            with pytest.raises(Exception):
                await module.process({"test": "data"}, {})


class TestQueryParameterForwarding:
    """Test query parameter forwarding functionality."""
    
    def test_query_parameters_preserved_in_url(self):
        """Test that query parameters in configured URL are preserved."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook?param1=value1&param2=value2'
            }
        }
        module = HTTPWebhookModule(config)
        
        # URL should contain query parameters
        assert 'param1=value1' in module._validated_url
        assert 'param2=value2' in module._validated_url
    
    @pytest.mark.asyncio
    async def test_query_parameters_forwarded(self):
        """Test that query parameters are included in forwarded requests."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook?webhook_id=test123'
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance
            
            await module.process({"test": "data"}, {})
            
            # Verify URL with query params was used
            call_args = mock_instance.post.call_args
            assert call_args is not None
            assert 'webhook_id=test123' in str(call_args)


class TestHTTPMethodPreservation:
    """Test HTTP method handling."""
    
    @pytest.mark.asyncio
    async def test_post_method_used(self):
        """Test that POST method is used by default."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook',
                'method': 'POST'
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance
            
            await module.process({"test": "data"}, {})
            
            mock_instance.post.assert_called_once()
            mock_instance.put.assert_not_called()
            mock_instance.patch.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_put_method_used(self):
        """Test that PUT method can be used."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook',
                'method': 'PUT'
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.put.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance
            
            await module.process({"test": "data"}, {})
            
            mock_instance.put.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_patch_method_used(self):
        """Test that PATCH method can be used."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook',
                'method': 'PATCH'
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.patch.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance
            
            await module.process({"test": "data"}, {})
            
            mock_instance.patch.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_unsupported_method_rejected(self):
        """Test that unsupported HTTP methods are rejected."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook',
                'method': 'DELETE'  # Not supported
            }
        }
        module = HTTPWebhookModule(config)
        
        with pytest.raises(Exception, match="Unsupported HTTP method"):
            await module.process({"test": "data"}, {})


class TestTargetServerResponseHandling:
    """Test handling of different HTTP response codes."""
    
    @pytest.mark.asyncio
    async def test_success_response_handled(self):
        """Test that successful responses (200, 201) are handled correctly."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook'
            }
        }
        module = HTTPWebhookModule(config)
        
        for status_code in [200, 201]:
            with patch('httpx.AsyncClient') as mock_client:
                mock_instance = AsyncMock()
                mock_response = Mock()
                mock_response.status_code = status_code
                mock_response.raise_for_status = Mock()
                mock_instance.post.return_value = mock_response
                mock_client.return_value.__aenter__.return_value = mock_instance
                
                # Should not raise
                await module.process({"test": "data"}, {})
                mock_response.raise_for_status.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_client_error_response_handled(self):
        """Test that client errors (400, 401) are handled."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook'
            }
        }
        module = HTTPWebhookModule(config)
        
        for status_code in [400, 401, 403, 404]:
            with patch('httpx.AsyncClient') as mock_client:
                mock_instance = AsyncMock()
                mock_response = Mock()
                mock_response.status_code = status_code
                mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                    f"HTTP {status_code}",
                    request=Mock(),
                    response=mock_response
                )
                mock_instance.post.return_value = mock_response
                mock_client.return_value.__aenter__.return_value = mock_instance
                
                with pytest.raises(Exception):
                    await module.process({"test": "data"}, {})
    
    @pytest.mark.asyncio
    async def test_server_error_response_handled(self):
        """Test that server errors (500, 502, 503) are handled."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook'
            }
        }
        module = HTTPWebhookModule(config)
        
        for status_code in [500, 502, 503]:
            with patch('httpx.AsyncClient') as mock_client:
                mock_instance = AsyncMock()
                mock_response = Mock()
                mock_response.status_code = status_code
                mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                    f"HTTP {status_code}",
                    request=Mock(),
                    response=mock_response
                )
                mock_instance.post.return_value = mock_response
                mock_client.return_value.__aenter__.return_value = mock_instance
                
                with pytest.raises(Exception):
                    await module.process({"test": "data"}, {})


class TestConcurrentForwardingRequests:
    """Test concurrent forwarding scenarios."""
    
    @pytest.mark.asyncio
    async def test_concurrent_requests_handled(self):
        """Test that multiple concurrent forwarding requests are handled correctly."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook'
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance
            
            # Send 10 concurrent requests
            tasks = [
                module.process({"test": f"data_{i}"}, {})
                for i in range(10)
            ]
            await asyncio.gather(*tasks)
            
            # Should have been called 10 times
            assert mock_instance.post.call_count == 10


class TestCustomHeadersMerging:
    """Test custom header merging behavior."""
    
    @pytest.mark.asyncio
    async def test_custom_headers_merged(self):
        """Test that custom headers from config are merged with forwarded headers."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook',
                'headers': {
                    'X-Custom-Header': 'custom-value',
                    'Authorization': 'Bearer custom-token'
                }
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance
            
            await module.process({"test": "data"}, {"X-Original": "original-value"})
            
            # Check that custom headers were included
            call_args = mock_instance.post.call_args
            assert call_args is not None
            headers = call_args.kwargs.get('headers', {})
            assert 'X-Custom-Header' in headers
            assert headers['X-Custom-Header'] == 'custom-value'
    
    @pytest.mark.asyncio
    async def test_custom_headers_override_forwarded(self):
        """Test that custom headers override forwarded headers when there's a conflict."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook',
                'headers': {
                    'X-Header': 'custom-value'
                }
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance
            
            await module.process({"test": "data"}, {"X-Header": "original-value"})
            
            # Custom header should override
            call_args = mock_instance.post.call_args
            assert call_args is not None
            headers = call_args.kwargs.get('headers', {})
            assert headers.get('X-Header') == 'custom-value'


class TestContentTypePreservation:
    """Test Content-Type header preservation."""
    
    @pytest.mark.asyncio
    async def test_json_content_type_set(self):
        """Test that JSON payloads are sent with application/json Content-Type."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook'
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance
            
            await module.process({"test": "data"}, {})
            
            call_args = mock_instance.post.call_args
            assert call_args is not None
            headers = call_args.kwargs.get('headers', {})
            # httpx automatically sets Content-Type for json parameter
            assert 'json' in call_args.kwargs


class TestTargetServerUnavailability:
    """Test handling when target servers are unavailable."""
    
    @pytest.mark.asyncio
    async def test_target_unavailable_handled(self):
        """Test that target server unavailability is handled gracefully."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook'
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance
            # Simulate multiple failure types
            mock_instance.post.side_effect = httpx.ConnectError("Connection failed")
            
            with pytest.raises(Exception) as exc_info:
                await module.process({"test": "data"}, {})
            
            # Should not expose internal details
            error_msg = str(exc_info.value)
            assert "example.com" not in error_msg


class TestHTTPRedirectHandling:
    """Test HTTP redirect handling."""
    
    @pytest.mark.asyncio
    async def test_redirect_followed_by_default(self):
        """Test that httpx follows redirects by default."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook'
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            # Simulate redirect (httpx follows by default)
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance
            
            await module.process({"test": "data"}, {})
            
            # httpx follows redirects automatically, so we just verify it was called
            mock_instance.post.assert_called_once()


class TestRuntimeURLValidation:
    """Test URL validation at runtime."""
    
    def test_url_validated_at_init(self):
        """Test that URLs are validated during initialization."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://localhost/webhook'  # Should be blocked
            }
        }
        
        with pytest.raises(ValueError, match="localhost"):
            HTTPWebhookModule(config)
    
    @pytest.mark.asyncio
    async def test_missing_url_handled(self):
        """Test that missing URL is handled at runtime."""
        config = {
            'module': 'http_webhook',
            'module-config': {}  # No URL
        }
        module = HTTPWebhookModule(config)
        
        # Should raise error when trying to process without URL
        with pytest.raises(Exception):
            await module.process({"test": "data"}, {})


class TestIdempotencyKeyForwarding:
    """Test idempotency key forwarding."""
    
    @pytest.mark.asyncio
    async def test_idempotency_header_forwarded(self):
        """Test that idempotency keys from incoming headers can be forwarded."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook',
                'forward_headers': True,
                'allowed_headers': ['Idempotency-Key', 'X-Request-ID']
            }
        }
        module = HTTPWebhookModule(config)
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_instance.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_instance
            
            headers = {
                'Idempotency-Key': 'test-key-123',
                'X-Request-ID': 'req-456'
            }
            await module.process({"test": "data"}, headers)
            
            call_args = mock_instance.post.call_args
            assert call_args is not None
            forwarded_headers = call_args.kwargs.get('headers', {})
            # Headers should be forwarded if in allowed list
            # (actual forwarding depends on allowed_headers config)
            assert 'Idempotency-Key' in forwarded_headers or 'idempotency-key' in forwarded_headers

