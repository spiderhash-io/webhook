"""
Security tests for SSRF prevention in HTTP webhook module.
Tests that URLs are properly validated to prevent Server-Side Request Forgery attacks.
"""
import pytest
from src.modules.http_webhook import HTTPWebhookModule


class TestHTTPSSRFPrevention:
    """Test suite for SSRF prevention in HTTP webhook module."""
    
    def test_localhost_blocked(self):
        """Test that localhost URLs are blocked."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://localhost:8080/webhook'
            }
        }
        
        with pytest.raises(ValueError, match="localhost is not allowed"):
            HTTPWebhookModule(config)
    
    def test_127_0_0_1_blocked(self):
        """Test that 127.0.0.1 is blocked."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://127.0.0.1:8080/webhook'
            }
        }
        
        with pytest.raises(ValueError, match="localhost is not allowed|loopback"):
            HTTPWebhookModule(config)
    
    def test_private_ip_ranges_blocked(self):
        """Test that private IP ranges (RFC 1918) are blocked."""
        private_ips = [
            '10.0.0.1',
            '172.16.0.1',
            '192.168.1.1',
            '10.10.10.10',
            '172.31.255.255',
            '192.168.255.255',
        ]
        
        for ip in private_ips:
            config = {
                'module': 'http_webhook',
                'module-config': {
                    'url': f'http://{ip}:8080/webhook'
                }
            }
            
            with pytest.raises(ValueError, match="private IP address"):
                HTTPWebhookModule(config)
    
    def test_link_local_blocked(self):
        """Test that link-local addresses (169.254.0.0/16) are blocked."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://169.254.169.254/latest/meta-data/'
            }
        }
        
        with pytest.raises(ValueError, match="link-local|private IP address"):
            HTTPWebhookModule(config)
    
    def test_cloud_metadata_endpoint_blocked(self):
        """Test that cloud metadata endpoints are blocked."""
        metadata_urls = [
            ('http://169.254.169.254/latest/meta-data/', "link-local|private IP address"),
            ('http://metadata.google.internal/', "metadata service"),
            ('http://metadata/', "metadata service"),
        ]
        
        for url, pattern in metadata_urls:
            config = {
                'module': 'http_webhook',
                'module-config': {
                    'url': url
                }
            }
            
            with pytest.raises(ValueError, match=pattern):
                HTTPWebhookModule(config)
    
    def test_file_scheme_blocked(self):
        """Test that file:// scheme is blocked."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'file:///etc/passwd'
            }
        }
        
        with pytest.raises(ValueError, match="scheme.*is not allowed"):
            HTTPWebhookModule(config)
    
    def test_gopher_scheme_blocked(self):
        """Test that gopher:// scheme is blocked."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'gopher://example.com'
            }
        }
        
        with pytest.raises(ValueError, match="scheme.*is not allowed"):
            HTTPWebhookModule(config)
    
    def test_https_allowed(self):
        """Test that https:// URLs are allowed."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'https://example.com/webhook'
            }
        }
        
        # Should not raise an exception
        module = HTTPWebhookModule(config)
        assert module._validated_url == 'https://example.com/webhook'
    
    def test_http_allowed(self):
        """Test that http:// URLs are allowed."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook'
            }
        }
        
        # Should not raise an exception
        module = HTTPWebhookModule(config)
        assert module._validated_url == 'http://example.com/webhook'
    
    def test_public_ip_allowed(self):
        """Test that public IP addresses are allowed."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://8.8.8.8/webhook'
            }
        }
        
        # Should not raise an exception
        module = HTTPWebhookModule(config)
        assert module._validated_url == 'http://8.8.8.8/webhook'
    
    def test_whitelist_allows_private_ip(self):
        """Test that whitelist allows private IPs if configured."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://192.168.1.1:8080/webhook',
                'allowed_hosts': ['192.168.1.1', 'example.com']
            }
        }
        
        # Should not raise an exception if whitelisted
        module = HTTPWebhookModule(config)
        assert module._validated_url == 'http://192.168.1.1:8080/webhook'
    
    def test_whitelist_allows_localhost(self):
        """Test that whitelist allows localhost if configured."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://localhost:8080/webhook',
                'allowed_hosts': ['localhost']
            }
        }
        
        # Should not raise an exception if whitelisted
        module = HTTPWebhookModule(config)
        assert module._validated_url == 'http://localhost:8080/webhook'
    
    def test_whitelist_blocks_non_whitelisted(self):
        """Test that non-whitelisted hosts are blocked even if public."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com/webhook',
                'allowed_hosts': ['allowed.com']
            }
        }
        
        with pytest.raises(ValueError, match="not in the allowed hosts whitelist"):
            HTTPWebhookModule(config)
    
    def test_whitelist_case_insensitive(self):
        """Test that whitelist is case-insensitive."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://EXAMPLE.COM/webhook',
                'allowed_hosts': ['example.com']
            }
        }
        
        # Should not raise an exception (case-insensitive match)
        module = HTTPWebhookModule(config)
        assert module._validated_url == 'http://EXAMPLE.COM/webhook'
    
    def test_loopback_variants_blocked(self):
        """Test that various localhost representations are blocked."""
        localhost_variants = [
            'http://127.0.0.1/webhook',
            'http://0.0.0.0/webhook',
            'http://::1/webhook',
            'http://[::1]/webhook',
        ]
        
        for url in localhost_variants:
            config = {
                'module': 'http_webhook',
                'module-config': {
                    'url': url
                }
            }
            
            with pytest.raises(ValueError):
                HTTPWebhookModule(config)
    
    def test_octal_ip_blocked(self):
        """Test that octal IP representations are blocked."""
        octal_ips = [
            'http://0177.0.0.1/webhook',  # 127.0.0.1 in octal
            'http://127.000.000.001/webhook',  # Padded zeros
        ]
        
        for url in octal_ips:
            config = {
                'module': 'http_webhook',
                'module-config': {
                    'url': url
                }
            }
            
            # Should be blocked (parsed as hostname, caught by localhost check)
            with pytest.raises(ValueError):
                HTTPWebhookModule(config)
    
    def test_multicast_blocked(self):
        """Test that multicast addresses are blocked."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://224.0.0.1/webhook'
            }
        }
        
        with pytest.raises(ValueError, match="multicast"):
            HTTPWebhookModule(config)
    
    def test_reserved_ip_blocked(self):
        """Test that reserved IP addresses are blocked."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://0.0.0.0/webhook'
            }
        }
        
        with pytest.raises(ValueError, match="localhost|reserved|loopback"):
            HTTPWebhookModule(config)
    
    def test_empty_url_rejected(self):
        """Test that empty URL is rejected."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': '   '  # Whitespace only
            }
        }
        
        with pytest.raises(ValueError, match="cannot be empty"):
            HTTPWebhookModule(config)
    
    def test_missing_url_allowed(self):
        """Test that missing URL is allowed (will fail in process())."""
        config = {
            'module': 'http_webhook',
            'module-config': {}
        }
        
        # Should not raise during init (will fail in process())
        module = HTTPWebhookModule(config)
        assert module._validated_url is None
    
    def test_invalid_url_format_rejected(self):
        """Test that invalid URL format is rejected."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'not a valid url'
            }
        }
        
        with pytest.raises(ValueError, match="scheme.*is not allowed|Invalid hostname|Invalid URL format"):
            HTTPWebhookModule(config)
    
    def test_url_with_path_allowed(self):
        """Test that URLs with paths are allowed."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'https://example.com/api/v1/webhook?param=value'
            }
        }
        
        # Should not raise an exception
        module = HTTPWebhookModule(config)
        assert 'example.com' in module._validated_url
    
    def test_url_with_port_allowed(self):
        """Test that URLs with ports are allowed."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://example.com:8080/webhook'
            }
        }
        
        # Should not raise an exception
        module = HTTPWebhookModule(config)
        assert module._validated_url == 'http://example.com:8080/webhook'
    
    def test_public_hostname_allowed(self):
        """Test that public hostnames are allowed."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'https://api.github.com/webhooks'
            }
        }
        
        # Should not raise an exception
        module = HTTPWebhookModule(config)
        assert 'github.com' in module._validated_url
    
    def test_ipv6_public_allowed(self):
        """Test that public IPv6 addresses are allowed."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://[2001:4860:4860::8888]/webhook'
            }
        }
        
        # Should not raise an exception (public IPv6)
        module = HTTPWebhookModule(config)
        assert '2001:4860:4860::8888' in module._validated_url or '[2001:4860:4860::8888]' in module._validated_url
    
    def test_ipv6_private_blocked(self):
        """Test that private IPv6 addresses are blocked."""
        config = {
            'module': 'http_webhook',
            'module-config': {
                'url': 'http://[fc00::1]/webhook'
            }
        }
        
        with pytest.raises(ValueError, match="private IP address|Invalid hostname"):
            HTTPWebhookModule(config)

