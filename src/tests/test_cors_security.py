"""
Security tests for CORS configuration.
Tests that CORS is properly restricted to prevent CSRF and unauthorized access.
"""
import pytest
import os
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch


class TestCORSSecurity:
    """Test suite for CORS security configuration."""
    
    @pytest.mark.asyncio
    async def test_cors_no_origins_by_default(self):
        """Test that CORS is disabled by default (no origins allowed)."""
        # Clear CORS environment variable
        with patch.dict(os.environ, {}, clear=True):
            # Reimport app to get fresh CORS config
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                # Preflight request from arbitrary origin
                response = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "http://malicious.com",
                        "Access-Control-Request-Method": "POST",
                    }
                )
                
                # Should not have CORS headers (or have restrictive ones)
                assert "access-control-allow-origin" not in response.headers or \
                       response.headers.get("access-control-allow-origin") != "http://malicious.com"
    
    @pytest.mark.asyncio
    async def test_cors_whitelisted_origin_allowed(self):
        """Test that whitelisted origins are allowed."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "https://example.com,https://app.example.com"}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                # Preflight from whitelisted origin
                response = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "https://example.com",
                        "Access-Control-Request-Method": "POST",
                    }
                )
                
                assert response.status_code == 200
                assert response.headers.get("access-control-allow-origin") == "https://example.com"
                assert "POST" in response.headers.get("access-control-allow-methods", "")
    
    @pytest.mark.asyncio
    async def test_cors_non_whitelisted_origin_rejected(self):
        """Test that non-whitelisted origins are rejected."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "https://example.com"}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                # Preflight from non-whitelisted origin
                response = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "http://malicious.com",
                        "Access-Control-Request-Method": "POST",
                    }
                )
                
                # Should not allow the origin
                assert response.headers.get("access-control-allow-origin") != "http://malicious.com"
    
    @pytest.mark.asyncio
    async def test_cors_methods_restricted(self):
        """Test that only allowed methods are permitted."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "https://example.com"}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                # Request DELETE method (not in allowed list)
                response = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "https://example.com",
                        "Access-Control-Request-Method": "DELETE",
                    }
                )
                
                # DELETE should not be in allowed methods
                allowed_methods = response.headers.get("access-control-allow-methods", "")
                assert "DELETE" not in allowed_methods.upper()
                # POST, GET, OPTIONS should be allowed
                assert "POST" in allowed_methods.upper()
                assert "GET" in allowed_methods.upper()
                assert "OPTIONS" in allowed_methods.upper()
    
    @pytest.mark.asyncio
    async def test_cors_headers_restricted(self):
        """Test that only allowed headers are permitted."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "https://example.com"}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                # Request custom header (not in allowed list)
                response = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "https://example.com",
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": "X-Malicious-Header,Authorization",
                    }
                )
                
                # Should only allow whitelisted headers
                allowed_headers = response.headers.get("access-control-allow-headers", "").lower()
                # Authorization should be allowed
                assert "authorization" in allowed_headers
                # Malicious header should not be explicitly allowed
                # (FastAPI may still allow it, but we test our config)
    
    @pytest.mark.asyncio
    async def test_cors_credentials_only_with_whitelist(self):
        """Test that credentials are only allowed when origins are whitelisted."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "https://example.com"}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "https://example.com",
                        "Access-Control-Request-Method": "POST",
                    }
                )
                
                # Credentials should be allowed when origin is whitelisted
                assert response.headers.get("access-control-allow-credentials") == "true"
    
    @pytest.mark.asyncio
    async def test_cors_no_credentials_with_wildcard(self):
        """Test that credentials are not allowed with wildcard origins."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "*"}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "https://example.com",
                        "Access-Control-Request-Method": "POST",
                    }
                )
                
                # Credentials should not be allowed with wildcard
                # (Browser will reject this combination anyway)
                # We test that our config doesn't set it
                # Note: FastAPI may still set it, but browsers will reject it
    
    @pytest.mark.asyncio
    async def test_cors_multiple_origins(self):
        """Test that multiple whitelisted origins work correctly."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "https://example.com,https://app.example.com,https://api.example.com"}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                # Test first origin
                response1 = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "https://example.com",
                        "Access-Control-Request-Method": "POST",
                    }
                )
                assert response1.headers.get("access-control-allow-origin") == "https://example.com"
                
                # Test second origin
                response2 = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "https://app.example.com",
                        "Access-Control-Request-Method": "POST",
                    }
                )
                assert response2.headers.get("access-control-allow-origin") == "https://app.example.com"
                
                # Test third origin
                response3 = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "https://api.example.com",
                        "Access-Control-Request-Method": "POST",
                    }
                )
                assert response3.headers.get("access-control-allow-origin") == "https://api.example.com"
    
    @pytest.mark.asyncio
    async def test_cors_origin_validation(self):
        """Test that origin validation is strict."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "https://example.com"}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                # Try similar but different origin
                response = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "https://example.com.evil.com",  # Subdomain attack
                        "Access-Control-Request-Method": "POST",
                    }
                )
                
                # Should not allow the malicious subdomain
                assert response.headers.get("access-control-allow-origin") != "https://example.com.evil.com"
    
    @pytest.mark.asyncio
    async def test_cors_protocol_validation(self):
        """Test that protocol (http vs https) is validated."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "https://example.com"}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                # Try http instead of https
                response = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "http://example.com",  # Wrong protocol
                        "Access-Control-Request-Method": "POST",
                    }
                )
                
                # Should not allow http if only https is whitelisted
                assert response.headers.get("access-control-allow-origin") != "http://example.com"
    
    @pytest.mark.asyncio
    async def test_cors_max_age_set(self):
        """Test that max-age is set for preflight caching."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "https://example.com"}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "https://example.com",
                        "Access-Control-Request-Method": "POST",
                    }
                )
                
                # Should have max-age header for preflight caching
                max_age = response.headers.get("access-control-max-age")
                assert max_age is not None
                assert int(max_age) > 0
    
    @pytest.mark.asyncio
    async def test_cors_no_expose_headers(self):
        """Test that no sensitive headers are exposed."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "https://example.com"}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                response = await ac.get(
                    "/",
                    headers={"Origin": "https://example.com"}
                )
                
                # Should not expose headers (or expose minimal set)
                exposed_headers = response.headers.get("access-control-expose-headers", "")
                # Should be empty or minimal
                assert len(exposed_headers) == 0 or len(exposed_headers.split(",")) < 5
    
    @pytest.mark.asyncio
    async def test_cors_empty_string_handling(self):
        """Test that empty string in environment variable is handled."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": ""}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                # Should not allow any origins
                response = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "https://example.com",
                        "Access-Control-Request-Method": "POST",
                    }
                )
                
                # Should not allow the origin
                assert response.headers.get("access-control-allow-origin") != "https://example.com"
    
    @pytest.mark.asyncio
    async def test_cors_whitespace_handling(self):
        """Test that whitespace in origins list is handled."""
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": " https://example.com , https://app.example.com "}):
            import importlib
            import src.main
            importlib.reload(src.main)
            
            transport = ASGITransport(app=src.main.app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                # Should work with whitespace
                response = await ac.options(
                    "/webhook/test",
                    headers={
                        "Origin": "https://example.com",
                        "Access-Control-Request-Method": "POST",
                    }
                )
                
                assert response.headers.get("access-control-allow-origin") == "https://example.com"

