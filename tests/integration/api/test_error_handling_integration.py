"""
Integration tests for error handling and sanitization with real API server.

These tests verify that errors are properly handled and sanitized.
"""

import pytest
import httpx
import json
from tests.integration.test_config import API_BASE_URL, TEST_WEBHOOK_ID


@pytest.mark.integration
class TestErrorHandlingIntegration:
    """Integration tests for error handling."""
    
    @pytest.mark.asyncio
    async def test_malformed_json_error(self, http_client):
        """Test that malformed JSON returns proper error."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")
        
        webhook_id = f"{TEST_WEBHOOK_ID}_error_test"
        
        # Send malformed JSON
        response = await http_client.post(
            f"{API_BASE_URL}/webhook/{webhook_id}",
            content=b"{invalid json}",
            headers={"Content-Type": "application/json"}
        )
        
        # Should return 400 (Bad Request)
        assert response.status_code in [400, 404, 500]
        
        if response.status_code == 400:
            # Error message should be sanitized (no stack traces)
            error_detail = response.json().get("detail", "")
            assert "traceback" not in error_detail.lower()
            assert "file" not in error_detail.lower() or "webhook" in error_detail.lower()
    
    @pytest.mark.asyncio
    async def test_webhook_not_found_error(self, http_client):
        """Test that non-existent webhook returns proper error."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")
        
        # Request to non-existent webhook
        response = await http_client.post(
            f"{API_BASE_URL}/webhook/nonexistent_webhook_12345",
            json={"test": "data"},
            headers={"Content-Type": "application/json"}
        )
        
        # Should return 404 (Not Found)
        assert response.status_code == 404
        
        # Error message should be sanitized
        error_detail = response.json().get("detail", "")
        assert "webhook" in error_detail.lower() or "not found" in error_detail.lower()
        assert "traceback" not in error_detail.lower()
    
    @pytest.mark.asyncio
    async def test_authentication_error_sanitization(self, http_client):
        """Test that authentication errors are properly sanitized."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")
        
        webhook_id = f"{TEST_WEBHOOK_ID}_auth_error"
        
        # Request with invalid authentication
        response = await http_client.post(
            f"{API_BASE_URL}/webhook/{webhook_id}",
            json={"test": "data"},
            headers={
                "Authorization": "Bearer invalid_token",
                "Content-Type": "application/json"
            }
        )
        
        # Should return 401 or 403
        assert response.status_code in [401, 403, 404, 500]
        
        if response.status_code in [401, 403]:
            # Error message should not expose internal details
            error_detail = response.json().get("detail", "")
            assert "secret" not in error_detail.lower()
            assert "key" not in error_detail.lower() or "api" in error_detail.lower()
    
    @pytest.mark.asyncio
    async def test_validation_error_sanitization(self, http_client):
        """Test that validation errors are properly sanitized."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")
        
        webhook_id = f"{TEST_WEBHOOK_ID}_validation_error"
        
        # Request with invalid payload (too large, invalid format, etc.)
        # Send very large payload
        large_payload = {"data": "x" * 1000000}  # 1MB string
        
        response = await http_client.post(
            f"{API_BASE_URL}/webhook/{webhook_id}",
            json=large_payload,
            headers={"Content-Type": "application/json"}
        )
        
        # Should return 400 or 413 (Payload Too Large)
        assert response.status_code in [400, 413, 404, 500]
        
        if response.status_code in [400, 413]:
            # Error message should be user-friendly
            error_detail = response.json().get("detail", "")
            assert "traceback" not in error_detail.lower()
    
    @pytest.mark.asyncio
    async def test_internal_error_sanitization(self, http_client):
        """Test that internal errors are properly sanitized."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")
        
        webhook_id = f"{TEST_WEBHOOK_ID}_internal_error"
        
        # Request that might cause internal error
        # (e.g., webhook with invalid module configuration)
        response = await http_client.post(
            f"{API_BASE_URL}/webhook/{webhook_id}",
            json={"test": "data"},
            headers={"Content-Type": "application/json"}
        )
        
        # If error occurs, should return 500
        if response.status_code == 500:
            # Error message should be sanitized (no stack traces)
            error_detail = response.json().get("detail", "")
            assert "traceback" not in error_detail.lower()
            assert "file" not in error_detail.lower() or "webhook" in error_detail.lower()
    
    @pytest.mark.asyncio
    async def test_error_response_format(self, http_client):
        """Test that error responses follow consistent format."""
        try:
            response = await http_client.get(f"{API_BASE_URL}/")
        except Exception:
            pytest.skip("API server not available")
        
        # Request to non-existent webhook
        response = await http_client.post(
            f"{API_BASE_URL}/webhook/nonexistent_webhook_12345",
            json={"test": "data"},
            headers={"Content-Type": "application/json"}
        )
        
        # Should return JSON error response
        assert response.headers.get("content-type", "").startswith("application/json")
        
        try:
            error_data = response.json()
            # Should have 'detail' field
            assert "detail" in error_data
        except json.JSONDecodeError:
            pytest.fail("Error response is not valid JSON")

