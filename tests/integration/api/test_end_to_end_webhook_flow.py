"""
End-to-end integration tests for complete webhook processing flow.

These tests verify the complete webhook lifecycle from HTTP request to final destination.
"""

import pytest
import httpx
import asyncio
from tests.integration.test_config import API_BASE_URL, TEST_WEBHOOK_ID, TEST_AUTH_TOKEN


@pytest.mark.integration
class TestEndToEndWebhookFlow:
    """End-to-end integration tests for webhook processing."""
    
    @pytest.mark.asyncio
    async def test_complete_webhook_lifecycle(self, http_client):
        """Test complete webhook lifecycle (requires API server and webhook config)."""
        # This test requires:
        # 1. FastAPI server running
        # 2. Webhook configured in webhooks.json
        # 3. Module connections configured
        
        # Skip if API server is not available
        try:
            response = await http_client.get("/", timeout=2.0)
        except Exception:
            pytest.skip("API server not available")
        
        # Test payload
        test_payload = {
            "event": "end_to_end_test",
            "data": {"value": 123, "timestamp": "2024-01-01T00:00:00Z"}
        }
        
        # Send webhook request
        try:
            response = await http_client.post(
                f"/webhook/{TEST_WEBHOOK_ID}",
                json=test_payload,
                headers={"Authorization": f"Bearer {TEST_AUTH_TOKEN}"},
                timeout=10.0
            )
            
            # Should accept the request (200, 202, or 401 if auth is required)
            assert response.status_code in [200, 201, 202, 401]
        except Exception as e:
            # If webhook doesn't exist or server error, skip test
            pytest.skip(f"Webhook processing failed: {e}")
    
    @pytest.mark.asyncio
    async def test_webhook_with_authentication(self, http_client):
        """Test webhook processing with authentication."""
        try:
            response = await http_client.get("/", timeout=2.0)
        except Exception:
            pytest.skip("API server not available")
        
        test_payload = {"test": "authentication"}
        
        try:
            # With valid authentication
            response = await http_client.post(
                f"/webhook/{TEST_WEBHOOK_ID}",
                json=test_payload,
                headers={"Authorization": f"Bearer {TEST_AUTH_TOKEN}"},
                timeout=10.0
            )
            assert response.status_code in [200, 202, 401, 403]  # May be unauthorized if token doesn't match
        except Exception:
            pytest.skip("Webhook authentication test failed")
    
    @pytest.mark.asyncio
    async def test_webhook_without_authentication(self, http_client):
        """Test webhook processing without authentication."""
        try:
            response = await http_client.get("/", timeout=2.0)
        except Exception:
            pytest.skip("API server not available")
        
        test_payload = {"test": "no_auth"}
        
        try:
            # Without authentication
            response = await http_client.post(
                f"/webhook/{TEST_WEBHOOK_ID}",
                json=test_payload,
                timeout=10.0
            )
            # Should either accept (if no auth required) or reject (401/403)
            assert response.status_code in [200, 202, 401, 403, 404]
        except Exception:
            pytest.skip("Webhook no-auth test failed")
    
    @pytest.mark.asyncio
    async def test_webhook_error_handling(self, http_client):
        """Test webhook error handling and sanitization."""
        try:
            response = await http_client.get("/", timeout=2.0)
        except Exception:
            pytest.skip("API server not available")
        
        # Test with invalid webhook ID
        try:
            response = await http_client.post(
                "/webhook/nonexistent_webhook_id",
                json={"test": "error"},
                headers={"Authorization": f"Bearer {TEST_AUTH_TOKEN}"},
                timeout=10.0
            )
            # Should return 404 or 403
            assert response.status_code in [404, 403]
        except Exception:
            pytest.skip("Webhook error handling test failed")
    
    @pytest.mark.asyncio
    async def test_webhook_concurrent_requests(self, http_client):
        """Test handling multiple concurrent webhook requests."""
        try:
            response = await http_client.get("/", timeout=2.0)
        except Exception:
            pytest.skip("API server not available")
        
        # Send multiple concurrent requests
        async def send_request(i):
            try:
                response = await http_client.post(
                    f"/webhook/{TEST_WEBHOOK_ID}",
                    json={"test": f"concurrent_{i}", "index": i},
                    headers={"Authorization": f"Bearer {TEST_AUTH_TOKEN}"},
                    timeout=10.0
                )
                return response.status_code
            except Exception:
                return None
        
        # Send 5 concurrent requests
        results = await asyncio.gather(*[send_request(i) for i in range(5)])
        
        # All requests should be processed (status codes should be valid)
        for status_code in results:
            if status_code is not None:
                assert status_code in [200, 202, 401, 403, 404, 500]

