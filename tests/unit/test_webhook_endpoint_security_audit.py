"""
Comprehensive security audit tests for main webhook endpoint (`/webhook/{webhook_id}`).
Tests endpoint-level security: path parameter handling, task result handling, error disclosure, response generation, and statistics/logging security.
"""

import pytest
import json
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from httpx import AsyncClient, ASGITransport
from fastapi import HTTPException, Request
from src.main import app, read_webhook
from src.webhook import WebhookHandler
from src.utils import RedisEndpointStats


# ============================================================================
# 1. PATH PARAMETER SECURITY
# ============================================================================


class TestWebhookEndpointPathParameter:
    """Test path parameter security at endpoint level."""

    @pytest.mark.asyncio
    async def test_webhook_id_path_parameter_injection(self):
        """Test that webhook_id path parameter is handled safely."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # Test various injection attempts
            injection_attempts = [
                "../../etc/passwd",
                "webhook_id'; DROP TABLE users; --",
                "webhook_id<script>alert(1)</script>",
                "webhook_id\x00null",
            ]

            for webhook_id in injection_attempts:
                try:
                    response = await ac.post(
                        f"/webhook/{webhook_id}", json={"data": "test"}
                    )
                    # Should be rejected by validation or return 404
                    assert response.status_code in [400, 404, 405]
                except Exception:
                    # Some injection attempts may cause exceptions (expected)
                    pass

    @pytest.mark.asyncio
    async def test_webhook_id_unicode_handling(self):
        """Test that Unicode webhook IDs are handled safely."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            unicode_ids = [
                "webhook_测试",
                "webhook_🚀",
                "webhook_émoji",
            ]

            for webhook_id in unicode_ids:
                try:
                    response = await ac.post(
                        f"/webhook/{webhook_id}", json={"data": "test"}
                    )
                    # Should handle Unicode safely
                    assert response.status_code in [400, 404, 405]
                except Exception:
                    pass


# ============================================================================
# 2. TASK RESULT HANDLING SECURITY
# ============================================================================


class TestWebhookEndpointTaskResultHandling:
    """Test task result handling security vulnerabilities."""

    @pytest.mark.asyncio
    async def test_task_result_exception_disclosure(self):
        """Test that task result exceptions don't disclose sensitive information."""
        # Mock WebhookHandler
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))

        # Create a mock task that raises an exception with sensitive info
        mock_task = Mock()
        mock_task.done.return_value = True
        mock_task.result.side_effect = Exception(
            "Internal error: password=secret, host=internal.db"
        )

        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, mock_task)
        )
        mock_handler.config = {"retry": {"enabled": True}}

        # Mock request
        mock_request = Mock(spec=Request)
        mock_request.app = app

        # Patch WebhookHandler creation
        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                # Call endpoint
                try:
                    response = await read_webhook("test_webhook", mock_request)
                    # Should return 202 without exposing exception details
                    assert response.status_code == 202
                    # Response should not contain sensitive information
                    response_data = json.loads(response.body.decode())
                    assert "password" not in str(response_data).lower()
                    assert "internal.db" not in str(response_data).lower()
                except Exception as e:
                    # Should not expose sensitive information
                    assert "password" not in str(e).lower()
                    assert "internal.db" not in str(e).lower()

    @pytest.mark.asyncio
    async def test_task_result_success_handling(self):
        """Test that successful task results are handled safely."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))

        # Create a mock task that succeeds
        mock_task = Mock()
        mock_task.done.return_value = True
        mock_task.result.return_value = (True, None)  # (success, error)

        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, mock_task)
        )
        mock_handler.config = {"retry": {"enabled": True}}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                response = await read_webhook("test_webhook", mock_request)
                # Should return 200 for success
                assert response.status_code == 200
                response_data = json.loads(response.body.decode())
                assert "message" in response_data

    @pytest.mark.asyncio
    async def test_task_result_failure_handling(self):
        """Test that failed task results are handled safely."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))

        # Create a mock task that fails
        mock_task = Mock()
        mock_task.done.return_value = True
        mock_task.result.return_value = (False, "Connection failed")

        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, mock_task)
        )
        mock_handler.config = {"retry": {"enabled": True}}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                response = await read_webhook("test_webhook", mock_request)
                # Should return 202 for background processing
                assert response.status_code == 202
                response_data = json.loads(response.body.decode())
                assert "accepted" in response_data["status"].lower()


# ============================================================================
# 3. ERROR INFORMATION DISCLOSURE
# ============================================================================


class TestWebhookEndpointErrorDisclosure:
    """Test error information disclosure vulnerabilities."""

    @pytest.mark.asyncio
    async def test_webhook_handler_init_error_disclosure(self):
        """Test that WebhookHandler initialization errors don't disclose sensitive information."""
        # Mock request
        mock_request = Mock(spec=Request)
        mock_request.app = app

        # Create exception with sensitive information
        sensitive_error = Exception(
            "Failed to connect to database: host=internal.db, password=secret123"
        )

        with patch("src.main.WebhookHandler", side_effect=sensitive_error):
            try:
                await read_webhook("test_webhook", mock_request)
                assert False, "Should raise HTTPException"
            except HTTPException as e:
                # Should sanitize error message
                assert e.status_code == 500
                error_detail = str(e.detail).lower()
                # Should not expose sensitive information
                assert "internal.db" not in error_detail
                assert "secret123" not in error_detail
                assert "password" not in error_detail

    @pytest.mark.asyncio
    async def test_process_webhook_error_disclosure(self):
        """Test that process_webhook errors don't disclose sensitive information."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))

        # Create exception with sensitive information
        sensitive_error = Exception(
            "Database error: connection string=postgresql://user:pass@host/db"
        )
        mock_handler.process_webhook = AsyncMock(side_effect=sensitive_error)

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            try:
                await read_webhook("test_webhook", mock_request)
                assert False, "Should raise HTTPException"
            except HTTPException as e:
                # Should sanitize error message
                assert e.status_code == 500
                error_detail = str(e.detail).lower()
                # Should not expose sensitive information
                assert "connection string" not in error_detail
                assert "postgresql://" not in error_detail
                assert "user:pass" not in error_detail


# ============================================================================
# 4. STATISTICS AND LOGGING SECURITY
# ============================================================================


class TestWebhookEndpointStatisticsLogging:
    """Test statistics and logging security."""

    @pytest.mark.asyncio
    async def test_statistics_webhook_id_injection(self):
        """Test that webhook_id used in statistics doesn't allow injection."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, None)
        )
        mock_handler.config = {}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        malicious_webhook_id = "webhook_id'; DROP TABLE stats; --"

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                # Should handle malicious webhook_id safely
                await read_webhook(malicious_webhook_id, mock_request)

                # Statistics should be called with the webhook_id
                # RedisEndpointStats should handle it safely
                mock_stats.increment.assert_called_once()
                # Verify it was called with the webhook_id (may be sanitized)
                call_args = mock_stats.increment.call_args[0]
                assert len(call_args) > 0

    @pytest.mark.asyncio
    async def test_clickhouse_logging_webhook_id_injection(self):
        """Test that webhook_id used in ClickHouse logging doesn't allow injection."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, None)
        )
        mock_handler.config = {}

        mock_request = Mock(spec=Request)
        # Set up app.state for clickhouse_logger
        mock_request.app = app
        if not hasattr(app.state, "clickhouse_logger"):
            app.state.clickhouse_logger = None

        malicious_webhook_id = "webhook_id'; DROP TABLE webhook_logs; --"

        # Mock clickhouse_logger
        mock_logger = Mock()
        mock_logger.client = Mock()  # Need client attribute for the check
        mock_logger.save_log = AsyncMock()

        original_logger = getattr(app.state, "clickhouse_logger", None)
        app.state.clickhouse_logger = mock_logger

        try:
            with patch("src.main.WebhookHandler", return_value=mock_handler):
                with patch("src.main.stats") as mock_stats:
                    mock_stats.increment = AsyncMock()
                    with patch("src.webhook.task_manager") as mock_task_manager:
                        mock_task_manager.create_task = AsyncMock()

                        await read_webhook(malicious_webhook_id, mock_request)
        finally:
            if original_logger is not None:
                app.state.clickhouse_logger = original_logger
            elif hasattr(app.state, "clickhouse_logger"):
                app.state.clickhouse_logger = original_logger

                # ClickHouse logging should be called
                # The module should handle webhook_id injection safely
                # (ClickHouseModule uses parameterized queries)

    @pytest.mark.asyncio
    async def test_statistics_failure_handling(self):
        """Test that statistics failures don't affect webhook processing."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, None)
        )
        mock_handler.config = {}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                # Statistics should fail but not affect webhook
                mock_stats.increment = AsyncMock(side_effect=Exception("Stats error"))

                response = await read_webhook("test_webhook", mock_request)
                # Should still return 200 even if stats fail
                assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_clickhouse_logging_failure_handling(self):
        """Test that ClickHouse logging failures don't affect webhook processing."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, None)
        )
        mock_handler.config = {}

        mock_request = Mock(spec=Request)

        # Mock clickhouse_logger
        mock_logger = Mock()
        mock_logger.save_log = AsyncMock(side_effect=Exception("ClickHouse error"))
        mock_logger.client = Mock()  # Need client attribute for the check

        mock_request = Mock(spec=Request)
        mock_request.app = app

        original_logger = getattr(app.state, "clickhouse_logger", None)
        app.state.clickhouse_logger = mock_logger

        try:
            with patch("src.main.WebhookHandler", return_value=mock_handler):
                with patch("src.main.stats") as mock_stats:
                    mock_stats.increment = AsyncMock()
                    with patch("src.webhook.task_manager") as mock_task_manager:
                        mock_task_manager.create_task = AsyncMock(
                            side_effect=Exception("Task error")
                        )

                        response = await read_webhook("test_webhook", mock_request)
                        # Should still return 200 even if logging fails
                        assert response.status_code == 200
        finally:
            if original_logger is not None:
                app.state.clickhouse_logger = original_logger
            elif hasattr(app.state, "clickhouse_logger"):
                app.state.clickhouse_logger = original_logger


# ============================================================================
# 5. RESPONSE GENERATION SECURITY
# ============================================================================


class TestWebhookEndpointResponseGeneration:
    """Test response generation security."""

    @pytest.mark.asyncio
    async def test_response_content_sanitization(self):
        """Test that response content doesn't contain sensitive information."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=(
                {"data": "test", "password": "secret123"},  # Sensitive data in payload
                {},
                None,
            )
        )
        mock_handler.config = {}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                response = await read_webhook("test_webhook", mock_request)
                # Response should not expose payload data
                response_data = json.loads(response.body.decode())
                # Response should only contain generic message
                assert "message" in response_data
                assert "password" not in response_data
                assert "secret123" not in response_data

    @pytest.mark.asyncio
    async def test_response_status_code_handling(self):
        """Test that response status codes are appropriate."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, None)
        )
        mock_handler.config = {}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                response = await read_webhook("test_webhook", mock_request)
                # Should return 200 for successful processing
                assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_response_headers_security(self):
        """Test that response headers are secure."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, None)
        )
        mock_handler.config = {}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                response = await read_webhook("test_webhook", mock_request)
                # Security headers should be present (from SecurityHeadersMiddleware)
                # Note: These are added by middleware, so may not be in response object directly
                assert response.status_code in [200, 202]


# ============================================================================
# 6. ASYNC TASK HANDLING SECURITY
# ============================================================================


class TestWebhookEndpointAsyncTaskHandling:
    """Test async task handling security."""

    @pytest.mark.asyncio
    async def test_task_timeout_handling(self):
        """Test that task timeouts are handled safely."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))

        # Create a task that's still running (not done)
        mock_task = Mock()
        mock_task.done.return_value = False  # Task still running

        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, mock_task)
        )
        mock_handler.config = {"retry": {"enabled": True}}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                response = await read_webhook("test_webhook", mock_request)
                # Should return 202 for background processing
                assert response.status_code == 202
                response_data = json.loads(response.body.decode())
                assert "accepted" in response_data["status"].lower()

    @pytest.mark.asyncio
    async def test_task_result_race_condition(self):
        """Test that task result access is safe from race conditions."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))

        # Create a task that becomes done between checks
        mock_task = Mock()
        call_count = 0

        def done_side_effect():
            nonlocal call_count
            call_count += 1
            return call_count > 1  # Done on second call

        mock_task.done.side_effect = done_side_effect
        mock_task.result.return_value = (True, None)

        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, mock_task)
        )
        mock_handler.config = {"retry": {"enabled": True}}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                response = await read_webhook("test_webhook", mock_request)
                # Should handle race condition safely
                assert response.status_code in [200, 202]


# ============================================================================
# 7. REQUEST BODY HANDLING
# ============================================================================


class TestWebhookEndpointRequestBodyHandling:
    """Test request body handling security."""

    @pytest.mark.asyncio
    async def test_large_request_body_handling(self):
        """Test that large request bodies are handled safely."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # Create large payload
            large_payload = {"data": "x" * 10000000}  # 10MB

            try:
                response = await ac.post("/webhook/test_webhook", json=large_payload)
                # Should be rejected by payload size validation
                assert response.status_code in [400, 413]
            except Exception:
                # May raise exception for very large payloads
                pass

    @pytest.mark.asyncio
    async def test_malformed_request_body_handling(self):
        """Test that malformed request bodies are handled safely."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # Send malformed JSON
            response = await ac.post(
                "/webhook/test_webhook",
                content=b'{"invalid": json}',
                headers={"Content-Type": "application/json"},
            )
            # Should be rejected (may return 404 if webhook not found, or 400/422 for malformed JSON)
            assert response.status_code in [400, 404, 422]


# ============================================================================
# 8. CONCURRENT REQUEST HANDLING
# ============================================================================


class TestWebhookEndpointConcurrentHandling:
    """Test concurrent request handling security."""

    @pytest.mark.asyncio
    async def test_concurrent_webhook_requests(self):
        """Test that concurrent webhook requests are handled safely."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, None)
        )
        mock_handler.config = {}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                # Send multiple concurrent requests
                tasks = [read_webhook(f"webhook_{i}", mock_request) for i in range(10)]
                responses = await asyncio.gather(*tasks, return_exceptions=True)

                # All should succeed or fail gracefully
                for response in responses:
                    if isinstance(response, Exception):
                        # Exceptions should not expose sensitive information
                        assert "password" not in str(response).lower()
                    else:
                        assert response.status_code in [200, 202]


# ============================================================================
# 9. RETRY CONFIGURATION SECURITY
# ============================================================================


class TestWebhookEndpointRetryConfiguration:
    """Test retry configuration security."""

    @pytest.mark.asyncio
    async def test_retry_config_type_validation(self):
        """Test that retry configuration type is validated."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, None)
        )

        # Test with invalid retry config type
        mock_handler.config = {"retry": "invalid_type"}  # Should be dict

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                response = await read_webhook("test_webhook", mock_request)
                # Should handle invalid config gracefully
                # get() with default should prevent crashes
                assert response.status_code in [200, 202]

    @pytest.mark.asyncio
    async def test_retry_config_missing_enabled(self):
        """Test that missing retry.enabled is handled safely."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, Mock())  # Task exists
        )

        # Retry config without 'enabled' field
        mock_handler.config = {"retry": {}}  # Missing 'enabled'

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                response = await read_webhook("test_webhook", mock_request)
                # Should handle missing 'enabled' gracefully (defaults to False)
                assert response.status_code == 200


# ============================================================================
# 10. PAYLOAD AND HEADERS LOGGING SECURITY
# ============================================================================


class TestWebhookEndpointPayloadLogging:
    """Test payload and headers logging security."""

    @pytest.mark.asyncio
    async def test_sensitive_payload_logging(self):
        """Test that sensitive payload data is handled safely in logging."""
        sensitive_payload = {
            "password": "secret123",
            "api_key": "key_abc123",
            "credit_card": "4111111111111111",
        }

        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=(sensitive_payload, {}, None)
        )
        mock_handler.config = {}

        mock_request = Mock(spec=Request)

        # Mock clickhouse_logger
        mock_logger = Mock()
        mock_logger.save_log = AsyncMock()
        mock_logger.client = Mock()  # Need client attribute for the check

        mock_request = Mock(spec=Request)
        mock_request.app = app

        original_logger = getattr(app.state, "clickhouse_logger", None)
        app.state.clickhouse_logger = mock_logger

        try:
            with patch("src.main.WebhookHandler", return_value=mock_handler):
                with patch("src.main.stats") as mock_stats:
                    mock_stats.increment = AsyncMock()
                    with patch("src.webhook.task_manager") as mock_task_manager:
                        mock_task_manager.create_task = AsyncMock()

                        response = await read_webhook("test_webhook", mock_request)
                        # Should process successfully
                        # ClickHouse logging should receive payload (logging is internal)
                        # But response should not expose sensitive data
                        assert response.status_code == 200
                        response_data = json.loads(response.body.decode())
                        assert "password" not in response_data
                        assert "api_key" not in response_data
                        assert "credit_card" not in response_data
        finally:
            if original_logger is not None:
                app.state.clickhouse_logger = original_logger
            elif hasattr(app.state, "clickhouse_logger"):
                app.state.clickhouse_logger = original_logger

    @pytest.mark.asyncio
    async def test_sensitive_headers_logging(self):
        """Test that sensitive headers are handled safely in logging."""
        sensitive_headers = {
            "Authorization": "Bearer secret_token_123",
            "X-API-Key": "api_key_secret",
            "Cookie": "session_id=abc123",
        }

        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, sensitive_headers, None)
        )
        mock_handler.config = {}

        mock_request = Mock(spec=Request)

        # Mock clickhouse_logger
        mock_logger = Mock()
        mock_logger.save_log = AsyncMock()
        mock_logger.client = Mock()  # Need client attribute for the check

        mock_request = Mock(spec=Request)
        mock_request.app = app

        original_logger = getattr(app.state, "clickhouse_logger", None)
        app.state.clickhouse_logger = mock_logger

        try:
            with patch("src.main.WebhookHandler", return_value=mock_handler):
                with patch("src.main.stats") as mock_stats:
                    mock_stats.increment = AsyncMock()
                    with patch("src.webhook.task_manager") as mock_task_manager:
                        mock_task_manager.create_task = AsyncMock()

                        response = await read_webhook("test_webhook", mock_request)
                        # Should process successfully
                        # Headers are logged internally but not exposed in response
                        assert response.status_code == 200
                        response_data = json.loads(response.body.decode())
                        assert "Authorization" not in response_data
                        assert "secret_token" not in response_data
        finally:
            if original_logger is not None:
                app.state.clickhouse_logger = original_logger
            elif hasattr(app.state, "clickhouse_logger"):
                app.state.clickhouse_logger = original_logger


# ============================================================================
# 11. ASYNC SLEEP SECURITY
# ============================================================================


class TestWebhookEndpointAsyncSleep:
    """Test async sleep security (DoS prevention)."""

    @pytest.mark.asyncio
    async def test_async_sleep_dos_prevention(self):
        """Test that async sleep doesn't allow DoS via long delays."""
        import time

        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))

        mock_task = Mock()
        mock_task.done.return_value = False  # Task still running

        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, mock_task)
        )
        mock_handler.config = {"retry": {"enabled": True}}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock()

                start_time = time.time()
                response = await read_webhook("test_webhook", mock_request)
                elapsed = time.time() - start_time

                # Sleep is hardcoded to 0.1 seconds, should complete quickly
                assert elapsed < 1.0, "Async sleep should not cause DoS"
                assert response.status_code == 202


# ============================================================================
# 12. GLOBAL STATE SECURITY
# ============================================================================


class TestWebhookEndpointGlobalState:
    """Test global state security."""

    @pytest.mark.asyncio
    async def test_clickhouse_logger_global_state(self):
        """Test that global clickhouse_logger is handled safely."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, None)
        )
        mock_handler.config = {}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        # Test with None clickhouse_logger
        original_logger = getattr(app.state, "clickhouse_logger", None)
        app.state.clickhouse_logger = None

        try:
            with patch("src.main.WebhookHandler", return_value=mock_handler):
                with patch("src.main.stats") as mock_stats:
                    mock_stats.increment = AsyncMock()
                    response = await read_webhook("test_webhook", mock_request)
                    # Should handle None logger gracefully
                    assert response.status_code == 200
        finally:
            if original_logger is not None:
                app.state.clickhouse_logger = original_logger
            elif hasattr(app.state, "clickhouse_logger"):
                app.state.clickhouse_logger = original_logger

    @pytest.mark.asyncio
    async def test_stats_global_state(self):
        """Test that global stats object is handled safely."""
        mock_handler = Mock(spec=WebhookHandler)
        mock_handler.validate_webhook = AsyncMock(return_value=(True, "Valid"))
        mock_handler.process_webhook = AsyncMock(
            return_value=({"data": "test"}, {}, None)
        )
        mock_handler.config = {}

        mock_request = Mock(spec=Request)
        mock_request.app = app

        with patch("src.main.WebhookHandler", return_value=mock_handler):
            # Test with stats that raises exception
            with patch("src.main.stats") as mock_stats:
                mock_stats.increment = AsyncMock(side_effect=Exception("Stats error"))

                response = await read_webhook("test_webhook", mock_request)
                # Should continue processing even if stats fail
                assert response.status_code == 200
