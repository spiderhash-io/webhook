"""
Unit tests for Health Check Endpoint (`/health`).

This test suite covers:
- Health endpoint functionality
- Component status checking
- Response format validation
- Error handling
- Security considerations
"""

import pytest
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from src.main import app, health_endpoint
from src.utils import RedisEndpointStats


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def client():
    """Create test client for health endpoint tests."""
    return TestClient(app)


@pytest.fixture
def app_state_backup():
    """Backup and restore app state for testing."""
    from src.main import app

    backup = {
        "config_manager": getattr(app.state, "config_manager", None),
        "clickhouse_logger": getattr(app.state, "clickhouse_logger", None),
        "webhook_connect_channel_manager": getattr(
            app.state, "webhook_connect_channel_manager", None
        ),
    }
    yield backup
    # Restore original state
    app.state.config_manager = backup["config_manager"]
    app.state.clickhouse_logger = backup["clickhouse_logger"]
    app.state.webhook_connect_channel_manager = backup[
        "webhook_connect_channel_manager"
    ]


# ============================================================================
# 1. BASIC FUNCTIONALITY
# ============================================================================


class TestHealthEndpointBasic:
    """Test basic health endpoint functionality."""

    def test_health_endpoint_returns_200_when_healthy(self, client):
        """Test that health endpoint returns 200 when service is healthy."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()

        assert "status" in data
        assert data["status"] == "healthy"
        assert "service" in data
        assert data["service"] == "webhook-service"
        assert "timestamp" in data
        assert "components" in data

    def test_health_endpoint_response_structure(self, client):
        """Test that health endpoint returns proper response structure."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()

        # Check required fields
        assert isinstance(data["status"], str)
        assert isinstance(data["service"], str)
        assert isinstance(data["timestamp"], (int, float))
        assert isinstance(data["components"], dict)

        # Check component statuses
        for component, status in data["components"].items():
            assert isinstance(status, str)
            assert status in [
                "healthy",
                "unhealthy",
                "unavailable",
                "not_configured",
                "disconnected",
                "running",
            ]

    def test_health_endpoint_timestamp(self, client):
        """Test that health endpoint includes timestamp."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()

        # Timestamp should be a valid number
        assert isinstance(data["timestamp"], (int, float))
        assert data["timestamp"] > 0

        # Timestamp should be recent (within last minute)
        current_time = time.time()
        assert abs(current_time - data["timestamp"]) < 60


# ============================================================================
# 2. COMPONENT STATUS CHECKING
# ============================================================================


class TestHealthEndpointComponents:
    """Test component status checking in health endpoint."""

    def test_health_endpoint_config_manager_healthy(self, client, app_state_backup):
        """Test health endpoint when ConfigManager is healthy."""
        # Set app state with healthy ConfigManager
        from src.main import app

        mock_config_manager = Mock()
        mock_config_manager.get_all_webhook_configs.return_value = {"webhook1": {}}
        app.state.config_manager = mock_config_manager
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["components"]["config_manager"] == "healthy"

    def test_health_endpoint_config_manager_unhealthy(self, client, app_state_backup):
        """Test health endpoint when ConfigManager is unhealthy."""
        # Set app state with unhealthy ConfigManager
        from src.main import app

        mock_config_manager = Mock()
        mock_config_manager.get_all_webhook_configs.side_effect = Exception(
            "Config error"
        )
        app.state.config_manager = mock_config_manager
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            response = client.get("/health")

            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "unhealthy"
            assert data["components"]["config_manager"] == "unhealthy"

    def test_health_endpoint_config_manager_not_configured(self, client):
        """Test health endpoint when ConfigManager is not configured."""
        # Set app state without ConfigManager
        from src.main import app

        original_config_manager = getattr(app.state, "config_manager", None)
        app.state.config_manager = None
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["components"]["config_manager"] == "not_configured"

        # Restore original state
        app.state.config_manager = original_config_manager

    def test_health_endpoint_redis_stats_healthy(self, client, app_state_backup):
        """Test health endpoint when Redis stats is healthy."""
        from src.main import app

        app.state.config_manager = None
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        # Mock stats to return successfully
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {"webhook1": {"count": 10}}

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["components"]["redis_stats"] == "healthy"

    def test_health_endpoint_redis_stats_unavailable(self, client, app_state_backup):
        """Test health endpoint when Redis stats is unavailable."""
        from src.main import app

        app.state.config_manager = None
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        # Mock stats to raise exception
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.side_effect = Exception("Redis connection failed")

            response = client.get("/health")

            # Redis stats are non-critical, so should still return 200
            assert response.status_code == 200
            data = response.json()
            assert data["components"]["redis_stats"] == "unavailable"

    def test_health_endpoint_clickhouse_healthy(self, client, app_state_backup):
        """Test health endpoint when ClickHouse is healthy."""
        from src.main import app

        app.state.config_manager = None
        mock_clickhouse = Mock()
        mock_clickhouse.client = Mock()  # Client exists
        app.state.clickhouse_logger = mock_clickhouse
        app.state.webhook_connect_channel_manager = None

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["components"]["clickhouse"] == "healthy"

    def test_health_endpoint_clickhouse_disconnected(self, client, app_state_backup):
        """Test health endpoint when ClickHouse is disconnected."""
        from src.main import app

        app.state.config_manager = None
        mock_clickhouse = Mock()
        mock_clickhouse.client = None  # Client is None
        app.state.clickhouse_logger = mock_clickhouse
        app.state.webhook_connect_channel_manager = None

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["components"]["clickhouse"] == "disconnected"

    def test_health_endpoint_clickhouse_not_configured(self, client, app_state_backup):
        """Test health endpoint when ClickHouse is not configured."""
        from src.main import app

        app.state.config_manager = None
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["components"]["clickhouse"] == "not_configured"

    def test_health_endpoint_webhook_connect_healthy(self, client, app_state_backup):
        """Test health endpoint when Webhook Connect is healthy."""
        from src.main import app

        app.state.config_manager = None
        app.state.clickhouse_logger = None
        mock_webhook_connect = Mock()
        mock_webhook_connect.is_running.return_value = True
        app.state.webhook_connect_channel_manager = mock_webhook_connect

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["components"]["webhook_connect"] == "healthy"

    def test_health_endpoint_webhook_connect_running(self, client, app_state_backup):
        """Test health endpoint when Webhook Connect is running but not checked."""
        from src.main import app

        app.state.config_manager = None
        app.state.clickhouse_logger = None
        mock_webhook_connect = Mock()
        # Don't add is_running method, so it defaults to "running"
        app.state.webhook_connect_channel_manager = mock_webhook_connect

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            # Should be "running" if is_running method doesn't exist
            assert data["components"]["webhook_connect"] in ["running", "healthy"]

    def test_health_endpoint_webhook_connect_not_configured(
        self, client, app_state_backup
    ):
        """Test health endpoint when Webhook Connect is not configured."""
        from src.main import app

        app.state.config_manager = None
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["components"]["webhook_connect"] == "not_configured"


# ============================================================================
# 3. ERROR HANDLING
# ============================================================================


class TestHealthEndpointErrorHandling:
    """Test error handling in health endpoint."""

    def test_health_endpoint_handles_component_exceptions(
        self, client, app_state_backup
    ):
        """Test that health endpoint handles exceptions from components gracefully."""
        from src.main import app

        # Make ConfigManager raise exception
        mock_config_manager = Mock()
        mock_config_manager.get_all_webhook_configs.side_effect = Exception(
            "Component error"
        )
        app.state.config_manager = mock_config_manager
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            response = client.get("/health")

            # Should return 503 when critical component fails
            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "unhealthy"

    def test_health_endpoint_handles_missing_app_state(self, client, app_state_backup):
        """Test that health endpoint handles missing app state gracefully."""
        from src.main import app

        # Remove attributes (they'll be handled by getattr with default None)
        if hasattr(app.state, "config_manager"):
            delattr(app.state, "config_manager")
        if hasattr(app.state, "clickhouse_logger"):
            delattr(app.state, "clickhouse_logger")
        if hasattr(app.state, "webhook_connect_channel_manager"):
            delattr(app.state, "webhook_connect_channel_manager")

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            # Should still work even if attributes are missing (getattr handles it)
            response = client.get("/health")
            # Should return 200 (components just marked as not_configured)
            assert response.status_code == 200


# ============================================================================
# 4. SECURITY CONSIDERATIONS
# ============================================================================


class TestHealthEndpointSecurity:
    """Test security aspects of health endpoint."""

    def test_health_endpoint_no_sensitive_information(self, client):
        """Test that health endpoint doesn't leak sensitive information."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        data_str = str(data).lower()

        # Should not contain sensitive information
        assert "password" not in data_str
        assert "secret" not in data_str
        assert "token" not in data_str
        assert "connection_string" not in data_str
        assert "postgresql://" not in data_str
        assert "mysql://" not in data_str
        assert "redis://" not in data_str
        assert "amqp://" not in data_str

    def test_health_endpoint_response_size(self, client):
        """Test that health endpoint response is reasonable size."""
        response = client.get("/health")

        # Response should be reasonable size (not too large)
        response_size = len(response.content)
        assert (
            response_size < 2000
        ), "Health endpoint response should be reasonable size"

    def test_health_endpoint_method_restrictions(self, client):
        """Test that health endpoint only accepts GET method."""
        # GET should work
        get_response = client.get("/health")
        assert get_response.status_code in [200, 503]  # Can be healthy or unhealthy

        # POST should fail (405 Method Not Allowed)
        post_response = client.post("/health")
        assert post_response.status_code == 405

        # PUT should fail
        put_response = client.put("/health")
        assert put_response.status_code == 405

        # DELETE should fail
        delete_response = client.delete("/health")
        assert delete_response.status_code == 405

    def test_health_endpoint_security_headers(self, client):
        """Test that health endpoint has security headers."""
        response = client.get("/health")

        # Security headers should be present (from SecurityHeadersMiddleware)
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"

        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"

    def test_health_endpoint_query_parameters_ignored(self, client):
        """Test that health endpoint ignores query parameters."""
        response = client.get("/health?test=value&injection=<script>")

        assert response.status_code in [200, 503]
        data = response.json()

        # Response should not contain query parameter values
        assert "test" not in str(data)
        assert "<script>" not in str(data)

    def test_health_endpoint_malicious_headers(self, client):
        """Test that health endpoint handles malicious headers safely."""
        malicious_headers = [
            {"X-Injection": "test\r\nInjected: header"},
            {"X-Injection": "test\nInjected: header"},
            {"X-Injection": "test\x00null"},
        ]

        for headers in malicious_headers:
            response = client.get("/health", headers=headers)
            # Should still return valid response
            assert response.status_code in [200, 503]
            # Response should not contain injected content
            assert "Injected" not in response.text


# ============================================================================
# 5. INTEGRATION WITH APP STATE
# ============================================================================


class TestHealthEndpointAppState:
    """Test health endpoint integration with app state."""

    def test_health_endpoint_reads_app_state(self, client):
        """Test that health endpoint correctly reads app state."""
        # This test verifies that the endpoint can access app.state
        # The actual state will depend on how the app was initialized
        response = client.get("/health")

        # Should return valid response regardless of app state
        assert response.status_code in [200, 503]
        data = response.json()
        assert "components" in data

    def test_health_endpoint_with_all_components_healthy(
        self, client, app_state_backup
    ):
        """Test health endpoint when all components are healthy."""
        from src.main import app

        # Setup all components as healthy
        mock_config_manager = Mock()
        mock_config_manager.get_all_webhook_configs.return_value = {"webhook1": {}}
        app.state.config_manager = mock_config_manager

        mock_clickhouse = Mock()
        mock_clickhouse.client = Mock()
        app.state.clickhouse_logger = mock_clickhouse

        mock_webhook_connect = Mock()
        mock_webhook_connect.is_running.return_value = True
        app.state.webhook_connect_channel_manager = mock_webhook_connect

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {"webhook1": {"count": 10}}

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["components"]["config_manager"] == "healthy"
            assert data["components"]["redis_stats"] == "healthy"
            assert data["components"]["clickhouse"] == "healthy"
            assert data["components"]["webhook_connect"] == "healthy"


# ============================================================================
# 6. STATUS CODE VALIDATION
# ============================================================================


class TestHealthEndpointStatusCodes:
    """Test status codes returned by health endpoint."""

    def test_health_endpoint_200_when_healthy(self, client, app_state_backup):
        """Test that health endpoint returns 200 when service is healthy."""
        from src.main import app

        app.state.config_manager = None  # Not critical if not configured
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            response = client.get("/health")

            # Should return 200 when no critical components are unhealthy
            assert response.status_code == 200

    def test_health_endpoint_503_when_unhealthy(self, client, app_state_backup):
        """Test that health endpoint returns 503 when service is unhealthy."""
        from src.main import app

        # Make ConfigManager unhealthy (critical component)
        mock_config_manager = Mock()
        mock_config_manager.get_all_webhook_configs.side_effect = Exception(
            "Critical error"
        )
        app.state.config_manager = mock_config_manager
        app.state.clickhouse_logger = None
        app.state.webhook_connect_channel_manager = None

        # Mock stats
        with patch("src.main.stats.get_stats", new_callable=AsyncMock) as mock_stats:
            mock_stats.return_value = {}

            response = client.get("/health")

            # Should return 503 when critical component is unhealthy
            assert response.status_code == 503
            data = response.json()
            assert data["status"] == "unhealthy"
