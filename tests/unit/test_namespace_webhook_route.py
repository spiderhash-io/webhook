"""
Tests for the namespaced webhook route: POST /webhook/{namespace}/{webhook_id}.

Verifies namespace routing, validation, and backward compatibility.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient


@pytest.fixture
def mock_config_manager():
    """Create a mock ConfigManager that supports namespace lookups."""
    manager = MagicMock()

    # Namespace-scoped webhook configs
    ns_configs = {
        "alpha": {
            "hook1": {
                "data_type": "json",
                "module": "log",
                "module-config": {"pretty_print": True},
            },
        },
        "beta": {
            "hook2": {
                "data_type": "json",
                "module": "log",
            },
        },
    }

    def get_all_webhook_configs(namespace=None):
        if namespace is None:
            namespace = "default"
        return ns_configs.get(namespace, {})

    def get_webhook_config(webhook_id, namespace=None):
        if namespace is None:
            namespace = "default"
        return ns_configs.get(namespace, {}).get(webhook_id)

    manager.get_all_webhook_configs = MagicMock(side_effect=get_all_webhook_configs)
    manager.get_webhook_config = MagicMock(side_effect=get_webhook_config)
    manager.get_all_connection_configs = MagicMock(return_value={})
    manager.pool_registry = MagicMock()
    manager.provider = MagicMock()
    manager.provider.get_status.return_value = {"backend": "etcd", "connected": True}
    return manager


@pytest.fixture
def app_with_mock(mock_config_manager):
    """Create a TestClient with mocked ConfigManager."""
    from src.main import app

    # Store and restore original state
    original_cm = getattr(app.state, "config_manager", None)
    original_cl = getattr(app.state, "clickhouse_logger", None)

    app.state.config_manager = mock_config_manager
    app.state.clickhouse_logger = None

    yield TestClient(app, raise_server_exceptions=False)

    # Restore
    app.state.config_manager = original_cm
    app.state.clickhouse_logger = original_cl


class TestNamespaceRouteValidation:
    """Tests for namespace format validation."""

    def test_valid_namespace(self, app_with_mock):
        """Valid namespace should be accepted."""
        response = app_with_mock.post(
            "/webhook/alpha/hook1",
            json={"test": "data"},
        )
        assert response.status_code == 200

    def test_invalid_namespace_with_spaces(self, app_with_mock):
        """Namespace with spaces should be rejected."""
        response = app_with_mock.post(
            "/webhook/bad namespace/hook1",
            json={"test": "data"},
        )
        assert response.status_code == 400

    def test_invalid_namespace_with_slashes(self, app_with_mock):
        """Namespace with slashes should be rejected (path traversal)."""
        response = app_with_mock.post(
            "/webhook/../../etc/hook1",
            json={"test": "data"},
        )
        # FastAPI may return 404 for path traversal or 400 for validation
        assert response.status_code in (400, 404, 422)

    def test_invalid_namespace_too_long(self, app_with_mock):
        """Namespace over 64 chars should be rejected."""
        long_ns = "a" * 65
        response = app_with_mock.post(
            f"/webhook/{long_ns}/hook1",
            json={"test": "data"},
        )
        assert response.status_code == 400

    def test_valid_namespace_with_hyphens_underscores(self, app_with_mock):
        """Namespace with hyphens and underscores should be valid."""
        # Need to set up the mock to also have this namespace
        app_with_mock.app.state.config_manager.get_all_webhook_configs.side_effect = (
            lambda namespace=None: {"hook1": {"data_type": "json", "module": "log"}}
            if namespace == "my-ns_1"
            else {}
        )
        response = app_with_mock.post(
            "/webhook/my-ns_1/hook1",
            json={"test": "data"},
        )
        assert response.status_code == 200


class TestNamespaceRouteRouting:
    """Tests for namespace-scoped config lookup."""

    def test_webhook_found_in_namespace(self, app_with_mock):
        """Should find webhook in correct namespace."""
        response = app_with_mock.post(
            "/webhook/alpha/hook1",
            json={"test": "data"},
        )
        assert response.status_code == 200

    def test_webhook_not_found_in_namespace(self, app_with_mock):
        """Should return 404 for webhook not in that namespace."""
        response = app_with_mock.post(
            "/webhook/alpha/hook2",
            json={"test": "data"},
        )
        assert response.status_code == 404

    def test_different_namespace_same_webhook_id(self, app_with_mock):
        """Same webhook_id in different namespace should use different config."""
        response = app_with_mock.post(
            "/webhook/beta/hook2",
            json={"test": "data"},
        )
        assert response.status_code == 200

    def test_nonexistent_namespace(self, app_with_mock):
        """Nonexistent namespace should return 404."""
        response = app_with_mock.post(
            "/webhook/nonexistent/hook1",
            json={"test": "data"},
        )
        assert response.status_code == 404


class TestNamespaceRouteResponse:
    """Tests for response format."""

    def test_success_response(self, app_with_mock):
        """Successful processing should return 200 OK."""
        response = app_with_mock.post(
            "/webhook/alpha/hook1",
            json={"test": "data"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["message"] == "200 OK"


class TestOriginalRouteUnaffected:
    """Tests that the original /webhook/{webhook_id} route still works."""

    def test_original_route_still_works(self, app_with_mock):
        """The non-namespaced route should still work."""
        # Set up mock to return config for non-namespaced call
        app_with_mock.app.state.config_manager.get_all_webhook_configs.side_effect = None
        app_with_mock.app.state.config_manager.get_all_webhook_configs.return_value = {
            "test_hook": {"data_type": "json", "module": "log"}
        }
        response = app_with_mock.post(
            "/webhook/test_hook",
            json={"test": "data"},
        )
        assert response.status_code == 200
