"""Tests for src/connector/__init__.py — lazy imports and __all__."""

import pytest
from unittest.mock import patch, MagicMock


class TestConnectorDirectImports:
    """Test that ConnectorConfig and TargetConfig import directly."""

    def test_import_connector_config(self):
        """ConnectorConfig should be directly importable from connector package."""
        from src.connector import ConnectorConfig

        assert ConnectorConfig is not None

    def test_import_target_config(self):
        """TargetConfig should be directly importable from connector package."""
        from src.connector import TargetConfig

        assert TargetConfig is not None


class TestConnectorLazyImportStreamClient:
    """Test lazy imports for stream_client module components."""

    def test_lazy_import_stream_client(self):
        """StreamClient should be lazily importable."""
        from src.connector import StreamClient

        assert StreamClient is not None

    def test_lazy_import_websocket_client(self):
        """WebSocketClient should be lazily importable."""
        from src.connector import WebSocketClient

        assert WebSocketClient is not None

    def test_lazy_import_sse_client(self):
        """SSEClient should be lazily importable."""
        from src.connector import SSEClient

        assert SSEClient is not None

    def test_lazy_import_create_client(self):
        """create_client should be lazily importable."""
        from src.connector import create_client

        assert callable(create_client)


class TestConnectorLazyImportProcessor:
    """Test lazy imports for processor module components."""

    def test_lazy_import_message_processor(self):
        """MessageProcessor should be lazily importable."""
        from src.connector import MessageProcessor

        assert MessageProcessor is not None

    def test_lazy_import_module_processor(self):
        """ModuleProcessor should be lazily importable."""
        from src.connector import ModuleProcessor

        assert ModuleProcessor is not None


class TestConnectorLazyImportLocalConnector:
    """Test lazy import for LocalConnector."""

    def test_lazy_import_local_connector(self):
        """LocalConnector should be lazily importable."""
        from src.connector import LocalConnector

        assert LocalConnector is not None


class TestConnectorAll:
    """Test __all__ list completeness."""

    def test_all_contains_expected_names(self):
        """__all__ should list all public names."""
        import src.connector as mod

        expected = [
            "ConnectorConfig",
            "TargetConfig",
            "StreamClient",
            "WebSocketClient",
            "SSEClient",
            "create_client",
            "MessageProcessor",
            "ModuleProcessor",
            "LocalConnector",
        ]
        for name in expected:
            assert name in mod.__all__, f"{name} missing from __all__"

    def test_all_names_are_importable(self):
        """Every name listed in __all__ should be importable."""
        import src.connector as mod

        for name in mod.__all__:
            obj = getattr(mod, name)
            assert obj is not None, f"Failed to import {name}"


class TestConnectorGetAttrUnknown:
    """Test __getattr__ raises AttributeError for unknown names."""

    def test_unknown_attribute_raises(self):
        """Accessing an unknown attribute should raise AttributeError."""
        import src.connector as mod

        with pytest.raises(AttributeError, match="has no attribute"):
            _ = mod.totally_nonexistent_attribute

    def test_error_message_includes_module_name(self):
        """The AttributeError message should include the module name."""
        import src.connector as mod

        with pytest.raises(AttributeError, match="src.connector"):
            _ = mod.does_not_exist
