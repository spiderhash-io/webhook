"""
Integration tests for mqtt.py module.
Tests cover missing coverage areas including error handling, connection failures, and edge cases.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from src.modules.mqtt import MQTTModule


class TestMQTTModuleConnection:
    """Test MQTT connection handling."""

    @pytest.mark.asyncio
    async def test_setup_with_connection_error(self):
        """Test setup with connection error."""
        config = {
            "module-config": {
                "topic": "test/topic",
                "host": "invalid-host",
                "port": 1883,
            },
            "connection_details": {"host": "invalid-host", "port": 1883},
        }

        module = MQTTModule(config)

        # Setup doesn't actually connect, it just creates the client
        # Connection happens in process() when using the client as context manager
        with patch("src.modules.mqtt.MQTTClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            # Setup should succeed (client creation doesn't fail)
            await module.setup()

            assert module.client == mock_client

    @pytest.mark.asyncio
    async def test_setup_with_valid_config(self):
        """Test setup with valid MQTT configuration."""
        config = {
            "module-config": {"topic": "test/topic", "host": "localhost", "port": 1883},
            "connection_details": {"host": "localhost", "port": 1883},
        }

        module = MQTTModule(config)

        with patch("src.modules.mqtt.MQTTClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            await module.setup()

            assert module.client == mock_client
            mock_client_class.assert_called_once()


class TestMQTTModulePublish:
    """Test MQTT publish operations."""

    @pytest.mark.asyncio
    async def test_process_with_publish_error(self):
        """Test process when publish fails."""
        config = {
            "module-config": {"topic": "test/topic", "host": "localhost", "port": 1883},
            "connection_details": {},
        }

        module = MQTTModule(config)

        mock_client = Mock()
        mock_client.publish = Mock(side_effect=Exception("Publish failed"))
        module.client = mock_client

        with pytest.raises(Exception):
            await module.process({"data": "test"}, {})

    @pytest.mark.asyncio
    async def test_process_without_client(self):
        """Test process without client (should setup first)."""
        config = {
            "module-config": {"topic": "test/topic", "host": "localhost", "port": 1883},
            "connection_details": {"host": "localhost", "port": 1883},
        }

        module = MQTTModule(config)
        module.client = None

        with patch.object(module, "setup", AsyncMock()) as mock_setup, patch(
            "src.modules.mqtt.MQTTClient"
        ) as mock_client_class:

            mock_client = AsyncMock()
            mock_client.publish = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client
            mock_setup.side_effect = lambda: setattr(module, "client", mock_client)

            await module.process({"data": "test"}, {})

            mock_setup.assert_called_once()
            mock_client.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_with_qos_setting(self):
        """Test process with QoS setting."""
        config = {
            "module-config": {
                "topic": "test/topic",
                "host": "localhost",
                "port": 1883,
                "qos": 2,
            },
            "connection_details": {"host": "localhost", "port": 1883},
        }

        module = MQTTModule(config)

        mock_client = AsyncMock()
        mock_client.publish = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        module.client = mock_client

        await module.process({"data": "test"}, {})

        # Check that publish was called with QoS
        mock_client.publish.assert_called_once()
        call_kwargs = mock_client.publish.call_args[1]
        assert call_kwargs.get("qos") == 2


class TestMQTTModuleDisconnect:
    """Test MQTT disconnect and cleanup."""

    @pytest.mark.asyncio
    async def test_teardown_with_client(self):
        """Test teardown with active client."""
        config = {
            "module-config": {"topic": "test/topic", "host": "localhost", "port": 1883},
            "connection_details": {},
        }

        module = MQTTModule(config)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        module.client = mock_client

        await module.teardown()

        # Client should be set to None
        assert module.client is None

    @pytest.mark.asyncio
    async def test_teardown_without_client(self):
        """Test teardown without client."""
        config = {
            "module-config": {"topic": "test/topic", "host": "localhost", "port": 1883},
            "connection_details": {},
        }

        module = MQTTModule(config)
        module.client = None

        # Should not raise error
        await module.teardown()

    @pytest.mark.asyncio
    async def test_teardown_with_disconnect_error(self):
        """Test teardown when disconnect fails."""
        config = {
            "module-config": {"topic": "test/topic", "host": "localhost", "port": 1883},
            "connection_details": {},
        }

        module = MQTTModule(config)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(side_effect=Exception("Disconnect failed"))
        module.client = mock_client

        # Should handle error gracefully
        await module.teardown()

        # Client should still be set to None even on error
        assert module.client is None
