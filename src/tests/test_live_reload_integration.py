"""Integration tests for live config reload feature."""
import pytest
import json
import tempfile
import os
import asyncio
from unittest.mock import AsyncMock
from src.config_manager import ConfigManager
from src.connection_pool_registry import ConnectionPoolRegistry


class TestLiveReloadIntegration:
    """Integration tests for live reload feature."""
    
    @pytest.fixture
    def temp_webhook_config(self, tmp_path):
        """Create temporary webhook config file."""
        config = {
            "test_webhook_1": {
                "data_type": "json",
                "module": "log"
            },
            "test_webhook_2": {
                "data_type": "json",
                "module": "log"
            }
        }
        config_file = tmp_path / "webhooks.json"
        with open(config_file, 'w') as f:
            json.dump(config, f)
        yield str(config_file)
    
    @pytest.fixture
    def temp_connection_config(self, tmp_path):
        """Create temporary connection config file."""
        config = {
            "test_connection": {
                "type": "rabbitmq",
                "host": "rabbitmq.example.com",
                "port": 5672
            }
        }
        config_file = tmp_path / "connections.json"
        with open(config_file, 'w') as f:
            json.dump(config, f)
        yield str(config_file)
    
    @pytest.fixture
    def pool_registry(self):
        """Create ConnectionPoolRegistry instance."""
        return ConnectionPoolRegistry(migration_timeout=1.0)
    
    @pytest.fixture
    def config_manager(self, temp_webhook_config, temp_connection_config, pool_registry):
        """Create ConfigManager instance with pool registry."""
        return ConfigManager(
            webhook_config_file=temp_webhook_config,
            connection_config_file=temp_connection_config,
            pool_registry=pool_registry
        )
    
    @pytest.mark.asyncio
    async def test_pool_migration_on_connection_change(self, config_manager, pool_registry, temp_connection_config):
        """Test that connection pool migrates when connection config changes."""
        await config_manager.initialize()
        
        # Create initial pool (use valid hostname to pass SSRF validation)
        # Mock the pool factory to avoid actual connection attempts
        async def mock_pool_factory(config):
            pool = AsyncMock()
            pool.close_all = AsyncMock()
            return pool
        
        connection_config1 = {"type": "rabbitmq", "host": "rabbitmq.example.com", "port": 5672}
        pool1 = await pool_registry.get_pool("conn1", connection_config1, mock_pool_factory)
        
        # Change connection config
        new_config = {
            "conn1": {
                "type": "rabbitmq",
                "host": "rabbitmq.example.com",
                "port": 5673  # Different port
            }
        }
        with open(temp_connection_config, 'w') as f:
            json.dump(new_config, f)
        
        await config_manager.reload_connections()
        
        # Get pool with new config
        connection_config2 = config_manager.get_connection_config("conn1")
        pool2 = await pool_registry.get_pool("conn1", connection_config2, mock_pool_factory)
        
        # Should be different pools
        assert pool1 is not pool2
        
        # Old pool should be deprecated
        assert len(pool_registry._deprecated_pools) > 0
    
    @pytest.mark.asyncio
    async def test_webhook_addition_without_restart(self, config_manager, temp_webhook_config):
        """Test that new webhooks can be added without restart."""
        await config_manager.initialize()
        
        # Verify initial webhooks exist
        assert config_manager.get_webhook_config("test_webhook_1") is not None
        assert config_manager.get_webhook_config("test_webhook_2") is not None
        assert config_manager.get_webhook_config("test_webhook_3") is None
        
        # Add new webhook
        new_config = {
            "test_webhook_1": {
                "data_type": "json",
                "module": "log"
            },
            "test_webhook_2": {
                "data_type": "json",
                "module": "log"
            },
            "test_webhook_3": {
                "data_type": "json",
                "module": "log"
            }
        }
        with open(temp_webhook_config, 'w') as f:
            json.dump(new_config, f)
        
        # Reload
        result = await config_manager.reload_webhooks()
        assert result.success is True
        
        # New webhook should be available
        assert config_manager.get_webhook_config("test_webhook_3") is not None
        # Old webhooks should still work
        assert config_manager.get_webhook_config("test_webhook_1") is not None
        assert config_manager.get_webhook_config("test_webhook_2") is not None

