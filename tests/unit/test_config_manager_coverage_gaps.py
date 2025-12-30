"""
Comprehensive unit tests to fill coverage gaps in config_manager.py.
Target: 100% coverage for ConfigManager class.
"""
import pytest
import json
import asyncio
import os
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock, patch, MagicMock, mock_open
from src.config_manager import ConfigManager, ReloadResult
from src.connection_pool_registry import ConnectionPoolRegistry


class TestConfigManagerInit:
    """Test ConfigManager.__init__() - all initialization paths."""
    
    @pytest.mark.todo
    def test_init_with_default_files(self):
        """Test initialization with default file paths."""
        manager = ConfigManager()
        assert manager.webhook_config_file == "webhooks.json"
        assert manager.connection_config_file == "connections.json"
        assert isinstance(manager.pool_registry, ConnectionPoolRegistry)
        assert manager._webhook_config == {}
        assert manager._connection_config == {}
        assert manager._reload_in_progress is False
        assert manager._last_reload is None
    
    @pytest.mark.todo
    def test_init_with_custom_files(self):
        """Test initialization with custom file paths."""
        manager = ConfigManager(
            webhook_config_file="custom_webhooks.json",
            connection_config_file="custom_connections.json"
        )
        assert manager.webhook_config_file == "custom_webhooks.json"
        assert manager.connection_config_file == "custom_connections.json"
    
    @pytest.mark.todo
    def test_init_with_custom_pool_registry(self):
        """Test initialization with custom pool registry."""
        custom_registry = ConnectionPoolRegistry()
        manager = ConfigManager(pool_registry=custom_registry)
        assert manager.pool_registry == custom_registry


class TestConfigManagerInitialize:
    """Test ConfigManager.initialize() - success and failure paths."""
    
    @pytest.mark.asyncio
    async def test_initialize_success(self):
        """Test successful initialization."""
        manager = ConfigManager()
        
        with patch.object(manager, 'reload_webhooks', return_value=ReloadResult(success=True)), \
             patch.object(manager, 'reload_connections', return_value=ReloadResult(success=True)):
            
            result = await manager.initialize()
            
            assert result.success is True
            assert 'webhooks_loaded' in result.details
            assert 'connections_loaded' in result.details
    
    @pytest.mark.asyncio
    async def test_initialize_webhook_failure(self):
        """Test initialization failure due to webhook reload failure."""
        manager = ConfigManager()
        
        with patch.object(manager, 'reload_webhooks', return_value=ReloadResult(success=False, error="Webhook error")):
            
            result = await manager.initialize()
            
            assert result.success is False
            assert "Webhook error" in result.error
    
    @pytest.mark.asyncio
    async def test_initialize_connection_failure(self):
        """Test initialization failure due to connection reload failure."""
        manager = ConfigManager()
        
        with patch.object(manager, 'reload_webhooks', return_value=ReloadResult(success=True)), \
             patch.object(manager, 'reload_connections', return_value=ReloadResult(success=False, error="Connection error")):
            
            result = await manager.initialize()
            
            assert result.success is False
            assert "Connection error" in result.error
    
    @pytest.mark.asyncio
    async def test_initialize_exception(self):
        """Test initialization with exception."""
        manager = ConfigManager()
        
        with patch.object(manager, 'reload_webhooks', side_effect=Exception("Unexpected error")):
            
            result = await manager.initialize()
            
            assert result.success is False
            assert "Initialization failed" in result.error


class TestConfigManagerReloadWebhooks:
    """Test ConfigManager.reload_webhooks() - all paths."""
    
    @pytest.mark.asyncio
    async def test_reload_webhooks_success(self):
        """Test successful webhook reload."""
        manager = ConfigManager()
        manager._webhook_config = {'old_webhook': {}}
        
        new_config = {
            'new_webhook': {'module': 'log'},
            'old_webhook': {'module': 'log', 'updated': True}
        }
        
        with patch.object(manager, '_load_webhook_config', return_value=new_config), \
             patch.object(manager, '_validate_webhook_config', return_value=None):
            
            result = await manager.reload_webhooks()
            
            assert result.success is True
            assert result.details['webhooks_added'] == 1
            assert result.details['webhooks_removed'] == 0
            assert result.details['webhooks_modified'] == 1
            assert manager._webhook_config == new_config
    
    @pytest.mark.asyncio
    async def test_reload_webhooks_file_not_found(self):
        """Test webhook reload with file not found."""
        manager = ConfigManager()
        
        with patch.object(manager, '_load_webhook_config', side_effect=FileNotFoundError()):
            
            result = await manager.reload_webhooks()
            
            assert result.success is False
            assert "file not found" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_reload_webhooks_invalid_json(self):
        """Test webhook reload with invalid JSON."""
        manager = ConfigManager()
        
        with patch.object(manager, '_load_webhook_config', side_effect=json.JSONDecodeError("Invalid JSON", "", 0)):
            
            result = await manager.reload_webhooks()
            
            assert result.success is False
            assert "Invalid JSON" in result.error
    
    @pytest.mark.asyncio
    async def test_reload_webhooks_validation_failure(self):
        """Test webhook reload with validation failure."""
        manager = ConfigManager()
        
        new_config = {'webhook1': {'module': 'invalid_module'}}
        
        with patch.object(manager, '_load_webhook_config', return_value=new_config), \
             patch.object(manager, '_validate_webhook_config', return_value="Validation error"):
            
            result = await manager.reload_webhooks()
            
            assert result.success is False
            assert "Validation failed" in result.error
    
    @pytest.mark.asyncio
    async def test_reload_webhooks_already_in_progress(self):
        """Test webhook reload when already in progress."""
        manager = ConfigManager()
        manager._reload_in_progress = True
        
        result = await manager.reload_webhooks()
        
        assert result.success is False
        assert "already in progress" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_reload_webhooks_exception(self):
        """Test webhook reload with exception."""
        manager = ConfigManager()
        
        with patch.object(manager, '_load_webhook_config', side_effect=Exception("Unexpected error")):
            
            result = await manager.reload_webhooks()
            
            assert result.success is False
            assert "Failed to reload webhooks" in result.error


class TestConfigManagerReloadConnections:
    """Test ConfigManager.reload_connections() - all paths."""
    
    @pytest.mark.asyncio
    async def test_reload_connections_success(self):
        """Test successful connection reload."""
        manager = ConfigManager()
        manager._connection_config = {'old_conn': {'type': 'redis-rq'}}
        
        new_config = {
            'new_conn': {'type': 'rabbitmq', 'host': 'localhost', 'port': 5672},
            'old_conn': {'type': 'redis-rq', 'host': 'localhost', 'port': 6379, 'updated': True}
        }
        
        with patch.object(manager, '_load_connection_config', return_value=new_config), \
             patch.object(manager, '_validate_connection_config', return_value=None), \
             patch.object(manager, '_update_connection_pool', return_value=None):
            
            result = await manager.reload_connections()
            
            assert result.success is True
            assert result.details['connections_added'] == 1
            assert result.details['connections_removed'] == 0
            assert result.details['connections_modified'] == 1
            assert manager._connection_config == new_config
    
    @pytest.mark.asyncio
    async def test_reload_connections_file_not_found(self):
        """Test connection reload with file not found."""
        manager = ConfigManager()
        
        with patch.object(manager, '_load_connection_config', side_effect=FileNotFoundError()):
            
            result = await manager.reload_connections()
            
            assert result.success is False
            assert "file not found" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_reload_connections_invalid_json(self):
        """Test connection reload with invalid JSON."""
        manager = ConfigManager()
        
        with patch.object(manager, '_load_connection_config', side_effect=json.JSONDecodeError("Invalid JSON", "", 0)):
            
            result = await manager.reload_connections()
            
            assert result.success is False
            assert "Invalid JSON" in result.error
    
    @pytest.mark.asyncio
    async def test_reload_connections_validation_failure(self):
        """Test connection reload with validation failure."""
        manager = ConfigManager()
        
        new_config = {'conn1': {'type': 'postgresql'}}  # Missing host/port
        
        with patch.object(manager, '_load_connection_config', return_value=new_config), \
             patch.object(manager, '_validate_connection_config', return_value="Validation error"):
            
            result = await manager.reload_connections()
            
            assert result.success is False
            assert "Validation failed" in result.error
    
    @pytest.mark.asyncio
    async def test_reload_connections_already_in_progress(self):
        """Test connection reload when already in progress."""
        manager = ConfigManager()
        manager._reload_in_progress = True
        
        result = await manager.reload_connections()
        
        assert result.success is False
        assert "already in progress" in result.error.lower()


class TestConfigManagerReloadAll:
    """Test ConfigManager.reload_all() - all paths."""
    
    @pytest.mark.asyncio
    async def test_reload_all_success(self):
        """Test successful reload_all."""
        manager = ConfigManager()
        
        webhook_result = ReloadResult(success=True, details={'total_webhooks': 5})
        connection_result = ReloadResult(success=True, details={'total_connections': 3})
        
        with patch.object(manager, 'reload_webhooks', return_value=webhook_result), \
             patch.object(manager, 'reload_connections', return_value=connection_result):
            
            result = await manager.reload_all()
            
            assert result.success is True
            assert 'webhooks' in result.details
            assert 'connections' in result.details
    
    @pytest.mark.asyncio
    async def test_reload_all_webhook_failure(self):
        """Test reload_all with webhook failure."""
        manager = ConfigManager()
        
        webhook_result = ReloadResult(success=False, error="Webhook error")
        connection_result = ReloadResult(success=True, details={})
        
        with patch.object(manager, 'reload_webhooks', return_value=webhook_result), \
             patch.object(manager, 'reload_connections', return_value=connection_result):
            
            result = await manager.reload_all()
            
            assert result.success is False
            assert "Webhook error" in result.error
    
    @pytest.mark.asyncio
    async def test_reload_all_connection_failure(self):
        """Test reload_all with connection failure."""
        manager = ConfigManager()
        
        webhook_result = ReloadResult(success=True, details={})
        connection_result = ReloadResult(success=False, error="Connection error")
        
        with patch.object(manager, 'reload_webhooks', return_value=webhook_result), \
             patch.object(manager, 'reload_connections', return_value=connection_result):
            
            result = await manager.reload_all()
            
            assert result.success is False
            assert "Connection error" in result.error
    
    @pytest.mark.asyncio
    async def test_reload_all_both_failures(self):
        """Test reload_all with both failures."""
        manager = ConfigManager()
        
        webhook_result = ReloadResult(success=False, error="Webhook error")
        connection_result = ReloadResult(success=False, error="Connection error")
        
        with patch.object(manager, 'reload_webhooks', return_value=webhook_result), \
             patch.object(manager, 'reload_connections', return_value=connection_result):
            
            result = await manager.reload_all()
            
            assert result.success is False
            assert "Webhook error" in result.error
            assert "Connection error" in result.error


class TestConfigManagerGetMethods:
    """Test ConfigManager get methods."""
    
    @pytest.mark.todo
    def test_get_webhook_config_found(self):
        """Test get_webhook_config with found webhook."""
        manager = ConfigManager()
        manager._webhook_config = {'webhook1': {'module': 'log'}}
        
        config = manager.get_webhook_config('webhook1')
        
        assert config == {'module': 'log'}
    
    @pytest.mark.todo
    def test_get_webhook_config_not_found(self):
        """Test get_webhook_config with not found webhook."""
        manager = ConfigManager()
        
        config = manager.get_webhook_config('nonexistent')
        
        assert config is None
    
    @pytest.mark.todo
    def test_get_connection_config_found(self):
        """Test get_connection_config with found connection."""
        manager = ConfigManager()
        manager._connection_config = {'conn1': {'type': 'redis-rq'}}
        
        config = manager.get_connection_config('conn1')
        
        assert config == {'type': 'redis-rq'}
    
    @pytest.mark.todo
    def test_get_connection_config_not_found(self):
        """Test get_connection_config with not found connection."""
        manager = ConfigManager()
        
        config = manager.get_connection_config('nonexistent')
        
        assert config is None
    
    @pytest.mark.todo
    def test_get_all_connection_configs(self):
        """Test get_all_connection_configs returns deep copy."""
        manager = ConfigManager()
        manager._connection_config = {
            'conn1': {'type': 'redis-rq', 'nested': {'key': 'value'}}
        }
        
        configs = manager.get_all_connection_configs()
        
        # Should be a copy, not the same object
        assert configs == manager._connection_config
        assert configs is not manager._connection_config
        
        # Modifying the copy shouldn't affect original
        configs['conn1']['new_key'] = 'new_value'
        assert 'new_key' not in manager._connection_config['conn1']


class TestConfigManagerGetStatus:
    """Test ConfigManager.get_status() - all status paths."""
    
    @pytest.mark.todo
    def test_get_status_with_reload(self):
        """Test get_status with last reload timestamp."""
        manager = ConfigManager()
        manager._last_reload = datetime.now(timezone.utc)
        manager._webhook_config = {'webhook1': {}}
        manager._connection_config = {'conn1': {}}
        
        mock_pool_info = {
            'conn1': {'deprecated': False},
            'conn2': {'deprecated': True}
        }
        
        with patch.object(manager.pool_registry, 'get_all_pools_info', return_value=mock_pool_info):
            status = manager.get_status()
            
            assert status['last_reload'] is not None
            assert status['reload_in_progress'] is False
            assert status['webhooks_count'] == 1
            assert status['connections_count'] == 1
            assert status['connection_pools']['active'] == 1
            assert status['connection_pools']['deprecated'] == 1
    
    @pytest.mark.todo
    def test_get_status_without_reload(self):
        """Test get_status without last reload."""
        manager = ConfigManager()
        manager._last_reload = None
        
        with patch.object(manager.pool_registry, 'get_all_pools_info', return_value={}):
            status = manager.get_status()
            
            assert status['last_reload'] is None


class TestConfigManagerLoadConfig:
    """Test ConfigManager _load_webhook_config and _load_connection_config."""
    
    @pytest.mark.asyncio
    async def test_load_webhook_config_success(self):
        """Test successful webhook config load."""
        manager = ConfigManager()
        config_data = {'webhook1': {'module': 'log'}}
        
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=json.dumps(config_data))), \
             patch('src.config_manager.load_env_vars', return_value=config_data):
            
            config = await manager._load_webhook_config()
            
            assert config == config_data
    
    @pytest.mark.asyncio
    async def test_load_webhook_config_file_not_exists(self):
        """Test webhook config load when file doesn't exist."""
        manager = ConfigManager()
        
        with patch('os.path.exists', return_value=False):
            config = await manager._load_webhook_config()
            
            assert config == {}
    
    @pytest.mark.asyncio
    async def test_load_connection_config_success(self):
        """Test successful connection config load."""
        manager = ConfigManager()
        config_data = {'conn1': {'type': 'redis-rq'}}
        
        with patch('os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=json.dumps(config_data))), \
             patch('src.config_manager.load_env_vars', return_value=config_data):
            
            config = await manager._load_connection_config()
            
            assert config == config_data
    
    @pytest.mark.asyncio
    async def test_load_connection_config_file_not_exists(self):
        """Test connection config load when file doesn't exist."""
        manager = ConfigManager()
        
        with patch('os.path.exists', return_value=False):
            with pytest.raises(FileNotFoundError):
                await manager._load_connection_config()


class TestConfigManagerValidateWebhookConfig:
    """Test ConfigManager._validate_webhook_config() - all validation paths."""
    
    @pytest.mark.asyncio
    async def test_validate_webhook_config_valid(self):
        """Test validation with valid webhook config."""
        manager = ConfigManager()
        config = {
            'webhook1': {
                'module': 'log'
            }
        }
        
        with patch('src.modules.registry.ModuleRegistry.get', return_value=Mock()):
            error = await manager._validate_webhook_config(config)
            
            assert error is None
    
    @pytest.mark.asyncio
    async def test_validate_webhook_config_invalid_id(self):
        """Test validation with invalid webhook ID."""
        manager = ConfigManager()
        config = {
            None: {'module': 'log'}  # Invalid ID
        }
        
        error = await manager._validate_webhook_config(config)
        
        assert error is not None
        assert "Invalid webhook ID" in error
    
    @pytest.mark.asyncio
    async def test_validate_webhook_config_missing_module(self):
        """Test validation with missing module."""
        manager = ConfigManager()
        config = {
            'webhook1': {}  # Missing module
        }
        
        error = await manager._validate_webhook_config(config)
        
        assert error is not None
        assert "missing required 'module' field" in error
    
    @pytest.mark.asyncio
    async def test_validate_webhook_config_unknown_module(self):
        """Test validation with unknown module."""
        manager = ConfigManager()
        config = {
            'webhook1': {
                'module': 'unknown_module'
            }
        }
        
        with patch('src.modules.registry.ModuleRegistry.get', side_effect=KeyError("Unknown module")):
            error = await manager._validate_webhook_config(config)
            
            assert error is not None
            assert "unknown module" in error.lower()
    
    @pytest.mark.asyncio
    async def test_validate_webhook_config_with_chain(self):
        """Test validation with chain configuration."""
        manager = ConfigManager()
        config = {
            'webhook1': {
                'chain': ['log', 'save_to_disk']
            }
        }
        
        with patch('src.chain_validator.ChainValidator.validate_chain_config', return_value=(True, None)):
            error = await manager._validate_webhook_config(config)
            
            assert error is None
    
    @pytest.mark.asyncio
    async def test_validate_webhook_config_invalid_chain(self):
        """Test validation with invalid chain configuration."""
        manager = ConfigManager()
        config = {
            'webhook1': {
                'chain': ['invalid_module']
            }
        }
        
        with patch('src.chain_validator.ChainValidator.validate_chain_config', return_value=(False, "Chain error")):
            error = await manager._validate_webhook_config(config)
            
            assert error is not None
            assert "invalid chain configuration" in error.lower()


class TestConfigManagerValidateConnectionConfig:
    """Test ConfigManager._validate_connection_config() - all validation paths."""
    
    @pytest.mark.asyncio
    async def test_validate_connection_config_valid(self):
        """Test validation with valid connection config."""
        manager = ConfigManager()
        config = {
            'conn1': {
                'type': 'postgresql',
                'host': 'localhost',
                'port': 5432
            }
        }
        
        with patch('src.config_manager._validate_connection_host', return_value='example.com'), \
             patch('src.config_manager._validate_connection_port', return_value=5432):
            
            error = await manager._validate_connection_config(config)
            
            assert error is None
    
    @pytest.mark.asyncio
    async def test_validate_connection_config_invalid_name(self):
        """Test validation with invalid connection name."""
        manager = ConfigManager()
        config = {
            None: {'type': 'postgresql'}  # Invalid name
        }
        
        error = await manager._validate_connection_config(config)
        
        assert error is not None
        assert "Invalid connection name" in error
    
    @pytest.mark.asyncio
    async def test_validate_connection_config_missing_type(self):
        """Test validation with missing type."""
        manager = ConfigManager()
        config = {
            'conn1': {}  # Missing type
        }
        
        error = await manager._validate_connection_config(config)
        
        assert error is not None
        assert "missing required 'type' field" in error
    
    @pytest.mark.asyncio
    async def test_validate_connection_config_missing_host(self):
        """Test validation with missing host."""
        manager = ConfigManager()
        config = {
            'conn1': {
                'type': 'postgresql',
                'port': 5432
            }
        }
        
        error = await manager._validate_connection_config(config)
        
        assert error is not None
        assert "missing required 'host' field" in error
    
    @pytest.mark.asyncio
    async def test_validate_connection_config_missing_port(self):
        """Test validation with missing port."""
        manager = ConfigManager()
        config = {
            'conn1': {
                'type': 'postgresql',
                'host': 'localhost'
            }
        }
        
        error = await manager._validate_connection_config(config)
        
        assert error is not None
        assert "missing required 'port' field" in error
    
    @pytest.mark.asyncio
    async def test_validate_connection_config_invalid_host(self):
        """Test validation with invalid host."""
        manager = ConfigManager()
        config = {
            'conn1': {
                'type': 'postgresql',
                'host': '192.168.1.1',
                'port': 5432
            }
        }
        
        with patch('src.config_manager._validate_connection_host', side_effect=ValueError("Invalid host")):
            error = await manager._validate_connection_config(config)
            
            assert error is not None
            assert "host validation failed" in error.lower()
    
    @pytest.mark.asyncio
    async def test_validate_connection_config_invalid_port(self):
        """Test validation with invalid port."""
        manager = ConfigManager()
        config = {
            'conn1': {
                'type': 'postgresql',
                'host': 'localhost',
                'port': 99999
            }
        }
        
        with patch('src.config_manager._validate_connection_host', return_value='example.com'), \
             patch('src.config_manager._validate_connection_port', side_effect=ValueError("Invalid port")):
            
            error = await manager._validate_connection_config(config)
            
            assert error is not None
            assert "port validation failed" in error.lower()


class TestConfigManagerUpdateConnectionPool:
    """Test ConfigManager._update_connection_pool() - all paths."""
    
    @pytest.mark.asyncio
    async def test_update_connection_pool_rabbitmq(self):
        """Test updating RabbitMQ connection pool."""
        manager = ConfigManager()
        conn_config = {
            'type': 'rabbitmq',
            'host': 'localhost',
            'port': 5672
        }
        
        with patch.object(manager.pool_registry, 'get_pool', return_value=None) as mock_get_pool:
            await manager._update_connection_pool('rabbitmq_conn', conn_config)
            
            mock_get_pool.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_connection_pool_redis(self):
        """Test updating Redis connection pool."""
        manager = ConfigManager()
        conn_config = {
            'type': 'redis-rq',
            'host': 'localhost',
            'port': 6379
        }
        
        with patch.object(manager.pool_registry, 'get_pool', return_value=None) as mock_get_pool:
            await manager._update_connection_pool('redis_conn', conn_config)
            
            mock_get_pool.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_connection_pool_postgresql(self):
        """Test updating PostgreSQL connection pool."""
        manager = ConfigManager()
        conn_config = {
            'type': 'postgresql',
            'host': 'localhost',
            'port': 5432
        }
        
        with patch.object(manager.pool_registry, 'get_pool', return_value=None) as mock_get_pool:
            await manager._update_connection_pool('postgres_conn', conn_config)
            
            mock_get_pool.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_connection_pool_mysql(self):
        """Test updating MySQL connection pool."""
        manager = ConfigManager()
        conn_config = {
            'type': 'mysql',
            'host': 'localhost',
            'port': 3306
        }
        
        with patch.object(manager.pool_registry, 'get_pool', return_value=None) as mock_get_pool:
            await manager._update_connection_pool('mysql_conn', conn_config)
            
            mock_get_pool.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_connection_pool_unknown_type(self):
        """Test updating connection pool for unknown type."""
        manager = ConfigManager()
        conn_config = {
            'type': 'unknown',
            'host': 'localhost',
            'port': 1234
        }
        
        # Should return early without creating pool
        await manager._update_connection_pool('unknown_conn', conn_config)
    
    @pytest.mark.asyncio
    async def test_update_connection_pool_exception(self):
        """Test updating connection pool with exception."""
        manager = ConfigManager()
        conn_config = {
            'type': 'postgresql',
            'host': 'localhost',
            'port': 5432
        }
        
        with patch.object(manager.pool_registry, 'get_pool', side_effect=Exception("Connection failed")), \
             patch('builtins.print'):
            
            # Should not raise exception
            await manager._update_connection_pool('postgres_conn', conn_config)


class TestReloadResult:
    """Test ReloadResult dataclass."""
    
    def test_reload_result_with_timestamp(self):
        """Test ReloadResult with explicit timestamp."""
        result = ReloadResult(
            success=True,
            timestamp="2023-01-01T00:00:00Z"
        )
        assert result.timestamp == "2023-01-01T00:00:00Z"
    
    def test_reload_result_without_timestamp(self):
        """Test ReloadResult without timestamp (auto-generated)."""
        result = ReloadResult(success=True)
        assert result.timestamp is not None
        assert len(result.timestamp) > 0

