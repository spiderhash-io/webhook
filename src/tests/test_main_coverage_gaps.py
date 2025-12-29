"""
Comprehensive tests to fill coverage gaps in main.py.

This test file focuses on achieving 100% coverage for main.py by testing:
- All startup event handler paths
- All shutdown event handler paths
- Connection validation for all database types
- Endpoint error paths and edge cases
- Security headers middleware
- CORS configuration
- Custom OpenAPI generation
- Cleanup task
"""
import pytest
import asyncio
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import Request, HTTPException

from src.main import (
    app, startup_event, shutdown_event, cleanup_task, custom_openapi,
    validate_connections, SecurityHeadersMiddleware,
    default_endpoint, stats_endpoint, reload_config_endpoint, config_status_endpoint,
    read_webhook
)
from src.config_manager import ConfigManager
from src.config_watcher import ConfigFileWatcher
from src.clickhouse_analytics import ClickHouseAnalytics


# ============================================================================
# STARTUP EVENT HANDLER TESTS
# ============================================================================

class TestStartupEventCoverage:
    """Test all startup event handler paths for complete coverage."""
    
    @pytest.mark.asyncio
    async def test_startup_configmanager_success_with_details(self):
        """Test ConfigManager initialization success with details."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()), \
             patch('src.main.asyncio.create_task') as mock_create_task, \
             patch('src.main.ConfigManager') as mock_cm_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(
                success=True,
                details={'webhooks_loaded': 5, 'connections_loaded': 3}
            )
            mock_cm._connection_config = {}
            mock_cm.get_all_connection_configs.return_value = {}
            mock_cm_class.return_value = mock_cm
            
            await startup_event()
            
            mock_cm.initialize.assert_called_once()
            mock_create_task.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_startup_configmanager_failure_warning(self):
        """Test ConfigManager initialization failure with warning (not exception)."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.connection_config', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()), \
             patch('src.main.inject_connection_details', AsyncMock(return_value={})), \
             patch('src.main.ConfigManager') as mock_cm_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(
                success=False,
                error="Configuration error"
            )
            mock_cm._connection_config = {}
            mock_cm.get_all_connection_configs.return_value = {}
            mock_cm_class.return_value = mock_cm
            
            await startup_event()
            
            mock_cm.initialize.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_startup_configmanager_exception_fallback(self):
        """Test ConfigManager initialization exception triggers fallback."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.connection_config', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()), \
             patch('src.main.inject_connection_details', AsyncMock(return_value={})), \
             patch('src.main.ConfigManager') as mock_cm_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.side_effect = Exception("Init failed")
            mock_cm._connection_config = {}
            mock_cm_class.return_value = mock_cm
            
            await startup_event()
            
            mock_cm.initialize.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_startup_connection_validation_with_configmanager(self):
        """Test connection validation with ConfigManager."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()) as mock_validate, \
             patch('src.main.asyncio.create_task'), \
             patch('src.main.ConfigManager') as mock_cm_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(success=True, details={})
            mock_cm._connection_config = {}
            mock_cm.get_all_connection_configs = Mock(return_value={'conn1': {'type': 'postgresql'}})
            mock_cm_class.return_value = mock_cm
            
            await startup_event()
            
            # Check that validate_connections was called
            assert mock_validate.called
    
    @pytest.mark.asyncio
    async def test_startup_connection_validation_with_legacy_config(self):
        """Test connection validation with legacy config."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.connection_config', {'conn1': {'type': 'postgresql'}}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()) as mock_validate, \
             patch('src.main.inject_connection_details', AsyncMock(return_value={})), \
             patch('src.main.asyncio.create_task'), \
             patch('src.main.ConfigManager') as mock_cm_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.side_effect = Exception("Init failed")
            mock_cm._connection_config = {}
            mock_cm_class.return_value = mock_cm
            
            await startup_event()
            
            # Check that validate_connections was called
            assert mock_validate.called
    
    @pytest.mark.asyncio
    async def test_startup_connection_validation_exception(self):
        """Test connection validation exception handling."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock(side_effect=Exception("Validation failed"))), \
             patch('src.main.asyncio.create_task'), \
             patch('src.main.ConfigManager') as mock_cm_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(success=True, details={})
            mock_cm._connection_config = {}
            mock_cm.get_all_connection_configs.return_value = {}
            mock_cm_class.return_value = mock_cm
            
            # Should not raise exception
            await startup_event()
    
    @pytest.mark.asyncio
    async def test_startup_clickhouse_with_configmanager(self):
        """Test ClickHouse initialization with ConfigManager."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()), \
             patch('src.main.asyncio.create_task'), \
             patch('src.main.ConfigManager') as mock_cm_class, \
             patch('src.main.ClickHouseAnalytics') as mock_ch_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(success=True, details={})
            mock_cm._connection_config = {
                'clickhouse1': {'type': 'clickhouse', 'host': 'localhost', 'port': 9000}
            }
            mock_cm.get_all_connection_configs.return_value = {}
            mock_cm_class.return_value = mock_cm
            
            mock_ch = AsyncMock()
            mock_ch.connect = AsyncMock()
            mock_ch_class.return_value = mock_ch
            
            await startup_event()
            
            mock_ch_class.assert_called_once()
            mock_ch.connect.assert_called_once()
    
    @pytest.mark.todo
    @pytest.mark.asyncio
    async def test_startup_clickhouse_with_legacy_config(self):
        """Test ClickHouse initialization with legacy config."""
        import src.main
        
        legacy_connection_config = {
            'clickhouse1': {'type': 'clickhouse', 'host': 'localhost', 'port': 9000}
        }
        
        with patch('src.main.webhook_config_data', {}), \
             patch('src.config.connection_config', legacy_connection_config), \
             patch('src.main.connection_config', legacy_connection_config), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()), \
             patch('src.main.inject_connection_details', AsyncMock(return_value={})), \
             patch('src.main.asyncio.create_task'), \
             patch('src.main.ConfigManager') as mock_cm_class, \
             patch('src.main.ClickHouseAnalytics') as mock_ch_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.side_effect = Exception("Init failed")
            mock_cm._connection_config = {}
            mock_cm_class.return_value = mock_cm
            
            # After exception, config_manager should be None (not set)
            # So we need to ensure it's None when the ClickHouse check happens
            original_cm = src.main.config_manager
            src.main.config_manager = None
            
            try:
                mock_ch = AsyncMock()
                mock_ch.connect = AsyncMock()
                mock_ch_class.return_value = mock_ch
                
                # Patch connection_config at the module level where it's imported
                with patch.object(src.main, 'connection_config', legacy_connection_config):
                    await startup_event()
                    
                    # ClickHouse should be initialized from legacy config
                    # The code creates ClickHouseAnalytics instance and calls connect
                    mock_ch_class.assert_called_once()
                    mock_ch.connect.assert_called_once()
            finally:
                src.main.config_manager = original_cm
    
    @pytest.mark.asyncio
    async def test_startup_clickhouse_connection_failure(self):
        """Test ClickHouse connection failure handling."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()), \
             patch('src.main.asyncio.create_task'), \
             patch('src.main.ConfigManager') as mock_cm_class, \
             patch('src.main.ClickHouseAnalytics') as mock_ch_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(success=True, details={})
            mock_cm._connection_config = {
                'clickhouse1': {'type': 'clickhouse', 'host': 'localhost', 'port': 9000}
            }
            mock_cm.get_all_connection_configs.return_value = {}
            mock_cm_class.return_value = mock_cm
            
            mock_ch = AsyncMock()
            mock_ch.connect = AsyncMock(side_effect=Exception("Connection failed"))
            mock_ch_class.return_value = mock_ch
            
            await startup_event()
            
            # Should handle error gracefully
            mock_ch.connect.assert_called_once()
    
    @pytest.mark.todo
    @pytest.mark.asyncio
    async def test_startup_clickhouse_attribute_error_fallback(self):
        """Test ClickHouse initialization with AttributeError fallback."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.connection_config', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()), \
             patch('src.main.inject_connection_details', AsyncMock(return_value={})), \
             patch('src.main.asyncio.create_task'), \
             patch('src.main.ConfigManager') as mock_cm_class:
            
            # Create a mock that doesn't have _connection_config attribute
            mock_cm = Mock()
            mock_cm.initialize = AsyncMock(return_value=Mock(success=True, details={}))
            # Don't set _connection_config - accessing it will raise AttributeError
            mock_cm.get_all_connection_configs = Mock(return_value={})
            mock_cm_class.return_value = mock_cm
            
            await startup_event()
            
            # Should handle AttributeError gracefully
    
    @pytest.mark.asyncio
    async def test_startup_file_watcher_enabled(self):
        """Test file watcher startup when enabled."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()), \
             patch('src.main.asyncio.create_task'), \
             patch.dict(os.environ, {'CONFIG_FILE_WATCHING_ENABLED': 'true', 'CONFIG_RELOAD_DEBOUNCE_SECONDS': '5.0'}), \
             patch('src.main.ConfigManager') as mock_cm_class, \
             patch('src.main.ConfigFileWatcher') as mock_watcher_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(success=True, details={})
            mock_cm._connection_config = {}
            mock_cm.get_all_connection_configs.return_value = {}
            mock_cm_class.return_value = mock_cm
            
            mock_watcher = Mock()
            mock_watcher.start = Mock()
            mock_watcher_class.return_value = mock_watcher
            
            await startup_event()
            
            mock_watcher_class.assert_called_once()
            mock_watcher.start.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_startup_file_watcher_debounce_too_small(self):
        """Test file watcher debounce validation - too small."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()), \
             patch('src.main.asyncio.create_task'), \
             patch.dict(os.environ, {'CONFIG_FILE_WATCHING_ENABLED': 'true', 'CONFIG_RELOAD_DEBOUNCE_SECONDS': '0.05'}), \
             patch('src.main.ConfigManager') as mock_cm_class, \
             patch('src.main.ConfigFileWatcher') as mock_watcher_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(success=True, details={})
            mock_cm._connection_config = {}
            mock_cm.get_all_connection_configs.return_value = {}
            mock_cm_class.return_value = mock_cm
            
            mock_watcher = Mock()
            mock_watcher.start = Mock()
            mock_watcher_class.return_value = mock_watcher
            
            await startup_event()
            
            # Should use default 3.0 instead of 0.05
            mock_watcher_class.assert_called_once_with(mock_cm, debounce_seconds=3.0)
    
    @pytest.mark.asyncio
    async def test_startup_file_watcher_debounce_too_large(self):
        """Test file watcher debounce validation - too large."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()), \
             patch('src.main.asyncio.create_task'), \
             patch.dict(os.environ, {'CONFIG_FILE_WATCHING_ENABLED': 'true', 'CONFIG_RELOAD_DEBOUNCE_SECONDS': '5000'}), \
             patch('src.main.ConfigManager') as mock_cm_class, \
             patch('src.main.ConfigFileWatcher') as mock_watcher_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(success=True, details={})
            mock_cm._connection_config = {}
            mock_cm.get_all_connection_configs.return_value = {}
            mock_cm_class.return_value = mock_cm
            
            mock_watcher = Mock()
            mock_watcher.start = Mock()
            mock_watcher_class.return_value = mock_watcher
            
            await startup_event()
            
            # Should cap at 3600
            mock_watcher_class.assert_called_once_with(mock_cm, debounce_seconds=3600)
    
    @pytest.mark.asyncio
    async def test_startup_file_watcher_debounce_invalid(self):
        """Test file watcher debounce validation - invalid value."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()), \
             patch('src.main.asyncio.create_task'), \
             patch.dict(os.environ, {'CONFIG_FILE_WATCHING_ENABLED': 'true', 'CONFIG_RELOAD_DEBOUNCE_SECONDS': 'invalid'}), \
             patch('src.main.ConfigManager') as mock_cm_class, \
             patch('src.main.ConfigFileWatcher') as mock_watcher_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(success=True, details={})
            mock_cm._connection_config = {}
            mock_cm.get_all_connection_configs.return_value = {}
            mock_cm_class.return_value = mock_cm
            
            mock_watcher = Mock()
            mock_watcher.start = Mock()
            mock_watcher_class.return_value = mock_watcher
            
            await startup_event()
            
            # Should use default 3.0 for invalid value
            mock_watcher_class.assert_called_once_with(mock_cm, debounce_seconds=3.0)
    
    @pytest.mark.asyncio
    async def test_startup_file_watcher_exception(self):
        """Test file watcher startup exception handling."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.config_watcher', None), \
             patch('src.main.validate_connections', AsyncMock()), \
             patch('src.main.asyncio.create_task'), \
             patch.dict(os.environ, {'CONFIG_FILE_WATCHING_ENABLED': 'true'}), \
             patch('src.main.ConfigManager') as mock_cm_class, \
             patch('src.main.ConfigFileWatcher') as mock_watcher_class:
            
            mock_cm = AsyncMock()
            mock_cm.initialize.return_value = Mock(success=True, details={})
            mock_cm._connection_config = {}
            mock_cm.get_all_connection_configs.return_value = {}
            mock_cm_class.return_value = mock_cm
            
            mock_watcher_class.side_effect = Exception("Watcher init failed")
            
            # Should not raise exception
            await startup_event()


# ============================================================================
# SHUTDOWN EVENT HANDLER TESTS
# ============================================================================

class TestShutdownEventCoverage:
    """Test all shutdown event handler paths for complete coverage."""
    
    @pytest.mark.asyncio
    async def test_shutdown_configwatcher_exception(self):
        """Test ConfigFileWatcher.stop() exception handling."""
        mock_watcher = Mock()
        mock_watcher.stop.side_effect = Exception("Stop failed")
        
        with patch('src.main.config_watcher', mock_watcher), \
             patch('src.main.config_manager', None), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.stats', AsyncMock()):
            
            # Should not raise exception
            await shutdown_event()
            mock_watcher.stop.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_shutdown_pool_registry_exception(self):
        """Test ConnectionPoolRegistry.close_all_pools() exception handling."""
        mock_manager = AsyncMock()
        mock_manager.pool_registry = AsyncMock()
        mock_manager.pool_registry.close_all_pools = AsyncMock(side_effect=Exception("Close failed"))
        
        with patch('src.main.config_watcher', None), \
             patch('src.main.config_manager', mock_manager), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.stats', AsyncMock()):
            
            # Should not raise exception
            await shutdown_event()
            mock_manager.pool_registry.close_all_pools.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_shutdown_clickhouse_exception(self):
        """Test ClickHouseAnalytics.disconnect() exception handling."""
        mock_clickhouse = AsyncMock()
        mock_clickhouse.disconnect = AsyncMock(side_effect=Exception("Disconnect failed"))
        
        with patch('src.main.config_watcher', None), \
             patch('src.main.config_manager', None), \
             patch('src.main.clickhouse_logger', mock_clickhouse), \
             patch('src.main.stats', AsyncMock()):
            
            # Should not raise exception
            await shutdown_event()
            mock_clickhouse.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_shutdown_redis_stats_exception(self):
        """Test RedisEndpointStats.close() exception handling."""
        mock_stats = AsyncMock()
        mock_stats.close = AsyncMock(side_effect=Exception("Stats close failed"))
        
        with patch('src.main.config_watcher', None), \
             patch('src.main.config_manager', None), \
             patch('src.main.clickhouse_logger', None), \
             patch('src.main.stats', mock_stats):
            
            # Should not raise exception
            await shutdown_event()
            mock_stats.close.assert_called_once()


# ============================================================================
# CONNECTION VALIDATION TESTS
# ============================================================================

class TestConnectionValidationCoverage:
    """Test connection validation for all database types."""
    
    @pytest.mark.asyncio
    async def test_validate_connections_postgresql_success(self):
        """Test PostgreSQL connection validation - success."""
        with patch('src.config._validate_connection_host', Mock(return_value=None)), \
             patch('src.config._validate_connection_port', Mock(return_value=None)), \
             patch('asyncpg.connect', AsyncMock()) as mock_connect:
            
            mock_conn = AsyncMock()
            mock_conn.fetchval = AsyncMock(return_value=1)
            mock_conn.close = AsyncMock()
            mock_connect.return_value = mock_conn
            
            conn_config = {
                'postgres1': {
                    'type': 'postgresql',
                    'host': 'localhost',
                    'port': 5432,
                    'database': 'testdb',
                    'user': 'testuser',
                    'password': 'testpass'
                }
            }
            
            await validate_connections(conn_config)
            
            mock_connect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_connections_postgresql_failure(self):
        """Test PostgreSQL connection validation - failure."""
        with patch('src.config._validate_connection_host', Mock(return_value=None)), \
             patch('src.config._validate_connection_port', Mock(return_value=None)), \
             patch('asyncpg.connect', AsyncMock(side_effect=Exception("Connection failed"))):
            
            conn_config = {
                'postgres1': {
                    'type': 'postgresql',
                    'host': 'localhost',
                    'port': 5432,
                    'database': 'testdb',
                    'user': 'testuser',
                    'password': 'testpass'
                }
            }
            
            # Should not raise exception
            await validate_connections(conn_config)
    
    @pytest.mark.asyncio
    async def test_validate_connections_postgresql_timeout(self):
        """Test PostgreSQL connection validation - timeout."""
        with patch('src.config._validate_connection_host', Mock(return_value=None)), \
             patch('src.config._validate_connection_port', Mock(return_value=None)), \
             patch('asyncio.wait_for', AsyncMock(side_effect=asyncio.TimeoutError())):
            
            conn_config = {
                'postgres1': {
                    'type': 'postgresql',
                    'host': 'localhost',
                    'port': 5432,
                    'database': 'testdb',
                    'user': 'testuser',
                    'password': 'testpass'
                }
            }
            
            # Should not raise exception
            await validate_connections(conn_config)
    
    @pytest.mark.asyncio
    async def test_validate_connections_postgresql_host_validation_failure(self):
        """Test PostgreSQL connection validation - host validation failure."""
        with patch('src.config._validate_connection_host', Mock(side_effect=ValueError("Invalid host"))):
            
            conn_config = {
                'postgres1': {
                    'type': 'postgresql',
                    'host': '192.168.1.1',
                    'port': 5432
                }
            }
            
            # Should not raise exception
            await validate_connections(conn_config)
    
    @pytest.mark.asyncio
    async def test_validate_connections_postgresql_port_validation_failure(self):
        """Test PostgreSQL connection validation - port validation failure."""
        with patch('src.config._validate_connection_host', Mock(return_value=None)), \
             patch('src.config._validate_connection_port', Mock(side_effect=ValueError("Invalid port"))):
            
            conn_config = {
                'postgres1': {
                    'type': 'postgresql',
                    'host': 'localhost',
                    'port': 99999
                }
            }
            
            # Should not raise exception
            await validate_connections(conn_config)
    
    @pytest.mark.asyncio
    async def test_validate_connections_mysql_success(self):
        """Test MySQL connection validation - success."""
        with patch('src.config._validate_connection_host', Mock(return_value=None)), \
             patch('src.config._validate_connection_port', Mock(return_value=None)), \
             patch('aiomysql.create_pool', AsyncMock()) as mock_create_pool:
            
            mock_pool = AsyncMock()
            mock_pool.acquire = AsyncMock()
            mock_pool.close = AsyncMock()
            mock_pool.wait_closed = AsyncMock()
            mock_create_pool.return_value = mock_pool
            
            async def mock_acquire():
                mock_conn = AsyncMock()
                mock_cur = AsyncMock()
                mock_cur.execute = AsyncMock()
                mock_cur.fetchone = AsyncMock(return_value=(1,))
                mock_conn.cursor = AsyncMock(return_value=mock_cur)
                return mock_conn
            
            mock_pool.acquire.return_value.__aenter__ = mock_acquire
            mock_pool.acquire.return_value.__aexit__ = AsyncMock()
            
            conn_config = {
                'mysql1': {
                    'type': 'mysql',
                    'host': 'localhost',
                    'port': 3306,
                    'database': 'testdb',
                    'user': 'testuser',
                    'password': 'testpass'
                }
            }
            
            await validate_connections(conn_config)
            
            mock_create_pool.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_connections_mysql_failure(self):
        """Test MySQL connection validation - failure."""
        with patch('src.config._validate_connection_host', Mock(return_value=None)), \
             patch('src.config._validate_connection_port', Mock(return_value=None)), \
             patch('aiomysql.create_pool', AsyncMock(side_effect=Exception("Connection failed"))):
            
            conn_config = {
                'mysql1': {
                    'type': 'mysql',
                    'host': 'localhost',
                    'port': 3306,
                    'database': 'testdb',
                    'user': 'testuser',
                    'password': 'testpass'
                }
            }
            
            # Should not raise exception
            await validate_connections(conn_config)
    
    @pytest.mark.asyncio
    async def test_validate_connections_kafka_success(self):
        """Test Kafka connection validation - success."""
        with patch('src.config._validate_connection_host', Mock(return_value=None)), \
             patch('src.config._validate_connection_port', Mock(return_value=None)), \
             patch('aiokafka.AIOKafkaProducer') as mock_producer_class:
            
            mock_producer = AsyncMock()
            mock_producer.start = AsyncMock()
            mock_producer.stop = AsyncMock()
            mock_producer_class.return_value = mock_producer
            
            conn_config = {
                'kafka1': {
                    'type': 'kafka',
                    'bootstrap_servers': 'localhost:9092'
                }
            }
            
            await validate_connections(conn_config)
            
            mock_producer_class.assert_called_once()
            mock_producer.start.assert_called_once()
            mock_producer.stop.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_connections_kafka_multiple_servers(self):
        """Test Kafka connection validation - multiple servers."""
        with patch('src.config._validate_connection_host', Mock(return_value=None)), \
             patch('src.config._validate_connection_port', Mock(return_value=None)), \
             patch('aiokafka.AIOKafkaProducer') as mock_producer_class:
            
            mock_producer = AsyncMock()
            mock_producer.start = AsyncMock()
            mock_producer.stop = AsyncMock()
            mock_producer_class.return_value = mock_producer
            
            conn_config = {
                'kafka1': {
                    'type': 'kafka',
                    'bootstrap_servers': 'localhost:9092,localhost:9093'
                }
            }
            
            await validate_connections(conn_config)
    
    @pytest.mark.asyncio
    async def test_validate_connections_kafka_host_validation_failure(self):
        """Test Kafka connection validation - host validation failure."""
        with patch('src.config._validate_connection_host', Mock(side_effect=ValueError("Invalid host"))):
            
            conn_config = {
                'kafka1': {
                    'type': 'kafka',
                    'bootstrap_servers': '192.168.1.1:9092'
                }
            }
            
            # Should not raise exception
            await validate_connections(conn_config)
    
    @pytest.mark.asyncio
    async def test_validate_connections_redis_rq_success(self):
        """Test Redis-RQ connection validation - success."""
        with patch('src.config._validate_connection_host', Mock(return_value=None)), \
             patch('src.config._validate_connection_port', Mock(return_value=None)), \
             patch('redis.Redis') as mock_redis_class:
            
            mock_redis = Mock()
            mock_redis.ping = Mock()
            mock_redis_class.return_value = mock_redis
            
            conn_config = {
                'redis1': {
                    'type': 'redis-rq',
                    'host': 'localhost',
                    'port': 6379,
                    'db': 0
                }
            }
            
            await validate_connections(conn_config)
            
            mock_redis_class.assert_called_once()
            mock_redis.ping.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_connections_rabbitmq_success(self):
        """Test RabbitMQ connection validation - success."""
        with patch('src.config._validate_connection_host', Mock(return_value=None)), \
             patch('src.config._validate_connection_port', Mock(return_value=None)), \
             patch('aio_pika.connect_robust', AsyncMock()) as mock_connect:
            
            mock_conn = AsyncMock()
            mock_conn.close = AsyncMock()
            mock_connect.return_value = mock_conn
            
            conn_config = {
                'rabbitmq1': {
                    'type': 'rabbitmq',
                    'host': 'localhost',
                    'port': 5672,
                    'user': 'guest',
                    'pass': 'guest'
                }
            }
            
            await validate_connections(conn_config)
            
            mock_connect.assert_called_once()
            mock_conn.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_connections_clickhouse_success(self):
        """Test ClickHouse connection validation - success."""
        with patch('src.config._validate_connection_host', Mock(return_value=None)), \
             patch('src.config._validate_connection_port', Mock(return_value=None)), \
             patch('clickhouse_driver.Client') as mock_client_class, \
             patch('asyncio.get_event_loop') as mock_get_loop:
            
            mock_client = Mock()
            mock_client.execute = Mock()
            mock_client_class.return_value = mock_client
            
            mock_loop = Mock()
            mock_executor = AsyncMock(return_value=True)
            mock_loop.run_in_executor = AsyncMock(return_value=True)
            mock_get_loop.return_value = mock_loop
            
            conn_config = {
                'clickhouse1': {
                    'type': 'clickhouse',
                    'host': 'localhost',
                    'port': 9000,
                    'database': 'testdb',
                    'user': 'testuser',
                    'password': 'testpass'
                }
            }
            
            await validate_connections(conn_config)
    
    @pytest.mark.asyncio
    async def test_validate_connections_unknown_type(self):
        """Test connection validation - unknown type."""
        conn_config = {
            'unknown1': {
                'type': 'unknown_db',
                'host': 'localhost',
                'port': 1234
            }
        }
        
        # Should not raise exception
        await validate_connections(conn_config)
    
    @pytest.mark.asyncio
    async def test_validate_connections_empty_config(self):
        """Test connection validation - empty config."""
        await validate_connections({})
    
    @pytest.mark.asyncio
    async def test_validate_connections_invalid_config_entry(self):
        """Test connection validation - invalid config entry."""
        conn_config = {
            'invalid1': None,
            'invalid2': 'not a dict'
        }
        
        # Should not raise exception
        await validate_connections(conn_config)


# ============================================================================
# ENDPOINT TESTS
# ============================================================================

class TestEndpointCoverage:
    """Test endpoint error paths and edge cases."""
    
    @pytest.mark.asyncio
    async def test_default_endpoint_rate_limit_exceeded(self):
        """Test default endpoint - rate limit exceeded."""
        mock_request = Mock()
        mock_request.headers = {'x-forwarded-for': '192.168.1.1'}
        mock_request.client = Mock()
        mock_request.client.host = '192.168.1.1'
        
        with patch('src.main.rate_limiter') as mock_rate_limiter:
            mock_rate_limiter.check_rate_limit = AsyncMock(return_value=(False, "Rate limit exceeded"))
            
            with pytest.raises(HTTPException) as exc_info:
                await default_endpoint(mock_request)
            
            assert exc_info.value.status_code == 429
    
    @pytest.mark.asyncio
    async def test_default_endpoint_ip_from_client_host(self):
        """Test default endpoint - IP from request.client.host."""
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.client = Mock()
        mock_request.client.host = '192.168.1.1'
        
        with patch('src.main.rate_limiter') as mock_rate_limiter:
            mock_rate_limiter.check_rate_limit = AsyncMock(return_value=(True, "OK"))
            
            response = await default_endpoint(mock_request)
            
            assert response.status_code == 200
            mock_rate_limiter.check_rate_limit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_stats_endpoint_with_bearer_token(self):
        """Test stats endpoint - Bearer token format."""
        mock_request = Mock()
        mock_request.headers = {'authorization': 'Bearer test-token-123'}
        mock_request.client = Mock()
        mock_request.client.host = '192.168.1.1'
        
        with patch.dict(os.environ, {'STATS_AUTH_TOKEN': 'test-token-123'}), \
             patch('src.main.rate_limiter') as mock_rate_limiter, \
             patch('src.main.stats') as mock_stats:
            
            mock_rate_limiter.check_rate_limit = AsyncMock(return_value=(True, "OK"))
            mock_stats.get_stats = AsyncMock(return_value={'webhook1': {'count': 10}})
            
            response = await stats_endpoint(mock_request)
            
            # Response should be a dict (not a Response object)
            assert isinstance(response, dict)
            assert 'webhook1' in response
    
    @pytest.mark.asyncio
    async def test_stats_endpoint_with_direct_token(self):
        """Test stats endpoint - direct token (no Bearer prefix)."""
        mock_request = Mock()
        mock_request.headers = {'authorization': 'test-token-123'}
        mock_request.client = Mock()
        mock_request.client.host = '192.168.1.1'
        
        with patch.dict(os.environ, {'STATS_AUTH_TOKEN': 'test-token-123'}), \
             patch('src.main.rate_limiter') as mock_rate_limiter, \
             patch('src.main.stats') as mock_stats:
            
            mock_rate_limiter.check_rate_limit = AsyncMock(return_value=(True, "OK"))
            mock_stats.get_stats = AsyncMock(return_value={'webhook1': {'count': 10}})
            
            response = await stats_endpoint(mock_request)
            
            # Response should be a dict (not a Response object)
            assert isinstance(response, dict)
            assert 'webhook1' in response
    
    @pytest.mark.asyncio
    async def test_stats_endpoint_ip_whitelist_allowed(self):
        """Test stats endpoint - IP whitelist allowed."""
        mock_request = Mock()
        mock_request.headers = {'x-forwarded-for': '192.168.1.1'}
        mock_request.client = Mock()
        mock_request.client.host = '192.168.1.1'
        
        with patch.dict(os.environ, {'STATS_ALLOWED_IPS': '192.168.1.1,192.168.1.2'}), \
             patch('src.main.rate_limiter') as mock_rate_limiter, \
             patch('src.main.stats') as mock_stats:
            
            mock_rate_limiter.check_rate_limit = AsyncMock(return_value=(True, "OK"))
            mock_stats.get_stats = AsyncMock(return_value={'webhook1': {'count': 10}})
            
            response = await stats_endpoint(mock_request)
            
            # Response should be a dict (not a Response object)
            assert isinstance(response, dict)
            assert 'webhook1' in response
    
    @pytest.mark.asyncio
    async def test_stats_endpoint_ip_whitelist_denied(self):
        """Test stats endpoint - IP whitelist denied."""
        mock_request = Mock()
        mock_request.headers = {'x-forwarded-for': '192.168.1.100'}
        mock_request.client = Mock()
        mock_request.client.host = '192.168.1.100'
        
        with patch.dict(os.environ, {'STATS_ALLOWED_IPS': '192.168.1.1,192.168.1.2'}), \
             patch('src.main.rate_limiter') as mock_rate_limiter:
            
            mock_rate_limiter.check_rate_limit = AsyncMock(return_value=(True, "OK"))
            
            with pytest.raises(HTTPException) as exc_info:
                await stats_endpoint(mock_request)
            
            assert exc_info.value.status_code == 403
    
    @pytest.mark.asyncio
    async def test_stats_endpoint_sanitize_ids_enabled(self):
        """Test stats endpoint - STATS_SANITIZE_IDS enabled."""
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.client = Mock()
        mock_request.client.host = '192.168.1.1'
        
        with patch.dict(os.environ, {'STATS_SANITIZE_IDS': 'true'}), \
             patch('src.main.rate_limiter') as mock_rate_limiter, \
             patch('src.main.stats') as mock_stats:
            
            mock_rate_limiter.check_rate_limit = AsyncMock(return_value=(True, "OK"))
            mock_stats.get_stats = AsyncMock(return_value={'webhook1': {'count': 10}})
            
            response = await stats_endpoint(mock_request)
            
            # Response should be a dict with sanitized keys
            assert isinstance(response, dict)
            # Keys should be hashed (start with 'webhook_')
            assert any(key.startswith('webhook_') for key in response.keys())
    
    @pytest.mark.asyncio
    async def test_read_webhook_with_configmanager(self):
        """Test webhook endpoint - with ConfigManager."""
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.client = Mock()
        mock_request.client.host = '192.168.1.1'
        mock_request.url = Mock()
        mock_request.url.path = '/webhook/test-webhook'
        
        mock_config_manager = Mock()
        mock_config_manager.get_webhook_config = Mock(return_value={'module': 'log'})
        mock_config_manager.get_all_connection_configs = Mock(return_value={})
        mock_config_manager.pool_registry = None
        
        with patch('src.main.config_manager', mock_config_manager), \
             patch('src.main.WebhookHandler') as mock_handler_class, \
             patch('src.main.stats') as mock_stats, \
             patch('src.main.clickhouse_logger', None):
            
            mock_handler = AsyncMock()
            mock_handler.validate_webhook = AsyncMock(return_value=(True, "OK"))
            mock_handler.process_webhook = AsyncMock(return_value=({}, {}, None))
            mock_handler.config = {}
            mock_handler_class.return_value = mock_handler
            
            mock_stats.increment = AsyncMock()
            
            response = await read_webhook('test-webhook', mock_request)
            
            assert response.status_code == 200
            mock_handler.validate_webhook.assert_called_once()
            mock_handler.process_webhook.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_read_webhook_handler_init_exception(self):
        """Test webhook endpoint - WebhookHandler initialization exception."""
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.client = Mock()
        mock_request.client.host = '192.168.1.1'
        
        mock_config_manager = Mock()
        mock_config_manager.get_webhook_config = Mock(return_value={'module': 'log'})
        mock_config_manager.get_all_connection_configs = Mock(return_value={})
        mock_config_manager.pool_registry = None
        
        with patch('src.main.config_manager', mock_config_manager), \
             patch('src.main.WebhookHandler', side_effect=Exception("Init failed")):
            
            with pytest.raises(HTTPException) as exc_info:
                await read_webhook('test-webhook', mock_request)
            
            assert exc_info.value.status_code == 500
    
    @pytest.mark.asyncio
    async def test_read_webhook_with_retry_and_task(self):
        """Test webhook endpoint - with retry configuration and task."""
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.client = Mock()
        mock_request.client.host = '192.168.1.1'
        
        mock_config_manager = Mock()
        mock_config_manager.get_webhook_config = Mock(return_value={
            'module': 'log',
            'retry': {'enabled': True}
        })
        mock_config_manager.get_all_connection_configs = Mock(return_value={})
        mock_config_manager.pool_registry = None
        
        mock_task = AsyncMock()
        mock_task.done = Mock(return_value=True)
        mock_task.result = Mock(return_value=(True, None))
        
        with patch('src.main.config_manager', mock_config_manager), \
             patch('src.main.WebhookHandler') as mock_handler_class, \
             patch('src.main.stats') as mock_stats, \
             patch('src.main.clickhouse_logger', None), \
             patch('asyncio.sleep', AsyncMock()):
            
            mock_handler = AsyncMock()
            mock_handler.validate_webhook = AsyncMock(return_value=(True, "OK"))
            mock_handler.process_webhook = AsyncMock(return_value=({}, {}, mock_task))
            mock_handler.config = {'retry': {'enabled': True}}
            mock_handler_class.return_value = mock_handler
            
            mock_stats.increment = AsyncMock()
            
            response = await read_webhook('test-webhook', mock_request)
            
            assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_read_webhook_process_exception(self):
        """Test webhook endpoint - process_webhook exception."""
        mock_request = Mock()
        mock_request.headers = {}
        mock_request.client = Mock()
        mock_request.client.host = '192.168.1.1'
        
        mock_config_manager = Mock()
        mock_config_manager.get_webhook_config = Mock(return_value={'module': 'log'})
        mock_config_manager.get_all_connection_configs = Mock(return_value={})
        mock_config_manager.pool_registry = None
        
        with patch('src.main.config_manager', mock_config_manager), \
             patch('src.main.WebhookHandler') as mock_handler_class, \
             patch('src.main.stats') as mock_stats, \
             patch('src.main.clickhouse_logger', None):
            
            mock_handler = AsyncMock()
            mock_handler.validate_webhook = AsyncMock(return_value=(True, "OK"))
            mock_handler.process_webhook = AsyncMock(side_effect=Exception("Process failed"))
            mock_handler.config = {}
            mock_handler_class.return_value = mock_handler
            
            mock_stats.increment = AsyncMock()
            
            with pytest.raises(HTTPException) as exc_info:
                await read_webhook('test-webhook', mock_request)
            
            assert exc_info.value.status_code == 500


# ============================================================================
# SECURITY HEADERS MIDDLEWARE TESTS
# ============================================================================

class TestSecurityHeadersMiddlewareCoverage:
    """Test SecurityHeadersMiddleware for complete coverage."""
    
    @pytest.mark.asyncio
    async def test_security_headers_https_detection(self):
        """Test security headers - HTTPS detection."""
        from starlette.requests import Request as StarletteRequest
        
        mock_request = Mock(spec=StarletteRequest)
        mock_request.url = Mock()
        mock_request.url.scheme = 'https'
        mock_request.url.path = '/test'
        mock_request.headers = {}
        
        mock_response = Mock()
        mock_response.headers = {}
        
        async def mock_call_next(request):
            return mock_response
        
        middleware = SecurityHeadersMiddleware(app=app)
        
        with patch.dict(os.environ, {'HSTS_MAX_AGE': '31536000'}):
            response = await middleware.dispatch(mock_request, mock_call_next)
            
            assert 'Strict-Transport-Security' in response.headers
    
    @pytest.mark.asyncio
    async def test_security_headers_https_via_forwarded_proto(self):
        """Test security headers - HTTPS via X-Forwarded-Proto."""
        from starlette.requests import Request as StarletteRequest
        
        mock_request = Mock(spec=StarletteRequest)
        mock_request.url = Mock()
        mock_request.url.scheme = 'http'
        mock_request.url.path = '/test'
        mock_request.headers = {'x-forwarded-proto': 'https'}
        
        mock_response = Mock()
        mock_response.headers = {}
        
        async def mock_call_next(request):
            return mock_response
        
        middleware = SecurityHeadersMiddleware(app=app)
        
        response = await middleware.dispatch(mock_request, mock_call_next)
        
        assert 'Strict-Transport-Security' in response.headers
    
    @pytest.mark.asyncio
    async def test_security_headers_hsts_max_age_negative(self):
        """Test security headers - HSTS max_age negative value."""
        from starlette.requests import Request as StarletteRequest
        
        mock_request = Mock(spec=StarletteRequest)
        mock_request.url = Mock()
        mock_request.url.scheme = 'https'
        mock_request.url.path = '/test'
        mock_request.headers = {}
        
        mock_response = Mock()
        mock_response.headers = {}
        
        async def mock_call_next(request):
            return mock_response
        
        middleware = SecurityHeadersMiddleware(app=app)
        
        with patch.dict(os.environ, {'HSTS_MAX_AGE': '-100'}):
            response = await middleware.dispatch(mock_request, mock_call_next)
            
            # Should use default 31536000
            assert 'Strict-Transport-Security' in response.headers
            assert 'max-age=31536000' in response.headers['Strict-Transport-Security']
    
    @pytest.mark.asyncio
    async def test_security_headers_hsts_max_age_too_large(self):
        """Test security headers - HSTS max_age too large."""
        from starlette.requests import Request as StarletteRequest
        
        mock_request = Mock(spec=StarletteRequest)
        mock_request.url = Mock()
        mock_request.url.scheme = 'https'
        mock_request.url.path = '/test'
        mock_request.headers = {}
        
        mock_response = Mock()
        mock_response.headers = {}
        
        async def mock_call_next(request):
            return mock_response
        
        middleware = SecurityHeadersMiddleware(app=app)
        
        with patch.dict(os.environ, {'HSTS_MAX_AGE': '100000000'}):
            response = await middleware.dispatch(mock_request, mock_call_next)
            
            # Should cap at 63072000
            assert 'Strict-Transport-Security' in response.headers
            assert 'max-age=63072000' in response.headers['Strict-Transport-Security']
    
    @pytest.mark.asyncio
    async def test_security_headers_hsts_include_subdomains(self):
        """Test security headers - HSTS includeSubDomains."""
        from starlette.requests import Request as StarletteRequest
        
        mock_request = Mock(spec=StarletteRequest)
        mock_request.url = Mock()
        mock_request.url.scheme = 'https'
        mock_request.url.path = '/test'
        mock_request.headers = {}
        
        mock_response = Mock()
        mock_response.headers = {}
        
        async def mock_call_next(request):
            return mock_response
        
        middleware = SecurityHeadersMiddleware(app=app)
        
        with patch.dict(os.environ, {'HSTS_INCLUDE_SUBDOMAINS': 'true'}):
            response = await middleware.dispatch(mock_request, mock_call_next)
            
            assert 'includeSubDomains' in response.headers['Strict-Transport-Security']
    
    @pytest.mark.asyncio
    async def test_security_headers_hsts_preload(self):
        """Test security headers - HSTS preload."""
        from starlette.requests import Request as StarletteRequest
        
        mock_request = Mock(spec=StarletteRequest)
        mock_request.url = Mock()
        mock_request.url.scheme = 'https'
        mock_request.url.path = '/test'
        mock_request.headers = {}
        
        mock_response = Mock()
        mock_response.headers = {}
        
        async def mock_call_next(request):
            return mock_response
        
        middleware = SecurityHeadersMiddleware(app=app)
        
        with patch.dict(os.environ, {'HSTS_PRELOAD': 'true'}):
            response = await middleware.dispatch(mock_request, mock_call_next)
            
            assert 'preload' in response.headers['Strict-Transport-Security']
    
    @pytest.mark.asyncio
    async def test_security_headers_csp_docs_endpoint(self):
        """Test security headers - CSP for docs endpoint."""
        from starlette.requests import Request as StarletteRequest
        
        mock_request = Mock(spec=StarletteRequest)
        mock_request.url = Mock()
        mock_request.url.scheme = 'http'
        mock_request.url.path = '/docs'
        mock_request.headers = {}
        
        mock_response = Mock()
        mock_response.headers = {}
        
        async def mock_call_next(request):
            return mock_response
        
        middleware = SecurityHeadersMiddleware(app=app)
        
        response = await middleware.dispatch(mock_request, mock_call_next)
        
        assert 'Content-Security-Policy' in response.headers
        # Docs endpoint should have more permissive CSP
        csp = response.headers['Content-Security-Policy']
        assert 'cdn.jsdelivr.net' in csp
    
    @pytest.mark.asyncio
    async def test_security_headers_csp_custom_policy(self):
        """Test security headers - Custom CSP policy from env."""
        from starlette.requests import Request as StarletteRequest
        
        mock_request = Mock(spec=StarletteRequest)
        mock_request.url = Mock()
        mock_request.url.scheme = 'http'
        mock_request.url.path = '/test'
        mock_request.headers = {}
        
        mock_response = Mock()
        mock_response.headers = {}
        
        async def mock_call_next(request):
            return mock_response
        
        middleware = SecurityHeadersMiddleware(app=app)
        
        with patch.dict(os.environ, {'CSP_POLICY': 'default-src \'self\'; script-src \'none\''}):
            response = await middleware.dispatch(mock_request, mock_call_next)
            
            assert response.headers['Content-Security-Policy'] == 'default-src \'self\'; script-src \'none\''


# ============================================================================
# CORS CONFIGURATION TESTS
# ============================================================================

class TestCORSConfigurationCoverage:
    """Test CORS configuration for complete coverage."""
    
    def test_cors_wildcard_rejection(self):
        """Test CORS - wildcard origin rejection."""
        # This is tested during app initialization
        # Check that wildcard is not in allowed origins
        assert '*' not in app.user_middleware[0].kwargs.get('allow_origins', [])
    
    def test_cors_null_rejection(self):
        """Test CORS - null origin rejection."""
        # Check that null is not in allowed origins
        origins = app.user_middleware[0].kwargs.get('allow_origins', [])
        assert 'null' not in origins


# ============================================================================
# CUSTOM OPENAPI TESTS
# ============================================================================

class TestCustomOpenAPICoverage:
    """Test custom OpenAPI generation for complete coverage."""
    
    def test_custom_openapi_with_empty_config(self):
        """Test custom OpenAPI - empty config."""
        with patch('src.main.config_manager', None), \
             patch('src.main.webhook_config_data', {}), \
             patch('src.main.original_openapi') as mock_orig:
            
            mock_orig.return_value = {'openapi': '3.0.0'}
            
            result = custom_openapi()
            
            # Should fallback to original
            assert result == {'openapi': '3.0.0'}


# ============================================================================
# CLEANUP TASK TESTS
# ============================================================================

class TestCleanupTaskCoverage:
    """Test cleanup task for complete coverage."""
    
    @pytest.mark.asyncio
    async def test_cleanup_task_loop(self):
        """Test cleanup task loop execution."""
        mock_rate_limiter = AsyncMock()
        mock_rate_limiter.cleanup_old_entries = AsyncMock()
        
        with patch('src.main.rate_limiter', mock_rate_limiter):
            task = asyncio.create_task(cleanup_task())
            
            # Wait a moment
            await asyncio.sleep(0.1)
            
            # Cancel task
            task.cancel()
            
            try:
                await task
            except asyncio.CancelledError:
                pass
            
            # Should have called cleanup
            assert mock_rate_limiter.cleanup_old_entries.called

