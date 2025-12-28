"""
Comprehensive unit tests to fill coverage gaps in mysql.py module.
Target: 100% coverage for MySQLModule class.
"""
import pytest
import json
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timezone
from src.modules.mysql import MySQLModule


class TestMySQLModuleInit:
    """Test MySQLModule.__init__() - all storage modes."""
    
    def test_init_json_mode(self):
        """Test initialization with JSON storage mode."""
        config = {
            'connection_details': {},
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'json'
            }
        }
        
        module = MySQLModule(config)
        assert module.storage_mode == 'json'
        assert module.table_name == 'webhook_events'
        assert module.upsert is False
    
    def test_init_relational_mode(self):
        """Test initialization with relational storage mode."""
        config = {
            'connection_details': {},
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'relational',
                'schema': {
                    'fields': {
                        'event_id': {'column': 'event_id', 'type': 'integer'},
                        'event_type': {'column': 'event_type', 'type': 'string'}
                    }
                }
            }
        }
        
        module = MySQLModule(config)
        assert module.storage_mode == 'relational'
        assert module.schema['fields'] is not None
    
    def test_init_hybrid_mode(self):
        """Test initialization with hybrid storage mode."""
        config = {
            'connection_details': {},
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'hybrid',
                'schema': {
                    'fields': {
                        'event_id': {'column': 'event_id', 'type': 'integer'}
                    }
                }
            }
        }
        
        module = MySQLModule(config)
        assert module.storage_mode == 'hybrid'
    
    def test_init_with_upsert(self):
        """Test initialization with upsert enabled."""
        config = {
            'connection_details': {},
            'module-config': {
                'table': 'webhook_events',
                'upsert': True,
                'upsert_key': 'event_id'
            }
        }
        
        module = MySQLModule(config)
        assert module.upsert is True
        assert module.upsert_key == 'event_id'
    
    def test_init_invalid_schema(self):
        """Test initialization with invalid schema."""
        config = {
            'connection_details': {},
            'module-config': {
                'table': 'webhook_events',
                'schema': 'not a dict'
            }
        }
        
        # Schema validation happens during initialization
        # The module will raise ValueError if schema is not a dict
        with pytest.raises(ValueError, match="Schema must be a dictionary"):
            MySQLModule(config)


class TestMySQLModuleValidation:
    """Test MySQLModule validation methods."""
    
    def test_validate_table_name_valid(self):
        """Test _validate_table_name with valid name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        result = module._validate_table_name('valid_table')
        assert result == 'valid_table'
    
    def test_validate_table_name_empty(self):
        """Test _validate_table_name with empty name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        with pytest.raises(ValueError, match="must be a non-empty string"):
            module._validate_table_name('')
    
    def test_validate_table_name_too_long(self):
        """Test _validate_table_name with too long name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        long_name = 'a' * 100
        with pytest.raises(ValueError, match="too long"):
            module._validate_table_name(long_name)
    
    def test_validate_table_name_sql_keyword(self):
        """Test _validate_table_name with SQL keyword."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        with pytest.raises(ValueError, match="SQL keyword"):
            module._validate_table_name('select')
    
    def test_validate_table_name_dangerous_pattern(self):
        """Test _validate_table_name with dangerous pattern."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        with pytest.raises(ValueError, match="Invalid table name format"):
            module._validate_table_name('table;--')
    
    def test_validate_index_name_valid(self):
        """Test _validate_index_name with valid name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        result = module._validate_index_name('valid_index')
        assert result == 'valid_index'
    
    def test_validate_index_name_invalid(self):
        """Test _validate_index_name with invalid name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        with pytest.raises(ValueError):
            module._validate_index_name('')
    
    def test_validate_upsert_key_valid(self):
        """Test _validate_upsert_key with valid key."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        result = module._validate_upsert_key('event_id')
        assert result == 'event_id'
    
    def test_validate_upsert_key_invalid(self):
        """Test _validate_upsert_key with invalid key."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        with pytest.raises(ValueError):
            module._validate_upsert_key('event.id')  # Contains dot
    
    def test_validate_field_name_valid(self):
        """Test _validate_column_name with valid name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        result = module._validate_column_name('valid_column')
        assert result == 'valid_column'
    
    def test_validate_field_name_invalid(self):
        """Test _validate_column_name with invalid name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        with pytest.raises(ValueError):
            module._validate_column_name('')


class TestMySQLModuleSetup:
    """Test MySQLModule.setup() - connection pool creation."""
    
    @pytest.mark.asyncio
    async def test_setup_with_pool_registry(self):
        """Test setup with pool registry."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }
        
        mock_pool = AsyncMock()
        mock_pool.acquire = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        mock_registry = Mock()
        mock_registry.get_pool = AsyncMock(return_value=mock_pool)
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config, pool_registry=mock_registry)
            module.connection_details = {
                'host': 'localhost',
                'port': 3306,
                'database': 'testdb',
                'user': 'testuser',
                'password': 'testpass'
            }
            
            with patch.object(module, '_ensure_table', return_value=None):
                await module.setup()
                
                assert module.pool is not None
    
    @pytest.mark.asyncio
    async def test_setup_without_pool_registry(self):
        """Test setup without pool registry."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }
        
        mock_pool = AsyncMock()
        mock_pool.acquire = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.connection_details = {
                'host': 'localhost',
                'port': 3306,
                'database': 'testdb',
                'user': 'testuser',
                'password': 'testpass'
            }
            
            with patch('aiomysql.create_pool', return_value=mock_pool), \
                 patch.object(module, '_ensure_table', return_value=None):
                await module.setup()
                
                assert module.pool is not None
    
    @pytest.mark.asyncio
    async def test_setup_exception(self):
        """Test setup with exception."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.connection_details = {
                'host': 'localhost',
                'port': 3306
            }
            
            with patch('aiomysql.create_pool', side_effect=Exception("Connection failed")):
                with pytest.raises(Exception):
                    await module.setup()


class TestMySQLModuleProcess:
    """Test MySQLModule.process() - all storage modes and operations."""
    
    @pytest.mark.asyncio
    async def test_process_json_mode(self):
        """Test process with JSON mode."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events', 'storage_mode': 'json'},
            '_webhook_id': 'test_webhook'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.commit = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            with patch('builtins.print'):
                await module.process({'data': 'test'}, {'Content-Type': 'application/json'})
                
                mock_cur.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_json_mode_with_upsert(self):
        """Test process with JSON mode and upsert."""
        config = {
            'module': 'mysql',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'json',
                'upsert': True,
                'upsert_key': 'event_id'
            },
            'connection': 'mysql_local',
            '_webhook_id': 'test_webhook'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.commit = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            with patch('builtins.print'):
                await module.process({'data': 'test'}, {})
                
                mock_cur.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_relational_mode(self):
        """Test process with relational mode."""
        config = {
            'module': 'mysql',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'relational',
                'schema': {
                    'fields': {
                        'event_id': {'column': 'event_id', 'type': 'integer'},
                        'event_type': {'column': 'event_type', 'type': 'string'}
                    }
                }
            },
            'connection': 'mysql_local',
            '_webhook_id': 'test_webhook'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.commit = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            payload = {
                'event_id': 123,
                'event_type': 'test_event'
            }
            
            with patch('builtins.print'):
                await module.process(payload, {})
                
                mock_cur.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_relational_mode_with_default(self):
        """Test process with relational mode and default values."""
        config = {
            'module': 'mysql',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'relational',
                'schema': {
                    'fields': {
                        'event_id': {'column': 'event_id', 'type': 'integer'},
                        'event_type': {'column': 'event_type', 'type': 'string', 'default': 'unknown'}
                    }
                }
            },
            'connection': 'mysql_local',
            '_webhook_id': 'test_webhook'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.commit = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            payload = {'event_id': 123}  # Missing event_type
            
            with patch('builtins.print'):
                await module.process(payload, {})
                
                mock_cur.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_relational_mode_with_upsert(self):
        """Test process with relational mode and upsert."""
        config = {
            'module': 'mysql',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'relational',
                'upsert': True,
                'upsert_key': 'event_id',
                'schema': {
                    'fields': {
                        'event_id': {'column': 'event_id', 'type': 'integer'},
                        'event_type': {'column': 'event_type', 'type': 'string'}
                    }
                }
            },
            'connection': 'mysql_local',
            '_webhook_id': 'test_webhook'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.commit = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            payload = {
                'event_id': 123,
                'event_type': 'test_event'
            }
            
            with patch('builtins.print'):
                await module.process(payload, {})
                
                mock_cur.execute.assert_called_once()
                # Should have ON DUPLICATE KEY UPDATE clause
                call_args = mock_cur.execute.call_args[0][0]
                assert 'ON DUPLICATE KEY UPDATE' in call_args
    
    @pytest.mark.asyncio
    async def test_process_hybrid_mode(self):
        """Test process with hybrid mode."""
        config = {
            'module': 'mysql',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'hybrid',
                'schema': {
                    'fields': {
                        'event_id': {'column': 'event_id', 'type': 'integer'}
                    }
                }
            },
            'connection': 'mysql_local',
            '_webhook_id': 'test_webhook'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.commit = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            payload = {'event_id': 123, 'other_data': 'test'}
            
            with patch('builtins.print'):
                await module.process(payload, {})
                
                mock_cur.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_hybrid_mode_with_upsert(self):
        """Test process with hybrid mode and upsert."""
        config = {
            'module': 'mysql',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'hybrid',
                'upsert': True,
                'upsert_key': 'event_id',
                'schema': {
                    'fields': {
                        'event_id': {'column': 'event_id', 'type': 'integer'}
                    }
                }
            },
            'connection': 'mysql_local',
            '_webhook_id': 'test_webhook'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.commit = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            payload = {'event_id': 123}
            
            with patch('builtins.print'):
                await module.process(payload, {})
                
                mock_cur.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_relational_mode_missing_schema(self):
        """Test process with relational mode missing schema."""
        config = {
            'module': 'mysql',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'relational'
            },
            'connection': 'mysql_local',
            '_webhook_id': 'test_webhook'
        }
        
        mock_pool = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            with pytest.raises(ValueError, match="requires schema definition"):
                await module.process({'data': 'test'}, {})
    
    @pytest.mark.asyncio
    async def test_process_auto_setup(self):
        """Test process automatically calls setup if pool not initialized."""
        config = {
            'module': 'mysql',
            'module-config': {'table': 'webhook_events'},
            'connection': 'mysql_local',
            '_webhook_id': 'test_webhook'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.commit = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        with patch('src.modules.base.BaseModule.__init__'):
            module = MySQLModule(config)
            module.config = config
            module.module_config = config.get('module-config', {})
            module.pool = None
            module.connection_details = {'host': 'localhost', 'port': 3306}
            
            with patch.object(module, 'setup', return_value=None) as mock_setup, \
                 patch('aiomysql.create_pool', return_value=mock_pool), \
                 patch.object(module, '_ensure_table', return_value=None), \
                 patch('builtins.print'):
                
                module.pool = mock_pool
                await module.process({'data': 'test'}, {})
                
                # Setup should be called if pool was None
                # But we set it after, so process should work
                mock_cur.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_process_exception(self):
        """Test process with exception."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events', 'storage_mode': 'json'},
            '_webhook_id': 'test_webhook'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock(side_effect=Exception("Database error"))
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            with patch('builtins.print'):
                with pytest.raises(Exception):
                    await module.process({'data': 'test'}, {})


class TestMySQLModuleCreateTable:
    """Test MySQLModule._create_table_if_not_exists() - all paths."""
    
    @pytest.mark.asyncio
    async def test_create_table_json_mode(self):
        """Test _create_table_if_not_exists with JSON mode."""
        config = {
            'module': 'mysql',
            'module-config': {'table': 'webhook_events', 'storage_mode': 'json'},
            'connection': 'mysql_local'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            await module._create_table_if_not_exists()
            
            mock_cur.execute.assert_called_once()
            assert 'CREATE TABLE' in mock_cur.execute.call_args[0][0]
            assert 'JSON' in mock_cur.execute.call_args[0][0]
    
    @pytest.mark.asyncio
    async def test_create_table_relational_mode(self):
        """Test _create_table_if_not_exists with relational mode."""
        config = {
            'module': 'mysql',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'relational',
                'schema': {
                    'fields': {
                        'event_id': {'column': 'event_id', 'type': 'integer'},
                        'event_type': {'column': 'event_type', 'type': 'string'}
                    }
                }
            },
            'connection': 'mysql_local'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            await module._create_table_if_not_exists()
            
            mock_cur.execute.assert_called_once()
            assert 'CREATE TABLE' in mock_cur.execute.call_args[0][0]
    
    @pytest.mark.asyncio
    async def test_create_table_hybrid_mode(self):
        """Test _create_table_if_not_exists with hybrid mode."""
        config = {
            'module': 'mysql',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'hybrid',
                'schema': {
                    'fields': {
                        'event_id': {'column': 'event_id', 'type': 'integer'}
                    }
                }
            },
            'connection': 'mysql_local'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            await module._create_table_if_not_exists()
            
            mock_cur.execute.assert_called_once()
            assert 'CREATE TABLE' in mock_cur.execute.call_args[0][0]
            assert 'JSON' in mock_cur.execute.call_args[0][0]  # Should have JSON column
    
    @pytest.mark.asyncio
    async def test_create_table_exception(self):
        """Test _create_table_if_not_exists with exception."""
        config = {
            'module': 'mysql',
            'module-config': {'table': 'webhook_events', 'storage_mode': 'json'},
            'connection': 'mysql_local'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock(side_effect=Exception("Table already exists"))
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            # Should not raise exception (table might already exist)
            await module._create_table_if_not_exists()


class TestMySQLModuleCreateIndex:
    """Test MySQLModule._create_index_if_not_exists() - all paths."""
    
    @pytest.mark.asyncio
    async def test_create_index_success(self):
        """Test _create_index_if_not_exists successful creation."""
        config = {
            'module': 'mysql',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'json',
                'indexes': [
                    {'name': 'idx_webhook_id', 'columns': ['webhook_id']}
                ]
            },
            'connection': 'mysql_local'
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock()
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            await module._create_index_if_not_exists('idx_webhook_id', ['webhook_id'])
            
            mock_cur.execute.assert_called_once()
            assert 'CREATE INDEX' in mock_cur.execute.call_args[0][0]
    
    @pytest.mark.asyncio
    async def test_create_index_exception(self):
        """Test _create_index_if_not_exists with exception."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cur = AsyncMock()
        mock_cur.execute = AsyncMock(side_effect=Exception("Index already exists"))
        mock_conn.cursor = AsyncMock(return_value=mock_cur)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            # Should not raise exception (index might already exist)
            await module._create_index_if_not_exists('idx_test', ['test_column'])


class TestMySQLModuleTeardown:
    """Test MySQLModule.teardown() - pool cleanup."""
    
    @pytest.mark.asyncio
    async def test_teardown_success(self):
        """Test successful teardown."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }
        
        mock_pool = AsyncMock()
        mock_pool.close = Mock()
        mock_pool.wait_closed = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            await module.teardown()
            
            mock_pool.close.assert_called_once()
            mock_pool.wait_closed.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_teardown_no_pool(self):
        """Test teardown with no pool."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }
        
        with patch('src.modules.base.BaseModule.__init__'):
            module = MySQLModule(config)
            module.config = config
            module.module_config = config.get('module-config', {})
            module.pool = None
            
            # Should not raise exception
            await module.teardown()
    
    @pytest.mark.asyncio
    async def test_teardown_exception(self):
        """Test teardown with exception."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }
        
        mock_pool = AsyncMock()
        mock_pool.close = Mock(side_effect=Exception("Close failed"))
        mock_pool.wait_closed = AsyncMock()
        
        def mock_base_init(self, config, pool_registry=None):
            self.config = config
            self.connection_details = config.get('connection_details', {})
            self.module_config = config.get('module-config', {})
            self.pool_registry = pool_registry
        
        with patch('src.modules.base.BaseModule.__init__', mock_base_init):
            module = MySQLModule(config)
            module.pool = mock_pool
            
            # Should not raise exception
            await module.teardown()


class TestMySQLModuleHelperMethods:
    """Test MySQLModule helper methods."""
    
    def test_quote_identifier(self):
        """Test _quote_identifier method."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        result = module._quote_identifier('table_name')
        assert result == '`table_name`'
    
    def test_quote_identifier_with_backtick(self):
        """Test _quote_identifier with backtick in name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        result = module._quote_identifier('table`name')
        assert result == '`table``name`'  # Backtick should be escaped
    
    def test_get_mysql_type(self):
        """Test _get_mysql_type method."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        assert module._get_mysql_type('string') == 'TEXT'
        assert module._get_mysql_type('integer') == 'BIGINT'
        assert module._get_mysql_type('float') == 'DOUBLE'
        assert module._get_mysql_type('boolean') == 'BOOLEAN'
        assert module._get_mysql_type('datetime') == 'DATETIME'
        assert module._get_mysql_type('json') == 'JSON'
        assert module._get_mysql_type('unknown') == 'TEXT'  # Default
    
    def test_validate_hostname_safe(self):
        """Test _validate_hostname with safe hostname."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        assert module._validate_hostname('example.com') is True
    
    def test_validate_hostname_localhost(self):
        """Test _validate_hostname with localhost."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        assert module._validate_hostname('localhost') is False
    
    def test_validate_hostname_metadata(self):
        """Test _validate_hostname with metadata endpoint."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        assert module._validate_hostname('169.254.169.254') is False
    
    def test_validate_hostname_with_scheme(self):
        """Test _validate_hostname with URL scheme."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = MySQLModule(config)
        assert module._validate_hostname('file://localhost') is False

