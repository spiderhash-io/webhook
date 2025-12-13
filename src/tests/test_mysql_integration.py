"""
Integration tests for mysql.py module.
Tests cover missing coverage areas including connection pool creation, query execution, and transaction handling.
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from src.modules.mysql import MySQLModule


class TestMySQLModuleConnectionPool:
    """Test MySQL connection pool creation and error handling."""
    
    @pytest.mark.asyncio
    async def test_setup_with_valid_config(self):
        """Test setup with valid MySQL configuration."""
        config = {
            'module-config': {
                'table': 'webhooks',
                'mode': 'columns'
            },
            'connection_details': {
                'host': 'db.example.org',
                'port': 3306,
                'user': 'test',
                'password': 'test',
                'database': 'testdb'
            }
        }
        
        module = MySQLModule(config)
        
        # Patch hostname validation to allow our test hostname
        with patch.object(module, '_validate_hostname', return_value=True):
            mock_conn = AsyncMock()
            mock_cursor = AsyncMock()
            mock_cursor.execute = AsyncMock()
            mock_cursor.fetchone = AsyncMock()
            mock_cursor.__aenter__ = AsyncMock(return_value=mock_cursor)
            mock_cursor.__aexit__ = AsyncMock(return_value=False)
            mock_conn.cursor = Mock(return_value=mock_cursor)
            mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_conn.__aexit__ = AsyncMock(return_value=False)
            
            mock_pool = Mock()
            mock_pool.acquire = Mock(return_value=mock_conn)
            
            async def create_pool_mock(*args, **kwargs):
                return mock_pool
            
            with patch('src.modules.mysql.aiomysql.create_pool', side_effect=create_pool_mock):
                await module.setup()
                
                assert module.pool == mock_pool
    
    @pytest.mark.asyncio
    async def test_setup_with_connection_error(self):
        """Test setup with connection error."""
        config = {
            'module-config': {
                'table': 'webhooks',
                'mode': 'columns'
            },
            'connection_details': {
                'host': 'invalid-host',
                'port': 3306,
                'user': 'test',
                'password': 'test',
                'database': 'testdb'
            }
        }
        
        module = MySQLModule(config)
        
        with patch('src.modules.mysql.aiomysql.create_pool', side_effect=Exception("Connection failed")):
            with pytest.raises(Exception):
                await module.setup()


class TestMySQLModuleQueryExecution:
    """Test MySQL query execution."""
    
    @pytest.mark.asyncio
    async def test_process_with_columns_mode(self):
        """Test process with columns mode."""
        config = {
            'module-config': {
                'table': 'webhooks',
                'mode': 'columns',
                'schema': {
                    'fields': {
                        'id': {'column': 'webhook_id', 'type': 'string'},
                        'data': {'column': 'payload_data', 'type': 'string'}
                    }
                }
            },
            'connection_details': {
                'host': 'localhost',
                'port': 3306,
                'user': 'test',
                'password': 'test',
                'database': 'testdb'
            }
        }
        
        module = MySQLModule(config)
        
        mock_conn = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.execute = AsyncMock()
        mock_cursor.__aenter__ = AsyncMock(return_value=mock_cursor)
        mock_cursor.__aexit__ = AsyncMock(return_value=False)
        mock_conn.cursor = Mock(return_value=mock_cursor)
        mock_conn.commit = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        
        mock_pool = Mock()
        mock_pool.acquire = Mock(return_value=mock_conn)
        module.pool = mock_pool
        
        payload = {'id': 'test123', 'data': 'test data'}
        headers = {}
        
        await module.process(payload, headers)
        
        mock_cursor.execute.assert_called()
    
    @pytest.mark.asyncio
    async def test_process_with_json_mode(self):
        """Test process with JSON mode."""
        config = {
            'module-config': {
                'table': 'webhooks',
                'mode': 'json'
            },
            'connection_details': {
                'host': 'localhost',
                'port': 3306,
                'user': 'test',
                'password': 'test',
                'database': 'testdb'
            }
        }
        
        module = MySQLModule(config)
        
        mock_conn = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.execute = AsyncMock()
        mock_cursor.__aenter__ = AsyncMock(return_value=mock_cursor)
        mock_cursor.__aexit__ = AsyncMock(return_value=False)
        mock_conn.cursor = Mock(return_value=mock_cursor)
        mock_conn.commit = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        
        mock_pool = Mock()
        mock_pool.acquire = Mock(return_value=mock_conn)
        module.pool = mock_pool
        
        payload = {'id': 'test123', 'data': 'test data'}
        headers = {}
        
        await module.process(payload, headers)
        
        mock_cursor.execute.assert_called()
    
    @pytest.mark.asyncio
    async def test_process_with_hybrid_mode(self):
        """Test process with hybrid mode."""
        config = {
            'module-config': {
                'table': 'webhooks',
                'mode': 'hybrid',
                'schema': {
                    'fields': {
                        'id': {'column': 'webhook_id', 'type': 'string'}
                    }
                }
            },
            'connection_details': {
                'host': 'localhost',
                'port': 3306,
                'user': 'test',
                'password': 'test',
                'database': 'testdb'
            }
        }
        
        module = MySQLModule(config)
        
        mock_conn = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.execute = AsyncMock()
        mock_cursor.__aenter__ = AsyncMock(return_value=mock_cursor)
        mock_cursor.__aexit__ = AsyncMock(return_value=False)
        mock_conn.cursor = Mock(return_value=mock_cursor)
        mock_conn.commit = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        
        mock_pool = Mock()
        mock_pool.acquire = Mock(return_value=mock_conn)
        module.pool = mock_pool
        
        payload = {'id': 'test123', 'data': 'test data'}
        headers = {}
        
        await module.process(payload, headers)
        
        mock_cursor.execute.assert_called()


class TestMySQLModuleValidation:
    """Test MySQL validation methods."""
    
    def test_validate_index_name_valid(self):
        """Test validate_index_name with valid name."""
        config = {'module-config': {}}
        module = MySQLModule(config)
        
        result = module._validate_index_name('idx_webhook_id')
        assert result == 'idx_webhook_id'
    
    def test_validate_index_name_invalid_format(self):
        """Test validate_index_name with invalid format."""
        config = {'module-config': {}}
        module = MySQLModule(config)
        
        with pytest.raises(ValueError, match="Invalid index name format"):
            module._validate_index_name('invalid-index-name')
    
    def test_validate_index_name_sql_keyword(self):
        """Test validate_index_name with SQL keyword."""
        config = {'module-config': {}}
        module = MySQLModule(config)
        
        with pytest.raises(ValueError, match="SQL keyword"):
            module._validate_index_name('SELECT')
    
    def test_validate_index_name_dangerous_pattern(self):
        """Test validate_index_name with dangerous pattern."""
        config = {'module-config': {}}
        module = MySQLModule(config)
        
        with pytest.raises(ValueError, match="dangerous pattern"):
            module._validate_index_name('idx_xp_cmdshell')
    
    def test_validate_index_name_too_long(self):
        """Test validate_index_name with too long name."""
        config = {'module-config': {}}
        module = MySQLModule(config)
        
        long_name = 'a' * 65
        with pytest.raises(ValueError, match="too long"):
            module._validate_index_name(long_name)


class TestMySQLModuleErrorHandling:
    """Test MySQL error handling."""
    
    @pytest.mark.asyncio
    async def test_process_with_pool_error(self):
        """Test process when pool acquisition fails."""
        config = {
            'module-config': {
                'table': 'webhooks',
                'mode': 'json'
            },
            'connection_details': {}
        }
        
        module = MySQLModule(config)
        
        mock_pool = AsyncMock()
        mock_pool.acquire = AsyncMock(side_effect=Exception("Pool exhausted"))
        module.pool = mock_pool
        
        with pytest.raises(Exception):
            await module.process({'data': 'test'}, {})
    
    @pytest.mark.asyncio
    async def test_process_with_query_error(self):
        """Test process when query execution fails."""
        config = {
            'module-config': {
                'table': 'webhooks',
                'mode': 'json'
            },
            'connection_details': {}
        }
        
        module = MySQLModule(config)
        
        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.execute = AsyncMock(side_effect=Exception("Query failed"))
        mock_cursor.__aenter__ = AsyncMock(return_value=mock_cursor)
        mock_cursor.__aexit__ = AsyncMock(return_value=False)
        mock_conn.cursor = Mock(return_value=mock_cursor)
        mock_conn.commit = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        mock_pool.acquire = AsyncMock(return_value=mock_conn)
        module.pool = mock_pool
        
        with pytest.raises(Exception):
            await module.process({'data': 'test'}, {})

