"""Tests for MySQL module."""
import pytest
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch
from src.modules.mysql import MySQLModule


class TestMySQLModule:
    """Test MySQL module functionality."""
    
    @pytest.fixture
    def mock_pool(self):
        """Create a mock aiomysql pool."""
        pool = AsyncMock()
        conn = AsyncMock()
        cur = AsyncMock()
        
        # Create a proper async context manager for acquire()
        acquire_ctx = MagicMock()
        acquire_ctx.__aenter__ = AsyncMock(return_value=conn)
        acquire_ctx.__aexit__ = AsyncMock(return_value=None)
        pool.acquire = MagicMock(return_value=acquire_ctx)
        
        # Create cursor context manager
        cursor_ctx = MagicMock()
        cursor_ctx.__aenter__ = AsyncMock(return_value=cur)
        cursor_ctx.__aexit__ = AsyncMock(return_value=None)
        conn.cursor = MagicMock(return_value=cursor_ctx)
        
        cur.execute = AsyncMock(return_value=None)
        cur.fetchone = AsyncMock(return_value=None)
        cur.fetchall = AsyncMock(return_value=[])
        conn.commit = AsyncMock(return_value=None)
        
        pool.close = MagicMock()
        pool.wait_closed = AsyncMock(return_value=None)
        
        return pool
    
    @pytest.fixture
    def basic_config(self):
        """Basic module configuration."""
        return {
            'connection_details': {
                'host': 'db.example.com',  # Use public hostname to pass SSRF check
                'port': 3306,
                'database': 'test_db',
                'user': 'test_user',
                'password': 'test_pass'
            },
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'json'
            },
            '_webhook_id': 'test_webhook'
        }
    
    def test_validate_table_name_valid(self):
        """Test table name validation with valid names."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'valid_table_name'}
        }
        module = MySQLModule(config)
        assert module.table_name == 'valid_table_name'
    
    def test_validate_table_name_invalid_characters(self):
        """Test table name validation rejects invalid characters."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'invalid-table-name'}
        }
        with pytest.raises(ValueError, match="Invalid table name format"):
            MySQLModule(config)
    
    def test_validate_table_name_sql_keyword(self):
        """Test table name validation rejects SQL keywords."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'select'}
        }
        with pytest.raises(ValueError, match="SQL keyword"):
            MySQLModule(config)
    
    def test_validate_table_name_too_long(self):
        """Test table name validation rejects names that are too long."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'a' * 65}
        }
        with pytest.raises(ValueError, match="too long"):
            MySQLModule(config)
    
    def test_validate_column_name_valid(self):
        """Test column name validation with valid names."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'test_table'}
        }
        module = MySQLModule(config)
        assert module._validate_column_name('valid_column') == 'valid_column'
    
    def test_validate_hostname_blocks_localhost(self):
        """Test hostname validation blocks localhost (but allows private IPs for internal networks)."""
        # Save original value and ensure localhost is blocked for this test
        original_value = os.environ.get("ALLOW_LOCALHOST_FOR_TESTS")
        try:
            # Explicitly set to false to ensure localhost is blocked
            os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = "false"
            
            config = {
                'connection_details': {},
                'module-config': {'table': 'test_table'}
            }
            module = MySQLModule(config)
            assert module._validate_hostname('localhost') is False
            assert module._validate_hostname('127.0.0.1') is False
            # Private IPs are now allowed for internal network usage
            assert module._validate_hostname('192.168.1.1') is True
            assert module._validate_hostname('10.0.0.1') is True
            # Still block link-local addresses
            assert module._validate_hostname('169.254.1.1') is False
        finally:
            # Restore original value
            if original_value is None:
                os.environ.pop("ALLOW_LOCALHOST_FOR_TESTS", None)
            else:
                os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = original_value
    
    def test_validate_hostname_allows_public(self):
        """Test hostname validation allows public hostnames."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'test_table'}
        }
        module = MySQLModule(config)
        assert module._validate_hostname('example.com') is True
        assert module._validate_hostname('db.example.com') is True
    
    def test_get_mysql_type_mapping(self):
        """Test MySQL type mapping."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'test_table'}
        }
        module = MySQLModule(config)
        assert module._get_mysql_type('string') == 'TEXT'
        assert module._get_mysql_type('integer') == 'BIGINT'
        assert module._get_mysql_type('float') == 'DOUBLE'
        assert module._get_mysql_type('boolean') == 'BOOLEAN'
        assert module._get_mysql_type('datetime') == 'DATETIME'
        assert module._get_mysql_type('json') == 'JSON'
    
    @pytest.mark.asyncio
    async def test_setup_creates_pool(self, basic_config, mock_pool):
        """Test setup creates connection pool."""
        async def create_pool(*args, **kwargs):
            return mock_pool
        
        with patch('aiomysql.create_pool', side_effect=create_pool):
            module = MySQLModule(basic_config)
            await module.setup()
            assert module.pool == mock_pool
    
    @pytest.mark.asyncio
    async def test_setup_validates_hostname(self, basic_config):
        """Test setup validates hostname for SSRF prevention."""
        # Save original value and ensure localhost is blocked for this test
        original_value = os.environ.get("ALLOW_LOCALHOST_FOR_TESTS")
        try:
            # Explicitly set to false to ensure localhost is blocked
            os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = "false"
            
            basic_config['connection_details']['host'] = '127.0.0.1'
            module = MySQLModule(basic_config)
            with pytest.raises(ValueError, match="Invalid or unsafe hostname"):
                await module.setup()
        finally:
            # Restore original value
            if original_value is None:
                os.environ.pop("ALLOW_LOCALHOST_FOR_TESTS", None)
            else:
                os.environ["ALLOW_LOCALHOST_FOR_TESTS"] = original_value
    
    @pytest.mark.asyncio
    async def test_process_json_mode(self, basic_config, mock_pool):
        """Test process in JSON mode."""
        module = MySQLModule(basic_config)
        module.pool = mock_pool
        module._table_created = True
        
        payload = {'event': 'test', 'data': {'key': 'value'}}
        headers = {'Content-Type': 'application/json'}
        
        await module.process(payload, headers)
        
        # Verify execute was called
        assert mock_pool.acquire.return_value.__aenter__.return_value.cursor.return_value.__aenter__.return_value.execute.called
    
    @pytest.mark.asyncio
    async def test_process_relational_mode(self, basic_config, mock_pool):
        """Test process in relational mode."""
        basic_config['module-config'] = {
            'table': 'webhook_events',
            'storage_mode': 'relational',
            'schema': {
                'fields': {
                    'event_id': {'type': 'string', 'column': 'event_id'},
                    'user_id': {'type': 'integer', 'column': 'user_id'}
                }
            }
        }
        
        module = MySQLModule(basic_config)
        module.pool = mock_pool
        module._table_created = True
        
        payload = {'event_id': 'evt_123', 'user_id': 456}
        headers = {}
        
        await module.process(payload, headers)
        
        # Verify execute was called
        assert mock_pool.acquire.return_value.__aenter__.return_value.cursor.return_value.__aenter__.return_value.execute.called
    
    @pytest.mark.asyncio
    async def test_process_hybrid_mode(self, basic_config, mock_pool):
        """Test process in hybrid mode."""
        basic_config['module-config'] = {
            'table': 'webhook_events',
            'storage_mode': 'hybrid',
            'include_headers': True,
            'schema': {
                'fields': {
                    'event_id': {'type': 'string', 'column': 'event_id'}
                }
            }
        }
        
        module = MySQLModule(basic_config)
        module.pool = mock_pool
        module._table_created = True
        
        payload = {'event_id': 'evt_123', 'extra': 'data'}
        headers = {'X-Custom': 'header'}
        
        await module.process(payload, headers)
        
        # Verify execute was called
        assert mock_pool.acquire.return_value.__aenter__.return_value.cursor.return_value.__aenter__.return_value.execute.called
    
    @pytest.mark.asyncio
    async def test_process_upsert_json_mode(self, basic_config, mock_pool):
        """Test process with upsert in JSON mode."""
        basic_config['module-config'] = {
            'table': 'webhook_events',
            'storage_mode': 'json',
            'upsert': True,
            'upsert_key': 'event_id'
        }
        
        module = MySQLModule(basic_config)
        module.pool = mock_pool
        module._table_created = True
        
        payload = {'event_id': 'evt_123', 'data': 'test'}
        headers = {}
        
        await module.process(payload, headers)
        
        # Verify execute was called
        assert mock_pool.acquire.return_value.__aenter__.return_value.cursor.return_value.__aenter__.return_value.execute.called
    
    @pytest.mark.asyncio
    async def test_teardown_closes_pool(self, basic_config, mock_pool):
        """Test teardown closes connection pool."""
        module = MySQLModule(basic_config)
        module.pool = mock_pool
        
        await module.teardown()
        
        mock_pool.close.assert_called_once()
        mock_pool.wait_closed.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_ensure_table_json_mode(self, basic_config, mock_pool):
        """Test table creation in JSON mode."""
        module = MySQLModule(basic_config)
        module.pool = mock_pool
        
        await module._ensure_table()
        
        # Verify table creation query was executed
        assert mock_pool.acquire.return_value.__aenter__.return_value.cursor.return_value.__aenter__.return_value.execute.called
        assert module._table_created is True
    
    @pytest.mark.asyncio
    async def test_ensure_table_relational_mode(self, basic_config, mock_pool):
        """Test table creation in relational mode."""
        basic_config['module-config'] = {
            'table': 'webhook_events',
            'storage_mode': 'relational',
            'schema': {
                'fields': {
                    'event_id': {'type': 'string', 'column': 'event_id', 'constraints': ['NOT NULL']},
                    'user_id': {'type': 'integer', 'column': 'user_id'}
                }
            }
        }
        
        module = MySQLModule(basic_config)
        module.pool = mock_pool
        
        await module._ensure_table()
        
        # Verify table creation query was executed
        assert mock_pool.acquire.return_value.__aenter__.return_value.cursor.return_value.__aenter__.return_value.execute.called
        assert module._table_created is True
    
    def test_quote_identifier(self, basic_config):
        """Test identifier quoting."""
        module = MySQLModule(basic_config)
        assert module._quote_identifier('test_table') == '`test_table`'
        assert module._quote_identifier('test`table') == '`test``table`'
    
    @pytest.mark.asyncio
    async def test_ensure_table_creates_indexes_after_table(self, basic_config, mock_pool):
        """Test that indexes are created AFTER table exists (not before)."""
        # Configure with schema that includes indexes
        basic_config['module-config'] = {
            'table': 'webhook_events',
            'storage_mode': 'relational',
            'schema': {
                'fields': {
                    'event_id': {'type': 'string', 'column': 'event_id', 'constraints': ['NOT NULL']},
                    'user_id': {'type': 'integer', 'column': 'user_id'}
                },
                'indexes': {
                    'idx_event_id': {'columns': ['event_id']},
                    'idx_user_id': {'columns': ['user_id']}
                }
            }
        }
        
        module = MySQLModule(basic_config)
        module.pool = mock_pool
        
        # Track the order of execute calls
        execute_calls = []
        original_execute = mock_pool.acquire.return_value.__aenter__.return_value.cursor.return_value.__aenter__.return_value.execute
        
        async def track_execute(query):
            execute_calls.append(query)
            return await original_execute(query)
        
        mock_pool.acquire.return_value.__aenter__.return_value.cursor.return_value.__aenter__.return_value.execute = track_execute
        
        await module._ensure_table()
        
        # Verify table was created first
        assert len(execute_calls) >= 1
        table_queries = [q for q in execute_calls if 'CREATE TABLE' in q.upper()]
        assert len(table_queries) > 0
        
        # Verify indexes were created after table
        index_queries = [q for q in execute_calls if 'CREATE INDEX' in q.upper()]
        if len(index_queries) > 0:
            # Find the position of first table creation and first index creation
            first_table_pos = next(i for i, q in enumerate(execute_calls) if 'CREATE TABLE' in q.upper())
            first_index_pos = next(i for i, q in enumerate(execute_calls) if 'CREATE INDEX' in q.upper())
            assert first_table_pos < first_index_pos, "Index creation should happen after table creation"
        
        assert module._table_created is True
    
    @pytest.mark.asyncio
    async def test_index_name_validation_and_quoting(self, basic_config, mock_pool):
        """Test that index names are properly validated and quoted."""
        basic_config['module-config'] = {
            'table': 'webhook_events',
            'storage_mode': 'relational',
            'schema': {
                'fields': {
                    'event_id': {'type': 'string', 'column': 'event_id'}
                },
                'indexes': {
                    'idx_event_id': {'columns': ['event_id']}
                }
            }
        }
        
        module = MySQLModule(basic_config)
        module.pool = mock_pool
        
        execute_calls = []
        original_execute = mock_pool.acquire.return_value.__aenter__.return_value.cursor.return_value.__aenter__.return_value.execute
        
        async def track_execute(query):
            execute_calls.append(query)
            return await original_execute(query)
        
        mock_pool.acquire.return_value.__aenter__.return_value.cursor.return_value.__aenter__.return_value.execute = track_execute
        
        await module._ensure_table()
        
        # Find the index creation query
        index_queries = [q for q in execute_calls if 'CREATE INDEX' in q.upper()]
        assert len(index_queries) > 0
        
        index_query = index_queries[0]
        # Verify index name is properly quoted (MySQL uses backticks)
        assert '`idx_event_id`' in index_query
        # Verify it references the table (which should be quoted)
        assert '`webhook_events`' in index_query
        # Verify it references the column (which should be quoted)
        assert '`event_id`' in index_query

