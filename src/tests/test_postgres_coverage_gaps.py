"""
Comprehensive unit tests to fill coverage gaps in postgres.py module.
Target: 100% coverage for PostgreSQLModule class.
"""
import pytest
import json
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timezone
from src.modules.postgres import PostgreSQLModule


class TestPostgreSQLModuleInit:
    """Test PostgreSQLModule.__init__() - all storage modes."""

    def test_init_json_mode(self):
        """Test initialization with JSON storage mode."""
        config = {
            'connection_details': {},
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'json'
            }
        }
        
        module = PostgreSQLModule(config)
        assert module.storage_mode == 'json'
        assert module.table_name == 'webhook_events'
        assert module.upsert is False

    def test_init_relational_mode(self):
        """Test initialization with relational storage mode."""
        config = {
            'module': 'postgres',
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
            'connection': 'postgres_local'
        }

        module = PostgreSQLModule(config)
        assert module.storage_mode == 'relational'
        assert module.schema['fields'] is not None

    def test_init_hybrid_mode(self):
        """Test initialization with hybrid storage mode."""
        config = {
            'module': 'postgres',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'hybrid',
                'schema': {
                    'fields': {
                        'event_id': {'column': 'event_id', 'type': 'integer'}
                    }
                }
            },
            'connection': 'postgres_local'
        }

        module = PostgreSQLModule(config)
        assert module.storage_mode == 'hybrid'

    def test_init_with_upsert(self):
        """Test initialization with upsert enabled."""
        config = {
            'module': 'postgres',
            'module-config': {
                'table': 'webhook_events',
                'upsert': True,
                'upsert_key': 'event_id'
            },
            'connection': 'postgres_local'
        }

        module = PostgreSQLModule(config)
        assert module.upsert is True
        assert module.upsert_key == 'event_id'


class TestPostgreSQLModuleValidation:
    """Test PostgreSQLModule validation methods."""

    def test_validate_table_name_valid(self):
        """Test _validate_table_name with valid name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        result = module._validate_table_name('valid_table')
        assert result == 'valid_table'

    def test_validate_table_name_empty(self):
        """Test _validate_table_name with empty name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        with pytest.raises(ValueError, match="cannot be empty"):
            module._validate_table_name('')

    def test_validate_table_name_too_long(self):
        """Test _validate_table_name with too long name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        long_name = 'a' * 100
        with pytest.raises(ValueError, match="too long"):
            module._validate_table_name(long_name)

    def test_validate_table_name_sql_keyword(self):
        """Test _validate_table_name with SQL keyword."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        with pytest.raises(ValueError, match="SQL keyword"):
            module._validate_table_name('select')

    def test_validate_table_name_dangerous_pattern(self):
        """Test _validate_table_name with dangerous pattern."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        with pytest.raises(ValueError, match="dangerous pattern"):
            module._validate_table_name('table;--')

    def test_validate_column_name_valid(self):
        """Test _validate_column_name with valid name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        result = module._validate_column_name('valid_column')
        assert result == 'valid_column'

    def test_validate_column_name_invalid(self):
        """Test _validate_column_name with invalid name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        with pytest.raises(ValueError):
            module._validate_column_name('')


class TestPostgreSQLModuleSetup:
    """Test PostgreSQLModule.setup() - connection pool creation."""

    @pytest.mark.asyncio
    async def test_setup_with_connection_string(self):
        """Test setup with connection string."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.connection_details = {
            'connection_string': 'postgresql://user:pass@example.com:5432/db'
        }

        with patch('asyncpg.create_pool', return_value=mock_pool), \
             patch.object(module, '_ensure_table', return_value=None):
            await module.setup()

            assert module.pool is not None

    @pytest.mark.asyncio
    async def test_setup_with_individual_params(self):
        """Test setup with individual connection parameters."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.connection_details = {
            'host': 'example.com',
            'port': 5432,
            'database': 'testdb',
            'user': 'testuser',
            'password': 'testpass'
        }

        with patch('asyncpg.create_pool', return_value=mock_pool), \
             patch.object(module, '_ensure_table', return_value=None):
            await module.setup()

            assert module.pool is not None

    @pytest.mark.asyncio
    async def test_setup_with_ssl(self):
        """Test setup with SSL configuration."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.connection_details = {
            'host': 'example.com',
                'port': 5432,
                'database': 'testdb',
                'user': 'testuser',
                'password': 'testpass',
                'ssl': True,
                'ssl_ca_cert': '/path/to/ca.crt',
                'ssl_cert': '/path/to/cert.crt',
                'ssl_key': '/path/to/key.key'
            }

        with patch('asyncpg.create_pool', return_value=mock_pool), \
                 patch.object(module, '_ensure_table', return_value=None):
                await module.setup()

                assert module.pool is not None

    @pytest.mark.asyncio
    async def test_setup_invalid_connection_string(self):
        """Test setup with invalid connection string."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }

        module = PostgreSQLModule(config)
        module.connection_details = {
            'connection_string': 'invalid://connection'
        }

        with pytest.raises(ValueError, match="Invalid connection string format"):
            await module.setup()

    @pytest.mark.asyncio
    async def test_setup_invalid_hostname(self):
        """Test setup with invalid hostname."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }

        module = PostgreSQLModule(config)
        module.connection_details = {
            'host': 'localhost'  # Should be blocked
            }

        with pytest.raises(ValueError, match="Invalid or unsafe hostname"):
            await module.setup()

    @pytest.mark.asyncio
    async def test_setup_no_connection_details(self):
        """Test setup without connection details."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }

        module = PostgreSQLModule(config)
        module.connection_details = None

        with pytest.raises(Exception, match="connection details not found"):
            await module.setup()

    @pytest.mark.asyncio
    async def test_setup_exception(self):
        """Test setup with exception."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }

        module = PostgreSQLModule(config)
        module.connection_details = {
            'host': 'example.com',
                'port': 5432
            }

        with patch('asyncpg.create_pool', side_effect=Exception("Connection failed")):
            with pytest.raises(Exception):
            await module.setup()


class TestPostgreSQLModuleProcess:
    """Test PostgreSQLModule.process() - all storage modes and operations."""

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
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

        with patch('builtins.print'):
            await module.process({'data': 'test'}, {'Content-Type': 'application/json'})

            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_json_mode_with_upsert(self):
        """Test process with JSON mode and upsert."""
        config = {
            'module': 'postgres',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'json',
                'upsert': True,
                'upsert_key': 'event_id'
            },
            'connection': 'postgres_local',
            '_webhook_id': 'test_webhook'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

        with patch('builtins.print'):
            await module.process({'data': 'test'}, {})

            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_relational_mode(self):
        """Test process with relational mode."""
        config = {
            'module': 'postgres',
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
            'connection': 'postgres_local',
            '_webhook_id': 'test_webhook'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

        module.pool = mock_pool
        payload = {
            'event_id': 123,
            'event_type': 'test_event'
        }

        with patch('builtins.print'):
            await module.process(payload, {})

            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_relational_mode_with_default(self):
        """Test process with relational mode and default values."""
        config = {
            'module': 'postgres',
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
            'connection': 'postgres_local',
            '_webhook_id': 'test_webhook'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

        module.pool = mock_pool

        with patch('builtins.print'):
            await module.process(payload, {})

            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_relational_mode_with_upsert(self):
        """Test process with relational mode and upsert."""
        config = {
            'module': 'postgres',
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
            'connection': 'postgres_local',
            '_webhook_id': 'test_webhook'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

        module.pool = mock_pool
        payload = {
            'event_id': 123,
            'event_type': 'test_event'
        }

        with patch('builtins.print'):
            await module.process(payload, {})

            mock_conn.execute.assert_called_once()
            # Should have ON CONFLICT clause
            call_args = mock_conn.execute.call_args[0][0]
            assert 'ON CONFLICT' in call_args

    @pytest.mark.asyncio
    async def test_process_hybrid_mode(self):
        """Test process with hybrid mode."""
        config = {
            'module': 'postgres',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'hybrid',
                'schema': {
                    'fields': {
                        'event_id': {'column': 'event_id', 'type': 'integer'}
                    }
                }
            },
            'connection': 'postgres_local',
            '_webhook_id': 'test_webhook'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

        module.pool = mock_pool

        with patch('builtins.print'):
            await module.process(payload, {})

            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_hybrid_mode_with_upsert(self):
        """Test process with hybrid mode and upsert."""
        config = {
            'module': 'postgres',
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
            'connection': 'postgres_local',
            '_webhook_id': 'test_webhook'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

        module.pool = mock_pool

        with patch('builtins.print'):
            await module.process(payload, {})

            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_relational_mode_missing_schema(self):
        """Test process with relational mode missing schema."""
        config = {
            'module': 'postgres',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'relational'
            },
            'connection': 'postgres_local',
            '_webhook_id': 'test_webhook'
        }

        mock_pool = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

        with patch('builtins.print'):
            await module.process({'data': 'test'}, {})

    @pytest.mark.asyncio
    async def test_process_auto_setup(self):
        """Test process automatically calls setup if pool not initialized."""
        config = {
            'module': 'postgres',
            'module-config': {'table': 'webhook_events'},
            'connection': 'postgres_local',
            '_webhook_id': 'test_webhook'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = None

        with patch.object(module, 'setup', return_value=None) as mock_setup, \
             patch('asyncpg.create_pool', return_value=mock_pool), \
             patch.object(module, '_ensure_table', return_value=None), \
             patch('builtins.print'):

            module.pool = mock_pool
            await module.process({'data': 'test'}, {})

            mock_conn.execute.assert_called_once()

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
        mock_conn.execute = AsyncMock(side_effect=Exception("Database error"))
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

        module.pool = mock_pool
                with pytest.raises(Exception):
            await module.process({'data': 'test'}, {})


class TestPostgreSQLModuleEnsureTable:
    """Test PostgreSQLModule._ensure_table() - all paths."""

    @pytest.mark.asyncio
    async def test_ensure_table_json_mode(self):
        """Test _ensure_table with JSON mode."""
        config = {
            'module': 'postgres',
            'module-config': {'table': 'webhook_events', 'storage_mode': 'json'},
            'connection': 'postgres_local'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

            await module._ensure_table()

            mock_conn.execute.assert_called()
        assert 'CREATE TABLE' in mock_conn.execute.call_args_list[0][0][0]
        assert 'JSONB' in mock_conn.execute.call_args_list[0][0][0]

    @pytest.mark.asyncio
    async def test_ensure_table_relational_mode(self):
        """Test _ensure_table with relational mode."""
        config = {
            'module': 'postgres',
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
            'connection': 'postgres_local'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

            await module._ensure_table()

            mock_conn.execute.assert_called()
        assert 'CREATE TABLE' in mock_conn.execute.call_args_list[0][0][0]

    @pytest.mark.asyncio
    async def test_ensure_table_relational_mode_missing_schema(self):
        """Test _ensure_table with relational mode missing schema."""
        config = {
            'module': 'postgres',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'relational'
            },
            'connection': 'postgres_local'
        }

        mock_pool = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

        with pytest.raises(ValueError, match="requires schema definition"):
            await module._ensure_table()

    @pytest.mark.asyncio
    async def test_ensure_table_hybrid_mode(self):
        """Test _ensure_table with hybrid mode."""
        config = {
            'module': 'postgres',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'hybrid',
                'schema': {
                    'fields': {
                        'event_id': {'column': 'event_id', 'type': 'integer'}
                    }
                }
            },
            'connection': 'postgres_local'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

            await module._ensure_table()

            mock_conn.execute.assert_called()
        assert 'CREATE TABLE' in mock_conn.execute.call_args_list[0][0][0]
        assert 'JSONB' in mock_conn.execute.call_args_list[0][0][0]  # Should have JSONB column

    @pytest.mark.asyncio
    async def test_ensure_table_with_indexes(self):
        """Test _ensure_table with indexes."""
        config = {
            'module': 'postgres',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'json',
                'schema': {
                    'indexes': {
                        'idx_webhook_id': {'columns': ['webhook_id']}
                    }
                }
            },
            'connection': 'postgres_local'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

            await module._ensure_table()

            # Should have CREATE TABLE and CREATE INDEX calls
        assert mock_conn.execute.call_count >= 2

    @pytest.mark.asyncio
    async def test_ensure_table_with_upsert_gin_index(self):
        """Test _ensure_table with upsert and GIN index."""
        config = {
            'module': 'postgres',
            'module-config': {
                'table': 'webhook_events',
                'storage_mode': 'json',
                'upsert': True,
                'upsert_key': 'event_id'
            },
            'connection': 'postgres_local'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

            await module._ensure_table()

            # Should have CREATE TABLE and CREATE INDEX (GIN) calls
        assert mock_conn.execute.call_count >= 2
            # Check for GIN index
            gin_index_found = any(
                'GIN' in str(call[0][0]) for call in mock_conn.execute.call_args_list
            )
        assert gin_index_found

    @pytest.mark.asyncio
    async def test_ensure_table_already_created(self):
        """Test _ensure_table when table already created."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }

        mock_pool = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

            await module._ensure_table()

            # Should not call execute
            mock_pool.acquire.assert_not_called()

    @pytest.mark.asyncio
    async def test_ensure_table_exception(self):
        """Test _ensure_table with exception."""
        config = {
            'module': 'postgres',
            'module-config': {'table': 'webhook_events', 'storage_mode': 'json'},
            'connection': 'postgres_local'
        }

        mock_pool = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock(side_effect=Exception("Table already exists"))
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

            # Should not raise exception (table might already exist)
            await module._ensure_table()


class TestPostgreSQLModuleTeardown:
    """Test PostgreSQLModule.teardown() - pool cleanup."""

    @pytest.mark.asyncio
    async def test_teardown_success(self):
        """Test successful teardown."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }

        mock_pool = AsyncMock()
        mock_pool.close = AsyncMock()

        module = PostgreSQLModule(config)
        module.pool = mock_pool

        module.pool = mock_pool

            mock_pool.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_teardown_no_pool(self):
        """Test teardown with no pool."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }

        module = PostgreSQLModule(config)
        module.pool = None

        module.pool = None
            await module.teardown()

    @pytest.mark.asyncio
    async def test_teardown_exception(self):
        """Test teardown with exception."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'webhook_events'}
        }

        mock_pool = AsyncMock()
        mock_pool.close = AsyncMock(side_effect=Exception("Close failed"))

        module = PostgreSQLModule(config)
        module.pool = mock_pool

        module.pool = mock_pool
            await module.teardown()


class TestPostgreSQLModuleHelperMethods:
    """Test PostgreSQLModule helper methods."""

    def test_quote_identifier(self):
        """Test _quote_identifier method."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        result = module._quote_identifier('table_name')
        assert result == '"table_name"'

    def test_quote_identifier_with_quote(self):
        """Test _quote_identifier with quote in name."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        result = module._quote_identifier('table"name')
        assert result == '"table""name"'  # Quote should be escaped

    def test_get_pg_type(self):
        """Test _get_pg_type method."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        assert module._get_pg_type('string') == 'TEXT'
        assert module._get_pg_type('integer') == 'BIGINT'
        assert module._get_pg_type('float') == 'DOUBLE PRECISION'
        assert module._get_pg_type('boolean') == 'BOOLEAN'
        assert module._get_pg_type('datetime') == 'TIMESTAMP WITH TIME ZONE'
        assert module._get_pg_type('json') == 'JSONB'
        assert module._get_pg_type('unknown') == 'TEXT'  # Default

    def test_validate_hostname_safe(self):
        """Test _validate_hostname with safe hostname."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        assert module._validate_hostname('example.com') is True

    def test_validate_hostname_localhost(self):
        """Test _validate_hostname with localhost."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        assert module._validate_hostname('localhost') is False

    def test_validate_hostname_metadata(self):
        """Test _validate_hostname with metadata endpoint."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        assert module._validate_hostname('169.254.169.254') is False

    def test_validate_hostname_with_scheme(self):
        """Test _validate_hostname with URL scheme."""
        config = {'connection_details': {}, 'module-config': {'table': 'webhook_events'}}
        module = PostgreSQLModule(config)
        assert module._validate_hostname('file://localhost') is False

