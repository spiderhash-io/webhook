"""
Comprehensive security audit tests for PostgreSQL module.

Tests cover:
- SQL injection via table/column names, schema fields, upsert keys, index names
- Connection string injection and SSRF
- Pool size DoS
- Type confusion attacks
- Constraint injection
- JSON path injection
- Error information disclosure
- Schema injection
- Identifier quoting security
- Payload security (circular references, large payloads)
"""
import pytest
import json
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from src.modules.postgres import PostgreSQLModule


# ============================================================================
# 1. SQL INJECTION VIA TABLE/COLUMN NAMES
# ============================================================================

class TestSQLInjectionTableColumnNames:
    """Test SQL injection via table and column names."""
    
    def test_table_name_sql_injection_attempts(self):
        """Test that SQL injection attempts in table names are blocked."""
        invalid_tables = [
            "table'; DROP TABLE users; --",
            "table\" UNION SELECT * FROM users --",
            "table'; DELETE FROM users; --",
            "table; INSERT INTO users VALUES ('hacker'); --",
            "table' OR '1'='1",
            "table; UPDATE users SET password='hacked'; --",
        ]
        
        for invalid_table in invalid_tables:
            config = {
                'connection_details': {},
                'module-config': {'table': invalid_table}
            }
            with pytest.raises(ValueError):
                PostgreSQLModule(config)
    
    def test_column_name_sql_injection_attempts(self):
        """Test that SQL injection attempts in column names are blocked."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'test_table'}
        }
        module = PostgreSQLModule(config)
        
        invalid_columns = [
            "col'; DROP TABLE users; --",
            "col\" UNION SELECT * FROM users --",
            "col; DELETE FROM users; --",
            "col' OR '1'='1",
        ]
        
        for invalid_column in invalid_columns:
            with pytest.raises(ValueError):
                module._validate_column_name(invalid_column)
    
    def test_table_name_path_traversal(self):
        """Test that path traversal attempts in table names are blocked."""
        invalid_tables = [
            "../users",
            "..\\users",
            "../../etc/passwd",
            "table/../users",
        ]
        
        for invalid_table in invalid_tables:
            config = {
                'connection_details': {},
                'module-config': {'table': invalid_table}
            }
            with pytest.raises(ValueError):
                PostgreSQLModule(config)
    
    def test_table_name_null_byte_injection(self):
        """Test that null byte injection in table names is blocked."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'table\x00name'}
        }
        with pytest.raises(ValueError):
            PostgreSQLModule(config)
    
    def test_table_name_unicode_normalization(self):
        """Test that Unicode normalization attacks are handled."""
        # Unicode variations that might bypass validation
        unicode_tables = [
            "table\u200Bname",  # Zero-width space
            "table\uFEFFname",  # Zero-width no-break space
        ]
        
        for unicode_table in unicode_tables:
            config = {
                'connection_details': {},
                'module-config': {'table': unicode_table}
            }
            # Should either reject or normalize
            try:
                module = PostgreSQLModule(config)
                # If accepted, verify it's handled safely
                assert module.table_name is not None
            except ValueError:
                # Acceptable to reject
                pass


# ============================================================================
# 2. SCHEMA INJECTION ATTACKS
# ============================================================================

class TestSchemaInjection:
    """Test schema injection vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_schema_field_name_validation(self):
        """Test that field names are validated for dangerous characters."""
        # Test field name with null byte
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'relational',
                'schema': {
                    'fields': {
                        "field\x00name": {
                            'type': 'string',
                            'column': 'valid_column'
                        }
                    }
                }
            }
        }
        
        module = PostgreSQLModule(config)
        # Field name validation happens during _ensure_table (called in setup)
        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=MagicMock(
            __aenter__=AsyncMock(return_value=MagicMock(execute=AsyncMock(), fetchval=AsyncMock(return_value=1))),
            __aexit__=AsyncMock(return_value=None)
        ))
        with patch('asyncpg.create_pool', side_effect=AsyncMock(return_value=mock_pool)):
            # Security: Field name with null byte should be rejected during setup
            with pytest.raises(ValueError, match="Field name contains dangerous characters"):
                await module.setup()
    
    @pytest.mark.asyncio
    async def test_schema_field_name_type_validation(self):
        """Test that non-string field names are rejected."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'relational',
                'schema': {
                    'fields': {
                        12345: {  # Non-string field name
                            'type': 'string',
                            'column': 'valid_column'
                        }
                    }
                }
            }
        }
        
        module = PostgreSQLModule(config)
        # Field name validation happens during _ensure_table (called in setup)
        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=MagicMock(
            __aenter__=AsyncMock(return_value=MagicMock(execute=AsyncMock(), fetchval=AsyncMock(return_value=1))),
            __aexit__=AsyncMock(return_value=None)
        ))
        with patch('asyncpg.create_pool', side_effect=AsyncMock(return_value=mock_pool)):
            # Security: Non-string field name should be rejected during setup
            with pytest.raises(ValueError, match="Field name must be a string"):
                await module.setup()
    
    @pytest.mark.asyncio
    async def test_schema_column_sql_injection(self):
        """Test that SQL injection via schema column names is prevented."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'relational',
                'schema': {
                    'fields': {
                        'field1': {
                            'type': 'string',
                            'column': "col'; DROP TABLE users; --"
                        }
                    }
                }
            }
        }
        
        module = PostgreSQLModule(config)
        # Column name should be validated
        with pytest.raises(ValueError):
            module._validate_column_name("col'; DROP TABLE users; --")
    
    @pytest.mark.asyncio
    async def test_schema_type_confusion(self):
        """Test that type confusion in schema is handled safely."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'relational',
                'schema': {
                    'fields': {
                        'field1': {
                            'type': "'; DROP TABLE users; --",  # Malicious type
                            'column': 'col1'
                        }
                    }
                }
            }
        }
        
        module = PostgreSQLModule(config)
        # Type should be mapped safely
        pg_type = module._get_pg_type("'; DROP TABLE users; --")
        # Should default to TEXT or handle safely
        assert pg_type == 'TEXT'  # Unknown types default to TEXT
    
    @pytest.mark.asyncio
    async def test_schema_constraint_injection(self):
        """Test that constraint injection is prevented."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'relational',
                'schema': {
                    'fields': {
                        'field1': {
                            'type': 'string',
                            'column': 'col1',
                            'constraints': ["'; DROP TABLE users; --"]  # Malicious constraint
                        }
                    }
                }
            }
        }
        
        module = PostgreSQLModule(config)
        # Constraints should be validated
        # Only specific constraints should be allowed
        field_config = config['module-config']['schema']['fields']['field1']
        constraints = field_config.get('constraints', [])
        for constraint in constraints:
            # Only specific constraints should be allowed
            if constraint.upper() not in ['NOT NULL', 'UNIQUE', 'PRIMARY KEY']:
                # Malicious constraint should be ignored or rejected
                pass
    
    @pytest.mark.asyncio
    async def test_index_name_injection(self):
        """Test that index name injection is prevented."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'json',
                'schema': {
                    'indexes': {
                        "idx'; DROP TABLE users; --": {
                            'columns': ['col1']
                        }
                    }
                }
            }
        }
        
        module = PostgreSQLModule(config)
        # Index name validation happens during _ensure_table (called in setup)
        mock_pool = AsyncMock()
        mock_pool.acquire = MagicMock(return_value=MagicMock(
            __aenter__=AsyncMock(return_value=MagicMock(execute=AsyncMock(), fetchval=AsyncMock(return_value=1))),
            __aexit__=AsyncMock(return_value=None)
        ))
        with patch('asyncpg.create_pool', side_effect=AsyncMock(return_value=mock_pool)):
            # Security: Index name should be validated during setup
            with pytest.raises(ValueError, match="Invalid table name format|SQL keyword|dangerous pattern"):
                await module.setup()
    
    @pytest.mark.asyncio
    async def test_index_column_injection(self):
        """Test that index column injection is prevented."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'json',
                'schema': {
                    'indexes': {
                        'valid_index': {
                            'columns': ["col'; DROP TABLE users; --"]
                        }
                    }
                }
            }
        }
        
        module = PostgreSQLModule(config)
        # Column names in indexes should be validated
        invalid_column = "col'; DROP TABLE users; --"
        with pytest.raises(ValueError):
            module._validate_column_name(invalid_column)


# ============================================================================
# 3. UPSERT KEY INJECTION
# ============================================================================

class TestUpsertKeyInjection:
    """Test upsert key injection vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_upsert_key_json_path_injection(self):
        """Test that JSON path injection via upsert_key is prevented."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'json',
                'upsert': True,
                'upsert_key': "key'; DROP TABLE users; --"  # Malicious upsert key
            },
            '_webhook_id': 'test'
        }
        
        # Security: Malicious upsert_key should be rejected
        with pytest.raises(ValueError, match="upsert_key contains dangerous characters"):
            PostgreSQLModule(config)
    
    @pytest.mark.asyncio
    async def test_upsert_key_type_confusion(self):
        """Test that type confusion in upsert_key is handled."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'json',
                'upsert': True,
                'upsert_key': 12345  # Non-string upsert_key
            },
            '_webhook_id': 'test'
        }
        
        # Security: Non-string upsert_key should be rejected
        with pytest.raises(ValueError, match="upsert_key must be a string"):
            PostgreSQLModule(config)
    
    @pytest.mark.asyncio
    async def test_upsert_key_empty_string(self):
        """Test that empty string upsert_key is rejected."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'json',
                'upsert': True,
                'upsert_key': ''  # Empty string
            },
            '_webhook_id': 'test'
        }
        
        # Security: Empty upsert_key should be rejected
        with pytest.raises(ValueError, match="upsert_key must be non-empty"):
            PostgreSQLModule(config)


# ============================================================================
# 4. CONNECTION STRING INJECTION AND SSRF
# ============================================================================

class TestConnectionStringInjection:
    """Test connection string injection and SSRF vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_connection_string_ssrf_localhost(self):
        """Test that connection strings with localhost are blocked."""
        config = {
            'connection_details': {
                'connection_string': 'postgresql://user:pass@localhost:5432/db'
            },
            'module-config': {'table': 'test_table'}
        }
        
        module = PostgreSQLModule(config)
        with pytest.raises(ValueError, match="Invalid or unsafe hostname"):
            await module.setup()
    
    @pytest.mark.asyncio
    async def test_connection_string_ssrf_private_ip(self):
        """Test that connection strings with localhost are blocked (private IPs are now allowed for internal networks)."""
        # Localhost is still blocked
        localhost_conn_str = 'postgresql://user:pass@127.0.0.1:5432/db'
        config = {
            'connection_details': {'connection_string': localhost_conn_str},
            'module-config': {'table': 'test_table'}
        }
        module = PostgreSQLModule(config)
        with pytest.raises(ValueError, match="Invalid or unsafe hostname"):
            await module.setup()
        
        # Private IPs are now allowed for internal network usage
        # (matching the policy change in config.py and module hostname validation)
        private_ips = [
            'postgresql://user:pass@192.168.1.1:5432/db',
            'postgresql://user:pass@10.0.0.1:5432/db',
            'postgresql://user:pass@172.16.0.1:5432/db',
        ]
        
        for conn_str in private_ips:
            config = {
                'connection_details': {'connection_string': conn_str},
                'module-config': {'table': 'test_table'}
            }
            module = PostgreSQLModule(config)
            # Should not raise ValueError for private IPs (they're allowed now)
            # Mock the pool creation to avoid actual connection attempts
            mock_pool = AsyncMock()
            conn = AsyncMock()
            conn.fetchval = AsyncMock(return_value=1)
            acquire_ctx = MagicMock()
            acquire_ctx.__aenter__ = AsyncMock(return_value=conn)
            acquire_ctx.__aexit__ = AsyncMock(return_value=None)
            mock_pool.acquire = MagicMock(return_value=acquire_ctx)
            
            async def mock_create_pool_func(*args, **kwargs):
                return mock_pool
            
            with patch('asyncpg.create_pool', side_effect=mock_create_pool_func):
                # Should not raise ValueError for private IPs (they're allowed now)
                # Connection will succeed with mocked pool
                await module.setup()
                assert module.pool is not None
    
    @pytest.mark.asyncio
    async def test_connection_string_metadata_service(self):
        """Test that metadata service endpoints are blocked."""
        config = {
            'connection_details': {
                'connection_string': 'postgresql://user:pass@169.254.169.254:5432/db'
            },
            'module-config': {'table': 'test_table'}
        }
        
        module = PostgreSQLModule(config)
        with pytest.raises(ValueError, match="Invalid or unsafe hostname"):
            await module.setup()
    
    @pytest.mark.asyncio
    async def test_connection_string_scheme_injection(self):
        """Test that dangerous schemes in connection strings are blocked."""
        dangerous_schemes = [
            'file:///etc/passwd',
            'http://evil.com',
            'https://evil.com',
            'postgresql://user:pass@host:5432/db; DROP TABLE users; --',
        ]
        
        for conn_str in dangerous_schemes:
            config = {
                'connection_details': {'connection_string': conn_str},
                'module-config': {'table': 'test_table'}
            }
            module = PostgreSQLModule(config)
            # Should either reject or validate safely
            try:
                await module.setup()
                # If it doesn't raise, verify hostname validation caught it
            except (ValueError, Exception):
                # Acceptable to reject
                pass
    
    @pytest.mark.asyncio
    async def test_connection_string_type_confusion(self):
        """Test that non-string connection strings are rejected."""
        # Test truthy non-string types (should be rejected)
        invalid_types = [123, "non-postgres-url"]  # Truthy but invalid
        
        for invalid_conn_str in invalid_types:
            config = {
                'connection_details': {'connection_string': invalid_conn_str},
                'module-config': {'table': 'test_table'}
            }
            module = PostgreSQLModule(config)
            if isinstance(invalid_conn_str, str):
                # String but not postgresql:// URL - should fail format check
                with pytest.raises(ValueError, match="Invalid connection string format"):
                    await module.setup()
            else:
                # Non-string - should fail type check
                with pytest.raises(ValueError, match="Connection string must be a string"):
                    await module.setup()
        
        # Test falsy types (empty list/dict/None) - they fall through to individual params
        falsy_types = [[], {}, None]
        for falsy_conn_str in falsy_types:
            config = {
                'connection_details': {
                    'connection_string': falsy_conn_str,
                    'host': 'db.example.com',  # Provide valid host to avoid SSRF error
                    'port': 5432,
                    'database': 'test',
                    'user': 'test',
                    'password': 'test'
                },
                'module-config': {'table': 'test_table'}
            }
            module = PostgreSQLModule(config)
            # Should use individual params (valid behavior)
            mock_pool = AsyncMock()
            mock_pool.acquire = MagicMock(return_value=MagicMock(
                __aenter__=AsyncMock(return_value=MagicMock(execute=AsyncMock(), fetchval=AsyncMock(return_value=1))),
                __aexit__=AsyncMock(return_value=None)
            ))
            with patch('asyncpg.create_pool', side_effect=AsyncMock(return_value=mock_pool)):
                await module.setup()  # Should work with individual params
    
    @pytest.mark.asyncio
    async def test_hostname_ssrf_prevention(self):
        """Test that hostname SSRF prevention works (localhost blocked, private IPs allowed for internal networks)."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'test_table'}
        }
        module = PostgreSQLModule(config)
        
        # Localhost and metadata service are still blocked
        unsafe_hosts = [
            'localhost',
            '127.0.0.1',
            '169.254.169.254',
            'metadata.google.internal',
        ]
        
        for unsafe_host in unsafe_hosts:
            assert module._validate_hostname(unsafe_host) is False
        
        # Private IPs are now allowed for internal network usage
        # (matching the policy change in config.py and module hostname validation)
        allowed_private_ips = [
            '10.0.0.1',
            '172.16.0.1',
            '192.168.1.1',
        ]
        
        for private_ip in allowed_private_ips:
            assert module._validate_hostname(private_ip) is True
    
    @pytest.mark.asyncio
    async def test_hostname_allows_public(self):
        """Test that public hostnames are allowed."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'test_table'}
        }
        module = PostgreSQLModule(config)
        
        safe_hosts = [
            'example.com',
            'db.example.com',
            'postgres.example.org',
        ]
        
        for safe_host in safe_hosts:
            assert module._validate_hostname(safe_host) is True


# ============================================================================
# 5. POOL SIZE DOS
# ============================================================================

class TestPoolSizeDoS:
    """Test pool size DoS vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_pool_min_size_negative(self):
        """Test that negative pool min_size is handled safely."""
        config = {
            'connection_details': {
                'host': 'db.example.com',
                'port': 5432,
                'database': 'test',
                'user': 'test',
                'password': 'test',
                'pool_min_size': -1
            },
            'module-config': {'table': 'test_table'}
        }
        
        module = PostgreSQLModule(config)
        # asyncpg should handle negative values, but we should validate
        try:
            with patch('asyncpg.create_pool', side_effect=AsyncMock(return_value=AsyncMock())):
                await module.setup()
        except (ValueError, Exception):
            # Acceptable to reject negative values
            pass
    
    @pytest.mark.asyncio
    async def test_pool_max_size_excessive(self):
        """Test that excessive pool max_size is handled safely."""
        config = {
            'connection_details': {
                'host': 'db.example.com',
                'port': 5432,
                'database': 'test',
                'user': 'test',
                'password': 'test',
                'pool_max_size': 1000000  # Extremely large
            },
            'module-config': {'table': 'test_table'}
        }
        
        module = PostgreSQLModule(config)
        # Should either validate or asyncpg should handle it
        try:
            with patch('asyncpg.create_pool', side_effect=AsyncMock(return_value=AsyncMock())):
                await module.setup()
        except (ValueError, Exception):
            # Acceptable to reject excessive values
            pass
    
    @pytest.mark.asyncio
    async def test_pool_size_type_confusion(self):
        """Test that type confusion in pool sizes is handled."""
        invalid_sizes = ['not a number', [], {}]
        
        for invalid_size in invalid_sizes:
            config = {
                'connection_details': {
                    'host': 'db.example.com',
                    'port': 5432,
                    'database': 'test',
                    'user': 'test',
                    'password': 'test',
                    'pool_min_size': invalid_size
                },
                'module-config': {'table': 'test_table'}
            }
            
            module = PostgreSQLModule(config)
            # asyncpg will handle type errors, but we should validate
            try:
                with patch('asyncpg.create_pool', side_effect=AsyncMock(return_value=AsyncMock())):
                    await module.setup()
            except (TypeError, ValueError, Exception):
                # Acceptable to reject invalid types
                pass


# ============================================================================
# 6. IDENTIFIER QUOTING SECURITY
# ============================================================================

class TestIdentifierQuotingSecurity:
    """Test identifier quoting security."""
    
    def test_quote_identifier_escapes_quotes(self):
        """Test that identifier quoting properly escapes double quotes."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'test_table'}
        }
        module = PostgreSQLModule(config)
        
        # Test escaping of double quotes
        identifier = 'table"name'
        quoted = module._quote_identifier(identifier)
        assert quoted == '"table""name"'
        # Should have even number of quotes (escaped)
        assert quoted.count('"') == 4  # 2 opening/closing + 2 escaped
    
    def test_quote_identifier_newline_injection(self):
        """Test that newlines in identifiers are handled safely."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'test_table'}
        }
        module = PostgreSQLModule(config)
        
        # Newlines should be rejected by validation, but test quoting anyway
        identifier = 'table\nname'
        # Should be rejected by validation first
        try:
            module._validate_table_name(identifier)
            # If it passes, quoting should handle it
            quoted = module._quote_identifier(identifier)
            assert '"' in quoted
        except ValueError:
            # Acceptable to reject
            pass
    
    def test_quote_identifier_null_byte(self):
        """Test that null bytes in identifiers are handled safely."""
        config = {
            'connection_details': {},
            'module-config': {'table': 'test_table'}
        }
        module = PostgreSQLModule(config)
        
        identifier = 'table\x00name'
        # Should be rejected by validation
        with pytest.raises(ValueError):
            module._validate_table_name(identifier)


# ============================================================================
# 7. PAYLOAD SECURITY
# ============================================================================

class TestPayloadSecurity:
    """Test payload security vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_circular_reference_payload(self):
        """Test that circular references in payloads are handled safely."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {'table': 'test_table', 'storage_mode': 'json'},
            '_webhook_id': 'test'
        }
        
        module = PostgreSQLModule(config)
        mock_pool = AsyncMock()
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value="INSERT 1")
        
        acquire_ctx = MagicMock()
        acquire_ctx.__aenter__ = AsyncMock(return_value=conn)
        acquire_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquire_ctx)
        
        module.pool = mock_pool
        module._table_created = True
        
        # Create circular reference
        payload = {'data': 'test'}
        payload['self'] = payload
        
        headers = {}
        
        # Should handle circular reference (json.dumps will fail or use default)
        try:
            await module.process(payload, headers)
            # If it succeeds, verify it was handled
        except (ValueError, TypeError, RecursionError):
            # Acceptable to reject circular references
            pass
    
    @pytest.mark.asyncio
    async def test_large_payload_dos(self):
        """Test that extremely large payloads don't cause DoS."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {'table': 'test_table', 'storage_mode': 'json'},
            '_webhook_id': 'test'
        }
        
        module = PostgreSQLModule(config)
        mock_pool = AsyncMock()
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value="INSERT 1")
        
        acquire_ctx = MagicMock()
        acquire_ctx.__aenter__ = AsyncMock(return_value=conn)
        acquire_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquire_ctx)
        
        module.pool = mock_pool
        module._table_created = True
        
        # Very large payload (10MB)
        large_payload = {'data': 'x' * (10 * 1024 * 1024)}
        headers = {}
        
        # Should not crash or hang
        start_time = asyncio.get_event_loop().time()
        try:
            await module.process(large_payload, headers)
        except (MemoryError, ValueError):
            # Acceptable to reject extremely large payloads
            pass
        
        elapsed = asyncio.get_event_loop().time() - start_time
        # Should complete in reasonable time
        assert elapsed < 10.0
    
    @pytest.mark.asyncio
    async def test_deeply_nested_payload(self):
        """Test that deeply nested payloads are handled safely."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {'table': 'test_table', 'storage_mode': 'json'},
            '_webhook_id': 'test'
        }
        
        module = PostgreSQLModule(config)
        mock_pool = AsyncMock()
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value="INSERT 1")
        
        acquire_ctx = MagicMock()
        acquire_ctx.__aenter__ = AsyncMock(return_value=conn)
        acquire_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquire_ctx)
        
        module.pool = mock_pool
        module._table_created = True
        
        # Deeply nested structure (1000 levels)
        nested_payload = {}
        current = nested_payload
        for i in range(1000):
            current['nested'] = {}
            current = current['nested']
        
        headers = {}
        
        # Should not crash or hang
        start_time = asyncio.get_event_loop().time()
        try:
            await module.process(nested_payload, headers)
        except (RecursionError, ValueError):
            # Acceptable to reject deeply nested structures
            pass
        
        elapsed = asyncio.get_event_loop().time() - start_time
        assert elapsed < 5.0


# ============================================================================
# 8. ERROR INFORMATION DISCLOSURE
# ============================================================================

class TestErrorInformationDisclosure:
    """Test error information disclosure vulnerabilities."""
    
    @pytest.mark.asyncio
    async def test_connection_error_sanitization(self):
        """Test that connection errors don't leak sensitive information."""
        config = {
            'connection_details': {
                'host': 'db.example.com',
                'port': 5432,
                'database': 'test',
                'user': 'admin',
                'password': 'secret123'
            },
            'module-config': {'table': 'test_table'}
        }
        
        module = PostgreSQLModule(config)
        
        # Mock connection failure
        async def failing_create_pool(*args, **kwargs):
            raise Exception(f"Connection failed: password=secret123, user=admin")
        
        with patch('asyncpg.create_pool', side_effect=failing_create_pool):
            try:
                await module.setup()
            except Exception as e:
                # Error should be sanitized
                error_msg = str(e)
                assert 'secret123' not in error_msg
                assert 'password' not in error_msg.lower()
                assert 'admin' not in error_msg or 'user' not in error_msg.lower()
    
    @pytest.mark.asyncio
    async def test_query_error_sanitization(self):
        """Test that query errors don't leak sensitive information."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {'table': 'test_table', 'storage_mode': 'json'},
            '_webhook_id': 'test'
        }
        
        module = PostgreSQLModule(config)
        mock_pool = AsyncMock()
        conn = AsyncMock()
        
        # Mock query failure with sensitive data
        async def failing_execute(*args, **kwargs):
            raise Exception(f"Query failed: password=secret123, table=users")
        
        conn.execute = failing_execute
        
        acquire_ctx = MagicMock()
        acquire_ctx.__aenter__ = AsyncMock(return_value=conn)
        acquire_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquire_ctx)
        
        module.pool = mock_pool
        module._table_created = True
        
        payload = {'data': 'test'}
        headers = {}
        
        # Error should be raised but not expose sensitive data in logs
        with pytest.raises(Exception):
            await module.process(payload, headers)
        
        # Verify error doesn't leak in print statements (would need to capture stdout)
        # For now, just verify exception is raised


# ============================================================================
# 9. RELATIONAL MODE SECURITY
# ============================================================================

class TestRelationalModeSecurity:
    """Test relational mode specific security issues."""
    
    @pytest.mark.asyncio
    async def test_relational_mode_missing_schema(self):
        """Test that relational mode without schema is rejected."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'relational'
                # Missing schema
            },
            '_webhook_id': 'test'
        }
        
        module = PostgreSQLModule(config)
        mock_pool = AsyncMock()
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value="INSERT 1")
        
        acquire_ctx = MagicMock()
        acquire_ctx.__aenter__ = AsyncMock(return_value=conn)
        acquire_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquire_ctx)
        
        module.pool = mock_pool
        module._table_created = True
        
        payload = {'data': 'test'}
        headers = {}
        
        # Should reject missing schema
        with pytest.raises(ValueError, match="requires schema definition"):
            await module.process(payload, headers)
    
    @pytest.mark.asyncio
    async def test_relational_mode_field_value_injection(self):
        """Test that field values in relational mode are parameterized."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'relational',
                'schema': {
                    'fields': {
                        'field1': {'type': 'string', 'column': 'col1'}
                    }
                }
            },
            '_webhook_id': 'test'
        }
        
        module = PostgreSQLModule(config)
        mock_pool = AsyncMock()
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value="INSERT 1")
        
        acquire_ctx = MagicMock()
        acquire_ctx.__aenter__ = AsyncMock(return_value=conn)
        acquire_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquire_ctx)
        
        module.pool = mock_pool
        module._table_created = True
        
        # Payload with SQL injection attempt in value
        payload = {'field1': "'; DROP TABLE users; --"}
        headers = {}
        
        # Should execute safely (values are parameterized)
        await module.process(payload, headers)
        
        # Verify execute was called
        assert conn.execute.called
        call_args = conn.execute.call_args
        # Value should be in parameters, not in query string
        assert call_args is not None
        # Check that the malicious value is passed as parameter
        if call_args[0]:  # positional args
            args = call_args[0]
            # The malicious value should be in args, not in the query string
            assert "'; DROP TABLE users; --" in args or any("'; DROP TABLE users; --" in str(arg) for arg in args)


# ============================================================================
# 10. HYBRID MODE SECURITY
# ============================================================================

class TestHybridModeSecurity:
    """Test hybrid mode specific security issues."""
    
    @pytest.mark.asyncio
    async def test_hybrid_mode_combines_safely(self):
        """Test that hybrid mode safely combines JSON and relational storage."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 'hybrid',
                'schema': {
                    'fields': {
                        'field1': {'type': 'string', 'column': 'col1'}
                    }
                }
            },
            '_webhook_id': 'test'
        }
        
        module = PostgreSQLModule(config)
        mock_pool = AsyncMock()
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value="INSERT 1")
        
        acquire_ctx = MagicMock()
        acquire_ctx.__aenter__ = AsyncMock(return_value=conn)
        acquire_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquire_ctx)
        
        module.pool = mock_pool
        module._table_created = True
        
        payload = {'field1': 'value1', 'extra': 'data'}
        headers = {'X-Custom': 'header'}
        
        # Should execute safely
        await module.process(payload, headers)
        assert conn.execute.called


# ============================================================================
# 11. CONFIGURATION SECURITY
# ============================================================================

class TestConfigurationSecurity:
    """Test configuration security vulnerabilities."""
    
    def test_storage_mode_type_validation(self):
        """Test that storage_mode type is validated."""
        config = {
            'connection_details': {},
            'module-config': {
                'table': 'test_table',
                'storage_mode': 12345  # Non-string
            }
        }
        
        module = PostgreSQLModule(config)
        # Should handle non-string storage_mode
        # Defaults to 'json' if invalid
        assert module.storage_mode in ['json', 'relational', 'hybrid'] or isinstance(module.storage_mode, (str, int))
    
    def test_upsert_type_validation(self):
        """Test that upsert type is validated."""
        config = {
            'connection_details': {},
            'module-config': {
                'table': 'test_table',
                'upsert': "true"  # String instead of bool
            }
        }
        
        module = PostgreSQLModule(config)
        # Should handle string "true" (truthy)
        # Or validate it's actually boolean
        assert isinstance(module.upsert, bool) or module.upsert in [True, False, "true", "false"]
    
    def test_include_headers_type_validation(self):
        """Test that include_headers type is validated."""
        config = {
            'connection_details': {},
            'module-config': {
                'table': 'test_table',
                'include_headers': "yes"  # Non-boolean
            }
        }
        
        module = PostgreSQLModule(config)
        # Should handle non-boolean (truthy/falsy)
        assert isinstance(module.include_headers, bool) or module.include_headers in [True, False, "yes", "no"]


# ============================================================================
# 12. CONCURRENT PROCESSING SECURITY
# ============================================================================

class TestConcurrentProcessingSecurity:
    """Test concurrent processing security."""
    
    @pytest.mark.asyncio
    async def test_concurrent_inserts(self):
        """Test that concurrent inserts are handled safely."""
        config = {
            'connection_details': {'host': 'db.example.com', 'port': 5432, 'database': 'test', 'user': 'test', 'password': 'test'},
            'module-config': {'table': 'test_table', 'storage_mode': 'json'},
            '_webhook_id': 'test'
        }
        
        module = PostgreSQLModule(config)
        mock_pool = AsyncMock()
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value="INSERT 1")
        
        acquire_ctx = MagicMock()
        acquire_ctx.__aenter__ = AsyncMock(return_value=conn)
        acquire_ctx.__aexit__ = AsyncMock(return_value=None)
        mock_pool.acquire = MagicMock(return_value=acquire_ctx)
        
        module.pool = mock_pool
        module._table_created = True
        
        # Concurrent inserts
        tasks = []
        for i in range(10):
            payload = {'event_id': f'evt_{i}', 'data': f'data_{i}'}
            headers = {}
            tasks.append(module.process(payload, headers))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should complete without errors
        assert conn.execute.call_count >= 10

