from typing import Any, Dict, Optional, List
import json
import uuid
import re
import asyncio
from datetime import datetime, timezone
import asyncpg
from src.modules.base import BaseModule
from src.utils import sanitize_error_message


class PostgreSQLModule(BaseModule):
    """Module for saving webhook payloads to PostgreSQL database.
    
    Supports three storage modes:
    1. JSON: Store entire payload in JSONB column (default)
    2. Relational: Map payload fields to table columns
    3. Hybrid: Store mapped fields in columns + full payload in JSONB column
    
    The module expects the following configuration in the webhook definition:
    ```json
    {
        "module": "postgresql",
        "connection": "postgres_local",
        "module-config": {
            "table": "webhook_events",
            "storage_mode": "json",
            "upsert": true,
            "upsert_key": "event_id",
            "include_headers": true,
            "include_timestamp": true
        }
    }
    ```
    """
    
    def __init__(self, config: Dict[str, Any], pool_registry=None):
        super().__init__(config, pool_registry)
        self.pool: Optional[asyncpg.Pool] = None
        raw_table_name = self.module_config.get('table', 'webhook_events')
        self.table_name = self._validate_table_name(raw_table_name)
        self.storage_mode = self.module_config.get('storage_mode', 'json')  # json, relational, hybrid
        self.upsert = self.module_config.get('upsert', False)
        self.upsert_key = self.module_config.get('upsert_key', 'id')
        self.include_headers = self.module_config.get('include_headers', True)
        self.include_timestamp = self.module_config.get('include_timestamp', True)
        self.schema = self.module_config.get('schema', {})
        self._table_created = False
    
    def _validate_table_name(self, table_name: str) -> str:
        """
        Validate and sanitize PostgreSQL table name to prevent SQL injection.
        
        Args:
            table_name: The table name from configuration
            
        Returns:
            Validated and sanitized table name
            
        Raises:
            ValueError: If table name is invalid or contains dangerous characters
        """
        if not table_name or not isinstance(table_name, str):
            raise ValueError("Table name must be a non-empty string")
        
        # Remove whitespace
        table_name = table_name.strip()
        
        if not table_name:
            raise ValueError("Table name cannot be empty")
        
        # Maximum length to prevent DoS (PostgreSQL identifier limit is 63 bytes, but we'll be more restrictive)
        if len(table_name) > 63:
            raise ValueError(f"Table name too long: {len(table_name)} characters (max: 63)")
        
        # Validate format: alphanumeric and underscore only
        # PostgreSQL allows quoted identifiers with special chars, but we restrict for security
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', table_name):
            raise ValueError(
                f"Invalid table name format: '{table_name}'. "
                f"Must start with letter or underscore and contain only alphanumeric characters and underscores."
            )
        
        # Reject SQL keywords that could be used in injection
        sql_keywords = [
            'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
            'truncate', 'exec', 'execute', 'union', 'script', '--', ';', '/*', '*/',
            'table', 'database', 'schema', 'user', 'role', 'grant', 'revoke'
        ]
        table_name_lower = table_name.lower()
        for keyword in sql_keywords:
            if table_name_lower == keyword:
                raise ValueError(f"Table name cannot be SQL keyword: '{keyword}'")
        
        # Reject dangerous patterns
        dangerous_patterns = ['..', '--', ';', '/*', '*/', 'xp_', 'sp_', 'pg_']
        for pattern in dangerous_patterns:
            if pattern in table_name_lower:
                raise ValueError(f"Table name contains dangerous pattern: '{pattern}'")
        
        return table_name
    
    def _validate_column_name(self, column_name: str) -> str:
        """
        Validate and sanitize PostgreSQL column name.
        
        Args:
            column_name: The column name to validate
            
        Returns:
            Validated column name
            
        Raises:
            ValueError: If column name is invalid
        """
        if not column_name or not isinstance(column_name, str):
            raise ValueError("Column name must be a non-empty string")
        
        column_name = column_name.strip()
        
        if not column_name:
            raise ValueError("Column name cannot be empty")
        
        if len(column_name) > 63:
            raise ValueError(f"Column name too long: {len(column_name)} characters (max: 63)")
        
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', column_name):
            raise ValueError(
                f"Invalid column name format: '{column_name}'. "
                f"Must start with letter or underscore and contain only alphanumeric characters and underscores."
            )
        
        return column_name
    
    def _validate_hostname(self, hostname: str) -> bool:
        """
        Validate hostname to prevent SSRF attacks.
        
        Args:
            hostname: The hostname to validate
            
        Returns:
            True if hostname is safe, False otherwise
        """
        if not hostname or not isinstance(hostname, str):
            return False
        
        hostname = hostname.strip().lower()
        
        # Block localhost variants
        localhost_variants = [
            'localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]',
            '127.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', '169.254.'
        ]
        
        for variant in localhost_variants:
            if hostname.startswith(variant):
                return False
        
        # Block file:// and other dangerous schemes
        if '://' in hostname:
            return False
        
        # Block metadata endpoints
        if 'metadata.google.internal' in hostname or '169.254.169.254' in hostname:
            return False
        
        return True
    
    def _quote_identifier(self, identifier: str) -> str:
        """
        Quote PostgreSQL identifier to prevent injection.
        
        Args:
            identifier: The identifier to quote
            
        Returns:
            Quoted identifier safe for use in SQL
        """
        # PostgreSQL uses double quotes for identifier quoting
        # Escape double quotes in the identifier
        escaped = identifier.replace('"', '""')
        return f'"{escaped}"'
    
    def _get_pg_type(self, field_type: str) -> str:
        """
        Map field type to PostgreSQL type.
        
        Args:
            field_type: The field type (string, integer, float, boolean, datetime, json)
            
        Returns:
            PostgreSQL type name
        """
        type_mapping = {
            'string': 'TEXT',
            'integer': 'BIGINT',
            'float': 'DOUBLE PRECISION',
            'boolean': 'BOOLEAN',
            'datetime': 'TIMESTAMP WITH TIME ZONE',
            'json': 'JSONB',
            'text': 'TEXT',
            'int': 'BIGINT',
            'number': 'DOUBLE PRECISION',
            'bool': 'BOOLEAN',
            'date': 'DATE',
            'time': 'TIME',
            'timestamp': 'TIMESTAMP WITH TIME ZONE'
        }
        
        return type_mapping.get(field_type.lower(), 'TEXT')
    
    async def setup(self) -> None:
        """Initialize PostgreSQL connection pool."""
        if not self.connection_details:
            raise Exception("PostgreSQL connection details not found")
        
        # Support both connection string and individual parameters
        connection_string = self.connection_details.get('connection_string')
        
        if connection_string:
            # Validate connection string doesn't contain dangerous patterns
            if not isinstance(connection_string, str):
                raise ValueError("Connection string must be a string")
            
            # Basic validation - don't expose connection string in errors
            try:
                # Parse connection string to extract hostname for SSRF check
                # Format: postgresql://user:pass@host:port/db
                if connection_string.startswith('postgresql://') or connection_string.startswith('postgres://'):
                    parts = connection_string.split('@')
                    if len(parts) > 1:
                        host_part = parts[1].split('/')[0].split(':')[0]
                        if not self._validate_hostname(host_part):
                            raise ValueError("Invalid or unsafe hostname in connection string")
            except Exception as e:
                raise ValueError("Invalid connection string format")
        else:
            # Build connection string from individual parameters
            host = self.connection_details.get('host', 'localhost')
            port = self.connection_details.get('port', 5432)
            database = self.connection_details.get('database', 'postgres')
            user = self.connection_details.get('user', 'postgres')
            password = self.connection_details.get('password', '')
            
            # SSRF prevention: validate hostname
            if not self._validate_hostname(host):
                raise ValueError("Invalid or unsafe hostname")
            
            # Build connection string
            if password:
                connection_string = f"postgresql://{user}:{password}@{host}:{port}/{database}"
            else:
                connection_string = f"postgresql://{user}@{host}:{port}/{database}"
        
        # SSL configuration
        ssl_config = {}
        if self.connection_details.get('ssl', False):
            ssl_config['ssl'] = 'require'
            if self.connection_details.get('ssl_ca_cert'):
                ssl_config['sslrootcert'] = self.connection_details.get('ssl_ca_cert')
            if self.connection_details.get('ssl_cert'):
                ssl_config['sslcert'] = self.connection_details.get('ssl_cert')
            if self.connection_details.get('ssl_key'):
                ssl_config['sslkey'] = self.connection_details.get('ssl_key')
        
        try:
            # Create connection pool
            min_size = self.connection_details.get('pool_min_size', 2)
            max_size = self.connection_details.get('pool_max_size', 10)
            
            self.pool = await asyncpg.create_pool(
                connection_string,
                min_size=min_size,
                max_size=max_size,
                **ssl_config
            )
            
            # Test connection
            async with self.pool.acquire() as conn:
                await conn.fetchval('SELECT 1')
            
            # Ensure table exists
            await self._ensure_table()
        except Exception as e:
            # Log detailed error server-side
            print(f"Failed to connect to PostgreSQL: {e}")
            # Raise generic error to client (don't expose connection details)
            raise Exception(sanitize_error_message(e, "PostgreSQL connection"))
    
    async def _ensure_table(self) -> None:
        """Ensure the webhook events table exists."""
        if self._table_created:
            return
        
        try:
            quoted_table_name = self._quote_identifier(self.table_name)
            
            if self.storage_mode == 'json':
                # JSON mode: simple table with JSONB column
                create_table_query = f"""
                CREATE TABLE IF NOT EXISTS {quoted_table_name} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    webhook_id TEXT NOT NULL,
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    payload JSONB NOT NULL,
                    headers JSONB,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                )
                """
                
                # Create unique index on JSONB path for upsert if configured
                if self.upsert and self.upsert_key:
                    # Create GIN index on payload for efficient JSONB queries
                    index_query = f"""
                    CREATE INDEX IF NOT EXISTS {quoted_table_name}_payload_gin 
                    ON {quoted_table_name} USING GIN (payload)
                    """
                    async with self.pool.acquire() as conn:
                        await conn.execute(index_query)
            elif self.storage_mode == 'relational':
                # Relational mode: create columns from schema
                if not self.schema or 'fields' not in self.schema:
                    raise ValueError("Relational mode requires schema definition with fields")
                
                columns = [
                    "id UUID PRIMARY KEY DEFAULT gen_random_uuid()",
                    "webhook_id TEXT NOT NULL",
                    "created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP"
                ]
                
                for field_name, field_config in self.schema['fields'].items():
                    column_name = self._validate_column_name(field_config.get('column', field_name))
                    column_type = self._get_pg_type(field_config.get('type', 'string'))
                    constraints = field_config.get('constraints', [])
                    
                    column_def = f"{self._quote_identifier(column_name)} {column_type}"
                    
                    # Add constraints
                    for constraint in constraints:
                        if constraint.upper() in ['NOT NULL', 'UNIQUE', 'PRIMARY KEY']:
                            column_def += f" {constraint.upper()}"
                    
                    columns.append(column_def)
                
                create_table_query = f"""
                CREATE TABLE IF NOT EXISTS {quoted_table_name} (
                    {', '.join(columns)}
                )
                """
            else:  # hybrid mode
                # Hybrid mode: columns + JSONB payload
                columns = [
                    "id UUID PRIMARY KEY DEFAULT gen_random_uuid()",
                    "webhook_id TEXT NOT NULL",
                    "payload JSONB NOT NULL",
                    "created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP"
                ]
                
                # Add headers column if configured
                if self.include_headers:
                    columns.append("headers JSONB")
                
                if self.schema and 'fields' in self.schema:
                    for field_name, field_config in self.schema['fields'].items():
                        column_name = self._validate_column_name(field_config.get('column', field_name))
                        column_type = self._get_pg_type(field_config.get('type', 'string'))
                        constraints = field_config.get('constraints', [])
                        
                        column_def = f"{self._quote_identifier(column_name)} {column_type}"
                        
                        for constraint in constraints:
                            if constraint.upper() in ['NOT NULL', 'UNIQUE']:
                                column_def += f" {constraint.upper()}"
                        
                        columns.append(column_def)
                
                create_table_query = f"""
                CREATE TABLE IF NOT EXISTS {quoted_table_name} (
                    {', '.join(columns)}
                )
                """
            
            async with self.pool.acquire() as conn:
                await conn.execute(create_table_query)
            
            # Create indexes if specified
            if self.schema and 'indexes' in self.schema:
                for index_name, index_config in self.schema['indexes'].items():
                    index_columns = index_config.get('columns', [])
                    if index_columns:
                        quoted_columns = ', '.join([self._quote_identifier(col) for col in index_columns])
                        quoted_index_name = self._quote_identifier(index_name)
                        index_query = f"""
                        CREATE INDEX IF NOT EXISTS {quoted_index_name} 
                        ON {quoted_table_name} ({quoted_columns})
                        """
                        async with self.pool.acquire() as conn:
                            await conn.execute(index_query)
            
            self._table_created = True
        except Exception as e:
            print(f"Failed to create PostgreSQL table: {e}")
            # Don't raise - table might already exist, but log the error
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Save webhook payload and headers to PostgreSQL."""
        if not self.pool:
            await self.setup()
        
        try:
            # Get webhook_id from config
            webhook_id = self.config.get('_webhook_id', 'unknown')
            
            # Prepare timestamp
            timestamp = datetime.now(timezone.utc)
            
            quoted_table_name = self._quote_identifier(self.table_name)
            
            if self.storage_mode == 'json':
                # JSON mode: insert payload as JSONB
                payload_json = json.dumps(payload) if not isinstance(payload, str) else payload
                headers_json = json.dumps(headers) if self.include_headers else None
                
                if self.upsert and self.upsert_key:
                    # Upsert mode: check if upsert key exists in payload
                    upsert_value = payload.get(self.upsert_key) if isinstance(payload, dict) else None
                    
                    if upsert_value:
                        # Use a CTE to check existence and update or insert
                        query = f"""
                        WITH existing AS (
                            SELECT id FROM {quoted_table_name}
                            WHERE payload->>$5 = $6
                            LIMIT 1
                        ),
                        inserted AS (
                            INSERT INTO {quoted_table_name} (webhook_id, timestamp, payload, headers)
                            SELECT $1, $2, $3::jsonb, $4::jsonb
                            WHERE NOT EXISTS (SELECT 1 FROM existing)
                            RETURNING id
                        )
                        UPDATE {quoted_table_name}
                        SET webhook_id = $1,
                            timestamp = $2,
                            payload = $3::jsonb,
                            headers = $4::jsonb
                        WHERE id IN (SELECT id FROM existing)
                        """
                        async with self.pool.acquire() as conn:
                            await conn.execute(query, webhook_id, timestamp, payload_json, headers_json, self.upsert_key, str(upsert_value))
                    else:
                        # Regular insert if upsert key not found
                        query = f"""
                        INSERT INTO {quoted_table_name} (webhook_id, timestamp, payload, headers)
                        VALUES ($1, $2, $3::jsonb, $4::jsonb)
                        """
                        async with self.pool.acquire() as conn:
                            await conn.execute(query, webhook_id, timestamp, payload_json, headers_json)
                else:
                    # Regular insert
                    query = f"""
                    INSERT INTO {quoted_table_name} (webhook_id, timestamp, payload, headers)
                    VALUES ($1, $2, $3::jsonb, $4::jsonb)
                    """
                    async with self.pool.acquire() as conn:
                        await conn.execute(query, webhook_id, timestamp, payload_json, headers_json)
            
            elif self.storage_mode == 'relational':
                # Relational mode: map fields to columns
                if not self.schema or 'fields' not in self.schema:
                    raise ValueError("Relational mode requires schema definition")
                
                columns = ['webhook_id']
                values = [webhook_id]
                placeholders = ['$1']
                param_index = 2
                
                for field_name, field_config in self.schema['fields'].items():
                    column_name = field_config.get('column', field_name)
                    # Get value from payload
                    value = payload.get(field_name) if isinstance(payload, dict) else None
                    
                    # Apply default if value is None
                    if value is None and 'default' in field_config:
                        default = field_config['default']
                        if default == 'CURRENT_TIMESTAMP':
                            value = timestamp
                        else:
                            value = default
                    
                    columns.append(self._quote_identifier(column_name))
                    values.append(value)
                    placeholders.append(f'${param_index}')
                    param_index += 1
                
                columns_str = ', '.join(columns)
                placeholders_str = ', '.join(placeholders)
                
                if self.upsert and self.upsert_key:
                    # Find upsert key column
                    upsert_col = None
                    for field_name, field_config in self.schema['fields'].items():
                        if field_name == self.upsert_key:
                            upsert_col = self._quote_identifier(field_config.get('column', field_name))
                            break
                    
                    if upsert_col:
                        # Build UPDATE clause
                        update_clauses = []
                        for i, col in enumerate(columns[1:], start=2):  # Skip webhook_id
                            update_clauses.append(f"{col} = EXCLUDED.{col}")
                        
                        query = f"""
                        INSERT INTO {quoted_table_name} ({columns_str})
                        VALUES ({placeholders_str})
                        ON CONFLICT ({upsert_col})
                        DO UPDATE SET {', '.join(update_clauses)}
                        """
                    else:
                        query = f"""
                        INSERT INTO {quoted_table_name} ({columns_str})
                        VALUES ({placeholders_str})
                        """
                else:
                    query = f"""
                    INSERT INTO {quoted_table_name} ({columns_str})
                    VALUES ({placeholders_str})
                    """
                
                async with self.pool.acquire() as conn:
                    await conn.execute(query, *values)
            
            else:  # hybrid mode
                # Hybrid mode: columns + JSONB payload
                payload_json = json.dumps(payload) if not isinstance(payload, str) else payload
                headers_json = json.dumps(headers) if self.include_headers else None
                
                columns = ['webhook_id', 'payload']
                values = [webhook_id, payload_json]
                placeholders = ['$1', '$2']
                param_index = 3
                
                # Add headers column if configured
                if self.include_headers:
                    columns.append('headers')
                    values.append(headers_json)
                    placeholders.append(f'${param_index}')
                    param_index += 1
                
                if self.schema and 'fields' in self.schema:
                    for field_name, field_config in self.schema['fields'].items():
                        column_name = field_config.get('column', field_name)
                        value = payload.get(field_name) if isinstance(payload, dict) else None
                        
                        if value is None and 'default' in field_config:
                            default = field_config['default']
                            if default == 'CURRENT_TIMESTAMP':
                                value = timestamp
                            else:
                                value = default
                        
                        columns.append(self._quote_identifier(column_name))
                        values.append(value)
                        placeholders.append(f'${param_index}')
                        param_index += 1
                
                columns_str = ', '.join(columns)
                placeholders_str = ', '.join(placeholders)
                
                if self.upsert and self.upsert_key:
                    upsert_col = None
                    if self.schema and 'fields' in self.schema:
                        for field_name, field_config in self.schema['fields'].items():
                            if field_name == self.upsert_key:
                                upsert_col = self._quote_identifier(field_config.get('column', field_name))
                                break
                    
                    if upsert_col:
                        update_clauses = []
                        for i, col in enumerate(columns[1:], start=2):
                            update_clauses.append(f"{col} = EXCLUDED.{col}")
                        
                        query = f"""
                        INSERT INTO {quoted_table_name} ({columns_str})
                        VALUES ({placeholders_str})
                        ON CONFLICT ({upsert_col})
                        DO UPDATE SET {', '.join(update_clauses)}
                        """
                    else:
                        query = f"""
                        INSERT INTO {quoted_table_name} ({columns_str})
                        VALUES ({placeholders_str})
                        """
                else:
                    query = f"""
                    INSERT INTO {quoted_table_name} ({columns_str})
                    VALUES ({placeholders_str})
                    """
                
                async with self.pool.acquire() as conn:
                    await conn.execute(query, *values)
            
            print(f"Saved webhook to PostgreSQL table '{self.table_name}'")
        except Exception as e:
            # Log the error but do not crash the webhook processing
            print(f"Failed to save to PostgreSQL: {e}")
            raise  # Re-raise to allow retry mechanism to handle it
    
    async def teardown(self) -> None:
        """Close PostgreSQL connection pool."""
        if self.pool:
            try:
                await self.pool.close()
            except Exception:
                pass

