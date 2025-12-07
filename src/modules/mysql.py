from typing import Any, Dict, Optional, List
import json
import uuid
import re
import asyncio
from datetime import datetime, timezone
import aiomysql
from src.modules.base import BaseModule
from src.utils import sanitize_error_message


class MySQLModule(BaseModule):
    """Module for saving webhook payloads to MySQL/MariaDB database.
    
    Supports three storage modes:
    1. JSON: Store entire payload in JSON column (default)
    2. Relational: Map payload fields to table columns
    3. Hybrid: Store mapped fields in columns + full payload in JSON column
    
    The module expects the following configuration in the webhook definition:
    ```json
    {
        "module": "mysql",
        "connection": "mysql_local",
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
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.pool: Optional[aiomysql.Pool] = None
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
        Validate and sanitize MySQL table name to prevent SQL injection.
        
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
        
        # Maximum length to prevent DoS (MySQL identifier limit is 64 bytes, but we'll be more restrictive)
        if len(table_name) > 64:
            raise ValueError(f"Table name too long: {len(table_name)} characters (max: 64)")
        
        # Validate format: alphanumeric and underscore only
        # MySQL allows backticks for special chars, but we restrict for security
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', table_name):
            raise ValueError(
                f"Invalid table name format: '{table_name}'. "
                f"Must start with letter or underscore and contain only alphanumeric characters and underscores."
            )
        
        # Reject SQL keywords that could be used in injection
        sql_keywords = [
            'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
            'truncate', 'exec', 'execute', 'union', 'script', '--', ';', '/*', '*/',
            'table', 'database', 'schema', 'user', 'role', 'grant', 'revoke',
            'show', 'describe', 'explain', 'use', 'set'
        ]
        table_name_lower = table_name.lower()
        for keyword in sql_keywords:
            if table_name_lower == keyword:
                raise ValueError(f"Table name cannot be SQL keyword: '{keyword}'")
        
        # Reject dangerous patterns
        dangerous_patterns = ['..', '--', ';', '/*', '*/', 'xp_', 'sp_', 'mysql.']
        for pattern in dangerous_patterns:
            if pattern in table_name_lower:
                raise ValueError(f"Table name contains dangerous pattern: '{pattern}'")
        
        return table_name
    
    def _validate_column_name(self, column_name: str) -> str:
        """
        Validate and sanitize MySQL column name.
        
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
        
        if len(column_name) > 64:
            raise ValueError(f"Column name too long: {len(column_name)} characters (max: 64)")
        
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
        Quote MySQL identifier to prevent injection.
        
        Args:
            identifier: The identifier to quote
            
        Returns:
            Quoted identifier safe for use in SQL
        """
        # MySQL uses backticks for identifier quoting
        # Escape backticks in the identifier
        escaped = identifier.replace('`', '``')
        return f"`{escaped}`"
    
    def _get_mysql_type(self, field_type: str) -> str:
        """
        Map field type to MySQL type.
        
        Args:
            field_type: The field type (string, integer, float, boolean, datetime, json)
            
        Returns:
            MySQL type name
        """
        type_mapping = {
            'string': 'TEXT',
            'integer': 'BIGINT',
            'float': 'DOUBLE',
            'boolean': 'BOOLEAN',
            'datetime': 'DATETIME',
            'json': 'JSON',
            'text': 'TEXT',
            'int': 'BIGINT',
            'number': 'DOUBLE',
            'bool': 'BOOLEAN',
            'date': 'DATE',
            'time': 'TIME',
            'timestamp': 'DATETIME'
        }
        
        return type_mapping.get(field_type.lower(), 'TEXT')
    
    async def setup(self) -> None:
        """Initialize MySQL connection pool."""
        if not self.connection_details:
            raise Exception("MySQL connection details not found")
        
        # aiomysql uses individual parameters, not connection strings
        # Build connection from individual parameters
        host = self.connection_details.get('host', 'localhost')
        port = self.connection_details.get('port', 3306)
        database = self.connection_details.get('database', 'mysql')
        user = self.connection_details.get('user', 'root')
        password = self.connection_details.get('password', '')
        
        # SSRF prevention: validate hostname
        if not self._validate_hostname(host):
            raise ValueError("Invalid or unsafe hostname")
        
        # SSL configuration
        ssl_config = {}
        if self.connection_details.get('ssl', False):
            ssl_config['ssl'] = {
                'ca': self.connection_details.get('ssl_ca_cert'),
                'cert': self.connection_details.get('ssl_cert'),
                'key': self.connection_details.get('ssl_key')
            }
        
        # Create connection pool
        min_size = self.connection_details.get('pool_min_size', 2)
        max_size = self.connection_details.get('pool_max_size', 10)
        
        try:
            self.pool = await aiomysql.create_pool(
                host=host,
                port=port,
                db=database,
                user=user,
                password=password,
                minsize=min_size,
                maxsize=max_size,
                **ssl_config
            )
            
            # Test connection
            async with self.pool.acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute('SELECT 1')
                    await cur.fetchone()
            
            # Ensure table exists
            await self._ensure_table()
        except Exception as e:
            # Log detailed error server-side
            print(f"Failed to connect to MySQL: {e}")
            # Raise generic error to client (don't expose connection details)
            raise Exception(sanitize_error_message(e, "MySQL connection"))
    
    async def _ensure_table(self) -> None:
        """Ensure the webhook events table exists."""
        if self._table_created:
            return
        
        try:
            quoted_table_name = self._quote_identifier(self.table_name)
            
            if self.storage_mode == 'json':
                # JSON mode: simple table with JSON column
                create_table_query = f"""
                CREATE TABLE IF NOT EXISTS {quoted_table_name} (
                    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
                    webhook_id TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    payload JSON NOT NULL,
                    headers JSON,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            elif self.storage_mode == 'relational':
                # Relational mode: create columns from schema
                if not self.schema or 'fields' not in self.schema:
                    raise ValueError("Relational mode requires schema definition with fields")
                
                columns = [
                    "id CHAR(36) PRIMARY KEY DEFAULT (UUID())",
                    "webhook_id TEXT NOT NULL",
                    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
                ]
                
                for field_name, field_config in self.schema['fields'].items():
                    column_name = self._validate_column_name(field_config.get('column', field_name))
                    column_type = self._get_mysql_type(field_config.get('type', 'string'))
                    constraints = field_config.get('constraints', [])
                    
                    column_def = f"{self._quote_identifier(column_name)} {column_type}"
                    
                    # Add constraints
                    for constraint in constraints:
                        if constraint.upper() in ['NOT NULL', 'UNIQUE']:
                            column_def += f" {constraint.upper()}"
                    
                    columns.append(column_def)
                
                create_table_query = f"""
                CREATE TABLE IF NOT EXISTS {quoted_table_name} (
                    {', '.join(columns)}
                )
                """
            else:  # hybrid mode
                # Hybrid mode: columns + JSON payload
                columns = [
                    "id CHAR(36) PRIMARY KEY DEFAULT (UUID())",
                    "webhook_id TEXT NOT NULL",
                    "payload JSON NOT NULL",
                    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
                ]
                
                if self.include_headers:
                    columns.append("headers JSON")
                
                if self.schema and 'fields' in self.schema:
                    for field_name, field_config in self.schema['fields'].items():
                        column_name = self._validate_column_name(field_config.get('column', field_name))
                        column_type = self._get_mysql_type(field_config.get('type', 'string'))
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
                async with conn.cursor() as cur:
                    await cur.execute(create_table_query)
                    await conn.commit()
            
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
                            async with conn.cursor() as cur:
                                await cur.execute(index_query)
                                await conn.commit()
            
            self._table_created = True
        except Exception as e:
            print(f"Failed to create MySQL table: {e}")
            # Don't raise - table might already exist, but log the error
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Save webhook payload and headers to MySQL."""
        if not self.pool:
            await self.setup()
        
        try:
            # Get webhook_id from config
            webhook_id = self.config.get('_webhook_id', 'unknown')
            
            # Prepare timestamp
            timestamp = datetime.now(timezone.utc)
            
            quoted_table_name = self._quote_identifier(self.table_name)
            
            if self.storage_mode == 'json':
                # JSON mode: insert payload as JSON
                payload_json = json.dumps(payload) if not isinstance(payload, str) else payload
                headers_json = json.dumps(headers) if self.include_headers else None
                
                if self.upsert and self.upsert_key:
                    # Upsert mode: check if upsert key exists in payload
                    upsert_value = payload.get(self.upsert_key) if isinstance(payload, dict) else None
                    
                    if upsert_value:
                        # Use a subquery to check existence and update or insert
                        # MySQL doesn't support CTEs in older versions, so use simpler approach
                        query = f"""
                        INSERT INTO {quoted_table_name} (webhook_id, timestamp, payload, headers)
                        VALUES (%s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                            webhook_id = VALUES(webhook_id),
                            timestamp = VALUES(timestamp),
                            payload = VALUES(payload),
                            headers = VALUES(headers)
                        """
                        # For JSON mode upsert, we need a unique index on the JSON path
                        # This is complex, so we'll use a simpler approach: check and update
                        check_query = f"""
                        SELECT id FROM {quoted_table_name}
                        WHERE JSON_EXTRACT(payload, %s) = %s
                        LIMIT 1
                        """
                        async with self.pool.acquire() as conn:
                            async with conn.cursor() as cur:
                                await cur.execute(check_query, (f'$.{self.upsert_key}', str(upsert_value)))
                                existing = await cur.fetchone()
                                
                                if existing:
                                    # Update existing record
                                    update_query = f"""
                                    UPDATE {quoted_table_name}
                                    SET webhook_id = %s,
                                        timestamp = %s,
                                        payload = %s,
                                        headers = %s
                                    WHERE id = %s
                                    """
                                    await cur.execute(update_query, (webhook_id, timestamp, payload_json, headers_json, existing[0]))
                                else:
                                    # Insert new record
                                    await cur.execute(query, (webhook_id, timestamp, payload_json, headers_json))
                                await conn.commit()
                    else:
                        # Regular insert if upsert key not found
                        query = f"""
                        INSERT INTO {quoted_table_name} (webhook_id, timestamp, payload, headers)
                        VALUES (%s, %s, %s, %s)
                        """
                        async with self.pool.acquire() as conn:
                            async with conn.cursor() as cur:
                                await cur.execute(query, (webhook_id, timestamp, payload_json, headers_json))
                                await conn.commit()
                else:
                    # Regular insert
                    query = f"""
                    INSERT INTO {quoted_table_name} (webhook_id, timestamp, payload, headers)
                    VALUES (%s, %s, %s, %s)
                    """
                    async with self.pool.acquire() as conn:
                        async with conn.cursor() as cur:
                            await cur.execute(query, (webhook_id, timestamp, payload_json, headers_json))
                            await conn.commit()
            
            elif self.storage_mode == 'relational':
                # Relational mode: map fields to columns
                if not self.schema or 'fields' not in self.schema:
                    raise ValueError("Relational mode requires schema definition")
                
                columns = ['webhook_id']
                placeholders = ['%s']
                values = [webhook_id]
                
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
                    placeholders.append('%s')
                    values.append(value)
                
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
                        for col in columns[1:]:  # Skip webhook_id
                            quoted_col = self._quote_identifier(col) if not col.startswith('`') else col
                            update_clauses.append(f"{quoted_col} = VALUES({quoted_col})")
                        
                        query = f"""
                        INSERT INTO {quoted_table_name} ({columns_str})
                        VALUES ({placeholders_str})
                        ON DUPLICATE KEY UPDATE {', '.join(update_clauses)}
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
                    async with conn.cursor() as cur:
                        await cur.execute(query, tuple(values))
                        await conn.commit()
            
            else:  # hybrid mode
                # Hybrid mode: columns + JSON payload
                payload_json = json.dumps(payload) if not isinstance(payload, str) else payload
                headers_json = json.dumps(headers) if self.include_headers else None
                
                columns = ['webhook_id', 'payload']
                placeholders = ['%s', '%s']
                values = [webhook_id, payload_json]
                
                # Add headers column if configured
                if self.include_headers:
                    columns.append('headers')
                    placeholders.append('%s')
                    values.append(headers_json)
                
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
                        placeholders.append('%s')
                        values.append(value)
                
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
                        for col in columns[1:]:  # Skip webhook_id
                            quoted_col = self._quote_identifier(col) if not col.startswith('`') else col
                            update_clauses.append(f"{quoted_col} = VALUES({quoted_col})")
                        
                        query = f"""
                        INSERT INTO {quoted_table_name} ({columns_str})
                        VALUES ({placeholders_str})
                        ON DUPLICATE KEY UPDATE {', '.join(update_clauses)}
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
                    async with conn.cursor() as cur:
                        await cur.execute(query, tuple(values))
                        await conn.commit()
            
            print(f"Saved webhook to MySQL table '{self.table_name}'")
        except Exception as e:
            # Log the error but do not crash the webhook processing
            print(f"Failed to save to MySQL: {e}")
            raise  # Re-raise to allow retry mechanism to handle it
    
    async def teardown(self) -> None:
        """Close MySQL connection pool."""
        if self.pool:
            try:
                self.pool.close()
                await self.pool.wait_closed()
            except Exception:
                pass

