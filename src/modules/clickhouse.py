from typing import Any, Dict
import json
import asyncio
import re
from datetime import datetime
from clickhouse_driver import Client
from src.modules.base import BaseModule


class ClickHouseModule(BaseModule):
    """Module for saving webhook logs to ClickHouse database.
    
    The module expects the following configuration in the webhook definition:
    ```json
    {
        "module": "clickhouse",
        "connection": "clickhouse_local",
        "module-config": {
            "table": "webhook_logs",
            "include_headers": true,
            "include_timestamp": true
        }
    }
    ```
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.client = None
        raw_table_name = self.module_config.get('table', 'webhook_logs')
        self.table_name = self._validate_table_name(raw_table_name)
        self.include_headers = self.module_config.get('include_headers', True)
        self.include_timestamp = self.module_config.get('include_timestamp', True)
        self._ensure_table_created = False
    
    def _validate_table_name(self, table_name: str) -> str:
        """
        Validate and sanitize ClickHouse table name to prevent SQL injection.
        
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
        
        # ClickHouse table names can contain alphanumeric, underscore, and dots
        # But we'll be more restrictive for security: alphanumeric and underscore only
        # Maximum length to prevent DoS
        if len(table_name) > 255:
            raise ValueError(f"Table name too long: {len(table_name)} characters (max: 255)")
        
        # Validate format: alphanumeric and underscore only
        # ClickHouse allows dots, but we restrict for security
        if not re.match(r'^[a-zA-Z0-9_]+$', table_name):
            raise ValueError(
                f"Invalid table name format: '{table_name}'. "
                f"Only alphanumeric characters and underscores are allowed."
            )
        
        # Reject SQL keywords that could be used in injection
        sql_keywords = [
            'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
            'truncate', 'exec', 'execute', 'union', 'script', '--', ';', '/*', '*/'
        ]
        table_name_lower = table_name.lower()
        for keyword in sql_keywords:
            if keyword in table_name_lower:
                raise ValueError(f"Table name contains forbidden keyword: '{keyword}'")
        
        # Reject dangerous patterns
        dangerous_patterns = ['..', '--', ';', '/*', '*/', 'xp_', 'sp_']
        for pattern in dangerous_patterns:
            if pattern in table_name_lower:
                raise ValueError(f"Table name contains dangerous pattern: '{pattern}'")
        
        return table_name
    
    def _quote_identifier(self, identifier: str) -> str:
        """
        Quote ClickHouse identifier to prevent injection.
        
        Args:
            identifier: The identifier to quote
            
        Returns:
            Quoted identifier safe for use in SQL
        """
        # ClickHouse uses backticks for identifier quoting
        # Escape backticks in the identifier
        escaped = identifier.replace('`', '``')
        return f"`{escaped}`"
    
    async def setup(self) -> None:
        """Initialize ClickHouse client connection."""
        if not self.connection_details:
            raise Exception("ClickHouse connection details not found")
        
        host = self.connection_details.get('host', 'localhost')
        port = self.connection_details.get('port', 9000)
        database = self.connection_details.get('database', 'default')
        user = self.connection_details.get('user', 'default')
        password = self.connection_details.get('password', '') or None
        
        try:
            # Run synchronous client creation in thread pool
            loop = asyncio.get_event_loop()
            # Build client kwargs - only include password if it's not None/empty
            # Note: clickhouse-driver may require password to be omitted entirely if empty
            def create_client():
                kwargs = {
                    'host': host,
                    'port': port,
                    'database': database,
                    'user': user,
                    'secure': False  # Disable SSL for local connections
                }
                # Only add password if it's provided and not empty
                if password and password.strip():
                    kwargs['password'] = password
                return Client(**kwargs)
            
            self.client = await loop.run_in_executor(None, create_client)
            # Test connection
            await loop.run_in_executor(None, lambda: self.client.execute('SELECT 1'))
            await self._ensure_table()
        except Exception as e:
            print(f"Failed to connect to ClickHouse: {e}")
            raise
    
    async def _ensure_table(self) -> None:
        """Ensure the webhook logs table exists."""
        if self._ensure_table_created:
            return
        
        try:
            # Quote table name to prevent injection
            quoted_table_name = self._quote_identifier(self.table_name)
            
            # Create table if it doesn't exist
            # Table name is validated and quoted, so it's safe to use in f-string
            create_table_query = f"""
            CREATE TABLE IF NOT EXISTS {quoted_table_name} (
                id String,
                webhook_id String,
                timestamp DateTime,
                payload String,
                headers String,
                created_at DateTime DEFAULT now()
            ) ENGINE = MergeTree()
            ORDER BY (webhook_id, timestamp)
            PARTITION BY toYYYYMM(timestamp)
            """
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: self.client.execute(create_table_query))
            self._ensure_table_created = True
        except Exception as e:
            print(f"Failed to create ClickHouse table: {e}")
            # Don't raise - table might already exist
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Save webhook payload and headers to ClickHouse."""
        if not self.client:
            await self.setup()
        
        try:
            # Generate unique ID
            import uuid
            record_id = str(uuid.uuid4())
            
            # Get webhook_id from config (it's stored in the config during processing)
            webhook_id = self.config.get('_webhook_id', 'unknown')
            
            # Prepare data
            timestamp = datetime.utcnow()
            payload_str = json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload)
            headers_str = json.dumps(headers) if self.include_headers else '{}'
            
            # Insert into ClickHouse
            # Table name is validated and quoted, so it's safe to use in f-string
            quoted_table_name = self._quote_identifier(self.table_name)
            insert_query = f"""
            INSERT INTO {quoted_table_name} (id, webhook_id, timestamp, payload, headers)
            VALUES
            """
            
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.execute(
                    insert_query,
                    [(record_id, webhook_id, timestamp, payload_str, headers_str)]
                )
            )
            
            print(f"Saved webhook log to ClickHouse table '{self.table_name}'")
        except Exception as e:
            # Log the error but do not crash the webhook processing
            print(f"Failed to save to ClickHouse: {e}")
    
    async def teardown(self) -> None:
        """Close ClickHouse connection."""
        if self.client:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, lambda: self.client.disconnect())
            except Exception:
                pass

