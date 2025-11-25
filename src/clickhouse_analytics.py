"""
ClickHouse Analytics Service

This service handles saving statistics and logs to ClickHouse database
for analytics and monitoring purposes.
"""
from typing import Dict, Optional, Any
import asyncio
from datetime import datetime
from clickhouse_driver import Client
import json


class ClickHouseAnalytics:
    """Service for saving analytics data to ClickHouse."""
    
    def __init__(self, connection_config: Optional[Dict] = None):
        """
        Initialize ClickHouse analytics service.
        
        Args:
            connection_config: ClickHouse connection configuration dict
                with keys: host, port, database, user, password
        """
        self.connection_config = connection_config
        self.client: Optional[Client] = None
        self.stats_table_created = False
        self.logs_table_created = False
    
    async def connect(self) -> None:
        """Establish connection to ClickHouse."""
        if not self.connection_config:
            raise Exception("ClickHouse connection config not provided")
        
        host = self.connection_config.get('host', 'localhost')
        port = self.connection_config.get('port', 9000)
        database = self.connection_config.get('database', 'default')
        user = self.connection_config.get('user', 'default')
        password = self.connection_config.get('password', '') or None
        
        try:
            # Run synchronous client creation in thread pool
            loop = asyncio.get_event_loop()
            # Build client kwargs - only include password if it's not None/empty
            # Note: clickhouse-driver may require password to be omitted entirely if empty
            def create_client():
                # For ClickHouse with no password, don't pass password parameter at all
                kwargs = {
                    'host': host,
                    'port': port,
                    'database': database,
                    'user': user,
                    'secure': False  # Disable SSL for local connections
                }
                # Only add password if it's provided and not empty
                # If password is empty/None, don't include it in kwargs at all
                if password and str(password).strip():
                    kwargs['password'] = str(password).strip()
                return Client(**kwargs)
            
            self.client = await loop.run_in_executor(None, create_client)
            # Test connection
            await loop.run_in_executor(None, lambda: self.client.execute('SELECT 1'))
            await self._ensure_tables()
        except Exception as e:
            print(f"Failed to connect to ClickHouse for analytics: {e}")
            raise
    
    async def _ensure_tables(self) -> None:
        """Ensure required tables exist."""
        if not self.client:
            return
        
        # Create webhook_stats table
        if not self.stats_table_created:
            try:
                create_stats_table = """
                CREATE TABLE IF NOT EXISTS webhook_stats (
                    id String,
                    webhook_id String,
                    timestamp DateTime,
                    total UInt64,
                    minute UInt64,
                    minute_5 UInt64,
                    minute_15 UInt64,
                    minute_30 UInt64,
                    hour UInt64,
                    day UInt64,
                    week UInt64,
                    month UInt64,
                    created_at DateTime DEFAULT now()
                ) ENGINE = MergeTree()
                ORDER BY (webhook_id, timestamp)
                PARTITION BY toYYYYMM(timestamp)
                """
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, lambda: self.client.execute(create_stats_table))
                self.stats_table_created = True
            except Exception as e:
                print(f"Failed to create stats table (might already exist): {e}")
        
        # Create webhook_logs table (for general logging)
        if not self.logs_table_created:
            try:
                create_logs_table = """
                CREATE TABLE IF NOT EXISTS webhook_logs (
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
                await loop.run_in_executor(None, lambda: self.client.execute(create_logs_table))
                self.logs_table_created = True
            except Exception as e:
                print(f"Failed to create logs table (might already exist): {e}")
    
    async def save_stats(self, stats: Dict[str, Dict]) -> None:
        """
        Save webhook statistics to ClickHouse.
        
        Args:
            stats: Dictionary of webhook_id -> stats dict
                Stats dict should contain: total, minute, 5_minutes, 15_minutes,
                30_minutes, hour, day, week, month
        """
        if not self.client:
            await self.connect()
        
        if not self.client:
            return
        
        try:
            import uuid
            timestamp = datetime.utcnow()
            
            records = []
            for webhook_id, webhook_stats in stats.items():
                record_id = str(uuid.uuid4())
                records.append((
                    record_id,
                    webhook_id,
                    timestamp,
                    webhook_stats.get('total', 0),
                    webhook_stats.get('minute', 0),
                    webhook_stats.get('5_minutes', 0),
                    webhook_stats.get('15_minutes', 0),
                    webhook_stats.get('30_minutes', 0),
                    webhook_stats.get('hour', 0),
                    webhook_stats.get('day', 0),
                    webhook_stats.get('week', 0),
                    webhook_stats.get('month', 0),
                ))
            
            if records:
                insert_query = """
                INSERT INTO webhook_stats (
                    id, webhook_id, timestamp, total, minute, minute_5, minute_15,
                    minute_30, hour, day, week, month
                ) VALUES
                """
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: self.client.execute(insert_query, records)
                )
                print(f"Saved {len(records)} stats records to ClickHouse")
        except Exception as e:
            print(f"Failed to save stats to ClickHouse: {e}")
    
    async def save_log(self, webhook_id: str, payload: Any, headers: Dict[str, str]) -> None:
        """
        Save a webhook log entry to ClickHouse.
        
        Args:
            webhook_id: The webhook identifier
            payload: The webhook payload
            headers: The request headers
        """
        if not self.client:
            await self.connect()
        
        if not self.client:
            return
        
        try:
            import uuid
            record_id = str(uuid.uuid4())
            timestamp = datetime.utcnow()
            
            payload_str = json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload)
            headers_str = json.dumps(headers)
            
            insert_query = """
            INSERT INTO webhook_logs (id, webhook_id, timestamp, payload, headers)
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
        except Exception as e:
            print(f"Failed to save log to ClickHouse: {e}")
    
    async def disconnect(self) -> None:
        """Close ClickHouse connection."""
        if self.client:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, lambda: self.client.disconnect())
            except Exception:
                pass


# Global analytics instance (will be initialized in main.py)
analytics: Optional[ClickHouseAnalytics] = None

