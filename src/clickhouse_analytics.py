"""
ClickHouse Analytics Service

This service handles saving statistics and logs to ClickHouse database
for analytics and monitoring purposes.
"""
from typing import Dict, Optional, Any, List, Tuple
import asyncio
from datetime import datetime
from clickhouse_driver import Client
import json
import uuid


class ClickHouseAnalytics:
    """Service for saving analytics data to ClickHouse."""
    
    def __init__(self, connection_config: Optional[Dict] = None, batch_size: int = 1000, flush_interval: float = 2.0):
        """
        Initialize ClickHouse analytics service.
        
        Args:
            connection_config: ClickHouse connection configuration dict
                with keys: host, port, database, user, password
            batch_size: Number of records to batch before flushing
            flush_interval: Maximum seconds to wait before flushing
        """
        self.connection_config = connection_config
        self.client: Optional[Client] = None
        self.stats_table_created = False
        self.logs_table_created = False
        
        # Batching settings
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.queue: Optional[asyncio.Queue] = None
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False
    
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
            
            def create_client():
                # For ClickHouse with no password, don't pass password parameter at all
                kwargs = {
                    'host': host,
                    'port': port,
                    'database': database,
                    'user': user,
                    'secure': False  # Disable SSL for local connections
                }
                if password and str(password).strip():
                    kwargs['password'] = str(password).strip()
                return Client(**kwargs)
            
            self.client = await loop.run_in_executor(None, create_client)
            # Test connection
            await loop.run_in_executor(None, lambda: self.client.execute('SELECT 1'))
            await self._ensure_tables()
            
            # Start background worker
            self.queue = asyncio.Queue()
            self._running = True
            self._worker_task = asyncio.create_task(self._worker())
            print("ClickHouse analytics worker started")
            
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

    async def _worker(self):
        """Background worker to flush logs and stats to ClickHouse."""
        log_buffer: List[Tuple] = []
        stats_buffer: List[Tuple] = []
        last_flush = datetime.now()
        
        while self._running or (self.queue and not self.queue.empty()) or log_buffer or stats_buffer:
            try:
                # Calculate timeout for next flush
                now = datetime.now()
                time_since_flush = (now - last_flush).total_seconds()
                timeout = max(0.1, self.flush_interval - time_since_flush)
                
                try:
                    if self.queue:
                        # Wait for new item
                        item = await asyncio.wait_for(self.queue.get(), timeout=timeout)
                        item_type, item_data = item
                        
                        if item_type == 'log':
                            log_buffer.append(item_data)
                        elif item_type == 'stats':
                            # item_data is a list of records
                            stats_buffer.extend(item_data)
                        
                        self.queue.task_done()
                except asyncio.TimeoutError:
                    pass  # Timeout reached, proceed to flush check
                except asyncio.CancelledError:
                    break
                
                # Check if we need to flush
                now = datetime.now()
                time_since_flush = (now - last_flush).total_seconds()
                should_flush = time_since_flush >= self.flush_interval
                
                if log_buffer and (len(log_buffer) >= self.batch_size or should_flush):
                    await self._flush_logs(log_buffer)
                    log_buffer = []
                
                if stats_buffer and (len(stats_buffer) >= self.batch_size or should_flush):
                    await self._flush_stats(stats_buffer)
                    stats_buffer = []
                
                if should_flush:
                    last_flush = now
                    
                # If we are stopping and queue is empty and buffers are empty, break
                if not self._running and self.queue and self.queue.empty() and not log_buffer and not stats_buffer:
                    break
                    
            except Exception as e:
                print(f"Error in ClickHouse worker: {e}")
                await asyncio.sleep(1)  # Backoff on error

    async def _flush_logs(self, buffer: List[Tuple]) -> None:
        """Flush logs buffer to ClickHouse."""
        if not self.client or not buffer:
            return
            
        try:
            insert_query = """
            INSERT INTO webhook_logs (id, webhook_id, timestamp, payload, headers)
            VALUES
            """
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.execute(insert_query, buffer)
            )
            # print(f"Flushed {len(buffer)} logs to ClickHouse")
        except Exception as e:
            print(f"Failed to flush logs to ClickHouse: {e}")

    async def _flush_stats(self, buffer: List[Tuple]) -> None:
        """Flush stats buffer to ClickHouse."""
        if not self.client or not buffer:
            return
            
        try:
            insert_query = """
            INSERT INTO webhook_stats (
                id, webhook_id, timestamp, total, minute, minute_5, minute_15,
                minute_30, hour, day, week, month
            ) VALUES
            """
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.execute(insert_query, buffer)
            )
            print(f"Flushed {len(buffer)} stats records to ClickHouse")
        except Exception as e:
            print(f"Failed to flush stats to ClickHouse: {e}")

    async def save_stats(self, stats: Dict[str, Dict]) -> None:
        """
        Save webhook statistics to ClickHouse.
        
        Args:
            stats: Dictionary of webhook_id -> stats dict
                Stats dict should contain: total, minute, 5_minutes, 15_minutes,
                30_minutes, hour, day, week, month
        """
        if not self.queue:
            if not self.client:
                await self.connect()
            if not self.queue:
                return

        try:
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
                await self.queue.put(('stats', records))
                
        except Exception as e:
            print(f"Failed to queue stats for ClickHouse: {e}")
    
    async def save_log(self, webhook_id: str, payload: Any, headers: Dict[str, str]) -> None:
        """
        Save a webhook log entry to ClickHouse.
        
        Credentials are automatically cleaned from payload and headers before logging
        to prevent credential exposure in analytics data.
        
        Args:
            webhook_id: The webhook identifier
            payload: The webhook payload
            headers: The request headers
        """
        if not self.queue:
            if not self.client:
                await self.connect()
            if not self.queue:
                return
        
        try:
            # Clean credentials from payload and headers before logging
            # Use default cleanup (mask mode) to ensure credentials are never logged
            from src.utils import CredentialCleaner
            import copy
            
            cleaner = CredentialCleaner(mode='mask')  # Always mask for logging
            
            # Clean payload (deep copy to avoid modifying original)
            # Handle recursion errors for extremely deeply nested structures
            try:
                if isinstance(payload, (dict, list)):
                    cleaned_payload = cleaner.clean_credentials(copy.deepcopy(payload))
                else:
                    cleaned_payload = payload  # For blob data, no cleaning needed
            except RecursionError:
                # For extremely deeply nested payloads, use a truncated version
                cleaned_payload = {"error": "Payload too deeply nested to clean", "type": type(payload).__name__}
            
            # Clean headers
            cleaned_headers = cleaner.clean_headers(headers)
            
            record_id = str(uuid.uuid4())
            timestamp = datetime.utcnow()
            
            # Serialize to JSON strings
            # Handle recursion errors during JSON serialization
            try:
                payload_str = json.dumps(cleaned_payload) if isinstance(cleaned_payload, (dict, list)) else str(cleaned_payload)
            except (RecursionError, ValueError) as json_error:
                # If JSON serialization fails due to recursion, use a simplified version
                payload_str = '{"error": "Payload too deeply nested to serialize"}'
            
            headers_str = json.dumps(cleaned_headers)
            
            await self.queue.put(('log', (record_id, webhook_id, timestamp, payload_str, headers_str)))
            
        except Exception as e:
            print(f"Failed to queue log for ClickHouse: {e}")
    
    async def disconnect(self) -> None:
        """Close ClickHouse connection."""
        self._running = False
        
        # Wait for worker to finish flushing
        if self._worker_task:
            try:
                await asyncio.wait_for(self._worker_task, timeout=5.0)
            except asyncio.TimeoutError:
                print("ClickHouse worker timed out during shutdown")
                self._worker_task.cancel()
            except Exception as e:
                print(f"Error waiting for ClickHouse worker: {e}")
        
        if self.client:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, lambda: self.client.disconnect())
            except Exception:
                pass


# Global analytics instance (will be initialized in main.py)
analytics: Optional[ClickHouseAnalytics] = None
