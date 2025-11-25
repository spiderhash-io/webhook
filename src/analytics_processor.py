"""
Analytics Processor Service

This is a separate service that runs independently from webhook instances.
It reads webhook events from ClickHouse and calculates aggregated statistics.

Run this as a separate process:
    python -m src.analytics_processor

Or as a service:
    uvicorn src.analytics_processor:app --host 0.0.0.0 --port 8001
"""
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, Optional
from clickhouse_driver import Client
from src.clickhouse_analytics import ClickHouseAnalytics
from src.config import connection_config
from src.utils import load_env_vars


class AnalyticsProcessor:
    """Service that processes webhook events from ClickHouse and calculates statistics."""
    
    def __init__(self, clickhouse_config: Dict):
        """
        Initialize analytics processor.
        
        Args:
            clickhouse_config: ClickHouse connection configuration
        """
        self.clickhouse_config = clickhouse_config
        self.client: Optional[Client] = None
        self.analytics: Optional[ClickHouseAnalytics] = None
    
    async def connect(self) -> None:
        """Connect to ClickHouse."""
        host = self.clickhouse_config.get('host', 'localhost')
        port = self.clickhouse_config.get('port', 9000)
        database = self.clickhouse_config.get('database', 'default')
        user = self.clickhouse_config.get('user', 'default')
        password = self.clickhouse_config.get('password', '') or None
        
        try:
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
            await loop.run_in_executor(None, lambda: self.client.execute('SELECT 1'))
            
            # Initialize analytics service for saving stats
            self.analytics = ClickHouseAnalytics(self.clickhouse_config)
            await self.analytics.connect()
            
            print("Analytics processor connected to ClickHouse")
        except Exception as e:
            print(f"Failed to connect to ClickHouse: {e}")
            raise
    
    async def calculate_stats(self, webhook_id: str) -> Dict:
        """
        Calculate statistics for a webhook_id from all events in ClickHouse.
        
        Args:
            webhook_id: The webhook identifier
            
        Returns:
            Dictionary with calculated statistics
        """
        if not self.client:
            return {}
        
        try:
            loop = asyncio.get_event_loop()
            
            # Calculate stats from ALL events for this webhook_id
            # Using ClickHouse's now() function to calculate rolling windows
            query = """
            SELECT 
                count() as total,
                countIf(timestamp > now() - INTERVAL 1 MINUTE) as minute,
                countIf(timestamp > now() - INTERVAL 5 MINUTE) as minute_5,
                countIf(timestamp > now() - INTERVAL 15 MINUTE) as minute_15,
                countIf(timestamp > now() - INTERVAL 30 MINUTE) as minute_30,
                countIf(timestamp > now() - INTERVAL 1 HOUR) as hour,
                countIf(timestamp > now() - INTERVAL 1 DAY) as day,
                countIf(timestamp > now() - INTERVAL 7 DAY) as week,
                countIf(timestamp > now() - INTERVAL 30 DAY) as month
            FROM webhook_logs
            WHERE webhook_id = {webhook_id:String}
            """
            
            result = await loop.run_in_executor(
                None,
                lambda: self.client.execute(
                    query,
                    {
                        'webhook_id': webhook_id
                    }
                )
            )
            
            if result and len(result) > 0:
                row = result[0]
                return {
                    'total': row[0],
                    'minute': row[1],
                    '5_minutes': row[2],
                    '15_minutes': row[3],
                    '30_minutes': row[4],
                    'hour': row[5],
                    'day': row[6],
                    'week': row[7],
                    'month': row[8],
                }
        except Exception as e:
            print(f"Error calculating stats for {webhook_id}: {e}")
        
        return {}
    
    async def get_all_webhook_ids(self) -> list:
        """Get list of all unique webhook_ids from ClickHouse."""
        if not self.client:
            return []
        
        try:
            loop = asyncio.get_event_loop()
            query = "SELECT DISTINCT webhook_id FROM webhook_logs"
            result = await loop.run_in_executor(
                None,
                lambda: self.client.execute(query)
            )
            return [row[0] for row in result] if result else []
        except Exception as e:
            print(f"Error getting webhook IDs: {e}")
            return []
    
    async def process_and_save_stats(self) -> None:
        """Process all webhooks and save aggregated statistics to ClickHouse."""
        if not self.client or not self.analytics:
            return
        
        try:
            # Get all webhook IDs
            webhook_ids = await self.get_all_webhook_ids()
            
            if not webhook_ids:
                print("No webhook events found in ClickHouse")
                return
            
            # Calculate stats for each webhook from all events
            stats_dict = {}
            for webhook_id in webhook_ids:
                stats = await self.calculate_stats(webhook_id)
                if stats:
                    stats_dict[webhook_id] = stats
            
            # Save aggregated stats to ClickHouse
            if stats_dict:
                await self.analytics.save_stats(stats_dict)
                print(f"Processed and saved stats for {len(stats_dict)} webhooks")
        except Exception as e:
            print(f"Error processing stats: {e}")
    
    async def disconnect(self) -> None:
        """Disconnect from ClickHouse."""
        if self.client:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, lambda: self.client.disconnect())
            except Exception:
                pass
        if self.analytics:
            await self.analytics.disconnect()


async def analytics_processing_loop():
    """Main processing loop that runs periodically."""
    # Load connection config
    config = load_env_vars(connection_config)
    
    # Find ClickHouse connection
    clickhouse_config = None
    for conn_name, conn_config in config.items():
        if conn_config.get('type') == 'clickhouse':
            clickhouse_config = conn_config
            break
    
    if not clickhouse_config:
        print("No ClickHouse connection found in connections.json")
        return
    
    processor = AnalyticsProcessor(clickhouse_config)
    
    try:
        await processor.connect()
        
        while True:
            print(f"[{datetime.utcnow()}] Processing analytics...")
            await processor.process_and_save_stats()
            
            # Process every 5 minutes
            await asyncio.sleep(300)
    except KeyboardInterrupt:
        print("Stopping analytics processor...")
    except Exception as e:
        print(f"Fatal error in analytics processor: {e}")
    finally:
        await processor.disconnect()


if __name__ == "__main__":
    print("Starting Analytics Processor Service...")
    print("This service reads webhook events from ClickHouse and calculates statistics")
    print("Press Ctrl+C to stop")
    asyncio.run(analytics_processing_loop())

