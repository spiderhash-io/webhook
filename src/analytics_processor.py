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
from datetime import datetime, timezone
from typing import Dict, Optional
from clickhouse_driver import Client
from src.clickhouse_analytics import ClickHouseAnalytics
from src.config import connection_config, _validate_connection_host
from src.utils import load_env_vars, sanitize_error_message


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

    def _validate_webhook_id(self, webhook_id: str) -> str:
        """
        Validate webhook_id to prevent injection attacks and DoS.

        Args:
            webhook_id: The webhook identifier to validate

        Returns:
            Validated webhook_id string

        Raises:
            ValueError: If webhook_id is invalid or contains dangerous characters
        """
        if not webhook_id or not isinstance(webhook_id, str):
            raise ValueError("webhook_id must be a non-empty string")

        webhook_id = webhook_id.strip()

        if not webhook_id:
            raise ValueError("webhook_id cannot be empty")

        # Maximum length to prevent DoS (256 chars is reasonable for identifiers)
        MAX_WEBHOOK_ID_LENGTH = 256
        if len(webhook_id) > MAX_WEBHOOK_ID_LENGTH:
            raise ValueError(
                f"webhook_id too long: {len(webhook_id)} characters (max: {MAX_WEBHOOK_ID_LENGTH})"
            )

        # Reject null bytes and control characters
        if "\x00" in webhook_id:
            raise ValueError("webhook_id cannot contain null bytes")

        # Reject dangerous characters that could be used in injection attacks
        dangerous_chars = [
            "\n",
            "\r",
            ";",
            "|",
            "&",
            "$",
            "`",
            "\\",
            "/",
            "(",
            ")",
            "<",
            ">",
        ]
        for char in dangerous_chars:
            if char in webhook_id:
                raise ValueError(f"webhook_id contains dangerous character: '{char}'")

        return webhook_id

    async def connect(self) -> None:
        """Connect to ClickHouse."""
        host = self.clickhouse_config.get("host", "localhost")
        port = self.clickhouse_config.get("port", 9000)
        database = self.clickhouse_config.get("database", "default")
        user = self.clickhouse_config.get("user", "default")
        password = self.clickhouse_config.get("password", "") or None

        try:
            # SECURITY: Validate host to prevent SSRF attacks
            try:
                validated_host = _validate_connection_host(host, "ClickHouse")
            except ValueError as e:
                # Re-raise validation errors
                raise ValueError(f"Host validation failed: {str(e)}")

            loop = asyncio.get_running_loop()

            # Build client kwargs - only include password if it's not None/empty
            # Note: clickhouse-driver may require password to be omitted entirely if empty
            def create_client():
                kwargs = {
                    "host": validated_host,
                    "port": port,
                    "database": database,
                    "user": user,
                    "secure": False,  # Disable SSL for local connections
                }
                # Only add password if it's provided and not empty
                if password and password.strip():
                    kwargs["password"] = password
                return Client(**kwargs)

            self.client = await loop.run_in_executor(None, create_client)
            await loop.run_in_executor(None, lambda: self.client.execute("SELECT 1"))

            # Initialize analytics service for saving stats
            self.analytics = ClickHouseAnalytics(self.clickhouse_config)
            await self.analytics.connect()

            print("Analytics processor connected to ClickHouse")
        except Exception as e:
            # SECURITY: Sanitize error messages to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "ClickHouse connection")
            print(f"Failed to connect to ClickHouse: {sanitized_error}")
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
            # SECURITY: Validate webhook_id to prevent injection attacks and DoS
            validated_webhook_id = self._validate_webhook_id(webhook_id)

            loop = asyncio.get_running_loop()

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
                    query, {"webhook_id": validated_webhook_id}
                ),
            )

            if result and len(result) > 0:
                row = result[0]
                return {
                    "total": row[0],
                    "minute": row[1],
                    "5_minutes": row[2],
                    "15_minutes": row[3],
                    "30_minutes": row[4],
                    "hour": row[5],
                    "day": row[6],
                    "week": row[7],
                    "month": row[8],
                }
        except ValueError:
            # Re-raise validation errors
            raise
        except Exception as e:
            # SECURITY: Sanitize error messages to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "stats calculation")
            print(f"Error calculating stats: {sanitized_error}")

        return {}

    async def get_all_webhook_ids(self) -> list:
        """Get list of all unique webhook_ids from ClickHouse."""
        if not self.client:
            return []

        try:
            loop = asyncio.get_running_loop()
            query = "SELECT DISTINCT webhook_id FROM webhook_logs"
            result = await loop.run_in_executor(
                None, lambda: self.client.execute(query)
            )
            webhook_ids = [row[0] for row in result] if result else []

            # SECURITY: Validate webhook_ids from database before using them
            # This prevents malicious webhook_ids stored in database from causing issues
            validated_ids = []
            for webhook_id in webhook_ids:
                try:
                    validated_id = self._validate_webhook_id(str(webhook_id))
                    validated_ids.append(validated_id)
                except ValueError:
                    # Skip invalid webhook_ids from database
                    continue

            return validated_ids
        except Exception as e:
            # SECURITY: Sanitize error messages to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "webhook ID retrieval")
            print(f"Error getting webhook IDs: {sanitized_error}")
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
            # SECURITY: Sanitize error messages to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "stats processing")
            print(f"Error processing stats: {sanitized_error}")

    async def disconnect(self) -> None:
        """Disconnect from ClickHouse."""
        if self.client:
            try:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, lambda: self.client.disconnect())
            except Exception:
                # SECURITY: Silently ignore disconnect errors during cleanup
                # This is intentional - disconnect failures during shutdown are non-critical
                # and logging them would create noise when services are intentionally unavailable
                pass  # nosec B110
        if self.analytics:
            await self.analytics.disconnect()


async def analytics_processing_loop():
    """Main processing loop that runs periodically."""
    # Load connection config
    config = load_env_vars(connection_config)

    # Find ClickHouse connection
    clickhouse_config = None
    for conn_name, conn_config in config.items():
        if conn_config.get("type") == "clickhouse":
            clickhouse_config = conn_config
            break

    if not clickhouse_config:
        print("No ClickHouse connection found in connections.json")
        return

    processor = AnalyticsProcessor(clickhouse_config)

    try:
        await processor.connect()

        while True:
            # SECURITY: Use timezone-aware datetime (datetime.utcnow() is deprecated)
            print(f"[{datetime.now(timezone.utc)}] Processing analytics...")
            await processor.process_and_save_stats()

            # Process every 5 minutes
            await asyncio.sleep(300)
    except KeyboardInterrupt:
        print("Stopping analytics processor...")
    except Exception as e:
        # SECURITY: Sanitize error messages to prevent information disclosure
        sanitized_error = sanitize_error_message(e, "analytics processor")
        print(f"Fatal error in analytics processor: {sanitized_error}")
    finally:
        await processor.disconnect()


if __name__ == "__main__":
    print("Starting Analytics Processor Service...")
    print("This service reads webhook events from ClickHouse and calculates statistics")
    print("Press Ctrl+C to stop")
    asyncio.run(analytics_processing_loop())
