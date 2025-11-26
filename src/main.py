from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from datetime import datetime

from src.webhook import WebhookHandler
from src.config import inject_connection_details, webhook_config_data, connection_config
from src.utils import RedisEndpointStats
from src.rate_limiter import rate_limiter
from src.clickhouse_analytics import ClickHouseAnalytics

app = FastAPI()
stats = RedisEndpointStats()  # Use Redis for persistent stats
clickhouse_logger: ClickHouseAnalytics = None  # For logging events only

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)


async def cleanup_task():
    while True:
        # Stats cleanup is handled by Redis TTL
        
        # Cleanup rate limiter
        await rate_limiter.cleanup_old_entries()
        print("Cleaning up old rate limiter entries")
        
        await asyncio.sleep(3600)  # Wait for 1 hour (3600 seconds) before next cleanup


# Removed analytics_task - statistics aggregation is now handled by separate analytics service


@app.on_event("startup")
async def startup_event():
    global webhook_config_data, clickhouse_logger
    
    webhook_config_data = await inject_connection_details(webhook_config_data, connection_config)
    print(webhook_config_data)

    # Initialize ClickHouse logger for automatic event logging
    # Look for any clickhouse connection (webhook instances just log events)
    clickhouse_config = None
    for conn_name, conn_config in connection_config.items():
        if conn_config.get('type') == 'clickhouse':
            clickhouse_config = conn_config
            break
    
    if clickhouse_config:
        try:
            clickhouse_logger = ClickHouseAnalytics(clickhouse_config)
            await clickhouse_logger.connect()
            print("ClickHouse event logger initialized - all webhook events will be logged")
        except Exception as e:
            print(f"Failed to initialize ClickHouse logger: {e}")
            print("Continuing without ClickHouse logging...")
    else:
        print("No ClickHouse connection found - webhook events will not be logged to ClickHouse")

    asyncio.create_task(cleanup_task())


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    global clickhouse_logger
    if clickhouse_logger:
        await clickhouse_logger.disconnect()
    # Close Redis connection
    await stats.close()


@app.post("/webhook/{webhook_id}")
async def read_webhook(webhook_id: str,  request: Request):

    try:
        webhook_handler = WebhookHandler(
            webhook_id,
            webhook_config_data,
            connection_config,
            request,
        )
    except HTTPException as e:
        raise e

    is_valid, message = await webhook_handler.validate_webhook()
    if not is_valid:
        raise HTTPException(status_code=401, detail=message)

    # Process webhook and get payload/headers for logging
    payload, headers = await webhook_handler.process_webhook()

    # Update stats (persistent in Redis)
    await stats.increment(webhook_id)

    # Automatically log all webhook events to ClickHouse
    # This allows analytics service to process them later
    global clickhouse_logger
    if clickhouse_logger:
        try:
            # Log asynchronously (fire and forget)
            asyncio.create_task(clickhouse_logger.save_log(webhook_id, payload, headers))
        except Exception as e:
            # Don't fail webhook if logging fails
            print(f"Failed to log webhook event to ClickHouse: {e}")

    return JSONResponse(content={"message": "200 OK"})


@app.get("/")
async def default_endpoint():
    return JSONResponse(content={"message": "200 OK"})


@app.get("/stats")
async def stats_endpoint():
    return await stats.get_stats()



