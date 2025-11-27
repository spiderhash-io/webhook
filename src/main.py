from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import os
from datetime import datetime

from src.webhook import WebhookHandler
from src.config import inject_connection_details, webhook_config_data, connection_config
from src.utils import RedisEndpointStats
from src.rate_limiter import rate_limiter
from src.clickhouse_analytics import ClickHouseAnalytics

app = FastAPI()
stats = RedisEndpointStats()  # Use Redis for persistent stats
clickhouse_logger: ClickHouseAnalytics = None  # For logging events only

# Configure CORS securely
# Read allowed origins from environment variable (comma-separated)
# Default: empty list (no CORS allowed) - most secure
# Example: CORS_ALLOWED_ORIGINS=https://example.com,https://app.example.com
cors_origins_env = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
if cors_origins_env:
    # Parse comma-separated origins
    cors_allowed_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]
else:
    # Default: no CORS (most secure)
    # Set to ["*"] only if explicitly needed (not recommended for production)
    cors_allowed_origins = []

# Only allow credentials if origins are explicitly configured (not wildcard)
cors_allow_credentials = len(cors_allowed_origins) > 0 and "*" not in cors_allowed_origins

# Restrict methods to only what's needed for webhooks
cors_allowed_methods = ["POST", "GET", "OPTIONS"]

# Restrict headers to common webhook headers
cors_allowed_headers = [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "X-HMAC-Signature",
    "X-HMAC-Signature-256",
    "X-Hub-Signature",
    "X-Hub-Signature-256",
    "X-API-Key",
    "X-Auth-Token",
    "X-Recaptcha-Token",
    "X-Forwarded-For",
    "X-Real-IP",
]

# Add CORS middleware with secure defaults
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_allowed_origins,  # Whitelist specific origins
    allow_credentials=cors_allow_credentials,  # Only if origins are whitelisted
    allow_methods=cors_allowed_methods,  # Restricted to needed methods
    allow_headers=cors_allowed_headers,  # Restricted to needed headers
    expose_headers=[],  # Don't expose any headers
    max_age=600,  # Cache preflight requests for 10 minutes
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
    # HTTPException should be re-raised (not caught), other exceptions are internal errors
    result = await webhook_handler.process_webhook()
    
    # Handle return value (always returns tuple of 3: payload, headers, task)
    payload, headers, task = result

    # Update stats (persistent in Redis)
    # Don't fail webhook if stats fail
    try:
        await stats.increment(webhook_id)
    except Exception as e:
        print(f"Failed to update stats: {e}")
        # Continue processing even if stats fail

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

    # Check if retry is configured and task is running
    retry_config = webhook_handler.config.get("retry", {})
    if task and retry_config.get("enabled", False):
        # Check task result after a short delay to see if it succeeded immediately
        # If task is still running, it means retries are happening
        await asyncio.sleep(0.1)  # Small delay to check initial attempt
        
        if task.done():
            try:
                success, error = task.result()
                if success:
                    return JSONResponse(content={"message": "200 OK", "status": "processed"})
                else:
                    # Retries configured but all attempts failed (will continue in background)
                    return JSONResponse(
                        content={
                            "message": "202 Accepted",
                            "status": "accepted",
                            "note": "Request accepted, processing in background with retries"
                        },
                        status_code=202
                    )
            except Exception as e:
                # Task raised an exception
                return JSONResponse(
                    content={
                        "message": "202 Accepted",
                        "status": "accepted",
                        "note": "Request accepted, processing in background"
                    },
                    status_code=202
                )
        else:
            # Task still running, retries in progress
            return JSONResponse(
                content={
                    "message": "202 Accepted",
                    "status": "accepted",
                    "note": "Request accepted, processing in background"
                },
                status_code=202
            )
    
    # No retry configured or immediate success
    return JSONResponse(content={"message": "200 OK"})


@app.get("/")
async def default_endpoint():
    return JSONResponse(content={"message": "200 OK"})


@app.get("/stats")
async def stats_endpoint():
    return await stats.get_stats()



