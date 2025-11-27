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
# SECURITY: Wildcard "*" is explicitly rejected for security
cors_origins_env = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
cors_allowed_origins = []

if cors_origins_env:
    # Parse comma-separated origins
    raw_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]
    
    # Validate each origin
    for origin in raw_origins:
        # Explicitly reject wildcard for security
        if origin == "*" or origin == "null":
            print(f"WARNING: CORS origin '{origin}' is rejected for security. Use specific origins only.")
            continue
        
        # Validate origin format (must be http:// or https:// with valid domain)
        if not (origin.startswith("http://") or origin.startswith("https://")):
            print(f"WARNING: CORS origin '{origin}' must start with http:// or https://. Skipping.")
            continue
        
        # Basic validation: must have domain after protocol
        # Remove protocol and check for valid domain pattern
        domain_part = origin.split("://", 1)[1] if "://" in origin else ""
        if not domain_part or domain_part.startswith("/") or " " in domain_part:
            print(f"WARNING: CORS origin '{origin}' has invalid format. Skipping.")
            continue
        
        # Reject origins with paths, fragments, or query strings (security: prevent subdomain confusion)
        # Origin should only be protocol + domain + optional port
        if "/" in domain_part or "#" in domain_part or "?" in domain_part or "@" in domain_part:
            # Extract just the domain:port part (before any /, #, ?, @)
            domain_only = domain_part.split("/")[0].split("#")[0].split("?")[0].split("@")[0]
            # If the domain part is different from what we extracted, reject it
            if domain_part != domain_only:
                print(f"WARNING: CORS origin '{origin}' contains path/fragment/query/userinfo. Use only domain: '{origin.split('://')[0]}://{domain_only}'. Skipping.")
                continue
        
        # Reject localhost and private IPs unless explicitly allowed via different config
        # (This is a security measure - localhost should not be in CORS for production)
        if origin.startswith("http://localhost") or origin.startswith("https://localhost"):
            print(f"WARNING: CORS origin '{origin}' uses localhost. Consider using 127.0.0.1 or specific domain.")
            # Still allow it, but warn
        
        cors_allowed_origins.append(origin)

# Only allow credentials if origins are explicitly configured (not wildcard)
# Credentials are NEVER allowed with wildcard origins (security requirement)
cors_allow_credentials = len(cors_allowed_origins) > 0

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
async def stats_endpoint(request: Request):
    """
    Statistics endpoint - requires authentication to prevent information disclosure.
    
    Authentication can be configured via environment variables:
    - STATS_AUTH_TOKEN: Bearer token for authentication (recommended)
    - STATS_ALLOWED_IPS: Comma-separated list of allowed IP addresses (optional)
    - STATS_RATE_LIMIT: Requests per minute (default: 60)
    """
    # Check authentication token if configured
    stats_auth_token = os.getenv("STATS_AUTH_TOKEN", "").strip()
    if stats_auth_token:
        auth_header = request.headers.get("authorization", "")
        if not auth_header:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Extract token (support both "Bearer token" and "token" formats)
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        else:
            token = auth_header.strip()
        
        # Use constant-time comparison to prevent timing attacks
        import hmac
        if not hmac.compare_digest(token.encode('utf-8'), stats_auth_token.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    # Check IP whitelist if configured
    stats_allowed_ips = os.getenv("STATS_ALLOWED_IPS", "").strip()
    if stats_allowed_ips:
        allowed_ips = {ip.strip() for ip in stats_allowed_ips.split(",") if ip.strip()}
        
        # Get client IP (check X-Forwarded-For header first, then direct connection)
        client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if not client_ip:
            client_ip = request.client.host if request.client else None
        
        if client_ip and client_ip not in allowed_ips:
            raise HTTPException(status_code=403, detail="Access denied from this IP address")
    
    # Rate limiting for stats endpoint
    stats_rate_limit = int(os.getenv("STATS_RATE_LIMIT", "60"))  # Default: 60 requests per minute
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else "unknown"
    
    # Use rate limiter with a separate key for stats endpoint
    stats_key = f"stats_endpoint:{client_ip}"
    is_allowed, remaining = await rate_limiter.check_rate_limit(
        stats_key, 
        max_requests=stats_rate_limit, 
        window_seconds=60
    )
    
    if not is_allowed:
        raise HTTPException(
            status_code=429, 
            detail=f"Rate limit exceeded. Limit: {stats_rate_limit} requests per minute"
        )
    
    # Get stats
    stats_data = await stats.get_stats()
    
    # Optionally sanitize webhook IDs if STATS_SANITIZE_IDS is enabled
    if os.getenv("STATS_SANITIZE_IDS", "false").lower() == "true":
        import hashlib
        sanitized_stats = {}
        for endpoint, data in stats_data.items():
            # Hash endpoint name to prevent enumeration while preserving statistics
            endpoint_hash = hashlib.sha256(endpoint.encode('utf-8')).hexdigest()[:16]
            sanitized_stats[f"webhook_{endpoint_hash}"] = data
        return sanitized_stats
    
    return stats_data



