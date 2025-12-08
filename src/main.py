from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response
import asyncio
import os
from datetime import datetime
from typing import Optional

from src.webhook import WebhookHandler
from src.config import inject_connection_details, webhook_config_data, connection_config
from src.utils import RedisEndpointStats
from src.rate_limiter import rate_limiter
from src.clickhouse_analytics import ClickHouseAnalytics
from src.config_manager import ConfigManager
from src.config_watcher import ConfigFileWatcher

# Check if OpenAPI docs should be disabled
DISABLE_OPENAPI_DOCS = os.getenv("DISABLE_OPENAPI_DOCS", "false").lower() == "true"

# Initialize FastAPI app
# Disable docs if requested
app = FastAPI(
    docs_url="/docs" if not DISABLE_OPENAPI_DOCS else None,
    redoc_url="/redoc" if not DISABLE_OPENAPI_DOCS else None,
    openapi_url="/openapi.json" if not DISABLE_OPENAPI_DOCS else None
)
stats = RedisEndpointStats()  # Use Redis for persistent stats
clickhouse_logger: ClickHouseAnalytics = None  # For logging events only
config_manager: Optional[ConfigManager] = None  # Config manager for live reload
config_watcher: Optional[ConfigFileWatcher] = None  # File watcher for auto-reload

# Override FastAPI's openapi() method to return custom schema
if not DISABLE_OPENAPI_DOCS:
    from functools import wraps
    
    original_openapi = app.openapi
    
    @wraps(original_openapi)
    def custom_openapi():
        """Generate custom OpenAPI schema from webhooks.json."""
        global config_manager, webhook_config_data
        try:
            from src.openapi_generator import generate_openapi_schema
            # Generate schema dynamically from current webhook config
            # Use ConfigManager if available, otherwise fallback
            if config_manager:
                # Build webhook config dict from ConfigManager
                # We need to access internal _webhook_config - for now use a workaround
                # In production, ConfigManager should have a get_all_webhook_configs() method
                # For now, we'll use the internal attribute (not ideal but works)
                try:
                    webhook_configs = config_manager._webhook_config
                    if webhook_configs:
                        return generate_openapi_schema(webhook_configs)
                except AttributeError:
                    # Fallback if _webhook_config not accessible
                    pass
                config_to_use = webhook_config_data
            else:
                config_to_use = webhook_config_data
            
            if config_to_use:
                return generate_openapi_schema(config_to_use)
        except Exception as e:
            print(f"WARNING: Failed to generate OpenAPI schema: {e}")
        # Fallback to default if generation fails
        return original_openapi()
    
    app.openapi = custom_openapi

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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all HTTP responses."""
    
    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)
        
        # X-Content-Type-Options: Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # X-Frame-Options: Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # X-XSS-Protection: Enable XSS filter (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer-Policy: Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions-Policy: Restrict browser features
        # Disable potentially dangerous features
        permissions_policy = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "accelerometer=()"
        )
        response.headers["Permissions-Policy"] = permissions_policy
        
        # Strict-Transport-Security: Force HTTPS (only if HTTPS is detected)
        # Check if request is over HTTPS
        is_https = (
            request.url.scheme == "https" or
            request.headers.get("x-forwarded-proto", "").lower() == "https" or
            os.getenv("FORCE_HTTPS", "false").lower() == "true"
        )
        
        if is_https:
            # HSTS: Force HTTPS for 1 year, include subdomains, preload
            # SECURITY: Validate HSTS_MAX_AGE to prevent crashes from invalid environment variables
            try:
                hsts_max_age = int(os.getenv("HSTS_MAX_AGE", "31536000"))  # Default: 1 year
                # Validate range: 0 to 2 years (63072000 seconds) to prevent DoS
                if hsts_max_age < 0:
                    hsts_max_age = 31536000  # Default to 1 year if negative
                elif hsts_max_age > 63072000:  # Max 2 years
                    hsts_max_age = 63072000
            except (ValueError, TypeError):
                # Invalid value, use default
                hsts_max_age = 31536000  # Default: 1 year
            
            hsts_include_subdomains = os.getenv("HSTS_INCLUDE_SUBDOMAINS", "true").lower() == "true"
            hsts_preload = os.getenv("HSTS_PRELOAD", "false").lower() == "true"
            
            hsts_value = f"max-age={hsts_max_age}"
            if hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            if hsts_preload:
                hsts_value += "; preload"
            
            response.headers["Strict-Transport-Security"] = hsts_value
        
        # Content-Security-Policy: Restrict resource loading
        # Default policy: Only allow same-origin resources
        csp_policy = os.getenv("CSP_POLICY", "")
        if csp_policy:
            # Use custom CSP if provided
            response.headers["Content-Security-Policy"] = csp_policy
        else:
            # Default restrictive CSP
            default_csp = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "  # Allow inline styles (needed for some frameworks)
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "  # Prevent framing (redundant with X-Frame-Options but more specific)
                "base-uri 'self'; "
                "form-action 'self'"
            )
            response.headers["Content-Security-Policy"] = default_csp
        
        return response


# Add security headers middleware (after CORS, before routes)
app.add_middleware(SecurityHeadersMiddleware)


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
    global webhook_config_data, clickhouse_logger, config_manager, config_watcher
    
    # Initialize ConfigManager for live reload
    config_manager = ConfigManager()
    try:
        init_result = await config_manager.initialize()
        if init_result.success:
            print(f"ConfigManager initialized: {init_result.details}")
        else:
            print(f"ConfigManager initialization warning: {init_result.error}")
    except Exception as e:
        print(f"Failed to initialize ConfigManager: {e}")
        # Fallback to old config loading
        webhook_config_data = await inject_connection_details(webhook_config_data, connection_config)
    else:
        # Use ConfigManager for config access
        # Build webhook_config_data from ConfigManager for backward compatibility
        webhook_config_data = {}
        # Note: ConfigManager will be used directly in webhook handler
    
    # Initialize ClickHouse logger for automatic event logging
    # Look for any clickhouse connection (webhook instances just log events)
    conn_config = config_manager.get_connection_config if config_manager else connection_config
    clickhouse_config = None
    if config_manager:
        for conn_name in conn_config.keys() if hasattr(conn_config, 'keys') else []:
            conn = config_manager.get_connection_config(conn_name)
            if conn and conn.get('type') == 'clickhouse':
                clickhouse_config = conn
                break
    else:
        for conn_name, conn in connection_config.items():
            if conn.get('type') == 'clickhouse':
                clickhouse_config = conn
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
    
    # Start file watcher if enabled
    file_watching_enabled = os.getenv("CONFIG_FILE_WATCHING_ENABLED", "false").lower() == "true"
    if file_watching_enabled and config_manager:
        try:
            debounce_seconds = float(os.getenv("CONFIG_RELOAD_DEBOUNCE_SECONDS", "3.0"))
            config_watcher = ConfigFileWatcher(config_manager, debounce_seconds=debounce_seconds)
            config_watcher.start()
            print("Config file watcher started - automatic reload enabled")
        except Exception as e:
            print(f"Failed to start config file watcher: {e}")

    asyncio.create_task(cleanup_task())


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    global clickhouse_logger, config_watcher, config_manager
    if config_watcher:
        config_watcher.stop()
    if config_manager:
        await config_manager.pool_registry.close_all_pools()
    if clickhouse_logger:
        await clickhouse_logger.disconnect()
    # Close Redis connection
    await stats.close()


@app.post("/webhook/{webhook_id}")
async def read_webhook(webhook_id: str,  request: Request):
    global config_manager
    
    # Get configs from ConfigManager if available, otherwise use fallback
    if config_manager:
        webhook_configs = {}
        # Build webhook configs dict from ConfigManager
        # For now, we'll get the specific webhook config
        webhook_config = config_manager.get_webhook_config(webhook_id)
        if webhook_config:
            webhook_configs[webhook_id] = webhook_config
        conn_configs = {}  # Connection configs accessed via pool_registry
        pool_registry = config_manager.pool_registry
    else:
        # Fallback to old config system
        webhook_configs = webhook_config_data
        conn_configs = connection_config
        pool_registry = None

    try:
        webhook_handler = WebhookHandler(
            webhook_id,
            webhook_configs,
            conn_configs,
            request,
            pool_registry=pool_registry
        )
    except HTTPException as e:
        # HTTPException is already sanitized, re-raise as-is
        raise e
    except Exception as e:
        # Log detailed error server-side
        print(f"ERROR: Failed to initialize webhook handler for '{webhook_id}': {e}")
        # Raise generic error to client (don't expose webhook ID or config details)
        from src.utils import sanitize_error_message
        raise HTTPException(
            status_code=500,
            detail=sanitize_error_message(e, "webhook initialization")
        )

    is_valid, message = await webhook_handler.validate_webhook()
    if not is_valid:
        raise HTTPException(status_code=401, detail=message)

    # Process webhook and get payload/headers for logging
    # HTTPException should be re-raised (not caught), other exceptions are internal errors
    try:
        result = await webhook_handler.process_webhook()
    except HTTPException as e:
        # HTTPException is already sanitized, re-raise as-is
        raise e
    except Exception as e:
        # SECURITY: Sanitize process_webhook errors to prevent information disclosure
        print(f"ERROR: Failed to process webhook '{webhook_id}': {e}")
        from src.utils import sanitize_error_message
        raise HTTPException(
            status_code=500,
            detail=sanitize_error_message(e, "webhook processing")
        )
    
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
            # Log asynchronously using task manager (fire and forget)
            from src.webhook import task_manager
            async def log_to_clickhouse():
                await clickhouse_logger.save_log(webhook_id, payload, headers)
            await task_manager.create_task(log_to_clickhouse())
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


@app.post("/admin/reload-config")
async def reload_config_endpoint(request: Request):
    """
    Admin endpoint to manually trigger configuration reload.
    
    Supports reloading webhooks, connections, or both.
    """
    global config_manager
    
    if not config_manager:
        raise HTTPException(status_code=503, detail="ConfigManager not initialized")
    
    # Check authentication if configured
    admin_token = os.getenv("CONFIG_RELOAD_ADMIN_TOKEN", "").strip()
    if admin_token:
        auth_header = request.headers.get("authorization", "")
        if not auth_header:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Extract token
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        else:
            token = auth_header.strip()
        
        # Constant-time comparison
        import hmac
        if not hmac.compare_digest(token.encode('utf-8'), admin_token.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    # Parse request body
    try:
        body = await request.json()
        reload_webhooks = body.get("reload_webhooks", True)
        reload_connections = body.get("reload_connections", True)
        validate_only = body.get("validate_only", False)
    except Exception:
        # Default: reload both
        reload_webhooks = True
        reload_connections = True
        validate_only = False
    
    # Perform reload
    if validate_only:
        # Validation only (not implemented in current version)
        return JSONResponse(content={
            "status": "validation_not_implemented",
            "message": "Validate-only mode not yet implemented"
        })
    
    if reload_webhooks and reload_connections:
        result = await config_manager.reload_all()
    elif reload_webhooks:
        result = await config_manager.reload_webhooks()
    elif reload_connections:
        result = await config_manager.reload_connections()
    else:
        return JSONResponse(content={
            "status": "error",
            "error": "No reload operation specified"
        })
    
    if result.success:
        return JSONResponse(content={
            "status": "success",
            "reloaded": {
                "webhooks": reload_webhooks,
                "connections": reload_connections
            },
            "details": result.details,
            "timestamp": result.timestamp
        })
    else:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "error": result.error,
                "details": result.details,
                "timestamp": result.timestamp
            }
        )


@app.get("/admin/config-status")
async def config_status_endpoint(request: Request):
    """
    Admin endpoint to get current configuration status.
    
    Returns information about:
    - Last reload time
    - Reload in progress status
    - Webhook and connection counts
    - Connection pool information
    """
    global config_manager
    
    if not config_manager:
        raise HTTPException(status_code=503, detail="ConfigManager not initialized")
    
    # Check authentication if configured
    admin_token = os.getenv("CONFIG_RELOAD_ADMIN_TOKEN", "").strip()
    if admin_token:
        auth_header = request.headers.get("authorization", "")
        if not auth_header:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # Extract token
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        else:
            token = auth_header.strip()
        
        # Constant-time comparison
        import hmac
        if not hmac.compare_digest(token.encode('utf-8'), admin_token.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    status = config_manager.get_status()
    
    # Add file watching status
    global config_watcher
    status["file_watching_enabled"] = config_watcher is not None and config_watcher.is_watching()
    
    return JSONResponse(content=status)


