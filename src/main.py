from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from contextlib import asynccontextmanager
import asyncio
import os
import time
from typing import Optional

from src.webhook import WebhookHandler
from src.config import inject_connection_details, webhook_config_data, connection_config
from src.utils import RedisEndpointStats, sanitize_error_message
from src.rate_limiter import rate_limiter
from src.clickhouse_analytics import ClickHouseAnalytics
from src.config_manager import ConfigManager
from src.config_watcher import ConfigFileWatcher

# Webhook Connect imports
from src.webhook_connect.channel_manager import ChannelManager
from src.webhook_connect.buffer.redis_buffer import RedisBuffer
from src.webhook_connect import api as webhook_connect_api
from src.webhook_connect import admin_api as webhook_connect_admin_api
from src.modules.webhook_connect_module import WebhookConnectModule

# Check if OpenAPI docs should be disabled
DISABLE_OPENAPI_DOCS = os.getenv("DISABLE_OPENAPI_DOCS", "false").lower() == "true"

# Get root path for reverse proxy support (e.g., /webhook when behind nginx with /webhook/ prefix)
# This allows FastAPI to generate correct URLs in OpenAPI schema when behind a proxy
# Note: This is used ONLY for URL generation, NOT for path stripping (uvicorn --root-path would do that)
ROOT_PATH = os.getenv("ROOT_PATH", "").rstrip("/")  # Remove trailing slash if present

# Global stats object (Redis-backed, stateless, safe to share)
stats = RedisEndpointStats()  # Use Redis for persistent stats


async def startup_logic(app: FastAPI):
    """
    Application startup logic - extracted for testability.
    
    This function contains all startup initialization logic and can be tested
    independently. It's called by the lifespan context manager.
    
    Args:
        app: FastAPI application instance (uses app.state for storage)
    """
    import sys
    import warnings
    
    # Suppress specific warnings that are not actionable
    warnings.filterwarnings("ignore", category=FutureWarning, module="google.api_core")
    
    # Print ASCII art banner with version info
    print("\n" + "=" * 60)
    print("""
██╗    ██╗███████╗██████╗ ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗
██║    ██║██╔════╝██╔══██╗██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝
██║ █╗ ██║█████╗  ██████╔╝███████║██║   ██║██║   ██║█████╔╝ 
██║███╗██║██╔══╝  ██╔══██╗██╔══██║██║   ██║██║   ██║██╔═██╗ 
╚███╔███╔╝███████╗██████╔╝██║  ██║╚██████╔╝╚██████╔╝██║  ██╗
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝
    """)
    print("=" * 60)
    print(f"Python Version: {sys.version.split()[0]}")
    print(f"Platform: {sys.platform}")
    print("=" * 60 + "\n")
    
    # Initialize ConfigManager for live reload
    print("📋 Initializing configuration manager...")
    app.state.config_manager = ConfigManager()
    try:
        init_result = await app.state.config_manager.initialize()
        if init_result.success:
            webhooks_count = init_result.details.get('webhooks_loaded', 0)
            connections_count = init_result.details.get('connections_loaded', 0)
            print(f"✅ ConfigManager initialized: {webhooks_count} webhook(s), {connections_count} connection(s)")
        else:
            print(f"⚠️  ConfigManager initialization warning: {init_result.error}")
    except Exception as e:
        # SECURITY: Sanitize error message to prevent information disclosure
        sanitized_error = sanitize_error_message(e, "startup_logic.ConfigManager")
        print(f"❌ Failed to initialize ConfigManager: {sanitized_error}")
        print("   Falling back to legacy config loading...")
        # Fallback to old config loading
        app.state.webhook_config_data = await inject_connection_details(webhook_config_data, connection_config)
        app.state.config_manager = None
    else:
        # Use ConfigManager for config access
        # Build webhook_config_data from ConfigManager for backward compatibility
        app.state.webhook_config_data = {}
        # Note: ConfigManager will be used directly in webhook handler
    
    # Validate all connections at startup
    try:
        if app.state.config_manager:
            # Get connection config from ConfigManager using public method
            conn_config = app.state.config_manager.get_all_connection_configs()
        else:
            # Use legacy connection_config
            conn_config = connection_config
        
        await validate_connections(conn_config)
    except Exception as e:
        # Don't fail startup if validation fails, just log it
        sanitized_error = sanitize_error_message(e, "connection validation")
        print(f"⚠️  Connection validation error: {sanitized_error}")
    
    # Initialize ClickHouse logger for automatic event logging
    # Look for any clickhouse connection (webhook instances just log events)
    clickhouse_config = None
    if app.state.config_manager:
        # Get all connection configs using public API (avoiding private _connection_config)
        try:
            all_conn_configs = app.state.config_manager.get_all_connection_configs()
            for conn_name, conn in all_conn_configs.items():
                if conn and conn.get('type') == 'clickhouse':
                    clickhouse_config = conn
                    break
        except Exception:
            # Fallback if method not accessible
            pass
    else:
        for conn_name, conn in connection_config.items():
            if conn.get('type') == 'clickhouse':
                clickhouse_config = conn
                break
    
    # Initialize ClickHouse logger for automatic event logging
    app.state.clickhouse_logger = None
    if clickhouse_config:
        print("📊 Checking ClickHouse connection...")
        try:
            app.state.clickhouse_logger = ClickHouseAnalytics(clickhouse_config)
            await app.state.clickhouse_logger.connect()
            print("✅ ClickHouse event logger initialized - all webhook events will be logged")
        except Exception as e:
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "startup_logic.ClickHouse")
            print(f"⚠️  ClickHouse logger unavailable: {sanitized_error}")
            print("   Continuing without ClickHouse logging...")
            app.state.clickhouse_logger = None
    
    # Initialize Webhook Connect if enabled
    app.state.webhook_connect_channel_manager = None
    webhook_connect_enabled = os.getenv("WEBHOOK_CONNECT_ENABLED", "false").lower() == "true"
    if webhook_connect_enabled:
        print("🔗 Initializing Webhook Connect...")
        try:
            # Get Redis URL for buffer (use same Redis as stats or dedicated one)
            redis_url = os.getenv("WEBHOOK_CONNECT_REDIS_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0"))

            # Create Redis buffer
            buffer = RedisBuffer(url=redis_url, prefix="webhook_connect")

            # Create channel manager
            channel_manager = ChannelManager(buffer)
            await channel_manager.start()

            # Store in app state
            app.state.webhook_connect_channel_manager = channel_manager

            # Inject into module and API handlers
            WebhookConnectModule.set_channel_manager(channel_manager)
            webhook_connect_api.set_channel_manager(channel_manager)
            webhook_connect_admin_api.set_channel_manager(channel_manager)

            print("✅ Webhook Connect initialized successfully")
        except Exception as e:
            sanitized_error = sanitize_error_message(e, "startup_logic.WebhookConnect")
            print(f"⚠️  Webhook Connect initialization failed: {sanitized_error}")
            print("   Webhook Connect module will not be available")
            app.state.webhook_connect_channel_manager = None

    # Start file watcher if enabled
    app.state.config_watcher = None
    file_watching_enabled = os.getenv("CONFIG_FILE_WATCHING_ENABLED", "false").lower() == "true"
    if file_watching_enabled and app.state.config_manager:
        try:
            # SECURITY: Validate debounce_seconds to prevent DoS via invalid values
            debounce_str = os.getenv("CONFIG_RELOAD_DEBOUNCE_SECONDS", "3.0")
            try:
                debounce_seconds = float(debounce_str)
                # Validate range: 0.1 to 3600 seconds (0.1s to 1 hour)
                if debounce_seconds < 0.1:
                    debounce_seconds = 3.0  # Default to 3.0 if too small
                    print(f"WARNING: CONFIG_RELOAD_DEBOUNCE_SECONDS too small, using default 3.0")
                elif debounce_seconds > 3600:
                    debounce_seconds = 3600  # Cap at 1 hour
                    print(f"WARNING: CONFIG_RELOAD_DEBOUNCE_SECONDS too large, capped at 3600")
            except (ValueError, TypeError):
                # Invalid value, use default
                debounce_seconds = 3.0
                print(f"WARNING: Invalid CONFIG_RELOAD_DEBOUNCE_SECONDS value '{debounce_str}', using default 3.0")
            
            app.state.config_watcher = ConfigFileWatcher(app.state.config_manager, debounce_seconds=debounce_seconds)
            app.state.config_watcher.start()
            print(f"✅ Config file watcher started - automatic reload enabled (debounce: {debounce_seconds}s)")
        except Exception as e:
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "startup_logic.ConfigFileWatcher")
            print(f"Failed to start config file watcher: {sanitized_error}")

    # Start background cleanup task
    app.state.cleanup_task = asyncio.create_task(cleanup_task())
    
    # Get server port from environment (default: 8000)
    server_port = os.getenv("PORT", "8000")
    server_host = os.getenv("HOST", "0.0.0.0")
    base_url = f"http://{server_host}:{server_port}"
    
    # Print startup completion message
    print("\n" + "=" * 60)
    print("🚀 Webhook service startup complete!")
    print("-" * 60)
    print(f"📍 Health check: {base_url}/health")
    print(f"📊 Statistics:   {base_url}/stats")
    print(f"📚 API Docs:     {base_url}/docs")
    print("=" * 60 + "\n")


async def shutdown_logic(app: FastAPI):
    """
    Application shutdown logic - extracted for testability.
    
    This function contains all shutdown cleanup logic and can be tested
    independently. It's called by the lifespan context manager.
    
    Args:
        app: FastAPI application instance (uses app.state for storage)
    """
    print("\n🛑 Shutting down webhook service...")
    
    # SECURITY: Handle errors gracefully during shutdown to prevent information disclosure
    if hasattr(app.state, 'config_watcher') and app.state.config_watcher:
        try:
            app.state.config_watcher.stop()
        except Exception as e:
            sanitized_error = sanitize_error_message(e, "shutdown_logic.ConfigFileWatcher")
            print(f"Error stopping config file watcher: {sanitized_error}")
    
    if hasattr(app.state, 'config_manager') and app.state.config_manager:
        try:
            await app.state.config_manager.pool_registry.close_all_pools()
        except Exception as e:
            sanitized_error = sanitize_error_message(e, "shutdown_logic.ConnectionPools")
            print(f"Error closing connection pools: {sanitized_error}")
    
    if hasattr(app.state, 'clickhouse_logger') and app.state.clickhouse_logger:
        try:
            await app.state.clickhouse_logger.disconnect()
        except Exception as e:
            sanitized_error = sanitize_error_message(e, "shutdown_logic.ClickHouse")
            print(f"Error disconnecting ClickHouse logger: {sanitized_error}")

    # Stop Webhook Connect channel manager
    if hasattr(app.state, 'webhook_connect_channel_manager') and app.state.webhook_connect_channel_manager:
        try:
            await app.state.webhook_connect_channel_manager.stop()
        except Exception as e:
            sanitized_error = sanitize_error_message(e, "shutdown_logic.WebhookConnect")
            print(f"Error stopping Webhook Connect: {sanitized_error}")

    # Close Redis connection
    try:
        await stats.close()
    except Exception as e:
        sanitized_error = sanitize_error_message(e, "shutdown_logic.RedisStats")
        print(f"Error closing Redis stats: {sanitized_error}")

    # Stop background cleanup task
    if hasattr(app.state, 'cleanup_task') and app.state.cleanup_task:
        try:
            app.state.cleanup_task.cancel()
            try:
                await asyncio.wait_for(app.state.cleanup_task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        except Exception as e:
            sanitized_error = sanitize_error_message(e, "shutdown_logic.CleanupTask")
            print(f"Error stopping cleanup task: {sanitized_error}")
    
    print("✅ Shutdown complete\n")


# Backward compatibility aliases for tests
async def startup_event():
    """Backward compatibility alias for startup_logic - for testing."""
    from fastapi import FastAPI
    # Create a minimal app instance for testing
    test_app = FastAPI()
    await startup_logic(test_app)
    return test_app


async def shutdown_event():
    """Backward compatibility alias for shutdown_logic - for testing."""
    from fastapi import FastAPI
    # Create a minimal app instance for testing
    test_app = FastAPI()
    await shutdown_logic(test_app)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager - handles startup and shutdown events.
    Uses app.state for storing application-scoped dependencies (thread-safe).
    Replaces deprecated @app.on_event decorators and global mutable state.
    """
    await startup_logic(app)
    yield  # Application runs here
    await shutdown_logic(app)


# Initialize FastAPI app with lifespan
# Disable docs if requested
# root_path is used when behind a reverse proxy to generate correct URLs in OpenAPI schema
# openapi_url must include ROOT_PATH so Swagger UI loads the correct JSON file
openapi_url_path = f"{ROOT_PATH}/openapi.json" if (ROOT_PATH and not DISABLE_OPENAPI_DOCS) else ("/openapi.json" if not DISABLE_OPENAPI_DOCS else None)
app = FastAPI(
    lifespan=lifespan,
    docs_url="/docs" if not DISABLE_OPENAPI_DOCS else None,
    redoc_url="/redoc" if not DISABLE_OPENAPI_DOCS else None,
    openapi_url=openapi_url_path,
    root_path=ROOT_PATH if ROOT_PATH else None  # Set root_path for reverse proxy support (URL generation only)
)


# Override FastAPI's openapi() method to return custom schema
if not DISABLE_OPENAPI_DOCS:
    from functools import wraps
    
    original_openapi = app.openapi
    
    @wraps(original_openapi)
    def custom_openapi():
        """Generate custom OpenAPI schema from webhooks.json."""
        try:
            from src.openapi_generator import generate_openapi_schema
            # Generate schema dynamically from current webhook config
            # Use ConfigManager if available, otherwise fallback
            config_manager = getattr(app.state, 'config_manager', None)
            if config_manager:
                # Build webhook config dict from ConfigManager using public API
                webhook_configs = config_manager.get_all_webhook_configs()
                if webhook_configs:  # Only call if non-empty dict
                    return generate_openapi_schema(webhook_configs)
            
            # Fallback to webhook_config_data if available
            webhook_config_data = getattr(app.state, 'webhook_config_data', None)
            if webhook_config_data:  # Only call if truthy (not None, not empty dict)
                return generate_openapi_schema(webhook_config_data)
        except Exception as e:
            # SECURITY: Sanitize error message to prevent information disclosure
            sanitized_error = sanitize_error_message(e, "custom_openapi")
            print(f"WARNING: Failed to generate OpenAPI schema: {sanitized_error}")
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
        # For OpenAPI docs endpoints, use more permissive CSP to allow Swagger UI resources
        is_docs_endpoint = request.url.path in ["/docs", "/redoc", "/openapi.json"]
        
        csp_policy = os.getenv("CSP_POLICY", "")
        if csp_policy:
            # Use custom CSP if provided
            response.headers["Content-Security-Policy"] = csp_policy
        elif is_docs_endpoint:
            # Permissive CSP for OpenAPI docs (Swagger UI needs CDN resources)
            docs_csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.jsdelivr.net; "
                "font-src 'self' data: https://cdn.jsdelivr.net; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            )
            response.headers["Content-Security-Policy"] = docs_csp
        else:
            # Default restrictive CSP for all other endpoints
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

# Include Webhook Connect routers (conditional - will only work if WEBHOOK_CONNECT_ENABLED=true)
# The routers handle the case when channel_manager is not set (returns 503)
app.include_router(webhook_connect_api.router)
app.include_router(webhook_connect_admin_api.router)


async def cleanup_task():
    while True:
        # Stats cleanup is handled by Redis TTL
        
        # Cleanup rate limiter
        await rate_limiter.cleanup_old_entries()
        print("Cleaning up old rate limiter entries")
        
        await asyncio.sleep(3600)  # Wait for 1 hour (3600 seconds) before next cleanup


# Removed analytics_task - statistics aggregation is now handled by separate analytics service


async def validate_connections(connection_config: dict):
    """
    Validate all connections at startup and log results.
    
    SECURITY: Validates host addresses to prevent SSRF attacks before attempting connections.
    
    Args:
        connection_config: Dictionary of connection configurations
    """
    if not connection_config:
        print("ℹ️  No connections configured")
        return
    
    print("\n🔌 Validating connections...")
    print("-" * 60)
    
    success_count = 0
    failure_count = 0
    
    # SECURITY: Import host validation function and ipaddress for private IP detection
    from src.config import _validate_connection_host, _validate_connection_port
    import ipaddress
    
    for conn_name, conn_details in connection_config.items():
        if not conn_details or not isinstance(conn_details, dict):
            continue
            
        conn_type = conn_details.get('type', 'unknown')
        status_icon = "⏳"
        status_msg = ""
        
        try:
            if conn_type == 'postgresql':
                # SECURITY: Validate host and port before attempting connection
                host = conn_details.get('host', 'localhost')
                port = conn_details.get('port', 5432)
                
                # Validate host to prevent SSRF (allows private IPs for internal networks)
                try:
                    _validate_connection_host(host, conn_type)
                except ValueError as e:
                    status_icon = "❌"
                    status_msg = f"Host validation failed: {str(e)}"
                    failure_count += 1
                    print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
                    continue
                
                # Validate port
                try:
                    _validate_connection_port(port, conn_type)
                except ValueError as e:
                    status_icon = "❌"
                    status_msg = f"Port validation failed: {str(e)}"
                    failure_count += 1
                    print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
                    continue
                
                # Test PostgreSQL connection
                import asyncpg
                database = conn_details.get('database', 'postgres')
                user = conn_details.get('user', 'postgres')
                password = conn_details.get('password', '')
                
                connection_string = f"postgresql://{user}:{password}@{host}:{port}/{database}"
                conn = await asyncio.wait_for(
                    asyncpg.connect(connection_string),
                    timeout=5.0
                )
                await conn.fetchval('SELECT 1')
                await conn.close()
                status_icon = "✅"
                status_msg = f"Connected to {host}:{port}/{database}"
                
            elif conn_type == 'mysql':
                # SECURITY: Validate host and port before attempting connection
                host = conn_details.get('host', 'localhost')
                port = conn_details.get('port', 3306)
                
                # Validate host to prevent SSRF (allows private IPs for internal networks)
                try:
                    _validate_connection_host(host, conn_type)
                except ValueError as e:
                    status_icon = "❌"
                    status_msg = f"Host validation failed: {str(e)}"
                    failure_count += 1
                    print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
                    continue
                
                # Validate port
                try:
                    _validate_connection_port(port, conn_type)
                except ValueError as e:
                    status_icon = "❌"
                    status_msg = f"Port validation failed: {str(e)}"
                    failure_count += 1
                    print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
                    continue
                
                # Test MySQL connection
                import aiomysql
                database = conn_details.get('database', 'mysql')
                user = conn_details.get('user', 'root')
                password = conn_details.get('password', '')
                
                pool = await asyncio.wait_for(
                    aiomysql.create_pool(
                        host=host,
                        port=port,
                        user=user,
                        password=password,
                        db=database,
                        minsize=1,
                        maxsize=1
                    ),
                    timeout=5.0
                )
                async with pool.acquire() as conn:
                    async with conn.cursor() as cur:
                        await cur.execute('SELECT 1')
                        await cur.fetchone()
                pool.close()
                await pool.wait_closed()
                status_icon = "✅"
                status_msg = f"Connected to {host}:{port}/{database}"
                
            elif conn_type == 'kafka':
                # SECURITY: Validate bootstrap_servers before attempting connection
                bootstrap_servers = conn_details.get('bootstrap_servers', 'localhost:9092')
                
                # Parse bootstrap_servers (format: "host:port" or "host1:port1,host2:port2")
                # SECURITY: Validate each host in bootstrap_servers
                servers = bootstrap_servers.split(',')
                for server in servers:
                    server = server.strip()
                    if ':' in server:
                        host = server.split(':')[0].strip()
                        try:
                            port_str = server.split(':')[1].strip()
                            port = int(port_str)
                            _validate_connection_port(port, conn_type)
                        except (ValueError, IndexError):
                            status_icon = "❌"
                            status_msg = f"Invalid port in bootstrap_servers: {server}"
                            failure_count += 1
                            print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
                            break
                    else:
                        host = server
                    
                    # Validate host to prevent SSRF (allows private IPs for internal networks)
                    try:
                        _validate_connection_host(host, conn_type)
                    except ValueError as e:
                        status_icon = "❌"
                        status_msg = f"Host validation failed in bootstrap_servers: {str(e)}"
                        failure_count += 1
                        print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
                        break
                else:
                    # All hosts validated, proceed with connection
                    # Test Kafka connection
                    from aiokafka import AIOKafkaProducer
                    producer = AIOKafkaProducer(
                        bootstrap_servers=bootstrap_servers,
                        value_serializer=lambda v: v
                    )
                    await asyncio.wait_for(producer.start(), timeout=5.0)
                    await producer.stop()
                    status_icon = "✅"
                    status_msg = f"Connected to {bootstrap_servers}"
                    continue
                
                # If we hit a validation error, skip connection attempt
                continue
                
            elif conn_type == 'redis-rq':
                # SECURITY: Validate host and port before attempting connection
                host = conn_details.get('host', 'localhost')
                port = conn_details.get('port', 6379)
                
                # Validate host to prevent SSRF (allows private IPs for internal networks)
                try:
                    _validate_connection_host(host, conn_type)
                except ValueError as e:
                    status_icon = "❌"
                    status_msg = f"Host validation failed: {str(e)}"
                    failure_count += 1
                    print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
                    continue
                
                # Validate port
                try:
                    _validate_connection_port(port, conn_type)
                except ValueError as e:
                    status_icon = "❌"
                    status_msg = f"Port validation failed: {str(e)}"
                    failure_count += 1
                    print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
                    continue
                
                # Test Redis connection
                from redis import Redis
                db = conn_details.get('db', 0)
                
                client = Redis(host=host, port=port, db=db, socket_connect_timeout=5)
                client.ping()
                status_icon = "✅"
                status_msg = f"Connected to {host}:{port}/{db}"
                
            elif conn_type == 'rabbitmq':
                # SECURITY: Validate host and port before attempting connection
                host = conn_details.get('host', 'localhost')
                port = conn_details.get('port', 5672)
                
                # Validate host to prevent SSRF (allows private IPs for internal networks)
                try:
                    _validate_connection_host(host, conn_type)
                except ValueError as e:
                    status_icon = "❌"
                    status_msg = f"Host validation failed: {str(e)}"
                    failure_count += 1
                    print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
                    continue
                
                # Validate port
                try:
                    _validate_connection_port(port, conn_type)
                except ValueError as e:
                    status_icon = "❌"
                    status_msg = f"Port validation failed: {str(e)}"
                    failure_count += 1
                    print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
                    continue
                
                # Test RabbitMQ connection
                import aio_pika
                user = conn_details.get('user', 'guest')
                password = conn_details.get('pass', 'guest')
                
                connection = await asyncio.wait_for(
                    aio_pika.connect_robust(f"amqp://{user}:{password}@{host}:{port}/"),
                    timeout=5.0
                )
                await connection.close()
                status_icon = "✅"
                status_msg = f"Connected to {host}:{port}"
                
            elif conn_type == 'clickhouse':
                # SECURITY: Validate host and port before attempting connection
                host = conn_details.get('host', 'localhost')
                port = conn_details.get('port', 9000)
                
                # Validate host to prevent SSRF (allows private IPs for internal networks)
                try:
                    _validate_connection_host(host, conn_type)
                except ValueError as e:
                    status_icon = "❌"
                    status_msg = f"Host validation failed: {str(e)}"
                    failure_count += 1
                    print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
                    continue
                
                # Validate port
                try:
                    _validate_connection_port(port, conn_type)
                except ValueError as e:
                    status_icon = "❌"
                    status_msg = f"Port validation failed: {str(e)}"
                    failure_count += 1
                    print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
                    continue
                
                # Test ClickHouse connection
                from clickhouse_driver import Client
                database = conn_details.get('database', 'default')
                user = conn_details.get('user', 'default')
                password = conn_details.get('password', '') or None
                
                def test_connection():
                    kwargs = {'host': host, 'port': port, 'database': database, 'user': user, 'secure': False}
                    if password:
                        kwargs['password'] = password
                    client = Client(**kwargs)
                    client.execute('SELECT 1')
                    return True
                
                loop = asyncio.get_event_loop()
                await asyncio.wait_for(
                    loop.run_in_executor(None, test_connection),
                    timeout=5.0
                )
                status_icon = "✅"
                status_msg = f"Connected to {host}:{port}/{database}"
                
            else:
                # Unknown connection type - skip validation but log
                status_icon = "⚠️ "
                status_msg = f"Connection type '{conn_type}' validation not implemented"
                
            if status_icon == "✅":
                success_count += 1
            else:
                failure_count += 1
                
        except asyncio.TimeoutError:
            status_icon = "❌"
            status_msg = "Connection timeout"
            failure_count += 1
        except Exception as e:
            status_icon = "❌"
            # SECURITY: Sanitize error message to prevent information disclosure
            # The error might contain connection strings, passwords, or other sensitive info
            # Check if error contains sensitive patterns before sanitizing
            error_str = str(e)
            # Check for connection string patterns in error message
            if any(pattern in error_str.lower() for pattern in ['postgresql://', 'mysql://', 'redis://', 'amqp://', 'password', 'secret']):
                # Error contains sensitive information - use generic message
                status_msg = f"Failed: Connection validation error"
            else:
                # Error doesn't contain obvious sensitive info, but still sanitize
                error_msg = sanitize_error_message(e, f"{conn_type} connection")
                status_msg = f"Failed: {error_msg}"
            failure_count += 1
        
        # SECURITY: Only print status if we haven't already printed it (for validation errors)
        if status_icon != "⏳":
            print(f"{status_icon} {conn_name} ({conn_type}): {status_msg}")
    
    print("-" * 60)
    print(f"✅ {success_count} connection(s) successful")
    if failure_count > 0:
        print(f"❌ {failure_count} connection(s) failed")
    print()





@app.post("/webhook/{webhook_id}", tags=["Webhooks"])
async def read_webhook(webhook_id: str,  request: Request):
    # Get configs from ConfigManager if available, otherwise use fallback
    config_manager = getattr(request.app.state, 'config_manager', None)
    if config_manager:
        # Get all webhook configs to support default fallback
        webhook_configs = config_manager.get_all_webhook_configs()
        # Pass connection_config for chain processor to inject connection_details
        # ConfigManager already has environment variables substituted
        conn_configs = config_manager.get_all_connection_configs()
        pool_registry = config_manager.pool_registry
    else:
        # Fallback to old config system
        webhook_configs = getattr(request.app.state, 'webhook_config_data', webhook_config_data)
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
    # Don't fail webhook if stats fail - silently skip if Redis unavailable
    try:
        await stats.increment(webhook_id)
    except Exception as e:
        # SECURITY: Silently skip stats update if Redis is unavailable
        # This is intentional - stats are non-critical and Redis may be intentionally not configured
        # Logging errors would create noise. The webhook processing should not fail due to stats.
        pass  # nosec B110

    # Automatically log all webhook events to ClickHouse
    # This allows analytics service to process them later
    # Only log if ClickHouse is available and connected
    clickhouse_logger = getattr(request.app.state, 'clickhouse_logger', None)
    if clickhouse_logger and clickhouse_logger.client:
        try:
            # Log asynchronously using task manager (fire and forget)
            from src.webhook import task_manager
            async def log_to_clickhouse():
                await clickhouse_logger.save_log(webhook_id, payload, headers)
            await task_manager.create_task(log_to_clickhouse())
        except Exception as e:
            # SECURITY: Silently skip ClickHouse logging if it fails
            # This is intentional - logging is non-critical and ClickHouse may be intentionally not configured
            # Logging errors would create noise. The webhook processing should not fail due to logging.
            pass  # nosec B110

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
async def default_endpoint(request: Request):
    """
    Default root endpoint - health check endpoint.
    
    SECURITY: Rate limited to prevent DoS attacks.
    Rate limit can be configured via environment variable:
    - DEFAULT_ENDPOINT_RATE_LIMIT: Requests per minute (default: 120)
    """
    # SECURITY: Rate limiting to prevent DoS attacks
    default_rate_limit = int(os.getenv("DEFAULT_ENDPOINT_RATE_LIMIT", "120"))  # Default: 120 requests per minute
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.client.host if request.client else "unknown"
    
    # Use rate limiter with a separate key for default endpoint
    default_key = f"default_endpoint:{client_ip}"
    is_allowed, remaining = await rate_limiter.check_rate_limit(
        default_key, 
        max_requests=default_rate_limit, 
        window_seconds=60
    )
    
    if not is_allowed:
        raise HTTPException(
            status_code=429, 
            detail=f"Rate limit exceeded. Limit: {default_rate_limit} requests per minute"
        )
    
    return JSONResponse(content={"message": "200 OK"})


@app.get("/health", tags=["Health"])
async def health_endpoint(request: Request):
    """
    Health check endpoint for monitoring and load balancers.
    
    Returns the health status of the service and critical components.
    This endpoint has minimal rate limiting to allow frequent health checks.
    
    Returns:
        - 200 OK: Service is healthy
        - 503 Service Unavailable: Service is unhealthy (critical components down)
    """
    health_status = {
        "status": "healthy",
        "service": "webhook-service",
        "timestamp": None
    }
    
    # Get current timestamp
    health_status["timestamp"] = time.time()
    
    # Check critical components
    components = {}
    overall_healthy = True
    
    # Check ConfigManager
    config_manager = getattr(request.app.state, 'config_manager', None)
    if config_manager:
        try:
            # Quick check if config manager is initialized
            config_manager.get_all_webhook_configs()
            components["config_manager"] = "healthy"
        except Exception:
            components["config_manager"] = "unhealthy"
            overall_healthy = False
    else:
        components["config_manager"] = "not_configured"
    
    # Check Redis stats (if used)
    try:
        # Quick ping to Redis if available
        await stats.get_stats()
        components["redis_stats"] = "healthy"
    except Exception:
        components["redis_stats"] = "unavailable"
        # Redis stats are non-critical, so don't mark as unhealthy
    
    # Check ClickHouse logger (if configured)
    clickhouse_logger = getattr(request.app.state, 'clickhouse_logger', None)
    if clickhouse_logger:
        try:
            if clickhouse_logger.client:
                components["clickhouse"] = "healthy"
            else:
                components["clickhouse"] = "disconnected"
        except Exception:
            components["clickhouse"] = "unavailable"
    else:
        components["clickhouse"] = "not_configured"
    
    # Check Webhook Connect (if enabled)
    webhook_connect_manager = getattr(request.app.state, 'webhook_connect_channel_manager', None)
    if webhook_connect_manager:
        try:
            # Check if channel manager is running and buffer is connected
            if hasattr(webhook_connect_manager, 'is_running') and webhook_connect_manager.is_running():
                components["webhook_connect"] = "healthy"
            else:
                components["webhook_connect"] = "degraded"  # Initialized but buffer not connected
        except Exception:
            components["webhook_connect"] = "unavailable"
    else:
        components["webhook_connect"] = "not_configured"
    
    health_status["components"] = components
    
    # If critical components are unhealthy, return 503
    if not overall_healthy:
        health_status["status"] = "unhealthy"
        return JSONResponse(
            content=health_status,
            status_code=503
        )
    
    return JSONResponse(content=health_status)


@app.get("/stats", tags=["Statistics"])
async def stats_endpoint(request: Request):
    """
    Statistics endpoint - requires authentication to prevent information disclosure.
    
    Authentication can be configured via environment variables:
    - STATS_AUTH_TOKEN: Bearer token for authentication (recommended)
    - STATS_ALLOWED_IPS: Comma-separated list of allowed IP addresses (optional)
    - STATS_RATE_LIMIT: Requests per minute (default: 60)
    
    Returns statistics about webhook endpoint usage including request counts, 
    success/failure rates, and response times.
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


@app.post("/admin/reload-config", tags=["Admin"])
async def reload_config_endpoint(request: Request):
    """
    Admin endpoint to manually trigger configuration reload.
    
    Supports reloading webhooks, connections, or both.
    
    Requires authentication via CONFIG_RELOAD_ADMIN_TOKEN environment variable.
    
    Request body (JSON):
    - reload_webhooks: boolean (optional, default: true)
    - reload_connections: boolean (optional, default: true)
    """
    config_manager = getattr(request.app.state, 'config_manager', None)
    
    if not config_manager:
        raise HTTPException(status_code=503, detail="ConfigManager not initialized")
    
    # Check authentication if configured
    # SECURITY: Get original value to check if it was set (even if whitespace-only)
    admin_token_raw = os.getenv("CONFIG_RELOAD_ADMIN_TOKEN", "")
    admin_token = admin_token_raw.strip()
    # SECURITY: If original was set but becomes empty after strip, treat as invalid (require auth but reject all)
    if admin_token_raw and not admin_token:
        # Whitespace-only token configured - require auth but reject all tokens
        auth_header = request.headers.get("authorization", "")
        if not auth_header:
            raise HTTPException(status_code=401, detail="Authentication required")
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    if admin_token:
        auth_header = request.headers.get("authorization", "")
        # SECURITY: Check for None/empty header before processing
        if not auth_header:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # SECURITY: Prevent header injection (newlines, carriage returns, null bytes)
        if "\n" in auth_header or "\r" in auth_header or "\x00" in auth_header:
            raise HTTPException(status_code=401, detail="Invalid authentication header")
        
        # Extract token
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        else:
            token = auth_header.strip()
        
        # SECURITY: Reject whitespace-only tokens
        if not token:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        
        # Constant-time comparison
        import hmac
        if not hmac.compare_digest(token.encode('utf-8'), admin_token.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    # Parse request body
    try:
        body = await request.json()
        # SECURITY: Type validation to prevent type confusion attacks
        reload_webhooks_raw = body.get("reload_webhooks", True)
        reload_connections_raw = body.get("reload_connections", True)
        validate_only_raw = body.get("validate_only", False)
        
        # Convert to boolean (handle type confusion)
        reload_webhooks = bool(reload_webhooks_raw) if reload_webhooks_raw is not None else True
        reload_connections = bool(reload_connections_raw) if reload_connections_raw is not None else True
        validate_only = bool(validate_only_raw) if validate_only_raw is not None else False
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
        # SECURITY: Sanitize details to prevent information disclosure
        sanitized_details = None
        if result.details:
            # Remove sensitive information from details
            sanitized_details = {}
            # SECURITY: List of sensitive keys to completely remove (not just redact)
            sensitive_keys = ["stack_trace", "traceback", "file_path", "connection_string", "password", "secret", "token"]
            for key, value in result.details.items():
                key_lower = key.lower()
                # Remove sensitive keys entirely
                if any(sensitive_key in key_lower for sensitive_key in sensitive_keys):
                    continue  # Skip this key entirely
                
                if isinstance(value, str):
                    # Check for sensitive patterns
                    value_lower = value.lower()
                    if any(pattern in value_lower for pattern in ["password", "secret", "token", "connection_string", "postgresql://", "mysql://", "redis://", "/etc/", "c:\\"]):
                        sanitized_details[key] = "[REDACTED]"
                    else:
                        sanitized_details[key] = value
                else:
                    sanitized_details[key] = value
        
        return JSONResponse(content={
            "status": "success",
            "reloaded": {
                "webhooks": reload_webhooks,
                "connections": reload_connections
            },
            "details": sanitized_details,
            "timestamp": result.timestamp
        })
    else:
        # SECURITY: Sanitize error message to prevent information disclosure
        # Additional pattern-based sanitization for connection strings and sensitive paths
        if result.error:
            sanitized_error = sanitize_error_message(result.error, "reload_config")
        else:
            sanitized_error = "Configuration reload failed"
        
        # SECURITY: Sanitize details to prevent information disclosure
        sanitized_details = None
        if result.details:
            sanitized_details = {}
            # SECURITY: List of sensitive keys to completely remove (not just redact)
            sensitive_keys = ["stack_trace", "traceback", "file_path", "connection_string", "password", "secret", "token"]
            for key, value in result.details.items():
                key_lower = key.lower()
                # Remove sensitive keys entirely
                if any(sensitive_key in key_lower for sensitive_key in sensitive_keys):
                    continue  # Skip this key entirely
                
                if isinstance(value, str):
                    value_lower = value.lower()
                    # Check for sensitive patterns in values
                    if any(pattern in value_lower for pattern in ["password", "secret", "token", "connection_string", "postgresql://", "mysql://", "redis://", "/etc/", "c:\\", "traceback", "stack_trace"]):
                        sanitized_details[key] = "[REDACTED]"
                    else:
                        sanitized_details[key] = value
                else:
                    sanitized_details[key] = value
        
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "error": sanitized_error,
                "details": sanitized_details,
                "timestamp": result.timestamp
            }
        )


@app.get("/admin/config-status", tags=["Admin"])
async def config_status_endpoint(request: Request):
    """
    Admin endpoint to get current configuration status.
    
    Returns information about:
    - Last reload time
    - Reload in progress status
    - Webhook and connection counts
    - Connection pool information
    
    Requires authentication via CONFIG_RELOAD_ADMIN_TOKEN environment variable.
    """
    config_manager = getattr(request.app.state, 'config_manager', None)
    
    if not config_manager:
        raise HTTPException(status_code=503, detail="ConfigManager not initialized")
    
    # Check authentication if configured
    # SECURITY: Get original value to check if it was set (even if whitespace-only)
    admin_token_raw = os.getenv("CONFIG_RELOAD_ADMIN_TOKEN", "")
    admin_token = admin_token_raw.strip()
    # SECURITY: If original was set but becomes empty after strip, treat as invalid (require auth but reject all)
    if admin_token_raw and not admin_token:
        # Whitespace-only token configured - require auth but reject all tokens
        auth_header = request.headers.get("authorization", "")
        if not auth_header:
            raise HTTPException(status_code=401, detail="Authentication required")
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    if admin_token:
        auth_header = request.headers.get("authorization", "")
        # SECURITY: Check for None/empty header before processing
        if not auth_header:
            raise HTTPException(status_code=401, detail="Authentication required")
        
        # SECURITY: Prevent header injection (newlines, carriage returns, null bytes)
        if "\n" in auth_header or "\r" in auth_header or "\x00" in auth_header:
            raise HTTPException(status_code=401, detail="Invalid authentication header")
        
        # Extract token
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        else:
            token = auth_header.strip()
        
        # SECURITY: Reject whitespace-only tokens
        if not token:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        
        # Constant-time comparison
        import hmac
        if not hmac.compare_digest(token.encode('utf-8'), admin_token.encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    status = config_manager.get_status()
    
    # SECURITY: Sanitize status to prevent information disclosure
    # Remove sensitive information from pool_details
    if "pool_details" in status and isinstance(status["pool_details"], dict):
        sanitized_pool_details = {}
        # SECURITY: List of sensitive keys to completely remove (not just redact)
        sensitive_keys = ["password", "secret", "token", "connection_string"]
        for pool_name, pool_info in status["pool_details"].items():
            sanitized_info = {}
            for key, value in pool_info.items():
                key_lower = key.lower()
                # Remove sensitive keys entirely
                if any(sensitive_key in key_lower for sensitive_key in sensitive_keys):
                    continue  # Skip this key entirely
                
                if isinstance(value, str):
                    value_lower = value.lower()
                    # Redact sensitive information in values
                    if any(pattern in value_lower for pattern in ["password", "secret", "token", "connection_string", "postgresql://", "mysql://", "redis://"]):
                        sanitized_info[key] = "[REDACTED]"
                    else:
                        sanitized_info[key] = value
                else:
                    sanitized_info[key] = value
            sanitized_pool_details[pool_name] = sanitized_info
        status["pool_details"] = sanitized_pool_details
    
    # Add file watching status
    config_watcher = getattr(request.app.state, 'config_watcher', None)
    status["file_watching_enabled"] = config_watcher is not None and config_watcher.is_watching()
    
    return JSONResponse(content=status)


