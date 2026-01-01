# src/config.py
import json
import ipaddress
from typing import Any, Dict
from redis import Redis
from src.utils import load_env_vars
from src.modules.rabbitmq import RabbitMQConnectionPool
import os
from dotenv import load_dotenv

load_dotenv()

# Get config file paths from environment variables or use defaults
# Default to config/development/ if files exist there, otherwise fall back to root
_default_webhooks = "config/development/webhooks.json" if os.path.exists("config/development/webhooks.json") else "webhooks.json"
_default_connections = "config/development/connections.json" if os.path.exists("config/development/connections.json") else "connections.json"
WEBHOOKS_CONFIG_FILE = os.getenv("WEBHOOKS_CONFIG_FILE", _default_webhooks)
CONNECTIONS_CONFIG_FILE = os.getenv("CONNECTIONS_CONFIG_FILE", _default_connections)

# Load webhooks.json if it exists (optional for analytics service)
webhook_config_data = {}
if os.path.exists(WEBHOOKS_CONFIG_FILE):
    try:
        with open(WEBHOOKS_CONFIG_FILE, 'r') as webhooks_file:
            webhook_config_data = json.load(webhooks_file)
        # Update the webhook config with environment variables
        webhook_config_data = load_env_vars(webhook_config_data)
    except json.JSONDecodeError as e:
        # SECURITY: Sanitize JSON parsing errors to prevent information disclosure
        print(f"ERROR: Failed to parse webhooks.json: Invalid JSON format")
        raise ValueError("Invalid webhooks.json configuration file format")
    except Exception as e:
        # SECURITY: Sanitize file loading errors to prevent information disclosure
        print(f"ERROR: Failed to load webhooks.json: {e}")
        raise ValueError("Failed to load webhooks.json configuration file")
else:
    # Default logging webhook when webhooks.json is not provided
    print("INFO: webhooks.json not found. Using default logging webhook with pretty print to console.")
    print("INFO: Default logging endpoint enabled. All webhook requests will be logged to console.")
    print("INFO: Sensitive data redaction is DISABLED for debugging. Set 'redact_sensitive: true' in module-config to enable.")
    webhook_config_data = {
        "default": {
            "data_type": "json",
            "module": "log",
            "module-config": {
                "pretty_print": True,
                "redact_sensitive": False  # Default: show everything for debugging
            }
        }
    }

# Load connections.json (required)
try:
    with open(CONNECTIONS_CONFIG_FILE, 'r') as connections_file:
        connection_config = json.load(connections_file)
    # Update the configuration with environment variables
    connection_config = load_env_vars(connection_config)
except FileNotFoundError:
    # SECURITY: Sanitize file not found errors to prevent information disclosure
    print("ERROR: connections.json file not found")
    raise ValueError("connections.json configuration file is required but not found")
except json.JSONDecodeError as e:
    # SECURITY: Sanitize JSON parsing errors to prevent information disclosure
    print(f"ERROR: Failed to parse connections.json: Invalid JSON format")
    raise ValueError("Invalid connections.json configuration file format")
except Exception as e:
    # SECURITY: Sanitize file loading errors to prevent information disclosure
    print(f"ERROR: Failed to load connections.json: {e}")
    raise ValueError("Failed to load connections.json configuration file")


def _validate_connection_host(host: str, connection_type: str) -> str:
    """
    Validate connection host to prevent SSRF attacks.
    
    This function:
    - Blocks private IP ranges (RFC 1918, localhost, link-local)
    - Blocks dangerous hostnames
    - Validates host format
    - Optionally allows whitelisting specific hosts
    
    Args:
        host: The host from connection configuration
        connection_type: Type of connection (for context in error messages)
        
    Returns:
        Validated host string
        
    Raises:
        ValueError: If host is invalid or poses SSRF risk
    """
    if not host or not isinstance(host, str):
        raise ValueError(f"{connection_type} host must be a non-empty string")
    
    host = host.strip()
    
    if not host:
        raise ValueError(f"{connection_type} host cannot be empty")
    
    # Maximum length to prevent DoS
    MAX_HOST_LENGTH = 253  # DNS max length
    if len(host) > MAX_HOST_LENGTH:
        raise ValueError(f"{connection_type} host too long: {len(host)} characters (max: {MAX_HOST_LENGTH})")
    
    # Check for null bytes
    if '\x00' in host:
        raise ValueError(f"{connection_type} host cannot contain null bytes")
    
    # Check for localhost variants FIRST (before dangerous character check for IPv6)
    # Allow localhost for integration tests if ALLOW_LOCALHOST_FOR_TESTS is set
    allow_localhost = os.getenv("ALLOW_LOCALHOST_FOR_TESTS", "false").lower() == "true"
    localhost_variants = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]']
    if host.lower() in localhost_variants and not allow_localhost:
        raise ValueError(
            f"Access to localhost '{host}' is not allowed for security reasons."
        )
    
    # Check for dangerous characters (but allow brackets for IPv6 addresses)
    # First, check if it's an IPv6 address in brackets
    is_ipv6_bracketed = host.startswith('[') and host.endswith(']')
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '?', '*', '!', '\\']
    for char in dangerous_chars:
        if char in host:
            raise ValueError(f"{connection_type} host contains dangerous character '{char}': '{host}'")
    
    # Handle IPv6 addresses in brackets
    host_for_parsing = host
    if host.startswith('[') and host.endswith(']'):
        # Extract IPv6 address from brackets
        host_for_parsing = host[1:-1]
    
    # Try to parse as IP address
    try:
        ip = ipaddress.ip_address(host_for_parsing)
        
        # NOTE: Private IP ranges are now allowed to support internal networks.
        # We still block clearly dangerous ranges (link-local, multicast, reserved)
        # and localhost-style addresses are handled above.
        
        # Block link-local addresses
        if ip.is_link_local:
            raise ValueError(
                f"Access to link-local IP '{host}' is not allowed for security reasons."
            )
        
        # Block loopback (localhost)
        if ip.is_loopback:
            raise ValueError(
                f"Access to localhost IP '{host}' is not allowed for security reasons."
            )
        
        # Block multicast
        if ip.is_multicast:
            raise ValueError(
                f"Access to multicast IP '{host}' is not allowed for security reasons."
            )
        
        # Block reserved addresses
        if ip.is_reserved:
            raise ValueError(
                f"Access to reserved IP '{host}' is not allowed for security reasons."
            )
        
        # Allow public and private IPs (except the blocked categories above)
        return host
    
    except ValueError as e:
        # If ValueError is raised by ipaddress, it might be a hostname
        # Check if it's our custom error message
        if "not allowed" in str(e):
            raise
        
        # Otherwise, it's not a valid IP, so treat as hostname
        pass
    
    # Validate hostname format
    # (localhost already checked above)
    
    # Block dangerous hostname patterns
    dangerous_patterns = [
        'metadata.google.internal',
        '169.254.169.254',  # AWS metadata
        'metadata.azure.com',
        'metadata.cloud.ibm.com',
    ]
    
    for pattern in dangerous_patterns:
        if pattern.lower() in host.lower():
            raise ValueError(
                f"Access to metadata endpoint '{host}' is not allowed for security reasons."
            )
    
    # Basic hostname validation (alphanumeric, dots, hyphens)
    # This is permissive but safe - actual DNS resolution will happen later
    # If it's an IPv6 address in brackets but wasn't a valid IP, reject it
    if is_ipv6_bracketed:
        # Bracketed but not a valid IP address - reject
        raise ValueError(f"Invalid {connection_type} IPv6 address format: '{host}'")
    
    # For regular hostnames, validate format
    if not all(c.isalnum() or c in '.-' for c in host):
        raise ValueError(
            f"Invalid {connection_type} hostname format: '{host}'. "
            f"Only alphanumeric characters, dots, and hyphens are allowed."
        )
    
    return host


def _validate_connection_port(port: Any, connection_type: str) -> int:
    """
    Validate connection port to prevent SSRF attacks.
    
    Args:
        port: The port from connection configuration
        connection_type: Type of connection (for context in error messages)
        
    Returns:
        Validated port as integer
        
    Raises:
        ValueError: If port is invalid or out of range
    """
    if port is None:
        raise ValueError(f"{connection_type} port must be specified")
    
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        raise ValueError(f"{connection_type} port must be a valid integer: {port}")
    
    # Valid port range
    if port_int < 1 or port_int > 65535:
        raise ValueError(f"{connection_type} port must be between 1 and 65535: {port_int}")
    
    # Optionally block common dangerous ports (can be configured)
    # For now, we'll allow all valid ports, but this can be restricted if needed
    
    return port_int


async def inject_connection_details(webhook_config_data: Dict[str, Any], connection_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Inject connection details into webhook configurations.
    
    This function:
    - Validates connection configurations
    - Creates connection pools/objects for supported connection types
    - Injects connection details into webhook configs
    
    Args:
        webhook_config_data: Dictionary of webhook configurations
        connection_config: Dictionary of connection configurations
        
    Returns:
        Updated webhook_config_data with connection details injected
    """
    # Iterate over webhook configuration items
    for webhook_id, config in webhook_config_data.items():
        # Check if 'connection' is in the webhook configuration
        connection_name = config.get('connection')
        if connection_name:
            # Find the corresponding connection details
            connection_details = connection_config.get(connection_name)
            if connection_details:
                # SECURITY: Validate connection type exists to prevent KeyError
                connection_type = connection_details.get('type')
                if not connection_type:
                    raise ValueError(f"Connection '{connection_name}' is missing required 'type' field")

                # Create Redis connection for Redis RQ
                if connection_type == "redis-rq":
                    # Validate host and port before creating connection
                    raw_host = connection_details.get("host")
                    raw_port = connection_details.get("port")
                    
                    validated_host = _validate_connection_host(raw_host, "Redis RQ")
                    validated_port = _validate_connection_port(raw_port, "Redis RQ")
                    
                    # Initialize a Redis connection with validated host/port
                    connection_details["conn"] = Redis(
                        host=validated_host,
                        port=validated_port,
                        db=connection_details.get("db", 0)
                    )

                # Create RabbitMQ connection pool
                if connection_type == "rabbitmq":
                    # Validate host and port before creating connection
                    raw_host = connection_details.get("host")
                    raw_port = connection_details.get("port")
                    
                    validated_host = _validate_connection_host(raw_host, "RabbitMQ")
                    validated_port = _validate_connection_port(raw_port, "RabbitMQ")
                    
                    # Initialize RabbitMQ connection pool globally
                    connection_details["connection_pool"] = RabbitMQConnectionPool()

                    await connection_details["connection_pool"].create_pool(
                        host=validated_host,
                        port=validated_port,
                        login=connection_details.get("user"),
                        password=connection_details.get("pass")
                    )

                # Inject the connection details into the webhook configuration
                config['connection_details'] = connection_details

    return webhook_config_data
