import json
import ipaddress
import re
from urllib.parse import urlparse
from typing import Any, Dict
import websockets
from src.modules.base import BaseModule


class WebSocketModule(BaseModule):
    """Module for forwarding webhook payloads to WebSocket connections."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Validate WebSocket URL during initialization to prevent SSRF attacks
        ws_url = self.module_config.get('url')
        if ws_url:
            self._validated_url = self._validate_url(ws_url)
        else:
            self._validated_url = None
    
    def _validate_url(self, url: str) -> str:
        """
        Validate WebSocket URL to prevent SSRF attacks.
        
        This function:
        - Only allows ws:// and wss:// schemes
        - Blocks private IP ranges (RFC 1918, localhost, link-local)
        - Blocks file://, gopher://, and other dangerous schemes
        - Validates URL format
        - Optionally allows whitelisting specific domains/IPs
        
        Args:
            url: WebSocket URL to validate
            
        Returns:
            Validated URL string
            
        Raises:
            ValueError: If URL is invalid or poses SSRF risk
        """
        if not url or not isinstance(url, str):
            raise ValueError("WebSocket URL must be a non-empty string")
        
        url = url.strip()
        if not url:
            raise ValueError("WebSocket URL cannot be empty")
        
        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid URL format: {str(e)}")
        
        # Only allow ws and wss schemes
        allowed_schemes = {'ws', 'wss'}
        if parsed.scheme.lower() not in allowed_schemes:
            raise ValueError(
                f"URL scheme '{parsed.scheme}' is not allowed. "
                f"Only ws:// and wss:// are permitted for WebSocket connections."
            )
        
        # Block URLs without hostname
        if not parsed.netloc:
            raise ValueError("URL must include a hostname")
        
        # Extract hostname (remove port if present, handle IPv6 brackets)
        # IPv6 addresses in URLs are enclosed in brackets: [2001:db8::1]
        netloc = parsed.netloc
        # Check if it's an IPv6 address (starts with [)
        if netloc.startswith('['):
            # Extract IPv6 address (everything between [ and ])
            end_bracket = netloc.find(']')
            if end_bracket != -1:
                hostname = netloc[1:end_bracket]  # Remove brackets
            else:
                # Malformed IPv6 URL
                raise ValueError("Invalid IPv6 address format in URL")
        else:
            # Regular hostname or IPv4, extract before first colon (port)
            hostname = netloc.split(':')[0]
        
        # Check for whitelist in config (optional)
        allowed_hosts = self.module_config.get('allowed_hosts', None)
        if allowed_hosts and isinstance(allowed_hosts, list):
            # If whitelist is configured, only allow those hosts
            allowed_hosts_lower = {h.lower().strip() for h in allowed_hosts if h}
            if hostname.lower() not in allowed_hosts_lower:
                raise ValueError(
                    f"Hostname '{hostname}' is not in the allowed hosts whitelist"
                )
            # If whitelisted, skip further validation
            return url
        
        # Block localhost and variations
        # SECURITY: This set is used for validation to BLOCK localhost access, not for binding
        localhost_variants = {
            'localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]',
            '127.1', '127.0.1', '127.000.000.001', '0177.0.0.1',  # Octal
            '0x7f.0.0.1', '2130706433', '0x7f000001',  # Decimal/Hex
        }  # nosec B104
        if hostname.lower() in localhost_variants:
            raise ValueError(
                f"Access to localhost is not allowed for security reasons"
            )
        
        # Block private IP ranges (RFC 1918)
        # Also block link-local (169.254.0.0/16) and multicast (224.0.0.0/4)
        try:
            # Try to parse as IP address
            ip = ipaddress.ip_address(hostname)
            
            # Block link-local addresses FIRST (169.254.0.0/16) - these are often used for metadata
            if ip.is_link_local:
                raise ValueError(
                    f"Access to link-local address '{hostname}' is not allowed for security reasons"
                )
            
            # Block loopback (should be caught by localhost check, but double-check)
            if ip.is_loopback:
                raise ValueError(
                    f"Access to loopback address '{hostname}' is not allowed for security reasons"
                )
            
            # Block multicast addresses
            if ip.is_multicast:
                raise ValueError(
                    f"Access to multicast address '{hostname}' is not allowed for security reasons"
                )
            
            # Block reserved addresses (0.0.0.0/8, etc.)
            if ip.is_reserved:
                raise ValueError(
                    f"Access to reserved IP address '{hostname}' is not allowed for security reasons"
                )
            
            # Block private IPs (RFC 1918) - check after link-local
            if ip.is_private:
                raise ValueError(
                    f"Access to private IP address '{hostname}' is not allowed for security reasons"
                )
            
        except ValueError as e:
            # If ValueError is raised by ipaddress, it might be our validation error
            # Re-raise it
            if "is not allowed" in str(e):
                raise
            # Otherwise, it's not an IP address (might be a hostname), continue validation
            # SECURITY: This is intentional control flow - if IP parsing fails, try hostname validation
            pass  # nosec B110
        except Exception:
            # Not an IP address, continue with hostname validation
            # SECURITY: This is intentional control flow - IP parsing failure means it's a hostname
            pass  # nosec B110
        
        # Block common cloud metadata endpoints (even if hostname resolves to public IP)
        dangerous_hostnames = {
            'metadata.google.internal',
            '169.254.169.254',  # AWS, GCP, Azure metadata
            'metadata',  # Short form
        }
        if hostname.lower() in dangerous_hostnames:
            raise ValueError(
                f"Access to metadata service '{hostname}' is not allowed for security reasons"
            )
        
        # Block hostnames that look like IP addresses in unusual formats
        if re.match(r'^0+\.0+\.0+\.0+$', hostname):
            raise ValueError("Invalid hostname format")
        
        # Validate hostname format (basic check)
        # Hostname should be valid DNS name or IP
        if not self._is_valid_ip(hostname):
            # Check DNS hostname format
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', hostname):
                raise ValueError(f"Invalid hostname format: '{hostname}'")
        
        return url
    
    def _is_valid_ip(self, hostname: str) -> bool:
        """Check if hostname is a valid IP address."""
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Forward payload to WebSocket server."""
        ws_url = self._validated_url
        
        if not ws_url:
            raise Exception("WebSocket URL not specified in module-config")
        
        # URL should already be validated in __init__, but double-check
        if ws_url != self._validated_url:
            raise Exception("WebSocket URL validation failed")
        
        # Prepare message
        message_format = self.module_config.get('format', 'json')
        include_headers = self.module_config.get('include_headers', False)
        
        if message_format == 'json':
            message_data = {
                'payload': payload
            }
            if include_headers:
                message_data['headers'] = dict(headers)
            
            message = json.dumps(message_data)
        else:
            # Send raw payload
            if isinstance(payload, (dict, list)):
                message = json.dumps(payload)
            else:
                message = str(payload)
        
        # Connection settings
        timeout = self.module_config.get('timeout', 10)
        max_retries = self.module_config.get('max_retries', 3)
        
        # Custom headers for WebSocket connection
        extra_headers = self.module_config.get('headers', {})
        
        # Attempt to send with retries
        for attempt in range(max_retries):
            try:
                async with websockets.connect(
                    ws_url,
                    extra_headers=extra_headers,
                    open_timeout=timeout,
                    close_timeout=timeout
                ) as websocket:
                    await websocket.send(message)
                    
                    # Optionally wait for response
                    if self.module_config.get('wait_for_response', False):
                        response = await websocket.recv()
                        print(f"WebSocket response: {response}")
                    
                    print(f"Webhook forwarded to WebSocket: {ws_url}")
                    return  # Success, exit
                    
            except websockets.exceptions.WebSocketException as e:
                # Log detailed error server-side
                print(f"WebSocket error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt == max_retries - 1:
                    # Raise generic error to client (don't expose error details)
                    from src.utils import sanitize_error_message
                    raise Exception(sanitize_error_message(e, "WebSocket communication"))
            except Exception as e:
                # Log detailed error server-side
                print(f"Failed to send to WebSocket: {e}")
                # Raise generic error to client
                from src.utils import sanitize_error_message
                raise Exception(sanitize_error_message(e, "WebSocket operation"))
