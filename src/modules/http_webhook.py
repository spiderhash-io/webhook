import httpx
import re
import ipaddress
from urllib.parse import urlparse, parse_qs
from typing import Any, Dict, Optional, List
from src.modules.base import BaseModule


class HTTPWebhookModule(BaseModule):
    """Module for forwarding webhook payloads to another HTTP endpoint."""
    
    # Valid HTTP header name pattern (RFC 7230)
    # Header names: token = 1*tchar, where tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
    VALID_HEADER_NAME_PATTERN = re.compile(r'^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$')
    
    # Dangerous characters in header values that could lead to injection
    # Includes standard newlines, Unicode line/paragraph separators, and control chars
    DANGEROUS_CHARS = ['\r', '\n', '\0', '\u2028', '\u2029', '\u000B', '\u000C']
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Get whitelist of allowed headers from config (optional)
        self.allowed_headers = self.module_config.get('allowed_headers', None)
        if self.allowed_headers is not None and isinstance(self.allowed_headers, list):
            # Empty list means block all headers
            if len(self.allowed_headers) == 0:
                self.allowed_headers = set()  # Empty set means block all
            else:
                # Normalize to lowercase for case-insensitive comparison
                self.allowed_headers = {h.lower() for h in self.allowed_headers}
        else:
            self.allowed_headers = None
        
        # Validate URL during initialization to prevent SSRF attacks
        url = self.module_config.get('url')
        if url:
            self._validated_url = self._validate_url(url)
        else:
            self._validated_url = None
    
    def _validate_header_name(self, name: str) -> bool:
        """
        Validate HTTP header name to prevent injection.
        
        Args:
            name: Header name to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not name or not isinstance(name, str):
            return False
        
        # Check length (RFC 7230 doesn't specify max, but we'll use a reasonable limit)
        if len(name) > 200:
            return False
        
        # Validate against RFC 7230 token pattern
        return bool(self.VALID_HEADER_NAME_PATTERN.match(name))
    
    def _sanitize_header_value(self, value: str) -> str:
        """
        Sanitize HTTP header value to prevent injection attacks.
        
        Args:
            value: Header value to sanitize
            
        Returns:
            Sanitized header value
            
        Raises:
            ValueError: If value contains dangerous characters
        """
        if not isinstance(value, str):
            value = str(value)
        
        # Check for dangerous characters (newlines, carriage returns, null bytes)
        for char in self.DANGEROUS_CHARS:
            if char in value:
                raise ValueError(
                    f"Header value contains forbidden character: {repr(char)}. "
                    f"Header injection attempt detected."
                )
        
        # Remove leading/trailing whitespace (but preserve internal whitespace)
        value = value.strip()
        
        # Check length (RFC 7230 doesn't specify max, but we'll use a reasonable limit)
        if len(value) > 8192:  # Common HTTP header value limit
            raise ValueError(f"Header value too long: {len(value)} characters (max: 8192)")
        
        return value
    
    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Sanitize and validate all headers to prevent injection attacks.
        
        Args:
            headers: Dictionary of headers to sanitize
            
        Returns:
            Dictionary of sanitized headers
            
        Raises:
            ValueError: If any header name or value is invalid
        """
        sanitized = {}
        
        for name, value in headers.items():
            # Validate header name
            if not self._validate_header_name(name):
                # Skip invalid header names instead of raising to be more resilient
                continue
            
            # Check whitelist if configured
            if self.allowed_headers is not None:
                # Empty set means block all headers
                if len(self.allowed_headers) == 0:
                    # Skip all headers if whitelist is empty
                    continue
                elif name.lower() not in self.allowed_headers:
                    # Skip headers not in whitelist
                    continue
            
            # Sanitize header value
            try:
                sanitized_value = self._sanitize_header_value(value)
                sanitized[name] = sanitized_value
            except ValueError as e:
                # Skip headers with invalid values instead of raising to be more resilient
                # Log the error but continue processing
                print(f"Warning: Skipping invalid header '{name}': {e}")
                continue
        
        return sanitized
    
    def _validate_url(self, url: str) -> str:
        """
        Validate URL to prevent SSRF attacks.
        
        This function:
        - Only allows http:// and https:// schemes
        - Blocks private IP ranges (RFC 1918, localhost, link-local)
        - Blocks file://, gopher://, and other dangerous schemes
        - Validates URL format
        - Optionally allows whitelisting specific domains/IPs
        
        Args:
            url: URL to validate
            
        Returns:
            Validated URL string
            
        Raises:
            ValueError: If URL is invalid or poses SSRF risk
        """
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string")
        
        url = url.strip()
        if not url:
            raise ValueError("URL cannot be empty")
        
        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid URL format: {str(e)}")
        
        # Only allow http and https schemes
        allowed_schemes = {'http', 'https'}
        if parsed.scheme.lower() not in allowed_schemes:
            raise ValueError(
                f"URL scheme '{parsed.scheme}' is not allowed. "
                f"Only http:// and https:// are permitted."
            )
        
        # Block URLs without hostname
        if not parsed.netloc:
            raise ValueError("URL must include a hostname")
        
        # Extract hostname (remove port if present, handle IPv6 brackets)
        # IPv6 addresses in URLs are enclosed in brackets: [2001:db8::1]
        # The netloc will be like "[2001:db8::1]:8080" or just "[2001:db8::1]"
        netloc = parsed.netloc
        # Check if it's an IPv6 address (starts with [)
        if netloc.startswith('['):
            # Extract IPv6 address (everything between [ and ])
            end_bracket = netloc.find(']')
            if end_bracket != -1:
                hostname = netloc[1:end_bracket]  # Remove brackets
                # Port might be after the closing bracket
                if end_bracket + 1 < len(netloc) and netloc[end_bracket + 1] == ':':
                    # Port is present, already extracted hostname
                    pass
            else:
                # Malformed IPv6 URL
                raise ValueError("Invalid IPv6 address format in URL")
        else:
            # Regular hostname or IPv4, extract before first colon (port)
            # Handle userinfo (user:pass@host) by splitting on @ first
            if '@' in netloc:
                # Extract hostname part after @
                hostname = netloc.split('@')[-1].split(':')[0]
            else:
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
        
        # Normalize and check for octal IP formats (0177.0.0.1, 127.0.00.1, etc.)
        # Python's urlparse doesn't interpret octal, but we should catch common patterns
        parts = hostname.split('.')
        if len(parts) == 4:
            try:
                decimal_parts = []
                has_octal = False
                
                for part in parts:
                    # Check if part looks like octal (starts with 0, has more digits, all 0-7)
                    # Examples: 0177, 00, 000, 001 (but not 0, 08, 09, 010)
                    if re.match(r'^0[0-7]+$', part):
                        # Parse as octal
                        decimal_parts.append(int(part, 8))
                        has_octal = True
                    elif re.match(r'^[0-9]+$', part):
                        # Regular decimal
                        decimal_parts.append(int(part))
                    else:
                        # Not numeric, skip octal check
                        break
                
                # Only check if we found octal parts and all 4 parts were numeric
                if has_octal and len(decimal_parts) == 4:
                    # Convert to normalized IP
                    normalized_ip = '.'.join(str(p) for p in decimal_parts)
                    # Check if normalized IP is localhost or private
                    try:
                        ip = ipaddress.ip_address(normalized_ip)
                        if ip.is_loopback or ip.is_private or ip.is_link_local:
                            raise ValueError(
                                f"Access to localhost/private IP is not allowed for security reasons"
                            )
                    except ValueError as e:
                        # Re-raise our validation errors, but let ipaddress errors pass through
                        if "is not allowed" in str(e):
                            raise
            except ValueError as e:
                # Re-raise validation errors from octal normalization
                if "is not allowed" in str(e):
                    raise
                # Otherwise, it's not a valid octal IP, continue
                pass
            except (AttributeError, TypeError):
                pass  # Not a valid octal IP, continue
        
        # Block localhost and variations
        localhost_variants = {
            'localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]',
            '127.1', '127.0.1', '127.000.000.001', '0177.0.0.1',  # Octal
            '0x7f.0.0.1', '2130706433', '0x7f000001',  # Decimal/Hex
        }
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
            pass
        except Exception:
            # Not an IP address, continue with hostname validation
            pass
        
        # Block common cloud metadata endpoints (even if hostname resolves to public IP)
        dangerous_hostnames = {
            'metadata.google.internal',
            '169.254.169.254',  # AWS, GCP, Azure metadata
            'metadata',  # Short form
            'metadata.azure.com',
            '100.100.100.200',  # Alibaba Cloud metadata
            '192.0.0.192',  # Oracle Cloud metadata
        }
        # Also check if hostname contains metadata-related patterns
        hostname_lower = hostname.lower()
        if hostname_lower in dangerous_hostnames:
            raise ValueError(
                f"Access to metadata service '{hostname}' is not allowed for security reasons"
            )
        # Check for metadata in hostname (e.g., metadata.example.com)
        if 'metadata' in hostname_lower and ('internal' in hostname_lower or 'azure' in hostname_lower or 'google' in hostname_lower):
            raise ValueError(
                f"Access to metadata service '{hostname}' is not allowed for security reasons"
            )
        
        # Block hostnames that look like IP addresses in unusual formats
        # (already handled by ipaddress, but check for common bypass attempts)
        if re.match(r'^0+\.0+\.0+\.0+$', hostname):
            raise ValueError("Invalid hostname format")
        
        # Validate hostname format (basic check)
        # Hostname should be valid DNS name or IP
        # IPv6 addresses are already validated by ipaddress.ip_address above
        if not self._is_valid_ip(hostname):
            # Block purely numeric hostnames (invalid DNS, potential IP encoding bypass)
            if re.match(r'^[0-9]+$', hostname):
                raise ValueError(f"Invalid hostname format: '{hostname}' (numeric-only hostnames are not allowed)")
            
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
        """Forward payload to configured HTTP endpoint."""
        url = self._validated_url
        method = self.module_config.get('method', 'POST').upper()
        forward_headers = self.module_config.get('forward_headers', True)
        timeout = self.module_config.get('timeout', 30)
        
        if not url:
            raise Exception("URL not specified in module-config")
        
        # URL should already be validated in __init__, but double-check
        if url != self._validated_url:
            raise Exception("URL validation failed")
        
        # Prepare headers
        request_headers = {}
        if forward_headers:
            # Filter out hop-by-hop headers
            skip_headers = {'host', 'connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'proxy-connection', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer'}
            filtered_headers = {k: v for k, v in headers.items() if k.lower() not in skip_headers}
            
            # Sanitize headers to prevent injection
            request_headers = self._sanitize_headers(filtered_headers)
        
        # Add custom headers from config (also sanitize these)
        custom_headers = self.module_config.get('headers', {})
        if custom_headers:
            sanitized_custom = self._sanitize_headers(custom_headers)
            request_headers.update(sanitized_custom)
        
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                if method == 'POST':
                    response = await client.post(url, json=payload, headers=request_headers)
                elif method == 'PUT':
                    response = await client.put(url, json=payload, headers=request_headers)
                elif method == 'PATCH':
                    response = await client.patch(url, json=payload, headers=request_headers)
                else:
                    raise Exception(f"Unsupported HTTP method: {method}")
                
                response.raise_for_status()
                print(f"HTTP webhook forwarded to {url}: {response.status_code}")
                
        except httpx.HTTPError as e:
            # Log detailed error server-side (includes URL for debugging)
            print(f"Failed to forward HTTP webhook to {url}: {e}")
            # Raise generic error to client (don't expose URL or error details)
            from src.utils import sanitize_error_message
            raise Exception(sanitize_error_message(e, "HTTP webhook forwarding"))
