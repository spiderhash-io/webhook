import httpx
import re
from typing import Any, Dict
from src.modules.base import BaseModule


class HTTPWebhookModule(BaseModule):
    """Module for forwarding webhook payloads to another HTTP endpoint."""
    
    # Valid HTTP header name pattern (RFC 7230)
    # Header names: token = 1*tchar, where tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
    VALID_HEADER_NAME_PATTERN = re.compile(r'^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$')
    
    # Dangerous characters in header values that could lead to injection
    DANGEROUS_CHARS = ['\r', '\n', '\0']
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Get whitelist of allowed headers from config (optional)
        self.allowed_headers = self.module_config.get('allowed_headers', None)
        if self.allowed_headers and isinstance(self.allowed_headers, list):
            # Normalize to lowercase for case-insensitive comparison
            self.allowed_headers = {h.lower() for h in self.allowed_headers}
        else:
            self.allowed_headers = None
    
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
                if name.lower() not in self.allowed_headers:
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
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Forward payload to configured HTTP endpoint."""
        url = self.module_config.get('url')
        method = self.module_config.get('method', 'POST').upper()
        forward_headers = self.module_config.get('forward_headers', True)
        timeout = self.module_config.get('timeout', 30)
        
        if not url:
            raise Exception("URL not specified in module-config")
        
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
            print(f"Failed to forward HTTP webhook to {url}: {e}")
            raise e
