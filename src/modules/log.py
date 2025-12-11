import json
import re
from typing import Any, Dict, Set
from src.modules.base import BaseModule


class LogModule(BaseModule):
    """Module for logging webhook payloads to stdout."""
    
    # Maximum output length per field to prevent DoS
    MAX_OUTPUT_LENGTH = 10000
    
    # Sensitive keys to redact
    SENSITIVE_KEYS = {
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'access_token', 'refresh_token', 'authorization', 'auth',
        'credential', 'credentials', 'private_key', 'privatekey',
        'session', 'cookie', 'ssn', 'credit_card', 'creditcard',
        'database_url', 'db_url', 'connection_string', 'conn_string'
    }
    
    def _sanitize_for_logging(self, data: Any, visited: Set[int] = None, depth: int = 0) -> str:
        """
        Sanitize data for safe logging.
        
        Prevents:
        - Information disclosure (redacts sensitive keys)
        - Log injection (sanitizes newlines and control characters)
        - Circular references (tracks visited objects)
        - DoS (limits output size and depth)
        
        Args:
            data: Data to sanitize
            visited: Set of object IDs to detect circular references
            depth: Current recursion depth
            
        Returns:
            Sanitized string representation
        """
        if visited is None:
            visited = set()
        
        # Prevent infinite recursion
        MAX_DEPTH = 10
        if depth > MAX_DEPTH:
            return "[Max depth exceeded]"
        
        # Handle circular references
        if isinstance(data, (dict, list)):
            obj_id = id(data)
            if obj_id in visited:
                return "[Circular reference]"
            visited.add(obj_id)
        
        try:
            # Convert to string representation
            if isinstance(data, dict):
                # Redact sensitive keys
                sanitized_dict = {}
                for key, value in data.items():
                    # Check if key contains sensitive patterns
                    key_lower = str(key).lower()
                    is_sensitive = any(sensitive in key_lower for sensitive in self.SENSITIVE_KEYS)
                    
                    if is_sensitive:
                        sanitized_dict[key] = "[REDACTED]"
                    else:
                        # Recursively sanitize value
                        sanitized_dict[key] = self._sanitize_for_logging(value, visited, depth + 1)
                
                result = str(sanitized_dict)
            elif isinstance(data, list):
                # Recursively sanitize list items
                sanitized_list = [
                    self._sanitize_for_logging(item, visited, depth + 1)
                    for item in data
                ]
                result = str(sanitized_list)
            else:
                result = str(data)
            
            # Remove circular reference from visited set
            if isinstance(data, (dict, list)):
                visited.discard(obj_id)
            
            # Sanitize log injection characters
            # Replace newlines, carriage returns, and other control characters
            result = re.sub(r'[\r\n]', '[NL]', result)  # Replace newlines
            result = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '[CTRL]', result)  # Replace control chars
            
            # Limit output length to prevent DoS
            if len(result) > self.MAX_OUTPUT_LENGTH:
                result = result[:self.MAX_OUTPUT_LENGTH] + "... [truncated]"
            
            return result
            
        except RecursionError:
            return "[Recursion error]"
        except Exception as e:
            return f"[Error serializing: {type(e).__name__}]"
    
    def _sanitize_config(self, config: Dict[str, Any]) -> str:
        """
        Sanitize config for logging (redact sensitive connection details).
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Sanitized config string
        """
        if not isinstance(config, dict):
            return str(config)
        
        sanitized = {}
        for key, value in config.items():
            # Redact connection_details entirely (contains sensitive data)
            if key == 'connection_details':
                sanitized[key] = "[REDACTED - connection details]"
            elif key == 'module-config':
                # Sanitize module config recursively
                sanitized[key] = self._sanitize_for_logging(value)
            else:
                # Check if key is sensitive
                key_lower = str(key).lower()
                if any(sensitive in key_lower for sensitive in self.SENSITIVE_KEYS):
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = self._sanitize_for_logging(value)
        
        return str(sanitized)
    
    def _sanitize_headers(self, headers: Dict[str, str]) -> str:
        """
        Sanitize headers for logging (redact sensitive headers).
        
        Args:
            headers: Headers dictionary
            
        Returns:
            Sanitized headers string
        """
        if not isinstance(headers, dict):
            return str(headers)
        
        sanitized = {}
        for key, value in headers.items():
            # Redact sensitive headers
            # Check if any sensitive keyword appears in the header name
            key_lower = str(key).lower()
            is_sensitive = False
            for sensitive in self.SENSITIVE_KEYS:
                # Check if sensitive keyword appears in header name (handles 'api-key', 'api_key', etc.)
                if sensitive.replace('_', '-') in key_lower or sensitive in key_lower:
                    is_sensitive = True
                    break
            
            if is_sensitive:
                sanitized[key] = "[REDACTED]"
            else:
                # Sanitize value for log injection
                sanitized_value = self._sanitize_for_logging(value)
                sanitized[key] = sanitized_value
        
        return str(sanitized)
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """
        Print payload and headers to stdout with security sanitization.
        
        SECURITY: All output is sanitized to prevent:
        - Information disclosure (sensitive data redaction)
        - Log injection (newline/control character sanitization)
        - DoS (output size limits)
        - Circular reference crashes
        """
        # Sanitize config (redact connection details)
        sanitized_config = self._sanitize_config(self.config)
        print(f"config: {sanitized_config}")
        
        # Sanitize headers (redact sensitive headers, prevent injection)
        sanitized_headers = self._sanitize_headers(headers)
        print(f"headers: {sanitized_headers}")
        
        # Sanitize payload (prevent injection, handle circular refs)
        sanitized_payload = self._sanitize_for_logging(payload)
        print(f"body: {sanitized_payload}")
