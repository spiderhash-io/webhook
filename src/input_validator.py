"""
Input validation and sanitization utilities.
Provides functions to validate and sanitize webhook inputs.
"""
import re
from typing import Any, Dict, Tuple


class InputValidator:
    """Validates and sanitizes webhook inputs."""
    
    # Maximum sizes
    MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_HEADER_SIZE = 8 * 1024  # 8KB
    MAX_HEADER_COUNT = 100
    MAX_JSON_DEPTH = 50
    MAX_STRING_LENGTH = 1024 * 1024  # 1MB
    
    # Dangerous patterns
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>.*?</script>',  # XSS
        r'javascript:',  # JavaScript protocol
        r'on\w+\s*=',  # Event handlers
    ]
    
    @staticmethod
    def validate_payload_size(payload: bytes) -> Tuple[bool, str]:
        """Validate payload size."""
        if len(payload) > InputValidator.MAX_PAYLOAD_SIZE:
            return False, f"Payload too large: {len(payload)} bytes (max: {InputValidator.MAX_PAYLOAD_SIZE})"
        return True, "Valid size"
    
    @staticmethod
    def validate_headers(headers: Dict[str, str]) -> Tuple[bool, str]:
        """Validate headers."""
        if len(headers) > InputValidator.MAX_HEADER_COUNT:
            return False, f"Too many headers: {len(headers)} (max: {InputValidator.MAX_HEADER_COUNT})"
        
        total_size = sum(len(k) + len(v) for k, v in headers.items())
        if total_size > InputValidator.MAX_HEADER_SIZE:
            return False, f"Headers too large: {total_size} bytes (max: {InputValidator.MAX_HEADER_SIZE})"
        
        return True, "Valid headers"
    
    @staticmethod
    def validate_json_depth(obj: Any, current_depth: int = 0) -> Tuple[bool, str]:
        """Validate JSON nesting depth."""
        if current_depth > InputValidator.MAX_JSON_DEPTH:
            return False, f"JSON too deeply nested: {current_depth} levels (max: {InputValidator.MAX_JSON_DEPTH})"
        
        if isinstance(obj, dict):
            for value in obj.values():
                is_valid, msg = InputValidator.validate_json_depth(value, current_depth + 1)
                if not is_valid:
                    return is_valid, msg
        elif isinstance(obj, list):
            for item in obj:
                is_valid, msg = InputValidator.validate_json_depth(item, current_depth + 1)
                if not is_valid:
                    return is_valid, msg
        
        return True, "Valid depth"
    
    @staticmethod
    def validate_string_length(obj: Any) -> Tuple[bool, str]:
        """Validate string lengths in payload."""
        if isinstance(obj, str):
            if len(obj) > InputValidator.MAX_STRING_LENGTH:
                return False, f"String too long: {len(obj)} chars (max: {InputValidator.MAX_STRING_LENGTH})"
        elif isinstance(obj, dict):
            for value in obj.values():
                is_valid, msg = InputValidator.validate_string_length(value)
                if not is_valid:
                    return is_valid, msg
        elif isinstance(obj, list):
            for item in obj:
                is_valid, msg = InputValidator.validate_string_length(item)
                if not is_valid:
                    return is_valid, msg
        
        return True, "Valid string lengths"
    
    @staticmethod
    def sanitize_string(value: str) -> str:
        """Sanitize string value (basic HTML escaping)."""
        if not isinstance(value, str):
            return value
        
        # Basic HTML escaping
        value = value.replace('&', '&amp;')
        value = value.replace('<', '&lt;')
        value = value.replace('>', '&gt;')
        value = value.replace('"', '&quot;')
        value = value.replace("'", '&#x27;')
        
        return value
    
    @staticmethod
    def check_dangerous_patterns(value: str) -> Tuple[bool, str]:
        """Check for dangerous patterns in string."""
        if not isinstance(value, str):
            return True, "Not a string"
        
        for pattern in InputValidator.DANGEROUS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return False, f"Dangerous pattern detected: {pattern}"
        
        return True, "No dangerous patterns"
    
    @staticmethod
    def validate_webhook_id(webhook_id: str) -> Tuple[bool, str]:
        """Validate webhook ID format."""
        # Only allow alphanumeric, underscore, and hyphen
        if not re.match(r'^[a-zA-Z0-9_-]+$', webhook_id):
            return False, "Invalid webhook ID format"
        
        if len(webhook_id) > 100:
            return False, "Webhook ID too long"
        
        return True, "Valid webhook ID"
    
    @staticmethod
    def validate_all(webhook_id: str, payload_bytes: bytes, headers: Dict[str, str], payload_obj: Any) -> Tuple[bool, str]:
        """Run all validations."""
        # Validate webhook ID
        is_valid, msg = InputValidator.validate_webhook_id(webhook_id)
        if not is_valid:
            return is_valid, msg
        
        # Validate payload size
        is_valid, msg = InputValidator.validate_payload_size(payload_bytes)
        if not is_valid:
            return is_valid, msg
        
        # Validate headers
        is_valid, msg = InputValidator.validate_headers(headers)
        if not is_valid:
            return is_valid, msg
        
        # Validate JSON depth
        is_valid, msg = InputValidator.validate_json_depth(payload_obj)
        if not is_valid:
            return is_valid, msg
        
        # Validate string lengths
        is_valid, msg = InputValidator.validate_string_length(payload_obj)
        if not is_valid:
            return is_valid, msg
        
        return True, "All validations passed"
