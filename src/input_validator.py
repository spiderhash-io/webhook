"""
Input validation and sanitization utilities.
Provides functions to validate and sanitize webhook inputs.
"""
import re
import html
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
        """
        Validate headers.
        
        SECURITY: Checks for header injection attacks (newlines, null bytes) and DoS (count/size).
        """
        if len(headers) > InputValidator.MAX_HEADER_COUNT:
            return False, f"Too many headers: {len(headers)} (max: {InputValidator.MAX_HEADER_COUNT})"
        
        # SECURITY: Check for header injection attacks (newlines, carriage returns, null bytes)
        dangerous_chars = ['\n', '\r', '\0', '\u2028', '\u2029']  # Include Unicode line/paragraph separators
        for header_name, header_value in headers.items():
            # Check header name
            for char in dangerous_chars:
                if char in header_name:
                    return False, f"Invalid header name: contains forbidden character"
            
            # Check header value
            if isinstance(header_value, str):
                for char in dangerous_chars:
                    if char in header_value:
                        return False, f"Invalid header value: contains forbidden character"
        
        # Calculate total header size (only count string values to avoid errors)
        total_size = sum(
            len(k) + (len(v) if isinstance(v, str) else 0)
            for k, v in headers.items()
        )
        if total_size > InputValidator.MAX_HEADER_SIZE:
            return False, f"Headers too large: {total_size} bytes (max: {InputValidator.MAX_HEADER_SIZE})"
        
        return True, "Valid headers"
    
    @staticmethod
    def validate_json_depth(obj: Any, current_depth: int = 0, visited: set = None) -> Tuple[bool, str]:
        """
        Validate JSON nesting depth.
        
        SECURITY: Uses visited set to prevent infinite recursion from circular references.
        """
        if visited is None:
            visited = set()
        
        # SECURITY: Check for circular references using object identity
        obj_id = id(obj)
        if obj_id in visited:
            # Circular reference detected - treat as valid (already visited, won't increase depth)
            return True, "Valid depth"
        visited.add(obj_id)
        
        try:
            if current_depth > InputValidator.MAX_JSON_DEPTH:
                return False, f"JSON too deeply nested: {current_depth} levels (max: {InputValidator.MAX_JSON_DEPTH})"
            
            if isinstance(obj, dict):
                for value in obj.values():
                    is_valid, msg = InputValidator.validate_json_depth(value, current_depth + 1, visited)
                    if not is_valid:
                        return is_valid, msg
            elif isinstance(obj, list):
                for item in obj:
                    is_valid, msg = InputValidator.validate_json_depth(item, current_depth + 1, visited)
                    if not is_valid:
                        return is_valid, msg
            
            return True, "Valid depth"
        finally:
            # Remove from visited set when done with this branch (allows same object at different paths)
            visited.discard(obj_id)
    
    @staticmethod
    def validate_string_length(obj: Any, visited: set = None) -> Tuple[bool, str]:
        """
        Validate string lengths in payload.
        
        SECURITY: Uses visited set to prevent infinite recursion from circular references.
        """
        if visited is None:
            visited = set()
        
        # SECURITY: Check for circular references using object identity
        obj_id = id(obj)
        if obj_id in visited:
            # Circular reference detected - skip validation (already visited)
            return True, "Valid string lengths"
        visited.add(obj_id)
        
        try:
            if isinstance(obj, str):
                if len(obj) > InputValidator.MAX_STRING_LENGTH:
                    return False, f"String too long: {len(obj)} chars (max: {InputValidator.MAX_STRING_LENGTH})"
            elif isinstance(obj, dict):
                for value in obj.values():
                    is_valid, msg = InputValidator.validate_string_length(value, visited)
                    if not is_valid:
                        return is_valid, msg
            elif isinstance(obj, list):
                for item in obj:
                    is_valid, msg = InputValidator.validate_string_length(item, visited)
                    if not is_valid:
                        return is_valid, msg
            
            return True, "Valid string lengths"
        finally:
            # Remove from visited set when done with this branch
            visited.discard(obj_id)
    
    @staticmethod
    def sanitize_string(value: str) -> str:
        """Sanitize string value (HTML escaping)."""
        if not isinstance(value, str):
            return value
        
        # Use html.escape() for proper HTML escaping (handles edge cases correctly)
        return html.escape(value, quote=True)
    
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
        """
        Validate webhook ID format and prevent DoS/reserved name conflicts.
        
        This function:
        - Validates format (alphanumeric, underscore, hyphen only)
        - Enforces reasonable length limit to prevent DoS
        - Blocks reserved names that conflict with system endpoints
        - Prevents empty or whitespace-only IDs
        
        Args:
            webhook_id: The webhook ID to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        if not webhook_id or not isinstance(webhook_id, str):
            return False, "Webhook ID must be a non-empty string"
        
        # Strip whitespace
        webhook_id = webhook_id.strip()
        
        # Check for empty after stripping
        if not webhook_id:
            return False, "Webhook ID cannot be empty or whitespace-only"
        
        # Enforce maximum length to prevent DoS attacks
        # Reduced from 100 to 64 characters for better security
        MAX_WEBHOOK_ID_LENGTH = 64
        if len(webhook_id) > MAX_WEBHOOK_ID_LENGTH:
            return False, f"Webhook ID too long: {len(webhook_id)} characters (max: {MAX_WEBHOOK_ID_LENGTH})"
        
        # Only allow alphanumeric, underscore, and hyphen
        # Must start with alphanumeric (not underscore or hyphen)
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', webhook_id):
            return False, "Invalid webhook ID format. Must start with alphanumeric and contain only alphanumeric, underscore, and hyphen characters"
        
        # Block reserved names that conflict with system endpoints
        # These are case-insensitive to prevent bypass attempts
        # Only exact matches are blocked (not substrings)
        RESERVED_NAMES = {
            'stats', 'health', 'docs', 'openapi.json', 'redoc',
            'api', 'admin', 'root', 'system', 'internal',
            'favicon.ico', 'robots.txt',  # Common web paths
        }
        
        if webhook_id.lower() in RESERVED_NAMES:
            return False, f"Webhook ID '{webhook_id}' is reserved and cannot be used"
        
        # Block names that start with reserved prefixes
        RESERVED_PREFIXES = ['_', '__', 'internal_', 'system_', 'admin_']
        for prefix in RESERVED_PREFIXES:
            if webhook_id.lower().startswith(prefix):
                return False, f"Webhook ID cannot start with reserved prefix '{prefix}'"
        
        # Block names that end with reserved suffixes (system/internal/admin only)
        # Note: _test and _debug are not blocked as they're common in development
        RESERVED_SUFFIXES = ['_internal', '_system', '_admin']
        for suffix in RESERVED_SUFFIXES:
            if webhook_id.lower().endswith(suffix):
                return False, f"Webhook ID cannot end with reserved suffix '{suffix}'"
        
        # Block consecutive special characters (e.g., 'webhook--id', 'webhook__id')
        # Check for 2+ consecutive hyphens or 2+ consecutive underscores
        if re.search(r'--+', webhook_id) or re.search(r'__+', webhook_id):
            return False, "Webhook ID cannot contain consecutive underscores or hyphens"
        
        # Block names that are only special characters
        if re.match(r'^[-_]+$', webhook_id):
            return False, "Webhook ID cannot consist only of underscores or hyphens"
        
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
