import re
import importlib
from typing import Any, Dict, Callable, Optional
from rq import Queue
from src.modules.base import BaseModule


class RedisRQModule(BaseModule):
    """Module for queuing webhook payloads to Redis RQ."""
    
    # Whitelist of allowed function names/patterns for security
    # Only functions matching these patterns are allowed
    ALLOWED_FUNCTION_PATTERNS = [
        r'^[a-zA-Z_][a-zA-Z0-9_]*$',  # Simple function name (e.g., "process_data")
        r'^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*$',  # Module.function (e.g., "utils.process")
        r'^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*$',  # Package.module.function
    ]
    
    # Explicitly blocked dangerous function names/patterns
    BLOCKED_FUNCTION_PATTERNS = [
        r'^os\.',  # os.system, os.popen, etc.
        r'^subprocess\.',  # subprocess.call, subprocess.run, etc.
        r'^eval$',  # eval function
        r'^exec$',  # exec function
        r'^compile$',  # compile function
        r'^__import__$',  # __import__ function
        r'^open$',  # open function (file operations)
        r'^file$',  # file function (Python 2)
        r'^input$',  # input function
        r'^raw_input$',  # raw_input function (Python 2)
        r'^execfile$',  # execfile function (Python 2)
        r'^reload$',  # reload function
        r'^getattr$',  # getattr function (can be used for code execution)
        r'^setattr$',  # setattr function
        r'^delattr$',  # delattr function
        r'^hasattr$',  # hasattr function
        r'^globals$',  # globals function
        r'^locals$',  # locals function
        r'^vars$',  # vars function
        r'^dir$',  # dir function
        r'^help$',  # help function
        r'^breakpoint$',  # breakpoint function
        r'^__.*__$',  # Magic methods (__builtins__, __import__, etc.)
    ]
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Validate function name during initialization to fail early
        raw_function_name = self.module_config.get('function')
        if raw_function_name:
            # Validate non-empty function name
            self._validated_function_name = self._validate_function_name(raw_function_name)
        elif raw_function_name == "":  # Explicitly check for empty string
            # Empty string should be validated and rejected
            self._validated_function_name = self._validate_function_name("")
        else:
            # None or missing key
            self._validated_function_name = None
    
    def _validate_function_name(self, function_name: str) -> str:
        """
        Validate function name to prevent code injection.
        
        This function:
        - Validates format (must match allowed patterns)
        - Blocks dangerous function names
        - Ensures function name is safe for RQ enqueue
        
        Args:
            function_name: The function name from configuration
            
        Returns:
            Validated function name
            
        Raises:
            ValueError: If function name is invalid, dangerous, or not whitelisted
        """
        if not function_name or not isinstance(function_name, str):
            raise ValueError("Function name must be a non-empty string")
        
        # Remove whitespace
        function_name = function_name.strip()
        
        if not function_name:
            raise ValueError("Function name cannot be empty")
        
        # Maximum length to prevent DoS
        MAX_FUNCTION_NAME_LENGTH = 255
        if len(function_name) > MAX_FUNCTION_NAME_LENGTH:
            raise ValueError(
                f"Function name too long: {len(function_name)} characters (max: {MAX_FUNCTION_NAME_LENGTH})"
            )
        
        # Check for null bytes
        if '\x00' in function_name:
            raise ValueError("Function name cannot contain null bytes")
        
        # Check for path traversal patterns
        if '..' in function_name or '/' in function_name or '\\' in function_name:
            raise ValueError(
                "Function name cannot contain path traversal sequences ('..', '/', '\\')"
            )
        
        # Additional validation: ensure no dangerous characters FIRST (before pattern checks)
        dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '[', ']', '{', '}', '<', '>', '?', '*', '!']
        for char in dangerous_chars:
            if char in function_name:
                raise ValueError(
                    f"Function name contains dangerous character '{char}': '{function_name}'"
                )
        
        # Check for dangerous patterns (before whitelist check)
        for pattern in self.BLOCKED_FUNCTION_PATTERNS:
            if re.match(pattern, function_name):
                raise ValueError(
                    f"Function name '{function_name}' is explicitly blocked for security reasons. "
                    f"Dangerous functions (os.*, eval, exec, etc.) are not allowed."
                )
        
        # Check if function name matches allowed patterns
        matches_allowed = False
        for pattern in self.ALLOWED_FUNCTION_PATTERNS:
            if re.match(pattern, function_name):
                matches_allowed = True
                break
        
        if not matches_allowed:
            raise ValueError(
                f"Function name '{function_name}' does not match allowed patterns. "
                f"Only simple function names (e.g., 'process_data') or module paths "
                f"(e.g., 'utils.process', 'package.module.function') are allowed."
            )
        
        return function_name
    
    def _get_function_callable(self, function_name: str) -> Optional[Callable]:
        """
        Get function callable from function name string.
        
        This attempts to import and return the function, but only if it's safe.
        If import fails, returns None (RQ can handle string function names).
        
        Args:
            function_name: The validated function name
            
        Returns:
            Function callable if importable, None otherwise
        """
        try:
            # Split module path and function name
            if '.' in function_name:
                parts = function_name.rsplit('.', 1)
                module_path = parts[0]
                func_name = parts[1]
                
                # Import module
                module = importlib.import_module(module_path)
                # Get function
                func = getattr(module, func_name, None)
                
                if func and callable(func):
                    return func
            else:
                # Simple function name - try to get from builtins or current module
                # This is less safe, so we'll prefer string-based enqueue
                return None
        except (ImportError, AttributeError, ValueError):
            # If import fails, return None - RQ can handle string function names
            return None
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Queue payload processing using Redis RQ."""
        connection = self.connection_details.get('conn')
        
        if not connection:
            raise Exception("Redis connection is not defined")
        
        queue_name = self.module_config.get('queue_name', 'default')
        
        # Use validated function name from initialization
        function_name = self._validated_function_name
        
        if not function_name:
            raise Exception("Function name not specified in module-config")
        
        try:
            # Create queue
            q = Queue(queue_name, connection=connection)
            
            # Enqueue the task
            # Use validated function name (string) - RQ will import it safely
            # We've already validated it's safe, so passing as string is acceptable
            result = q.enqueue(function_name, payload, headers)
            
            print(f"Task queued to Redis RQ: {result.id}")
        except Exception as e:
            # SECURITY: Sanitize error messages to prevent information disclosure
            from src.utils import sanitize_error_message
            raise Exception(f"Failed to queue task to Redis RQ: {sanitize_error_message(e, 'Redis RQ operation')}")
