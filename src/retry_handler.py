"""
Retry handler for module execution with exponential backoff.
"""
import asyncio
import logging
from typing import Callable, Dict, Any, Tuple, Optional, List
from functools import wraps

logger = logging.getLogger(__name__)

# Default retryable error types
DEFAULT_RETRYABLE_ERRORS = [
    "ConnectionError",
    "ConnectionRefusedError",
    "TimeoutError",
    "OSError",
    "IOError",
]

# Default non-retryable error types
DEFAULT_NON_RETRYABLE_ERRORS = [
    "AuthenticationError",
    "PermissionError",
    "ValueError",
    "KeyError",
    "TypeError",
]


class RetryHandler:
    """Handles retry logic for module execution."""
    
    def __init__(self):
        """Initialize retry handler with default configuration."""
        pass
    
    def _is_retryable_error(self, error: Exception, retryable_errors: List[str], non_retryable_errors: List[str]) -> bool:
        """
        Determine if an error is retryable.
        
        Args:
            error: The exception that occurred
            retryable_errors: List of retryable error type names
            non_retryable_errors: List of non-retryable error type names
            
        Returns:
            True if error is retryable, False otherwise
        """
        error_type_name = type(error).__name__
        error_module = type(error).__module__
        full_error_name = f"{error_module}.{error_type_name}" if error_module else error_type_name
        
        # Check non-retryable first (takes precedence)
        for non_retryable in non_retryable_errors:
            if non_retryable in error_type_name or non_retryable in full_error_name:
                return False
        
        # Check retryable errors
        for retryable in retryable_errors:
            if retryable in error_type_name or retryable in full_error_name:
                return True
        
        # Check by exception type hierarchy
        if isinstance(error, (ConnectionError, TimeoutError, OSError, IOError)):
            return True
        
        # Default: assume retryable for unknown errors
        return True
    
    def _calculate_backoff(self, attempt: int, initial_delay: float, max_delay: float, backoff_multiplier: float) -> float:
        """
        Calculate backoff delay for retry attempt.
        
        Args:
            attempt: Current attempt number (0-indexed)
            initial_delay: Initial delay in seconds
            max_delay: Maximum delay in seconds
            backoff_multiplier: Multiplier for exponential backoff
            
        Returns:
            Delay in seconds
        """
        delay = initial_delay * (backoff_multiplier ** attempt)
        return min(delay, max_delay)
    
    async def execute_with_retry(
        self,
        func: Callable,
        *args,
        retry_config: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Tuple[bool, Optional[Exception]]:
        """
        Execute function with retry logic.
        
        Args:
            func: The async function to execute
            *args: Positional arguments for the function
            retry_config: Retry configuration dictionary
            **kwargs: Keyword arguments for the function
            
        Returns:
            Tuple of (success: bool, last_error: Optional[Exception])
        """
        if not retry_config or not retry_config.get("enabled", False):
            # No retry configured, execute once
            try:
                await func(*args, **kwargs)
                return True, None
            except Exception as e:
                logger.error(f"Module execution failed (no retry): {e}")
                return False, e
        
        # Extract retry configuration
        max_attempts = retry_config.get("max_attempts", 3)
        initial_delay = retry_config.get("initial_delay", 1.0)
        max_delay = retry_config.get("max_delay", 60.0)
        backoff_multiplier = retry_config.get("backoff_multiplier", 2.0)
        
        retryable_errors = retry_config.get("retryable_errors", DEFAULT_RETRYABLE_ERRORS)
        non_retryable_errors = retry_config.get("non_retryable_errors", DEFAULT_NON_RETRYABLE_ERRORS)
        
        last_error = None
        
        for attempt in range(max_attempts):
            try:
                await func(*args, **kwargs)
                if attempt > 0:
                    logger.info(f"Module execution succeeded after {attempt + 1} attempts")
                return True, None
                
            except Exception as e:
                last_error = e
                
                # Check if error is retryable
                if not self._is_retryable_error(e, retryable_errors, non_retryable_errors):
                    logger.warning(f"Non-retryable error encountered: {e}")
                    return False, e
                
                # Check if we have more attempts
                if attempt < max_attempts - 1:
                    backoff_delay = self._calculate_backoff(attempt, initial_delay, max_delay, backoff_multiplier)
                    logger.warning(
                        f"Module execution failed (attempt {attempt + 1}/{max_attempts}): {e}. "
                        f"Retrying in {backoff_delay:.2f} seconds..."
                    )
                    await asyncio.sleep(backoff_delay)
                else:
                    logger.error(f"Module execution failed after {max_attempts} attempts: {e}")
        
        return False, last_error


# Global instance
retry_handler = RetryHandler()

