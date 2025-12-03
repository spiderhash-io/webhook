"""
Retry handler for module execution with exponential backoff.

SECURITY: This handler validates all configuration values to prevent DoS attacks
via resource exhaustion (unbounded retries, excessive delays, etc.).
"""
import asyncio
import logging
from typing import Callable, Dict, Any, Tuple, Optional, List
from functools import wraps

logger = logging.getLogger(__name__)

# Security limits to prevent DoS attacks
MAX_ATTEMPTS_LIMIT = 20  # Maximum allowed retry attempts (prevents DoS via excessive retries)
MAX_DELAY_LIMIT = 60.0  # Maximum allowed delay in seconds (1 minute - prevents DoS via excessive delays)
MAX_BACKOFF_MULTIPLIER = 10.0  # Maximum allowed backoff multiplier
MIN_ATTEMPTS = 1  # Minimum allowed retry attempts
MIN_DELAY = 0.0  # Minimum allowed delay (0 is acceptable for immediate retry)
MIN_BACKOFF_MULTIPLIER = 0.1  # Minimum allowed backoff multiplier

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
    
    def _validate_retry_config(self, retry_config: Dict[str, Any]) -> Tuple[int, float, float, float, List[str], List[str]]:
        """
        Validate and sanitize retry configuration to prevent DoS attacks.
        
        SECURITY: This function enforces limits on all configuration values to prevent
        resource exhaustion attacks via malicious retry configurations.
        
        Args:
            retry_config: Retry configuration dictionary
            
        Returns:
            Tuple of (max_attempts, initial_delay, max_delay, backoff_multiplier, retryable_errors, non_retryable_errors)
            
        Raises:
            ValueError: If configuration values are invalid or out of bounds
        """
        # Validate max_attempts
        max_attempts = retry_config.get("max_attempts", 3)
        if not isinstance(max_attempts, int):
            logger.warning(f"Invalid max_attempts type: {type(max_attempts)}, defaulting to 3")
            max_attempts = 3
        if max_attempts < MIN_ATTEMPTS:
            logger.warning(f"max_attempts {max_attempts} is below minimum {MIN_ATTEMPTS}, setting to {MIN_ATTEMPTS}")
            max_attempts = MIN_ATTEMPTS
        if max_attempts > MAX_ATTEMPTS_LIMIT:
            logger.warning(f"max_attempts {max_attempts} exceeds security limit {MAX_ATTEMPTS_LIMIT}, capping to {MAX_ATTEMPTS_LIMIT}")
            max_attempts = MAX_ATTEMPTS_LIMIT
        
        # Validate initial_delay
        initial_delay = retry_config.get("initial_delay", 1.0)
        if not isinstance(initial_delay, (int, float)):
            logger.warning(f"Invalid initial_delay type: {type(initial_delay)}, defaulting to 1.0")
            initial_delay = 1.0
        if initial_delay < MIN_DELAY:
            logger.warning(f"initial_delay {initial_delay} is below minimum {MIN_DELAY}, setting to {MIN_DELAY}")
            initial_delay = MIN_DELAY
        if initial_delay > MAX_DELAY_LIMIT:
            logger.warning(f"initial_delay {initial_delay} exceeds security limit {MAX_DELAY_LIMIT}, capping to {MAX_DELAY_LIMIT}")
            initial_delay = MAX_DELAY_LIMIT
        
        # Validate max_delay
        max_delay = retry_config.get("max_delay", 60.0)
        if not isinstance(max_delay, (int, float)):
            logger.warning(f"Invalid max_delay type: {type(max_delay)}, defaulting to 60.0")
            max_delay = 60.0
        if max_delay < MIN_DELAY:
            logger.warning(f"max_delay {max_delay} is below minimum {MIN_DELAY}, setting to {MIN_DELAY}")
            max_delay = MIN_DELAY
        if max_delay > MAX_DELAY_LIMIT:
            logger.warning(f"max_delay {max_delay} exceeds security limit {MAX_DELAY_LIMIT}, capping to {MAX_DELAY_LIMIT}")
            max_delay = MAX_DELAY_LIMIT
        
        # Ensure max_delay >= initial_delay
        if max_delay < initial_delay:
            logger.warning(f"max_delay {max_delay} is less than initial_delay {initial_delay}, setting max_delay to {initial_delay}")
            max_delay = initial_delay
        
        # Validate backoff_multiplier
        backoff_multiplier = retry_config.get("backoff_multiplier", 2.0)
        if not isinstance(backoff_multiplier, (int, float)):
            logger.warning(f"Invalid backoff_multiplier type: {type(backoff_multiplier)}, defaulting to 2.0")
            backoff_multiplier = 2.0
        if backoff_multiplier < MIN_BACKOFF_MULTIPLIER:
            logger.warning(f"backoff_multiplier {backoff_multiplier} is below minimum {MIN_BACKOFF_MULTIPLIER}, setting to {MIN_BACKOFF_MULTIPLIER}")
            backoff_multiplier = MIN_BACKOFF_MULTIPLIER
        if backoff_multiplier > MAX_BACKOFF_MULTIPLIER:
            logger.warning(f"backoff_multiplier {backoff_multiplier} exceeds security limit {MAX_BACKOFF_MULTIPLIER}, capping to {MAX_BACKOFF_MULTIPLIER}")
            backoff_multiplier = MAX_BACKOFF_MULTIPLIER
        
        # Validate error lists (sanitize to only strings)
        retryable_errors = retry_config.get("retryable_errors", DEFAULT_RETRYABLE_ERRORS)
        if not isinstance(retryable_errors, list):
            logger.warning(f"Invalid retryable_errors type: {type(retryable_errors)}, using defaults")
            retryable_errors = DEFAULT_RETRYABLE_ERRORS
        else:
            # Filter to only valid string entries
            retryable_errors = [str(e) for e in retryable_errors if isinstance(e, (str, type(None))) and e is not None]
        
        non_retryable_errors = retry_config.get("non_retryable_errors", DEFAULT_NON_RETRYABLE_ERRORS)
        if not isinstance(non_retryable_errors, list):
            logger.warning(f"Invalid non_retryable_errors type: {type(non_retryable_errors)}, using defaults")
            non_retryable_errors = DEFAULT_NON_RETRYABLE_ERRORS
        else:
            # Filter to only valid string entries
            non_retryable_errors = [str(e) for e in non_retryable_errors if isinstance(e, (str, type(None))) and e is not None]
        
        return max_attempts, float(initial_delay), float(max_delay), float(backoff_multiplier), retryable_errors, non_retryable_errors
    
    def _is_retryable_error(self, error: Exception, retryable_errors: List[str], non_retryable_errors: List[str]) -> bool:
        """
        Determine if an error is retryable.
        
        SECURITY: Uses exact matching for error classification to prevent bypass attacks.
        Unknown errors default to non-retryable for security (fail-safe).
        
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
        # Use exact matching to prevent bypass attacks
        for non_retryable in non_retryable_errors:
            if non_retryable == error_type_name or non_retryable == full_error_name:
                return False
            # Also check if it's a substring match for backward compatibility, but prefer exact
            if non_retryable in error_type_name or non_retryable in full_error_name:
                return False
        
        # Check retryable errors
        # Use exact matching to prevent bypass attacks
        for retryable in retryable_errors:
            if retryable == error_type_name or retryable == full_error_name:
                return True
            # Also check if it's a substring match for backward compatibility
            if retryable in error_type_name or retryable in full_error_name:
                return True
        
        # Check by exception type hierarchy (built-in Python exceptions)
        if isinstance(error, (ConnectionError, TimeoutError, OSError, IOError)):
            return True
        
        # SECURITY: Default to non-retryable for unknown errors (fail-safe)
        # This prevents retrying security-related or unexpected errors
        logger.warning(f"Unknown error type '{full_error_name}' - defaulting to non-retryable for security")
        return False
    
    def _calculate_backoff(self, attempt: int, initial_delay: float, max_delay: float, backoff_multiplier: float) -> float:
        """
        Calculate backoff delay for retry attempt.
        
        SECURITY: Validates inputs and prevents overflow/infinity values.
        
        Args:
            attempt: Current attempt number (0-indexed)
            initial_delay: Initial delay in seconds
            max_delay: Maximum delay in seconds
            backoff_multiplier: Multiplier for exponential backoff
            
        Returns:
            Delay in seconds (capped at max_delay, never negative or infinite)
        """
        # Validate inputs
        if attempt < 0:
            attempt = 0
        if initial_delay < 0:
            initial_delay = 0.0
        if max_delay < 0:
            max_delay = 0.0
        if backoff_multiplier < 0:
            backoff_multiplier = 1.0
        
        try:
            # Calculate exponential backoff
            delay = initial_delay * (backoff_multiplier ** attempt)
            
            # Check for overflow/infinity
            if not (delay >= 0 and delay != float('inf') and delay == delay):  # delay == delay checks for NaN
                logger.warning(f"Backoff calculation resulted in invalid value: {delay}, using max_delay")
                delay = max_delay
            
            # Cap at max_delay
            delay = min(delay, max_delay)
            
            # Ensure non-negative
            return max(0.0, delay)
        except (OverflowError, ValueError) as e:
            logger.warning(f"Backoff calculation error: {e}, using max_delay")
            return min(max_delay, MAX_DELAY_LIMIT)
    
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
        
        # SECURITY: Validate and sanitize retry configuration to prevent DoS attacks
        max_attempts, initial_delay, max_delay, backoff_multiplier, retryable_errors, non_retryable_errors = \
            self._validate_retry_config(retry_config)
        
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

