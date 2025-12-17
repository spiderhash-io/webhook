import json
import asyncio
from typing import Optional, Any, Dict

from fastapi import HTTPException, Request
from src.modules.registry import ModuleRegistry
from src.validators import AuthorizationValidator, BasicAuthValidator, HMACValidator, IPWhitelistValidator, JWTValidator, RateLimitValidator, JsonSchemaValidator, RecaptchaValidator, QueryParameterAuthValidator, HeaderAuthValidator, OAuth2Validator, DigestAuthValidator, OAuth1Validator
from src.input_validator import InputValidator
from src.retry_handler import retry_handler
from src.chain_validator import ChainValidator
from src.chain_processor import ChainProcessor


class TaskManager:
    """
    Manages concurrent async tasks to prevent memory exhaustion.
    
    Features:
    - Semaphore-based concurrency limiting
    - Task queue monitoring
    - Task timeout protection
    - Automatic cleanup of completed tasks
    
    SECURITY: Validates configuration values to prevent DoS attacks via malicious config.
    """
    
    # Security limits to prevent DoS attacks
    MIN_CONCURRENT_TASKS = 1  # Minimum allowed concurrent tasks
    MAX_CONCURRENT_TASKS_LIMIT = 10000  # Maximum allowed concurrent tasks (prevents DoS)
    MIN_TASK_TIMEOUT = 0.1  # Minimum allowed timeout (0.1 seconds)
    MAX_TASK_TIMEOUT = 3600.0  # Maximum allowed timeout (1 hour)
    
    def __init__(self, max_concurrent_tasks: int = 100, task_timeout: float = 300.0):
        """
        Initialize task manager.
        
        SECURITY: Validates and sanitizes configuration values to prevent DoS attacks.
        
        Args:
            max_concurrent_tasks: Maximum number of concurrent tasks allowed
            task_timeout: Maximum time (seconds) for a task to complete
        """
        # SECURITY: Validate and sanitize max_concurrent_tasks
        if not isinstance(max_concurrent_tasks, int):
            raise ValueError(f"max_concurrent_tasks must be an integer, got {type(max_concurrent_tasks)}")
        if max_concurrent_tasks < TaskManager.MIN_CONCURRENT_TASKS:
            raise ValueError(f"max_concurrent_tasks must be >= {TaskManager.MIN_CONCURRENT_TASKS}, got {max_concurrent_tasks}")
        if max_concurrent_tasks > TaskManager.MAX_CONCURRENT_TASKS_LIMIT:
            raise ValueError(f"max_concurrent_tasks exceeds security limit {TaskManager.MAX_CONCURRENT_TASKS_LIMIT}, got {max_concurrent_tasks}")
        
        # SECURITY: Validate and sanitize task_timeout
        if not isinstance(task_timeout, (int, float)):
            raise ValueError(f"task_timeout must be a number, got {type(task_timeout)}")
        if task_timeout < TaskManager.MIN_TASK_TIMEOUT:
            raise ValueError(f"task_timeout must be >= {TaskManager.MIN_TASK_TIMEOUT}, got {task_timeout}")
        if task_timeout > TaskManager.MAX_TASK_TIMEOUT:
            raise ValueError(f"task_timeout exceeds security limit {TaskManager.MAX_TASK_TIMEOUT}, got {task_timeout}")
        
        self.max_concurrent_tasks = max_concurrent_tasks
        self.task_timeout = float(task_timeout)
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self.active_tasks = set()
        self._total_tasks_created = 0
        self._total_tasks_completed = 0
        self._total_tasks_timeout = 0
        self._lock = asyncio.Lock()
    
    async def create_task(self, coro, timeout: Optional[float] = None) -> asyncio.Task:
        """
        Create a task with concurrency limiting and timeout protection.
        
        SECURITY: Validates timeout value and ensures proper cleanup even on errors.
        
        Args:
            coro: Coroutine to execute
            timeout: Optional timeout override (uses self.task_timeout if None)
            
        Returns:
            asyncio.Task object
            
        Raises:
            Exception: If task queue is full or timeout exceeded
            ValueError: If timeout value is invalid
        """
        # SECURITY: Validate timeout value
        if timeout is not None:
            if not isinstance(timeout, (int, float)):
                raise ValueError(f"timeout must be a number, got {type(timeout)}")
            if timeout < TaskManager.MIN_TASK_TIMEOUT:
                raise ValueError(f"timeout must be >= {TaskManager.MIN_TASK_TIMEOUT}, got {timeout}")
            if timeout > TaskManager.MAX_TASK_TIMEOUT:
                raise ValueError(f"timeout exceeds security limit {TaskManager.MAX_TASK_TIMEOUT}, got {timeout}")
        
        timeout = timeout or self.task_timeout
        
        # Acquire semaphore (will block if limit reached)
        # This provides natural backpressure - tasks will wait if queue is full
        await self.semaphore.acquire()
        
        # Create task first, then reference it in wrapper to avoid closure issues
        # We'll set the task reference after creation so the wrapper can access it
        task_ref = {'task': None}  # Use dict to allow mutation in closure
        
        async def task_wrapper():
            """Wrapper to handle cleanup and timeout."""
            # Get the task reference (will be set after task creation)
            current_task = task_ref['task']
            try:
                # Execute with timeout
                return await asyncio.wait_for(coro, timeout=timeout)
            except asyncio.TimeoutError:
                async with self._lock:
                    self._total_tasks_timeout += 1
                raise Exception(f"Task exceeded timeout of {timeout}s")
            finally:
                # Release semaphore and remove from active tasks
                self.semaphore.release()
                async with self._lock:
                    if current_task:
                        self.active_tasks.discard(current_task)
                    self._total_tasks_completed += 1
                    # Clean up completed tasks periodically (every 10 completions)
                    if self._total_tasks_completed % 10 == 0:
                        self._cleanup_completed_tasks()
        
        # Create task and set reference
        task = asyncio.create_task(task_wrapper())
        task_ref['task'] = task  # Set reference for wrapper
        
        async with self._lock:
            self.active_tasks.add(task)
            self._total_tasks_created += 1
        
        return task
    
    def _cleanup_completed_tasks(self):
        """Remove completed tasks from active_tasks set."""
        completed = {t for t in self.active_tasks if t.done()}
        self.active_tasks -= completed
    
    def get_metrics(self) -> dict:
        """
        Get task manager metrics.
        
        Returns:
            Dictionary with task metrics
        """
        # Clean up completed tasks before getting metrics
        self._cleanup_completed_tasks()
        
        return {
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "active_tasks": len(self.active_tasks),
            "total_tasks_created": self._total_tasks_created,
            "total_tasks_completed": self._total_tasks_completed,
            "total_tasks_timeout": self._total_tasks_timeout,
            "queue_usage_percent": (len(self.active_tasks) / self.max_concurrent_tasks * 100) if self.max_concurrent_tasks > 0 else 0.0,
        }


# Global task manager instance
# Can be configured via environment variables
# SECURITY: Configuration is validated in TaskManager.__init__()
import os
try:
    _max_concurrent_tasks = int(os.getenv("MAX_CONCURRENT_TASKS", "100"))
    _task_timeout = float(os.getenv("TASK_TIMEOUT", "300.0"))
    task_manager = TaskManager(max_concurrent_tasks=_max_concurrent_tasks, task_timeout=_task_timeout)
except (ValueError, TypeError) as e:
    # SECURITY: If environment variables are invalid, use safe defaults
    print(f"WARNING: Invalid task manager configuration from environment: {e}")
    print("WARNING: Using safe default values")
    task_manager = TaskManager(max_concurrent_tasks=100, task_timeout=300.0)


class WebhookHandler:
    def __init__(self, webhook_id, configs, connection_config, request: Request, pool_registry=None):
        # SECURITY: Validate webhook_id early to prevent injection attacks
        is_valid, msg = InputValidator.validate_webhook_id(webhook_id)
        if not is_valid:
            raise HTTPException(status_code=400, detail=msg)
        
        self.webhook_id = webhook_id
        self.config = configs.get(webhook_id)
        if not self.config:
            raise HTTPException(status_code=404, detail="Webhook ID not found")
        self.connection_config = connection_config
        self.request = request
        self.pool_registry = pool_registry
        self.headers = self.request.headers
        self._cached_body = None  # Cache request body after first read
        
        # SECURITY: Validate config type before validator instantiation to prevent type confusion
        if not isinstance(self.config, dict):
            raise HTTPException(
                status_code=500,
                detail="Invalid webhook configuration: configuration must be a dictionary"
            )
        
        # Initialize validators
        # SECURITY: Validator instantiation is wrapped in try-except to handle instantiation errors
        try:
            self.validators = [
                RateLimitValidator(self.config, webhook_id),  # Check rate limit first
                RecaptchaValidator(self.config),  # Google reCAPTCHA validation
                BasicAuthValidator(self.config),  # Basic auth
                DigestAuthValidator(self.config),  # Digest auth
                JWTValidator(self.config),  # JWT auth
                OAuth1Validator(self.config),  # OAuth 1.0 signature validation
                OAuth2Validator(self.config),  # OAuth 2.0 token validation
                AuthorizationValidator(self.config),  # Bearer token (simple)
                HMACValidator(self.config),  # HMAC signature
                IPWhitelistValidator(self.config, request=self.request),  # IP whitelist (pass request for secure IP detection)
                JsonSchemaValidator(self.config),  # JSON Schema validation
                QueryParameterAuthValidator(self.config),  # Query parameter auth
                HeaderAuthValidator(self.config),  # Header-based API key auth
            ]
        except TypeError as e:
            # SECURITY: Handle type errors during validator instantiation
            # This can occur if config is not a dict (caught by BaseValidator)
            print(f"ERROR: Failed to instantiate validators for webhook '{webhook_id}': {e}")
            from src.utils import sanitize_error_message
            raise HTTPException(
                status_code=500,
                detail=sanitize_error_message(e, "validator instantiation")
            )
        except Exception as e:
            # SECURITY: Handle other exceptions during validator instantiation
            print(f"ERROR: Failed to instantiate validators for webhook '{webhook_id}': {e}")
            from src.utils import sanitize_error_message
            raise HTTPException(
                status_code=500,
                detail=sanitize_error_message(e, "validator instantiation")
            )

    async def validate_webhook(self):
        """Validate webhook using all configured validators."""
        # Get raw body for HMAC validation
        # Cache body after first read since FastAPI Request.body() can only be read once
        if self._cached_body is None:
            self._cached_body = await self.request.body()
        
        body = self._cached_body
        
        # Convert headers to dict
        headers_dict = {k.lower(): v for k, v in self.request.headers.items()}
        
        # Get query parameters for query auth validation
        query_params = dict(self.request.query_params)
        
        # Run all validators
        for validator in self.validators:
            try:
                # Query parameter auth needs special handling
                if isinstance(validator, QueryParameterAuthValidator):
                    is_valid, message = QueryParameterAuthValidator.validate_query_params(
                        query_params, self.config
                    )
                else:
                    is_valid, message = await validator.validate(headers_dict, body)
                
                # SECURITY: Validate validator return types to prevent type confusion attacks
                # Ensure is_valid is a boolean (or truthy/falsy value that can be evaluated)
                if not isinstance(is_valid, bool):
                    # Convert to boolean using truthiness, but log warning
                    print(f"WARNING: Validator {type(validator).__name__} returned non-boolean is_valid: {type(is_valid).__name__}")
                    is_valid = bool(is_valid)
                
                # Ensure message is a string
                if not isinstance(message, str):
                    # Convert to string safely
                    if message is None:
                        message = "Validation failed"
                    else:
                        message = str(message)
                
                if not is_valid:
                    return False, message
            except Exception as e:
                # SECURITY: Catch and sanitize validator exceptions to prevent information disclosure
                # Log detailed error server-side only
                print(f"ERROR: Validator exception for webhook '{self.webhook_id}': {e}")
                # Return generic error to client (don't expose internal details)
                from src.utils import sanitize_error_message
                return False, sanitize_error_message(e, "webhook validation")
        
        return True, "Valid webhook"

    async def process_webhook(self):
        """Process webhook payload using the configured module."""
        # Validate webhook ID format
        is_valid, msg = InputValidator.validate_webhook_id(self.webhook_id)
        if not is_valid:
            raise HTTPException(status_code=400, detail=msg)
        
        # Get raw body for validation
        # Reuse cached body from validate_webhook() since FastAPI Request.body() can only be read once
        if self._cached_body is None:
            # If validate_webhook() wasn't called, read body now (shouldn't happen in normal flow)
            self._cached_body = await self.request.body()
        
        body = self._cached_body
        
        # Validate headers
        headers_dict = {k: v for k, v in self.request.headers.items()}
        is_valid, msg = InputValidator.validate_headers(headers_dict)
        if not is_valid:
            raise HTTPException(status_code=400, detail=msg)
        
        # Validate payload size
        is_valid, msg = InputValidator.validate_payload_size(body)
        if not is_valid:
            raise HTTPException(status_code=413, detail=msg)
        
        # Read the incoming data based on its type
        # SECURITY: Validate data_type exists and is a string to prevent KeyError and type confusion
        # Default to "json" if data_type is not specified (most common use case)
        data_type = self.config.get('data_type', 'json')
        
        if not isinstance(data_type, str):
            raise HTTPException(status_code=400, detail="Invalid data_type configuration: must be a string")
        
        if data_type == 'json':
            try:
                # Safely decode body with encoding detection and fallback
                from src.utils import safe_decode_body
                content_type = self.headers.get('content-type', '')
                decoded_body, encoding_used = safe_decode_body(body, content_type)
                payload = json.loads(decoded_body)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Malformed JSON payload")
            except HTTPException:
                # Re-raise HTTPException from safe_decode_body
                raise
            except Exception as e:
                # Handle any other decoding errors
                from src.utils import sanitize_error_message
                raise HTTPException(
                    status_code=400,
                    detail=sanitize_error_message(e, "request body decoding")
                )
            
            # Validate JSON depth
            is_valid, msg = InputValidator.validate_json_depth(payload)
            if not is_valid:
                raise HTTPException(status_code=400, detail=msg)
            
            # Validate string lengths
            is_valid, msg = InputValidator.validate_string_length(payload)
            if not is_valid:
                raise HTTPException(status_code=400, detail=msg)
            
        elif data_type == 'blob':
            payload = body
        else:
            raise HTTPException(status_code=415, detail="Unsupported data type")

        # Check if chain is configured (chain takes precedence over module for backward compatibility)
        chain = self.config.get('chain')
        if chain is not None:
            # Process chain
            return await self._process_chain(payload, headers_dict)
        
        # Backward compatibility: process single module
        # Get the module from registry
        module_name = self.config.get('module')
        if not module_name:
            raise HTTPException(status_code=400, detail="Module configuration error")
        
        # SECURITY: Validate module name type (should be string)
        if not isinstance(module_name, str):
            raise HTTPException(status_code=400, detail="Module configuration error")
        
        try:
            module_class = ModuleRegistry.get(module_name)
        except (KeyError, ValueError) as e:
            # Don't expose module name to prevent information disclosure
            # Log detailed error server-side only
            print(f"ERROR: Unsupported module '{module_name}' for webhook '{self.webhook_id}': {e}")
            raise HTTPException(status_code=501, detail="Module configuration error")
        
        # Credential cleanup: Clean credentials from payload and headers before storing/logging
        # Original data is preserved for validation, only cleaned copy is passed to modules
        cleanup_config = self.config.get("credential_cleanup", {})
        cleanup_enabled = cleanup_config.get("enabled", True)  # Default: enabled (opt-out)
        
        cleaned_payload = payload
        cleaned_headers = dict(self.headers.items())
        
        if cleanup_enabled:
            from src.utils import CredentialCleaner
            
            # Get cleanup mode (mask or remove)
            cleanup_mode = cleanup_config.get("mode", "mask")
            custom_fields = cleanup_config.get("fields", [])
            
            try:
                cleaner = CredentialCleaner(custom_fields=custom_fields, mode=cleanup_mode)
                
                # Clean payload (deep copy to avoid modifying original)
                if isinstance(payload, (dict, list)):
                    import copy
                    cleaned_payload = cleaner.clean_credentials(copy.deepcopy(payload))
                else:
                    cleaned_payload = payload  # For blob data, no cleaning needed
                
                # Clean headers
                cleaned_headers = cleaner.clean_headers(cleaned_headers)
            except Exception as e:
                # If cleanup fails, log but don't crash - use original data
                print(f"WARNING: Credential cleanup failed for webhook '{self.webhook_id}': {e}")
                cleaned_payload = payload
                cleaned_headers = dict(self.headers.items())
        
        # Instantiate and process
        # Add webhook_id to config for modules that need it (e.g., ClickHouse)
        module_config = {**self.config, '_webhook_id': self.webhook_id}
        try:
            module = module_class(module_config, pool_registry=self.pool_registry)
        except Exception as e:
            # SECURITY: Catch and sanitize module instantiation errors to prevent information disclosure
            # Log detailed error server-side only
            print(f"ERROR: Module instantiation failed for webhook '{self.webhook_id}': {e}")
            # Raise generic error to client (don't expose internal details)
            from src.utils import sanitize_error_message
            raise HTTPException(
                status_code=500,
                detail=sanitize_error_message(e, "module initialization")
            )
        
        # Get retry configuration
        retry_config = self.config.get("retry", {})
        
        # If retry is enabled, execute with retry handler
        if retry_config.get("enabled", False):
            # Execute module with retry logic (use cleaned data)
            async def execute_module():
                return await retry_handler.execute_with_retry(
                    module.process,
                    cleaned_payload,
                    cleaned_headers,
                    retry_config=retry_config
                )
            
            # Execute with retry using task manager (fire-and-forget, but track result)
            try:
                task = await task_manager.create_task(execute_module())
            except Exception as e:
                # If task queue is full, log and continue (task will be lost, but webhook is accepted)
                print(f"WARNING: Could not create task for webhook '{self.webhook_id}': {e}")
                # Return None for task to indicate it wasn't created
                return payload, dict(self.headers.items()), None
            
            # Return original payload and headers for logging (before cleanup)
            return payload, dict(self.headers.items()), task
        else:
            # No retry configured, execute normally using task manager (fire-and-forget)
            # Use cleaned data for module processing
            async def execute_module():
                await module.process(cleaned_payload, cleaned_headers)
            
            try:
                # Create task with task manager (fire-and-forget, no tracking needed)
                await task_manager.create_task(execute_module())
            except Exception as e:
                # If task queue is full, log and continue (task will be lost, but webhook is accepted)
                print(f"WARNING: Could not create task for webhook '{self.webhook_id}': {e}")
            
            # Return original payload and headers for logging (before cleanup)
            return payload, dict(self.headers.items()), None
    
    async def _process_chain(self, payload: Any, headers: Dict[str, str]):
        """
        Process webhook using chain configuration.
        
        SECURITY: Validates chain configuration before processing.
        """
        # Validate chain configuration
        is_valid, error = ChainValidator.validate_chain_config(self.config)
        if not is_valid:
            raise HTTPException(status_code=400, detail=f"Invalid chain configuration: {error}")
        
        # Get chain and chain-config
        chain = self.config.get('chain')
        chain_config = self.config.get('chain-config', {})
        
        # Credential cleanup: Clean credentials from payload and headers before storing/logging
        # Original data is preserved for validation, only cleaned copy is passed to modules
        cleanup_config = self.config.get("credential_cleanup", {})
        cleanup_enabled = cleanup_config.get("enabled", True)  # Default: enabled (opt-out)
        
        cleaned_payload = payload
        cleaned_headers = dict(headers)
        
        if cleanup_enabled:
            from src.utils import CredentialCleaner
            
            # Get cleanup mode (mask or remove)
            cleanup_mode = cleanup_config.get("mode", "mask")
            custom_fields = cleanup_config.get("fields", [])
            
            try:
                cleaner = CredentialCleaner(custom_fields=custom_fields, mode=cleanup_mode)
                
                # Clean payload (deep copy to avoid modifying original)
                if isinstance(payload, (dict, list)):
                    import copy
                    cleaned_payload = cleaner.clean_credentials(copy.deepcopy(payload))
                else:
                    cleaned_payload = payload  # For blob data, no cleaning needed
                
                # Clean headers
                cleaned_headers = cleaner.clean_headers(cleaned_headers)
            except Exception as e:
                # If cleanup fails, log but don't crash - use original data
                print(f"WARNING: Credential cleanup failed for webhook '{self.webhook_id}': {e}")
                cleaned_payload = payload
                cleaned_headers = dict(headers)
        
        # Add webhook_id to config for modules that need it
        webhook_config_with_id = {**self.config, '_webhook_id': self.webhook_id}
        
        # Create chain processor
        processor = ChainProcessor(
            chain=chain,
            chain_config=chain_config,
            webhook_config=webhook_config_with_id,
            pool_registry=self.pool_registry
        )
        
        # Execute chain using task manager (fire-and-forget)
        async def execute_chain():
            try:
                results = await processor.execute(cleaned_payload, cleaned_headers)
                summary = processor.get_summary(results)
                
                # Log chain execution summary
                successful = summary['successful']
                failed = summary['failed']
                total = summary['total_modules']
                
                if failed > 0:
                    print(f"Chain execution for webhook '{self.webhook_id}': {successful}/{total} modules succeeded, {failed} failed")
                    # Log individual failures
                    for result in summary['results']:
                        if not result['success']:
                            print(f"  - Module '{result['module']}' failed: {result['error']}")
                else:
                    print(f"Chain execution for webhook '{self.webhook_id}': All {total} modules succeeded")
            except Exception as e:
                # Log chain execution errors
                print(f"ERROR: Chain execution failed for webhook '{self.webhook_id}': {e}")
        
        try:
            # Create task with task manager (fire-and-forget)
            await task_manager.create_task(execute_chain())
        except Exception as e:
            # If task queue is full, log and continue (task will be lost, but webhook is accepted)
            print(f"WARNING: Could not create task for chain execution in webhook '{self.webhook_id}': {e}")
        
        # Return original payload and headers for logging (before cleanup)
        return payload, dict(self.headers.items()), None
