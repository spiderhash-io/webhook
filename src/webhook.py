import json
import asyncio
import time
from typing import Optional

from fastapi import HTTPException, Request
from src.modules.registry import ModuleRegistry
from src.validators import AuthorizationValidator, BasicAuthValidator, HMACValidator, IPWhitelistValidator, JWTValidator, RateLimitValidator, JsonSchemaValidator, RecaptchaValidator, QueryParameterAuthValidator, HeaderAuthValidator, OAuth2Validator, DigestAuthValidator, OAuth1Validator
from src.input_validator import InputValidator
from src.retry_handler import retry_handler


class TaskManager:
    """
    Manages concurrent async tasks to prevent memory exhaustion.
    
    Features:
    - Semaphore-based concurrency limiting
    - Task queue monitoring
    - Task timeout protection
    - Automatic cleanup of completed tasks
    """
    
    def __init__(self, max_concurrent_tasks: int = 100, task_timeout: float = 300.0):
        """
        Initialize task manager.
        
        Args:
            max_concurrent_tasks: Maximum number of concurrent tasks allowed
            task_timeout: Maximum time (seconds) for a task to complete
        """
        self.max_concurrent_tasks = max_concurrent_tasks
        self.task_timeout = task_timeout
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self.active_tasks = set()
        self._total_tasks_created = 0
        self._total_tasks_completed = 0
        self._total_tasks_timeout = 0
        self._lock = asyncio.Lock()
    
    async def create_task(self, coro, timeout: Optional[float] = None) -> asyncio.Task:
        """
        Create a task with concurrency limiting and timeout protection.
        
        Args:
            coro: Coroutine to execute
            timeout: Optional timeout override (uses self.task_timeout if None)
            
        Returns:
            asyncio.Task object
            
        Raises:
            Exception: If task queue is full or timeout exceeded
        """
        timeout = timeout or self.task_timeout
        
        # Acquire semaphore (will block if limit reached)
        # This provides natural backpressure - tasks will wait if queue is full
        await self.semaphore.acquire()
        
        async def task_wrapper():
            """Wrapper to handle cleanup and timeout."""
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
                    self.active_tasks.discard(task)
                    self._total_tasks_completed += 1
                    # Clean up completed tasks periodically
                    if len(self.active_tasks) % 10 == 0:
                        self._cleanup_completed_tasks()
        
        # Create task
        task = asyncio.create_task(task_wrapper())
        
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
import os
_max_concurrent_tasks = int(os.getenv("MAX_CONCURRENT_TASKS", "100"))
_task_timeout = float(os.getenv("TASK_TIMEOUT", "300.0"))
task_manager = TaskManager(max_concurrent_tasks=_max_concurrent_tasks, task_timeout=_task_timeout)


class WebhookHandler:
    def __init__(self, webhook_id, configs, connection_config, request: Request):
        self.webhook_id = webhook_id
        self.config = configs.get(webhook_id)
        if not self.config:
            raise HTTPException(status_code=404, detail="Webhook ID not found")
        self.connection_config = connection_config
        self.request = request
        self.headers = self.request.headers
        self._cached_body = None  # Cache request body after first read
        
        # Initialize validators
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
            # Query parameter auth needs special handling
            if isinstance(validator, QueryParameterAuthValidator):
                is_valid, message = QueryParameterAuthValidator.validate_query_params(
                    query_params, self.config
                )
            else:
                is_valid, message = await validator.validate(headers_dict, body)
            
            if not is_valid:
                return False, message
        
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
        if self.config['data_type'] == 'json':
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
            
        elif self.config['data_type'] == 'blob':
            payload = body
            # Additional blob handling...
        else:
            raise HTTPException(status_code=415, detail="Unsupported data type")

        # Get the module from registry
        module_name = self.config['module']
        try:
            module_class = ModuleRegistry.get(module_name)
        except KeyError:
            # Don't expose module name to prevent information disclosure
            # Log detailed error server-side only
            print(f"ERROR: Unsupported module '{module_name}' for webhook '{self.webhook_id}'")
            raise HTTPException(status_code=501, detail="Module configuration error")
        
        # Instantiate and process
        # Add webhook_id to config for modules that need it (e.g., ClickHouse)
        module_config = {**self.config, '_webhook_id': self.webhook_id}
        module = module_class(module_config)
        
        # Get retry configuration
        retry_config = self.config.get("retry", {})
        
        # If retry is enabled, execute with retry handler
        if retry_config.get("enabled", False):
            # Execute module with retry logic
            async def execute_module():
                return await retry_handler.execute_with_retry(
                    module.process,
                    payload,
                    dict(self.headers.items()),
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
            
            # Return payload, headers, and task for status checking
            return payload, dict(self.headers.items()), task
        else:
            # No retry configured, execute normally using task manager (fire-and-forget)
            async def execute_module():
                await module.process(payload, dict(self.headers.items()))
            
            try:
                # Create task with task manager (fire-and-forget, no tracking needed)
                await task_manager.create_task(execute_module())
            except Exception as e:
                # If task queue is full, log and continue (task will be lost, but webhook is accepted)
                print(f"WARNING: Could not create task for webhook '{self.webhook_id}': {e}")
            
            return payload, dict(self.headers.items()), None
