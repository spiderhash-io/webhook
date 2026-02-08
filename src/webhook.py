import json
import asyncio
import logging
from typing import Optional, Any, Dict, List, Tuple

from fastapi import HTTPException, Request
from src.modules.registry import ModuleRegistry
from src.validators import (
    AuthorizationValidator,
    BasicAuthValidator,
    HMACValidator,
    IPWhitelistValidator,
    JWTValidator,
    RateLimitValidator,
    JsonSchemaValidator,
    RecaptchaValidator,
    QueryParameterAuthValidator,
    HeaderAuthValidator,
    OAuth2Validator,
    DigestAuthValidator,
    OAuth1Validator,
)
from src.input_validator import InputValidator
from src.retry_handler import retry_handler
from src.chain_validator import ChainValidator
from src.chain_processor import ChainProcessor


logger = logging.getLogger(__name__)


# Global metrics (in-memory counters for observability)
# These would ideally be integrated with Prometheus/Grafana
metrics = {
    "chain_tasks_dropped_total": 0,
    "chain_execution_total": 0,
    "chain_execution_failed_total": 0,
    "chain_execution_partial_success_total": 0,
    "module_execution_dropped_total": 0,
}


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
    MAX_CONCURRENT_TASKS_LIMIT = (
        10000  # Maximum allowed concurrent tasks (prevents DoS)
    )
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
            raise ValueError(
                f"max_concurrent_tasks must be an integer, got {type(max_concurrent_tasks)}"
            )
        if max_concurrent_tasks < TaskManager.MIN_CONCURRENT_TASKS:
            raise ValueError(
                f"max_concurrent_tasks must be >= {TaskManager.MIN_CONCURRENT_TASKS}, got {max_concurrent_tasks}"
            )
        if max_concurrent_tasks > TaskManager.MAX_CONCURRENT_TASKS_LIMIT:
            raise ValueError(
                f"max_concurrent_tasks exceeds security limit {TaskManager.MAX_CONCURRENT_TASKS_LIMIT}, got {max_concurrent_tasks}"
            )

        # SECURITY: Validate and sanitize task_timeout
        if not isinstance(task_timeout, (int, float)):
            raise ValueError(f"task_timeout must be a number, got {type(task_timeout)}")
        if task_timeout < TaskManager.MIN_TASK_TIMEOUT:
            raise ValueError(
                f"task_timeout must be >= {TaskManager.MIN_TASK_TIMEOUT}, got {task_timeout}"
            )
        if task_timeout > TaskManager.MAX_TASK_TIMEOUT:
            raise ValueError(
                f"task_timeout exceeds security limit {TaskManager.MAX_TASK_TIMEOUT}, got {task_timeout}"
            )

        self.max_concurrent_tasks = max_concurrent_tasks
        self.task_timeout = float(task_timeout)
        self._semaphore: Optional[asyncio.Semaphore] = None  # Lazy initialization
        self._lock: Optional[asyncio.Lock] = None  # Lazy initialization
        self.active_tasks = set()
        self._total_tasks_created = 0
        self._total_tasks_completed = 0
        self._total_tasks_timeout = 0

    def _get_semaphore(self) -> asyncio.Semaphore:
        """Get or create the async semaphore (lazy initialization)."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent_tasks)
        return self._semaphore

    def _get_lock(self) -> asyncio.Lock:
        """Get or create the async lock (lazy initialization)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    @property
    def semaphore(self) -> asyncio.Semaphore:
        """Property to access semaphore (for backward compatibility)."""
        return self._get_semaphore()

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
                raise ValueError(
                    f"timeout must be >= {TaskManager.MIN_TASK_TIMEOUT}, got {timeout}"
                )
            if timeout > TaskManager.MAX_TASK_TIMEOUT:
                raise ValueError(
                    f"timeout exceeds security limit {TaskManager.MAX_TASK_TIMEOUT}, got {timeout}"
                )

        timeout = timeout or self.task_timeout

        # Acquire semaphore (will block if limit reached)
        # This provides natural backpressure - tasks will wait if queue is full
        await self._get_semaphore().acquire()

        # Create task first, then reference it in wrapper to avoid closure issues
        # We'll set the task reference after creation so the wrapper can access it
        task_ref: Dict[str, Any] = {
            "task": None
        }  # Use dict to allow mutation in closure

        async def task_wrapper():
            """Wrapper to handle cleanup and timeout."""
            # Get the task reference (will be set after task creation)
            current_task = task_ref["task"]
            try:
                # Execute with timeout
                return await asyncio.wait_for(coro, timeout=timeout)
            except asyncio.TimeoutError:
                async with self._get_lock():
                    self._total_tasks_timeout += 1
                raise Exception(f"Task exceeded timeout of {timeout}s")
            finally:
                # Release semaphore and remove from active tasks
                self._get_semaphore().release()
                async with self._get_lock():
                    if current_task:
                        self.active_tasks.discard(current_task)
                    self._total_tasks_completed += 1
                    # Clean up completed tasks periodically (every 10 completions)
                    if self._total_tasks_completed % 10 == 0:
                        self._cleanup_completed_tasks()

        # Create task and set reference
        task = asyncio.create_task(task_wrapper())
        task_ref["task"] = task  # Set reference for wrapper

        async with self._get_lock():
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
            "queue_usage_percent": (
                (len(self.active_tasks) / self.max_concurrent_tasks * 100)
                if self.max_concurrent_tasks > 0
                else 0.0
            ),
        }


# Global task manager instance
# Can be configured via environment variables
# SECURITY: Configuration is validated in TaskManager.__init__()
import os

try:
    _max_concurrent_tasks = int(os.getenv("MAX_CONCURRENT_TASKS", "100"))
    _task_timeout = float(os.getenv("TASK_TIMEOUT", "300.0"))
    task_manager = TaskManager(
        max_concurrent_tasks=_max_concurrent_tasks, task_timeout=_task_timeout
    )
except (ValueError, TypeError) as e:
    # SECURITY: If environment variables are invalid, use safe defaults
    logger.warning(f"Invalid task manager configuration from environment: {e}")
    logger.warning("Using safe default values")
    task_manager = TaskManager(max_concurrent_tasks=100, task_timeout=300.0)


class WebhookHandler:
    def __init__(
        self,
        webhook_id,
        configs,
        connection_config,
        request: Request,
        pool_registry=None,
        namespace: Optional[str] = None,
    ):
        # SECURITY: Validate webhook_id early to prevent injection attacks
        is_valid, msg = InputValidator.validate_webhook_id(webhook_id)
        if not is_valid:
            raise HTTPException(status_code=400, detail=msg)

        self.webhook_id = webhook_id
        self.namespace = namespace
        self.config = configs.get(webhook_id)
        # Fallback to default webhook if requested webhook_id not found and default exists
        if not self.config and "default" in configs:
            self.config = configs.get("default")
            # Log that we're using the default webhook
            logger.info(
                f"Webhook ID '{webhook_id}' not found, using default logging webhook"
            )
        elif not self.config:
            raise HTTPException(status_code=404, detail="Webhook ID not found")
        self.connection_config = connection_config
        self.request = request
        self.pool_registry = pool_registry
        self.headers = self.request.headers
        self._cached_body = None  # Cache request body after first read
        self._body_reading_lock: Optional[asyncio.Lock] = (
            None  # Lazy initialization - SECURITY: Lock to prevent race conditions when reading body
        )

        # SECURITY: Validate config type before validator instantiation to prevent type confusion
        if not isinstance(self.config, dict):
            raise HTTPException(
                status_code=500,
                detail="Invalid webhook configuration: configuration must be a dictionary",
            )

        # Initialize validators
        # SECURITY: Validator instantiation is wrapped in try-except to handle instantiation errors
        try:
            self.validators = []

            # Optimization: Only instantiate validators that are configured for this webhook
            # Check for each validator type in config and only instantiate if configured
            if "rate_limit" in self.config:
                self.validators.append(RateLimitValidator(self.config, webhook_id))

            if "recaptcha" in self.config:
                self.validators.append(RecaptchaValidator(self.config))

            if "basic_auth" in self.config:
                self.validators.append(BasicAuthValidator(self.config))

            if "digest_auth" in self.config:
                self.validators.append(
                    DigestAuthValidator(self.config, request=self.request)
                )

            if "jwt" in self.config:
                self.validators.append(JWTValidator(self.config))

            if "oauth1" in self.config:
                self.validators.append(
                    OAuth1Validator(self.config, request=self.request)
                )

            if "oauth2" in self.config:
                self.validators.append(OAuth2Validator(self.config))

            if "authorization" in self.config:
                self.validators.append(AuthorizationValidator(self.config))

            if "hmac" in self.config:
                self.validators.append(HMACValidator(self.config))

            if "ip_whitelist" in self.config:
                self.validators.append(
                    IPWhitelistValidator(self.config, request=self.request)
                )

            if "json_schema" in self.config:
                self.validators.append(JsonSchemaValidator(self.config))

            if "query_auth" in self.config:
                self.validators.append(QueryParameterAuthValidator(self.config))

            if "header_auth" in self.config:
                self.validators.append(HeaderAuthValidator(self.config))

        except TypeError as e:
            # SECURITY: Handle type errors during validator instantiation
            # This can occur if config is not a dict (caught by BaseValidator)
            logger.error(
                f"Failed to instantiate validators for webhook '{webhook_id}': {e}"
            )
            from src.utils import sanitize_error_message

            raise HTTPException(
                status_code=500,
                detail=sanitize_error_message(e, "validator instantiation"),
            )
        except Exception as e:
            # SECURITY: Handle other exceptions during validator instantiation
            logger.error(
                f"Failed to instantiate validators for webhook '{webhook_id}': {e}"
            )
            from src.utils import sanitize_error_message

            raise HTTPException(
                status_code=500,
                detail=sanitize_error_message(e, "validator instantiation"),
            )

    def _get_body_reading_lock(self) -> asyncio.Lock:
        """Get or create the body reading lock (lazy initialization)."""
        if self._body_reading_lock is None:
            self._body_reading_lock = asyncio.Lock()
        return self._body_reading_lock

    async def validate_webhook(self):
        """Validate webhook using all configured validators."""
        # Get raw body for HMAC validation
        # Cache body after first read since FastAPI Request.body() can only be read once
        # SECURITY: Use lock to prevent race conditions when reading body concurrently
        if self._cached_body is None:
            async with self._get_body_reading_lock():
                # Double-check after acquiring lock (another coroutine might have read it)
                if self._cached_body is None:
                    # SECURITY: Wrap body reading in try-except to handle exceptions gracefully
                    try:
                        self._cached_body = await self.request.body()
                    except Exception as e:
                        # SECURITY: Sanitize error message to prevent information disclosure
                        from src.utils import sanitize_error_message

                        error_msg = sanitize_error_message(e, "request body reading")
                        logger.error(
                            f"Failed to read request body for webhook '{self.webhook_id}': {error_msg}"
                        )
                        # Set cached_body to empty bytes to prevent retry
                        self._cached_body = b""
                        # Return validation failure with sanitized error
                        return False, "Failed to read request body"

        body = self._cached_body

        # Convert headers to dict
        headers_dict = {k.lower(): v for k, v in self.request.headers.items()}

        # Get query parameters for query auth validation
        # SECURITY: Validate query_params is dict-like before conversion to prevent type confusion
        try:
            # FastAPI's QueryParams is dict-like, but validate defensively
            if self.request.query_params is None:
                query_params = {}
            elif hasattr(self.request.query_params, "items"):
                # QueryParams-like object, convert to dict
                query_params = dict(self.request.query_params)
            elif isinstance(self.request.query_params, dict):
                # Already a dict, use as-is
                query_params = self.request.query_params.copy()
            else:
                # Unexpected type, default to empty dict
                logger.warning(
                    f"Unexpected query_params type: {type(self.request.query_params).__name__}"
                )
                query_params = {}
        except (TypeError, AttributeError) as e:
            # If conversion fails, default to empty dict and log error
            # SECURITY: Sanitize error message to prevent information disclosure
            from src.utils import sanitize_error_message

            sanitized_error = sanitize_error_message(e, "query parameter extraction")
            logger.error(
                f"Failed to extract query parameters for webhook '{self.webhook_id}': {sanitized_error}"
            )
            query_params = {}

        # SECURITY: Ensure query_params is a dict (defensive check)
        if not isinstance(query_params, dict):
            query_params = {}

        # Run all validators
        for validator in self.validators:
            try:
                # Query parameter auth needs special handling
                if isinstance(validator, QueryParameterAuthValidator):
                    is_valid, message = (
                        QueryParameterAuthValidator.validate_query_params(
                            query_params, self.config
                        )
                    )
                else:
                    is_valid, message = await validator.validate(headers_dict, body)

                # SECURITY: Validate validator return types to prevent type confusion attacks
                # Ensure is_valid is a boolean (or truthy/falsy value that can be evaluated)
                if not isinstance(is_valid, bool):
                    # Convert to boolean using truthiness, but log warning
                    logger.warning(
                        f"Validator {type(validator).__name__} returned non-boolean is_valid: {type(is_valid).__name__}"
                    )
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
                # SECURITY: Catch and sanitize validator execution errors
                # Log detailed error server-side only
                logger.error(
                    f"Validator exception for webhook '{self.webhook_id}': {e}"
                )
                # Re-raise as HTTPException to prevent further processing
                from src.utils import sanitize_error_message

                return False, sanitize_error_message(e, "webhook validation")

        return True, "Valid webhook"

    def _get_cleaned_data(
        self, payload: Any, headers: Dict[str, str]
    ) -> Tuple[Any, Dict[str, str]]:
        """
        Clean credentials from payload and headers based on configuration.
        Returns a tuple of (cleaned_payload, cleaned_headers).

        This method is intended to be called within background tasks to avoid
        blocking the request/response cycle.
        """
        cleanup_config = self.config.get("credential_cleanup", {})
        cleanup_enabled = cleanup_config.get("enabled", True)

        if not cleanup_enabled:
            return payload, headers

        try:
            from src.utils import CredentialCleaner

            cleanup_mode = cleanup_config.get("mode", "mask")
            custom_fields = cleanup_config.get("fields", [])
            cleaner = CredentialCleaner(custom_fields=custom_fields, mode=cleanup_mode)

            cleaned_payload = payload
            if isinstance(payload, (dict, list)):
                cleaned_payload = cleaner.clean_credentials(payload)

            cleaned_headers = cleaner.clean_headers(headers)
            return cleaned_payload, cleaned_headers
        except Exception as e:
            # Fallback to original data on failure
            logger.warning(
                f"Credential cleanup failed for webhook '{self.webhook_id}': {e}"
            )
            return payload, headers

    async def process_webhook(self):
        """Process webhook payload using the configured module."""
        # Validate webhook ID format
        is_valid, msg = InputValidator.validate_webhook_id(self.webhook_id)
        if not is_valid:
            raise HTTPException(status_code=400, detail=msg)

        # Get raw body for validation
        # Reuse cached body from validate_webhook() since FastAPI Request.body() can only be read once
        # SECURITY: Use lock to prevent race conditions when reading body concurrently
        if self._cached_body is None:
            async with self._get_body_reading_lock():
                # Double-check after acquiring lock (another coroutine might have read it)
                if self._cached_body is None:
                    # If validate_webhook() wasn't called, read body now (shouldn't happen in normal flow)
                    # SECURITY: Wrap body reading in try-except to handle exceptions gracefully
                    try:
                        self._cached_body = await self.request.body()
                    except Exception as e:
                        # SECURITY: Sanitize error message to prevent information disclosure
                        from src.utils import sanitize_error_message

                        error_msg = sanitize_error_message(e, "request body reading")
                        logger.error(
                            f"Failed to read request body for webhook '{self.webhook_id}': {error_msg}"
                        )
                        # Set cached_body to empty bytes to prevent retry
                        self._cached_body = b""
                        # Raise HTTPException with sanitized error
                        raise HTTPException(
                            status_code=400, detail="Failed to read request body"
                        )

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
        data_type = self.config.get("data_type", "json")

        if not isinstance(data_type, str):
            raise HTTPException(
                status_code=400,
                detail="Invalid data_type configuration: must be a string",
            )

        if data_type == "json":
            try:
                # Safely decode body with encoding detection and fallback
                from src.utils import safe_decode_body

                content_type = self.headers.get("content-type", "")
                decoded_body, encoding_used = safe_decode_body(body, content_type)
                # SECURITY: Use asyncio.to_thread for JSON parsing to avoid blocking the event loop for large payloads
                payload = await asyncio.to_thread(json.loads, decoded_body)
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
                    detail=sanitize_error_message(e, "request body decoding"),
                )

            # Validate JSON depth
            is_valid, msg = InputValidator.validate_json_depth(payload)
            if not is_valid:
                raise HTTPException(status_code=400, detail=msg)

            # Validate string lengths
            is_valid, msg = InputValidator.validate_string_length(payload)
            if not is_valid:
                raise HTTPException(status_code=400, detail=msg)

        elif data_type == "blob":
            payload = body
        else:
            raise HTTPException(status_code=415, detail="Unsupported data type")

        # Check if chain is configured (chain takes precedence over module for backward compatibility)
        chain = self.config.get("chain")
        if chain is not None:
            # Process chain
            return await self._process_chain(payload, headers_dict)

        # Backward compatibility: process single module
        # Get the module from registry
        module_name = self.config.get("module")
        if not module_name:
            raise HTTPException(status_code=400, detail="Module configuration error")

        # SECURITY: Validate module name type (should be string)
        if not isinstance(module_name, str):
            raise HTTPException(status_code=400, detail="Module configuration error")

        try:
            module_class = ModuleRegistry.get(module_name)
        except Exception as e:
            # Log detailed error server-side only
            logger.error(
                f"Unsupported module '{module_name}' for webhook '{self.webhook_id}': {e}"
            )
            raise HTTPException(status_code=501, detail="Module configuration error")

        # Note: Credential cleanup is now deferred to the background task for better performance

        # Instantiate and process
        # Add webhook_id to config for modules that need it (e.g., ClickHouse)
        module_config = {**self.config, "_webhook_id": self.webhook_id}

        # Inject connection_details if connection is specified
        connection_name = self.config.get("connection")
        if (
            connection_name
            and self.connection_config
            and connection_name in self.connection_config
        ):
            import copy

            try:
                connection_details = copy.deepcopy(
                    self.connection_config[connection_name]
                )
            except (RecursionError, MemoryError):
                # Fallback to shallow copy if deep copy fails
                connection_details = dict(self.connection_config[connection_name])
            module_config["connection_details"] = connection_details

        try:
            module = module_class(module_config, pool_registry=self.pool_registry)
        except Exception as e:
            # SECURITY: Catch and sanitize module instantiation errors to prevent information disclosure
            # Log detailed error server-side only
            logger.error(
                f"Module instantiation failed for webhook '{self.webhook_id}': {e}"
            )
            # Raise generic error to client (don't expose internal details)
            from src.utils import sanitize_error_message

            raise HTTPException(
                status_code=500,
                detail=sanitize_error_message(e, "module initialization"),
            )

        # Get retry configuration
        retry_config = self.config.get("retry", {})

        # If retry is enabled, execute with retry handler
        if retry_config.get("enabled", False):
            # Execute module with retry logic (performing cleanup in background)
            async def execute_module_with_retry():
                # Perform credential cleanup in background
                target_payload, target_headers = self._get_cleaned_data(
                    payload, headers_dict
                )

                return await retry_handler.execute_with_retry(
                    module.process,
                    target_payload,
                    target_headers,
                    retry_config=retry_config,
                )

            # Execute with retry using task manager (fire-and-forget, but track result)
            try:
                task = await task_manager.create_task(execute_module_with_retry())
            except Exception as e:
                # If task queue is full, log and continue (task will be lost, but webhook is accepted)
                metrics["module_execution_dropped_total"] += 1
                logger.error(
                    f"Could not create task for webhook '{self.webhook_id}'",
                    extra={
                        "webhook_id": self.webhook_id,
                        "error": str(e),
                        "retry_enabled": True,
                    },
                )
                # Return None for task to indicate it wasn't created
                return payload, dict(self.headers.items()), None

            # Return original payload and headers for logging (before cleanup)
            return payload, dict(self.headers.items()), task
        else:
            # No retry configured, execute normally using task manager (fire-and-forget)
            # Use cleaned data for module processing (performing cleanup in background)
            async def execute_module():
                # Perform credential cleanup in background
                target_payload, target_headers = self._get_cleaned_data(
                    payload, headers_dict
                )
                await module.process(target_payload, target_headers)

            try:
                # Create task with task manager (fire-and-forget, no tracking needed)
                await task_manager.create_task(execute_module())
            except Exception as e:
                # If task queue is full, log and continue (task will be lost, but webhook is accepted)
                metrics["module_execution_dropped_total"] += 1
                logger.error(
                    f"Could not create task for webhook '{self.webhook_id}'",
                    extra={
                        "webhook_id": self.webhook_id,
                        "error": str(e),
                        "retry_enabled": False,
                    },
                )

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
            raise HTTPException(
                status_code=400, detail=f"Invalid chain configuration: {error}"
            )

        # Get chain and chain-config
        chain = self.config.get("chain")
        chain_config = self.config.get("chain-config", {})

        # Note: Credential cleanup is now deferred to the background task for better performance

        # Add webhook_id to config for modules that need it
        webhook_config_with_id = {**self.config, "_webhook_id": self.webhook_id}

        # Create chain processor
        processor = ChainProcessor(
            chain=chain,
            chain_config=chain_config,
            webhook_config=webhook_config_with_id,
            pool_registry=self.pool_registry,
            connection_config=self.connection_config,
        )

        # Execute chain using task manager (fire-and-forget)
        async def execute_chain():
            metrics["chain_execution_total"] += 1
            try:
                # Perform credential cleanup in background
                target_payload, target_headers = self._get_cleaned_data(
                    payload, headers
                )
                results = await processor.execute(target_payload, target_headers)
                summary = processor.get_summary(results)

                # Log chain execution summary
                successful = summary["successful"]
                failed = summary["failed"]
                total = summary["total_modules"]

                log_extra = {
                    "webhook_id": self.webhook_id,
                    "total_modules": total,
                    "successful": successful,
                    "failed": failed,
                }

                if failed > 0:
                    if successful > 0:
                        metrics["chain_execution_partial_success_total"] += 1
                    else:
                        metrics["chain_execution_failed_total"] += 1

                    logger.warning(
                        f"Chain execution for webhook '{self.webhook_id}': {successful}/{total} modules succeeded, {failed} failed",
                        extra=log_extra,
                    )
                    # Log individual failures
                    for result in summary["results"]:
                        if not result["success"]:
                            logger.error(
                                f"Module '{result['module']}' in chain failed: {result['error']}",
                                extra={
                                    **log_extra,
                                    "module": result["module"],
                                    "error": str(result["error"]),
                                },
                            )
                else:
                    logger.info(
                        f"Chain execution for webhook '{self.webhook_id}': All {total} modules succeeded",
                        extra=log_extra,
                    )
            except Exception as e:
                # Log chain execution errors
                metrics["chain_execution_failed_total"] += 1
                logger.error(
                    f"Chain execution failed for webhook '{self.webhook_id}': {e}",
                    extra={"webhook_id": self.webhook_id, "error": str(e)},
                )

        try:
            # Create task with task manager (fire-and-forget)
            await task_manager.create_task(execute_chain())
        except Exception as e:
            # If task queue is full, log and continue (task will be lost, but webhook is accepted)
            metrics["chain_tasks_dropped_total"] += 1
            logger.error(
                f"Could not create task for chain execution in webhook '{self.webhook_id}'",
                extra={"webhook_id": self.webhook_id, "error": str(e)},
            )

        # Return original payload and headers for logging (before cleanup)
        return payload, dict(headers), None
