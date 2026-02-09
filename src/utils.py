import requests
import uuid
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import asyncio
import logging
from typing import Any, Tuple, Optional, Dict, List, Union, TYPE_CHECKING
import redis.asyncio as redis

if TYPE_CHECKING:
    from starlette.requests import Request

# Pre-compiled regex patterns for load_env_vars() — compiled once at import time
_EXACT_ENV_PATTERN = re.compile(r"^\{\$(?!vault:)(\w+)(?::(.*))?\}$")
_EMBEDDED_ENV_PATTERN = re.compile(r"\{\$(?!vault:)(\w+)(?::([^}]*))?\}")
_EXACT_VAULT_PATTERN = re.compile(r"^\{\$vault:([^}]+)\}$")
_EMBEDDED_VAULT_PATTERN = re.compile(r"\{\$vault:([^}]+)\}")

logger = logging.getLogger(__name__)


def sanitize_error_message(error: Any, context: str = None) -> str:
    """
    Sanitize error messages to prevent information disclosure.

    This function removes sensitive information from error messages that
    will be sent to clients, while logging detailed information server-side.

    Args:
        error: The error object or error message string
        context: Optional context about where the error occurred

    Returns:
        Generic error message safe for client exposure
    """
    # Convert error to string
    error_str = str(error)

    # Log detailed error server-side (for debugging)
    if context:
        logger.error("Error [%s]: %s", context, error_str)
    else:
        logger.error("Error: %s", error_str)

    # Return generic message for client
    # Don't expose:
    # - URLs, file paths, hostnames
    # - Module names, configuration details
    # - Internal error details
    # - Stack traces

    # SECURITY: Check for sensitive strings first (simpler and more reliable)
    error_lower = error_str.lower()
    sensitive_strings = [
        "postgresql://",
        "mysql://",
        "redis://",
        "mongodb://",
        "secret",
        "password",
        "/etc/",
        "c:\\",
        "traceback",
        "stack_trace",
        "connection_string",
        "connection string",
    ]
    for sensitive_str in sensitive_strings:
        if sensitive_str in error_lower:
            # SECURITY: Sanitize context if it contains sensitive patterns
            if context:
                sanitized_context = _sanitize_context(context)
                return f"Processing error occurred in {sanitized_context}"
            return "An error occurred while processing the request"

    # Check for common sensitive patterns (regex)
    sensitive_patterns = [
        (r"http[s]?://[^\s]+", "URL"),
        (r"file://[^\s]+", "file path"),
        (r"/[^\s]+", "file path"),
        (
            r"[a-zA-Z0-9_\-]+://[^\s]+",
            "URL",
        ),  # Include hyphens for schemes like postgresql://
        (r"localhost:\d+", "service address"),
        (r"\d+\.\d+\.\d+\.\d+:\d+", "service address"),
        (r"module[_\s]+[\w]+", "module name"),
        (r"Failed to.*:\s*[^\n]+", "error details"),
    ]

    # If error contains sensitive patterns, return generic message
    for pattern, pattern_type in sensitive_patterns:
        if re.search(pattern, error_str, re.IGNORECASE):
            # SECURITY: Sanitize context if it contains sensitive patterns
            if context:
                sanitized_context = _sanitize_context(context)
                return f"Processing error occurred in {sanitized_context}"
            return "An error occurred while processing the request"

    # For generic errors, return a safe message
    # Don't expose the actual error text
    # SECURITY: Sanitize context to prevent information disclosure
    if context:
        sanitized_context = _sanitize_context(context)
        return f"Processing error occurred in {sanitized_context}"
    return "An error occurred while processing the request"


def get_client_ip(request: "Request", trusted_proxies: Optional[List[str]] = None) -> Tuple[str, bool]:
    """
    Securely get client IP address with trusted proxy validation.

    This function prevents IP spoofing attacks by only trusting X-Forwarded-For
    and X-Real-IP headers when the direct connection comes from a trusted proxy.

    Security considerations:
    - Only trusts proxy headers when request comes from a trusted proxy IP
    - Falls back to request.client.host for direct connections
    - Returns empty string if IP cannot be determined securely

    Args:
        request: FastAPI Request object
        trusted_proxies: Optional list of trusted proxy IPs. If None, reads from
                         TRUSTED_PROXY_IPS environment variable (comma-separated).

    Returns:
        Tuple of (client_ip, is_from_trusted_proxy)
        - client_ip: The client IP address or empty string if not determinable
        - is_from_trusted_proxy: True if IP was obtained via trusted proxy headers
    """
    # Get trusted proxy IPs from parameter or environment variable
    if trusted_proxies is None:
        trusted_proxies_env = os.getenv("TRUSTED_PROXY_IPS", "").strip()
        if trusted_proxies_env:
            trusted_proxies = [ip.strip() for ip in trusted_proxies_env.split(",") if ip.strip()]
        else:
            trusted_proxies = []

    # Get headers as dict (case-insensitive lookup)
    headers = {k.lower(): v for k, v in request.headers.items()}

    # If we have the Request object, use it as primary source (most secure)
    if request and hasattr(request, "client") and request.client:
        # Safely get client.host (may not exist or be empty)
        try:
            actual_client_ip = getattr(request.client, "host", None)
        except AttributeError:
            actual_client_ip = None

        # If we have a valid client IP from Request object
        if actual_client_ip and actual_client_ip.strip():
            # If we're behind a trusted proxy, check X-Forwarded-For
            if trusted_proxies and actual_client_ip in trusted_proxies:
                # Trust X-Forwarded-For only if actual client is a trusted proxy
                x_forwarded_for = headers.get("x-forwarded-for", "").strip()
                if x_forwarded_for:
                    # Validate and sanitize X-Forwarded-For header
                    # Remove newlines and null bytes to prevent header injection
                    x_forwarded_for = (
                        x_forwarded_for.replace("\n", "")
                        .replace("\r", "")
                        .replace("\0", "")
                    )
                    # X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
                    # The first IP is the original client
                    client_ip = x_forwarded_for.split(",")[0].strip()
                    if client_ip:
                        return client_ip, True

                # Fallback to X-Real-IP if X-Forwarded-For is not present
                x_real_ip = headers.get("x-real-ip", "").strip()
                if x_real_ip:
                    # Sanitize X-Real-IP header
                    x_real_ip = (
                        x_real_ip.replace("\n", "")
                        .replace("\r", "")
                        .replace("\0", "")
                    )
                    if x_real_ip:
                        return x_real_ip, True

            # Use actual client IP from connection (most secure, cannot be spoofed)
            return actual_client_ip, False

    # SECURITY: If no Request object or no valid client IP, return "unknown"
    # This is more explicit than empty string
    return "unknown", False


def _sanitize_context(context: str) -> str:
    """
    Sanitize context string to prevent information disclosure.

    This function checks if context contains sensitive patterns (URLs, file paths, etc.)
    and returns a generic context if sensitive patterns are found.

    Args:
        context: The context string to sanitize

    Returns:
        Sanitized context string (original if no sensitive patterns found)
    """
    if not context or not isinstance(context, str):
        return "processing"

    context_lower = context.lower()

    # Check for sensitive strings
    sensitive_strings = [
        "postgresql://",
        "mysql://",
        "redis://",
        "mongodb://",
        "secret",
        "password",
        "/etc/",
        "c:\\",
        "traceback",
        "stack_trace",
        "connection_string",
        "connection string",
        "localhost:",
        "127.0.0.1",
        "192.168.",
        "10.",
        "172.",
    ]
    for sensitive_str in sensitive_strings:
        if sensitive_str in context_lower:
            return "processing"  # Return generic context

    # Check for sensitive patterns (regex)
    sensitive_patterns = [
        (r"http[s]?://[^\s]+", "URL"),
        (r"file://[^\s]+", "file path"),
        (r"/[^\s]+", "file path"),
        (r"[a-zA-Z0-9_\-]+://[^\s]+", "URL"),
        (r"localhost:\d+", "service address"),
        (r"\d+\.\d+\.\d+\.\d+:\d+", "service address"),
    ]

    for pattern, pattern_type in sensitive_patterns:
        if re.search(pattern, context, re.IGNORECASE):
            return "processing"  # Return generic context

    # Context is safe, return as-is
    return context


def detect_encoding_from_content_type(content_type: Optional[str]) -> Optional[str]:
    """
    Detect encoding from Content-Type header.

    SECURITY: Validates charset name to prevent injection attacks.
    Only allows alphanumeric characters, hyphens, underscores, and dots.

    Args:
        content_type: Content-Type header value (e.g., "application/json; charset=utf-8")

    Returns:
        Encoding name if found and valid, None otherwise
    """
    if not content_type:
        return None

    # Parse charset from Content-Type header
    # Format: "type/subtype; charset=encoding" or "type/subtype; charset='encoding'"
    charset_match = re.search(
        r'charset\s*=\s*["\']?([^"\'\s;]+)["\']?', content_type, re.IGNORECASE
    )
    if charset_match:
        charset_name = charset_match.group(1).lower()

        # SECURITY: Validate charset name to prevent injection attacks
        # Only allow alphanumeric, hyphens, underscores, and dots (for encoding names like "iso-8859-1")
        # Reject dangerous characters: command separators, path traversal, null bytes, etc.
        MAX_CHARSET_LENGTH = 64  # Prevent DoS via extremely long charset names
        if len(charset_name) > MAX_CHARSET_LENGTH:
            logger.warning(
                "Charset name too long: %d characters (max: %d), rejecting",
                len(charset_name), MAX_CHARSET_LENGTH,
            )
            return None

        # Validate charset name format (alphanumeric, hyphen, underscore, dot only)
        if not re.match(r"^[a-z0-9._-]+$", charset_name):
            logger.warning(
                "Invalid charset name format (contains dangerous characters): %s, rejecting",
                charset_name[:50],
            )
            return None

        # Reject null bytes and control characters
        if "\x00" in charset_name or any(
            ord(c) < 32 and c not in "\t\n\r" for c in charset_name
        ):
            logger.warning(
                "Charset name contains null bytes or control characters, rejecting"
            )
            return None

        return charset_name

    return None


def safe_decode_body(
    body: bytes, content_type: Optional[str] = None, default_encoding: str = "utf-8"
) -> Tuple[str, str]:
    """
    Safely decode request body bytes to string with encoding detection and fallback.

    This function:
    - Detects encoding from Content-Type header if available
    - Falls back to common encodings (UTF-8, UTF-16, Latin-1, etc.)
    - Handles UnicodeDecodeError gracefully
    - Sanitizes error messages to prevent information disclosure

    Args:
        body: Request body as bytes
        content_type: Optional Content-Type header value
        default_encoding: Default encoding to use if detection fails (default: 'utf-8')

    Returns:
        Tuple of (decoded_string, encoding_used)

    Raises:
        HTTPException: If body cannot be decoded with any encoding
    """
    from fastapi import HTTPException

    # Try encoding from Content-Type header first
    detected_encoding = detect_encoding_from_content_type(content_type)

    # SECURITY: Whitelist of safe encodings to prevent encoding confusion attacks
    # UTF-16 variants can decode almost any byte sequence, which is a security risk
    # Only allow UTF-16 if explicitly requested and validated
    SAFE_ENCODINGS = ["utf-8", "latin-1", "iso-8859-1", "cp1252", "ascii"]

    # List of encodings to try (in order of preference)
    encodings_to_try = []

    if detected_encoding:
        # SECURITY: Only use detected encoding if it's in the safe list
        # UTF-16 variants are only allowed if explicitly requested (for compatibility)
        if detected_encoding in SAFE_ENCODINGS:
            encodings_to_try.append(detected_encoding)
        elif detected_encoding in ["utf-16", "utf-16le", "utf-16be"]:
            # Allow UTF-16 variants only if explicitly requested (for backward compatibility)
            # But prefer safe encodings first
            encodings_to_try.append(detected_encoding)
        else:
            # Unknown/dangerous encoding - log warning and skip
            logger.warning(
                "Unknown or potentially dangerous encoding '%s' requested, using safe fallback",
                detected_encoding,
            )

    # Add safe encodings as fallback (UTF-8 first, then others)
    for enc in SAFE_ENCODINGS:
        if enc not in encodings_to_try:
            encodings_to_try.append(enc)

    # Try each encoding
    for encoding in encodings_to_try:
        try:
            decoded = body.decode(encoding)
            return decoded, encoding
        except (UnicodeDecodeError, LookupError):
            # LookupError for invalid encoding names
            continue

    # Final fallback: try default encoding with error handling
    try:
        # Use 'replace' error handling to get partial decode
        decoded = body.decode(default_encoding, errors="replace")
        # If we got here, return it but log a warning
        logger.warning(
            "Request body decoded with errors using %s. Some characters may be lost.",
            default_encoding,
        )
        return decoded, default_encoding
    except Exception:
        # If even this fails, raise an error
        raise HTTPException(
            status_code=400,
            detail="Request body encoding could not be determined or decoded. Please ensure the body is valid UTF-8 or specify charset in Content-Type header.",
        )


async def save_to_disk(payload, config):
    my_uuid = uuid.uuid4()

    module_config = config.get("module-config", {})
    path = module_config.get("path", ".")

    if path != "." and not os.path.exists(path):
        os.makedirs(path)

    file_path = os.path.join(path, f"{my_uuid}.txt")
    with open(file_path, mode="w") as f:
        f.write(str(payload))
        f.flush()


async def print_to_stdout(payload, headers, config):
    print("config: " + str(config))
    print("headers: " + str(headers))
    print("body: " + str(payload))
    # await asyncio.sleep(5)  # Simulating delay


def _sanitize_env_value(value: str, context_key: str = None) -> str:
    """
    Sanitize environment variable value to prevent injection attacks.

    This function:
    - Removes or escapes dangerous characters that could be used for injection
    - Validates value format based on context
    - Prevents command injection, URL injection, and code injection

    Args:
        value: The environment variable value to sanitize
        context_key: Optional context key to determine validation rules

    Returns:
        Sanitized value
    """
    if not isinstance(value, str):
        return value

    original_value = value

    # Remove null bytes (always dangerous)
    if "\x00" in value:
        logger.warning(
            "Environment variable value contains null byte (context: %s), removing",
            context_key,
        )
        value = value.replace("\x00", "")

    # Check for URL injection patterns FIRST (if context suggests URL)
    # This must be done before command injection checks to catch schemes
    if context_key and ("url" in context_key.lower() or "host" in context_key.lower()):
        # Check for dangerous URL schemes
        dangerous_schemes = ["javascript:", "data:", "vbscript:", "file:", "gopher:"]
        for scheme in dangerous_schemes:
            if value.lower().startswith(scheme):
                logger.warning(
                    "Environment variable value contains dangerous URL scheme (context: %s): %s",
                    context_key, scheme,
                )
                # Remove the dangerous scheme
                value = value[len(scheme) :].lstrip()

    # Check for command injection patterns - remove dangerous characters
    # Command separators and injection characters
    dangerous_chars = [";", "|", "&", "`", "$", "(", ")", "{", "}"]
    for char in dangerous_chars:
        if char in value:
            logger.warning(
                "Environment variable value contains dangerous character '%s' (context: %s): %s",
                char, context_key, value[:50],
            )
            value = value.replace(char, "")

    # Check for SQL injection patterns (if context suggests SQL)
    if context_key and (
        "sql" in context_key.lower()
        or "query" in context_key.lower()
        or "table" in context_key.lower()
    ):
        sql_injection_patterns = [
            r"';",  # SQL injection with single quote
            r'";',  # SQL injection with double quote
            r"--",  # SQL comment
            r"/\*",  # SQL comment start
            r"\*/",  # SQL comment end
            r"union\s+select",  # UNION SELECT
            r"drop\s+table",  # DROP TABLE
            r"delete\s+from",  # DELETE FROM
            r"insert\s+into",  # INSERT INTO
            r"update\s+set",  # UPDATE SET
        ]
        for pattern in sql_injection_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(
                    "Environment variable value contains potential SQL injection pattern (context: %s): %s",
                    context_key, value[:50],
                )
                # Remove SQL injection patterns
                value = re.sub(pattern, "", value, flags=re.IGNORECASE)

    # Check for path traversal patterns
    if ".." in value:
        logger.warning(
            "Environment variable value contains path traversal pattern (context: %s): %s",
            context_key, value[:50],
        )
        # Remove path traversal
        value = value.replace("..", "")

    # Check for absolute paths in non-path contexts
    if (
        value.startswith("/")
        and context_key
        and "path" not in context_key.lower()
        and "url" not in context_key.lower()
    ):
        logger.warning(
            "Environment variable value contains absolute path (context: %s): %s",
            context_key, value[:50],
        )
        # Remove leading slash
        value = value.lstrip("/")

    # Remove common command injection keywords
    command_keywords = ["rm ", "rm -rf", "cat ", "ls ", "pwd", "whoami", "id", "uname"]
    for keyword in command_keywords:
        if keyword.lower() in value.lower():
            logger.warning(
                "Environment variable value contains command keyword '%s' (context: %s): %s",
                keyword, context_key, value[:50],
            )
            # Remove the keyword and surrounding context
            value = re.sub(re.escape(keyword), "", value, flags=re.IGNORECASE)

    # Limit length to prevent DoS
    MAX_ENV_VALUE_LENGTH = 4096
    if len(value) > MAX_ENV_VALUE_LENGTH:
        logger.warning(
            "Environment variable value too long (context: %s): %d characters, truncating",
            context_key, len(value),
        )
        value = value[:MAX_ENV_VALUE_LENGTH]

    # If value became empty after sanitization, return a safe default
    if not value.strip() and original_value.strip():
        logger.warning(
            "Environment variable value was completely sanitized (context: %s), using safe default",
            context_key,
        )
        return "sanitized_value"

    return value


def load_env_vars(data, visited=None, depth=0, vault_resolver=None):
    """
    Load environment variables and Vault secrets from configuration data.

    Supports multiple patterns:
    1. {$VAR} - Replace entire value with environment variable
    2. {$VAR:default} - Use environment variable or default value if not set
    3. Embedded variables in strings: "http://{$HOST}:{$PORT}"
    4. {$vault:path/to/secret#field} - Replace with Vault secret field
    5. {$vault:path/to/secret#field:default} - Vault secret with fallback default
    6. Embedded Vault refs in strings: "Bearer {$vault:auth/api#token}"

    Examples:
        "host": "{$REDIS_HOST}" -> replaced with env var value
        "host": "{$REDIS_HOST:localhost}" -> replaced with env var or "localhost"
        "url": "http://{$HOST}:{$PORT}/api" -> embedded env vars in string
        "token": "{$vault:secrets/api#token}" -> replaced with Vault secret
        "token": "{$vault:secrets/api#token:fallback}" -> Vault secret or "fallback"

    Security: All resolved values are sanitized to prevent injection attacks.

    SECURITY: Implements depth limit and visited set tracking to prevent:
    - Deep recursion DoS attacks (stack overflow)
    - Circular reference infinite loops

    Args:
        data: Configuration data (dict, list, or primitive)
        visited: Set of object IDs already visited (for circular reference detection)
        depth: Current recursion depth (for depth limit enforcement)
        vault_resolver: Optional VaultSecretResolver instance (auto-created if None)

    Returns:
        Data with environment variables and Vault secrets replaced and sanitized
    """
    # SECURITY: Limit recursion depth to prevent stack overflow DoS attacks
    MAX_RECURSION_DEPTH = 100
    if depth > MAX_RECURSION_DEPTH:
        # Return data as-is if depth limit exceeded (fail-safe)
        return data

    # SECURITY: Track visited objects to prevent infinite loops from circular references
    if visited is None:
        visited = set()

    # For mutable objects (dict, list), track by id to detect circular references
    if isinstance(data, (dict, list)):
        data_id = id(data)
        if data_id in visited:
            # Circular reference detected - return data as-is to prevent infinite loop
            return data
        visited.add(data_id)

    # Lazy import to avoid unnecessary dependency initialization when Vault is unused
    if vault_resolver is None:
        from src.vault_secret_resolver import get_vault_secret_resolver

        vault_resolver = get_vault_secret_resolver()

    def process_string(value, context_key=None):
        """Process a string value to replace environment variables."""
        # Try exact Vault match first (entire string is a Vault reference)
        exact_vault_match = _EXACT_VAULT_PATTERN.match(value)
        if exact_vault_match:
            reference = exact_vault_match.group(1)
            resolved = vault_resolver.resolve_reference(
                reference, context_key=context_key
            )

            if resolved is None:
                logger.warning(
                    "Vault secret reference '%s' could not be resolved for key '%s'",
                    reference, context_key,
                )
                return f"Undefined vault secret {reference}"

            return _sanitize_env_value(str(resolved), context_key)

        # Try exact env match next (entire string is an env variable)
        exact_env_match = _EXACT_ENV_PATTERN.match(value)
        if exact_env_match:
            env_var = exact_env_match.group(1)
            default = exact_env_match.group(2)  # Can be None or empty string
            env_value = os.getenv(env_var)

            if env_value is not None:
                # Sanitize environment variable value
                sanitized = _sanitize_env_value(env_value, context_key)
                return sanitized
            elif default is not None:  # Includes empty string
                # Sanitize default value as well
                sanitized = _sanitize_env_value(default, context_key)
                return sanitized
            else:
                # No default provided and env var not set
                logger.warning(
                    "Environment variable '%s' not set and no default provided for key '%s'",
                    env_var, context_key,
                )
                return f"Undefined variable {env_var}"
        else:
            # First resolve embedded Vault references (if any)
            def replace_embedded_vault(match):
                reference = match.group(1)
                resolved = vault_resolver.resolve_reference(
                    reference, context_key=context_key
                )
                if resolved is None:
                    logger.warning(
                        "Vault secret reference '%s' not resolved in embedded string for key '%s'",
                        reference, context_key,
                    )
                    return match.group(0)  # Keep original placeholder

                return _sanitize_env_value(str(resolved), context_key)

            new_value = _EMBEDDED_VAULT_PATTERN.sub(replace_embedded_vault, value)

            # Then resolve embedded env variables (variables within strings)
            def replace_embedded_env(match):
                env_var = match.group(1)
                default = match.group(2)  # Can be None or empty string
                env_value = os.getenv(env_var)

                if env_value is not None:
                    # Sanitize environment variable value
                    sanitized = _sanitize_env_value(env_value, context_key)
                    return sanitized
                elif default is not None:  # Includes empty string
                    # Sanitize default value as well
                    sanitized = _sanitize_env_value(default, context_key)
                    return sanitized
                else:
                    # Keep original if not found and no default
                    logger.warning(
                        "Environment variable '%s' not set in embedded string for key '%s'",
                        env_var, context_key,
                    )
                    return match.group(0)  # Return original placeholder

            # Replace all embedded variables
            new_value = _EMBEDDED_ENV_PATTERN.sub(replace_embedded_env, new_value)
            return new_value

    try:
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    data[key] = process_string(value, key)
                else:
                    # Recursive call for nested dictionaries or lists
                    load_env_vars(value, visited, depth + 1, vault_resolver)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, str):
                    data[i] = process_string(item, f"list[{i}]")
                else:
                    load_env_vars(item, visited, depth + 1, vault_resolver)
        elif isinstance(data, str):
            # SECURITY: Handle string values directly (not in dict/list)
            return process_string(data)
        # For other types (int, bool, None, etc.), return as-is
    finally:
        # Clean up visited set when done with this branch
        if isinstance(data, (dict, list)):
            visited.discard(id(data))

    return data


class EndpointStats:
    # SECURITY: Limits to prevent DoS attacks
    MAX_ENDPOINT_NAME_LENGTH = 256  # Maximum endpoint name length
    MAX_ENDPOINTS = 100000  # Maximum number of unique endpoints

    def __init__(self):
        self.stats = defaultdict(lambda: defaultdict(int))
        self.timestamps = defaultdict(dict)  # Using dict for timestamps
        self.lock = asyncio.Lock()
        self.bucket_size = timedelta(minutes=1)  # Smallest bucket size

    def _validate_endpoint_name(self, endpoint_name):
        """
        Validate endpoint name to prevent DoS and type confusion attacks.

        SECURITY: Validates type, length, and dangerous characters.
        """
        # Type validation
        if not isinstance(endpoint_name, str):
            raise TypeError(
                f"endpoint_name must be a string, got {type(endpoint_name).__name__}"
            )

        # Length validation
        if len(endpoint_name) > self.MAX_ENDPOINT_NAME_LENGTH:
            raise ValueError(
                f"endpoint_name too long: {len(endpoint_name)} chars (max: {self.MAX_ENDPOINT_NAME_LENGTH})"
            )

        # Null byte detection
        if "\x00" in endpoint_name:
            raise ValueError("endpoint_name contains null byte")

        # Check endpoint count limit
        if (
            len(self.timestamps) >= self.MAX_ENDPOINTS
            and endpoint_name not in self.timestamps
        ):
            raise ValueError(
                f"Maximum number of endpoints ({self.MAX_ENDPOINTS}) exceeded"
            )

        return endpoint_name

    async def increment(self, endpoint_name):
        # SECURITY: Validate endpoint name before processing
        endpoint_name = self._validate_endpoint_name(endpoint_name)

        async with self.lock:
            now = datetime.now(timezone.utc)
            bucket = self._get_bucket(now)
            self.timestamps[endpoint_name][bucket] = (
                self.timestamps[endpoint_name].get(bucket, 0) + 1
            )
            self.stats[endpoint_name]["total"] += 1
            self._cleanup_old_buckets(endpoint_name, now)  # Cleanup old buckets

    def _get_bucket(self, timestamp):
        """
        Align timestamp to the start of the bucket.

        SECURITY: Fixed timezone-aware datetime handling to prevent TypeError.
        """
        # SECURITY: Handle timezone-aware timestamps correctly
        # Use epoch (1970-01-01) as reference point instead of datetime.min
        # to avoid timezone-naive/aware mixing issues
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        delta = timestamp - epoch
        # Align to bucket boundary
        bucket_offset = delta % self.bucket_size
        return timestamp - bucket_offset

    def _cleanup_old_buckets(self, endpoint_name, now):
        # Remove buckets older than a certain cutoff (e.g., 1 day)
        cutoff = now - timedelta(days=1)
        old_buckets = [
            bucket_time
            for bucket_time in self.timestamps[endpoint_name]
            if bucket_time < cutoff
        ]
        for bucket in old_buckets:
            del self.timestamps[endpoint_name][bucket]

    def get_stats(self):
        stats_summary = defaultdict(dict)
        now = datetime.now(timezone.utc)
        for endpoint in self.timestamps:
            stats_summary[endpoint]["total"] = self.stats[endpoint]["total"]
            stats_summary[endpoint]["minute"] = sum(
                count
                for bucket_time, count in self.timestamps[endpoint].items()
                if bucket_time > now - timedelta(minutes=1)
            )
            stats_summary[endpoint]["5_minutes"] = sum(
                count
                for bucket_time, count in self.timestamps[endpoint].items()
                if bucket_time > now - timedelta(minutes=5)
            )
            stats_summary[endpoint]["15_minutes"] = sum(
                count
                for bucket_time, count in self.timestamps[endpoint].items()
                if bucket_time > now - timedelta(minutes=15)
            )
            stats_summary[endpoint]["30_minutes"] = sum(
                count
                for bucket_time, count in self.timestamps[endpoint].items()
                if bucket_time > now - timedelta(minutes=30)
            )
            stats_summary[endpoint]["hour"] = sum(
                count
                for bucket_time, count in self.timestamps[endpoint].items()
                if bucket_time > now - timedelta(hours=1)
            )
            stats_summary[endpoint]["day"] = sum(
                count
                for bucket_time, count in self.timestamps[endpoint].items()
                if bucket_time > now - timedelta(days=1)
            )
            stats_summary[endpoint]["week"] = sum(
                count
                for bucket_time, count in self.timestamps[endpoint].items()
                if bucket_time > now - timedelta(weeks=1)
            )
            stats_summary[endpoint]["month"] = sum(
                count
                for bucket_time, count in self.timestamps[endpoint].items()
                if bucket_time > now - timedelta(days=30)
            )

        return stats_summary


class RedisEndpointStats:
    def __init__(self, redis_url=None):
        # Use REDIS_HOST env var if not provided, default to localhost
        if not redis_url:
            redis_host = os.getenv("REDIS_HOST", "localhost")
            redis_port = os.getenv("REDIS_PORT", "6379")
            redis_url = f"redis://{redis_host}:{redis_port}"

        self._redis_url = redis_url
        self._redis = None
        self.bucket_size_seconds = 60  # 1 minute
        self._known_endpoints = set()
        self._increment_script = None

    @property
    def redis(self):
        """Get Redis connection, creating it if needed."""
        if self._redis is None:
            self._redis = redis.from_url(self._redis_url, decode_responses=True)
            self._increment_script = None  # Reset script on new connection
        return self._redis

    def _get_increment_script(self):
        """Get or register the Lua script for atomic increment."""
        if self._increment_script is None:
            lua = """
            local endpoint = ARGV[1]
            local now = tonumber(ARGV[2])
            local minute_ts = now - (now % 60)
            local hour_ts = now - (now % 3600)
            local day_ts = now - (now % 86400)

            -- Add to endpoints set
            redis.call('SADD', 'stats:endpoints', endpoint)

            -- Increment total in Hash
            redis.call('HINCRBY', 'stats:totals', endpoint, 1)

            -- Minute bucket
            local minute_key = 'stats:' .. endpoint .. ':bucket:60:' .. minute_ts
            redis.call('INCR', minute_key)
            redis.call('EXPIRE', minute_key, 7200)

            -- Hour bucket
            local hour_key = 'stats:' .. endpoint .. ':bucket:3600:' .. hour_ts
            redis.call('INCR', hour_key)
            redis.call('EXPIRE', hour_key, 172800)

            -- Day bucket
            local day_key = 'stats:' .. endpoint .. ':bucket:86400:' .. day_ts
            redis.call('INCR', day_key)
            redis.call('EXPIRE', day_key, 3000000)

            return 1
            """
            self._increment_script = self.redis.register_script(lua)
        return self._increment_script

    async def close(self):
        """Close the Redis connection."""
        if self._redis:
            try:
                await self._redis.aclose()
            except Exception:
                # SECURITY: Silently ignore Redis close errors during cleanup
                # This is intentional - close failures during teardown are non-critical
                pass  # nosec B110
            finally:
                self._redis = None

    def _ensure_connection(self):
        """Ensure Redis connection is valid, recreate if needed."""
        if self._redis is None:
            self._redis = redis.from_url(self._redis_url, decode_responses=True)
        return self._redis

    async def _reconnect_if_needed(self):
        """Reconnect Redis if connection is invalid."""
        if self._redis is None:
            self._redis = redis.from_url(self._redis_url, decode_responses=True)
            self._increment_script = None
            return

        # Try to check if connection is still valid
        try:
            # This will raise an error if the connection is bound to a closed event loop
            await self._redis.ping()
        except (RuntimeError, AttributeError) as e:
            # Event loop is closed or connection is invalid, recreate it
            try:
                await self._redis.aclose()
            except Exception:
                # SECURITY: Silently ignore Redis close errors during cleanup
                # This is intentional - close failures during teardown are non-critical
                pass  # nosec B110
            self._redis = redis.from_url(self._redis_url, decode_responses=True)
            self._increment_script = None

    async def increment_multi_resolution(self, endpoint_name):
        # SECURITY: Validate endpoint_name to prevent key manipulation and DoS
        if not endpoint_name or not isinstance(endpoint_name, str):
            raise ValueError("endpoint_name must be a non-empty string")

        endpoint_name = endpoint_name.strip()
        if not endpoint_name:
            raise ValueError("endpoint_name cannot be empty or whitespace-only")

        # SECURITY: Limit endpoint name length to prevent DoS via large keys
        MAX_ENDPOINT_NAME_LENGTH = 256  # Reasonable limit for Redis keys
        if len(endpoint_name) > MAX_ENDPOINT_NAME_LENGTH:
            raise ValueError(
                f"endpoint_name too long: {len(endpoint_name)} characters (max: {MAX_ENDPOINT_NAME_LENGTH})"
            )

        # SECURITY: Check for null bytes (dangerous in keys)
        if "\x00" in endpoint_name:
            raise ValueError("endpoint_name cannot contain null bytes")

        # SECURITY: Check for newlines/carriage returns (could cause issues)
        if "\n" in endpoint_name or "\r" in endpoint_name:
            raise ValueError(
                "endpoint_name cannot contain newlines or carriage returns"
            )

        await self._reconnect_if_needed()
        now = int(time.time())

        try:
            # OPTIMIZATION: Use Lua script for atomic multi-increment (1 round-trip)
            # This replaces multiple INCR/EXPIRE/SADD calls with a single Redis operation
            script = self._get_increment_script()
            await script(args=[endpoint_name, now])

            # Update local cache of known endpoints
            self._known_endpoints.add(endpoint_name)
        except Exception as e:
            # Connection issue or script error, reconnect and retry once
            await self._reconnect_if_needed()
            try:
                script = self._get_increment_script()
                await script(args=[endpoint_name, now])
                self._known_endpoints.add(endpoint_name)
            except Exception as retry_err:
                logger.error("Failed to increment stats even after retry: %s", retry_err)

    # Override increment to use multi-resolution
    async def increment(self, endpoint_name):
        await self.increment_multi_resolution(endpoint_name)

    async def get_stats(self):
        await self._reconnect_if_needed()
        return await self._get_stats_optimized()

    async def _get_stats_optimized(self):
        stats_summary = defaultdict(dict)
        try:
            endpoints = await self.redis.smembers("stats:endpoints")
        except Exception:
            await self._reconnect_if_needed()
            endpoints = await self.redis.smembers("stats:endpoints")

        for endpoint in endpoints:
            # SECURITY: Validate endpoint names from Redis
            if not endpoint or not isinstance(endpoint, str) or len(endpoint) > 256:
                continue

            # OPTIMIZATION: Read total from Hash instead of individual keys
            # Migration path: fallback to individual key if not in Hash
            total = await self.redis.hget("stats:totals", endpoint)
            if total is None:
                # Fallback for legacy data
                total = await self.redis.get(f"stats:{endpoint}:total")

            stats_summary[endpoint]["total"] = int(total) if total else 0

            now = int(time.time())

            # Helper to generate keys (multi-resolution)
            def get_keys(resolution_seconds, count):
                keys = []
                current_bucket = now - (now % resolution_seconds)
                for i in range(count):
                    t = current_bucket - (i * resolution_seconds)
                    keys.append(f"stats:{endpoint}:bucket:{resolution_seconds}:{t}")
                return keys

            minute_keys = get_keys(60, 60)
            hour_keys = get_keys(3600, 24)
            day_keys = get_keys(86400, 30)

            all_keys = minute_keys + hour_keys + day_keys

            if all_keys:
                values = await self.redis.mget(all_keys)
                data = dict(zip(all_keys, [int(v) if v else 0 for v in values]))

                def sum_keys(keys):
                    return sum(data.get(k, 0) for k in keys)

                stats_summary[endpoint]["minute"] = sum_keys(minute_keys[:1])
                stats_summary[endpoint]["5_minutes"] = sum_keys(minute_keys[:5])
                stats_summary[endpoint]["15_minutes"] = sum_keys(minute_keys[:15])
                stats_summary[endpoint]["30_minutes"] = sum_keys(minute_keys[:30])
                stats_summary[endpoint]["hour"] = sum_keys(minute_keys[:60])
                stats_summary[endpoint]["day"] = sum_keys(hour_keys[:24])
                stats_summary[endpoint]["week"] = sum_keys(day_keys[:7])
                stats_summary[endpoint]["month"] = sum_keys(day_keys[:30])

        return stats_summary


class CredentialCleaner:
    """
    Utility class for cleaning credentials from data structures.

    Removes or masks sensitive credential fields from payloads, headers, and
    other data structures before logging or storing to prevent credential exposure.
    """

    # Default credential field names (case-insensitive matching)
    DEFAULT_CREDENTIAL_FIELDS = [
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "authorization",
        "auth",
        "credential",
        "credentials",
        "private_key",
        "privatekey",
        "api_secret",
        "client_secret",
        "bearer",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "session_id",
        "sessionid",
        "session_token",
        "csrf_token",
        "csrf",
        "oauth_token",
        "oauth_secret",
        "consumer_secret",
        "token_secret",
    ]

    # Default mask value
    MASK_VALUE = "***REDACTED***"

    def __init__(self, custom_fields: Optional[List[str]] = None, mode: str = "mask"):
        """
        Initialize credential cleaner.

        Args:
            custom_fields: Additional field names to treat as credentials
            mode: 'mask' to replace with mask value, 'remove' to delete field

        Raises:
            ValueError: If mode is invalid
            TypeError: If custom_fields is not a list or None
        """
        # SECURITY: Validate mode type and value to prevent injection attacks
        if mode is None:
            raise ValueError("Mode must be 'mask' or 'remove', got None")
        if not isinstance(mode, str):
            raise ValueError(f"Mode must be a string, got {type(mode).__name__}")

        self.mode = mode.lower()
        if self.mode not in ("mask", "remove"):
            raise ValueError(f"Mode must be 'mask' or 'remove', got '{mode}'")

        # SECURITY: Validate custom_fields type to prevent type confusion attacks
        if custom_fields is not None and not isinstance(custom_fields, list):
            raise TypeError(
                f"custom_fields must be a list or None, got {type(custom_fields).__name__}"
            )

        # Combine default and custom fields
        all_fields = set(field.lower() for field in self.DEFAULT_CREDENTIAL_FIELDS)
        if custom_fields:
            # SECURITY: Filter out non-string items from custom_fields to prevent type confusion
            string_fields = [field for field in custom_fields if isinstance(field, str)]
            all_fields.update(field.lower() for field in string_fields)

        self.credential_fields = list(all_fields)

    def _is_credential_field(self, field_name: str) -> bool:
        """
        Check if a field name matches credential patterns.

        Args:
            field_name: The field name to check

        Returns:
            True if field should be treated as credential
        """
        if not field_name or not isinstance(field_name, str):
            return False

        field_lower = field_name.lower().strip()

        # Direct match
        if field_lower in self.credential_fields:
            return True

        # Pattern matching for common credential patterns
        credential_patterns = [
            r".*password.*",
            r".*secret.*",
            r".*token.*",
            r".*key.*",
            r".*credential.*",
            r".*auth.*",
            r"x-.*-key",
            r"x-.*-token",
            r"x-.*-secret",
        ]

        for pattern in credential_patterns:
            if re.match(pattern, field_lower):
                return True

        return False

    def _clean_dict_recursive(
        self, data: Any, path: str = "", visited: Optional[set] = None, depth: int = 0
    ) -> Any:
        """
        Recursively clean credentials from dictionary or list structures.

        SECURITY: Implements depth limit and visited set tracking to prevent:
        - Deep recursion DoS attacks (stack overflow)
        - Circular reference infinite loops

        Args:
            data: The data structure to clean (dict, list, or primitive)
            path: Current path in the structure (for debugging)
            visited: Set of object IDs already visited (for circular reference detection)
            depth: Current recursion depth (for depth limit enforcement)

        Returns:
            Cleaned data structure
        """
        # SECURITY: Limit recursion depth to prevent stack overflow DoS attacks
        MAX_RECURSION_DEPTH = 100
        if depth > MAX_RECURSION_DEPTH:
            # Return data as-is if depth limit exceeded (fail-safe)
            return data

        # SECURITY: Track visited objects to prevent infinite loops from circular references
        if visited is None:
            visited = set()

        # For mutable objects (dict, list), track by id to detect circular references
        if isinstance(data, (dict, list)):
            data_id = id(data)
            if data_id in visited:
                # Circular reference detected - return data as-is to prevent infinite loop
                return data
            visited.add(data_id)

        try:
            if isinstance(data, dict):
                cleaned = {}
                for key, value in data.items():
                    if self._is_credential_field(key):
                        # Only mask if value is a primitive (not a container)
                        # Containers should be processed recursively to clean their contents
                        if isinstance(value, (dict, list)):
                            # Process container recursively to clean its contents
                            cleaned[key] = self._clean_dict_recursive(
                                value,
                                f"{path}.{key}" if path else key,
                                visited,
                                depth + 1,
                            )
                        elif self.mode == "mask":
                            cleaned[key] = self.MASK_VALUE
                        # else: remove mode - don't add to cleaned dict
                    else:
                        # Recursively clean nested structures
                        cleaned[key] = self._clean_dict_recursive(
                            value, f"{path}.{key}" if path else key, visited, depth + 1
                        )
                return cleaned
            elif isinstance(data, list):
                # Clean each item in the list
                return [
                    self._clean_dict_recursive(
                        item, f"{path}[{i}]" if path else f"[{i}]", visited, depth + 1
                    )
                    for i, item in enumerate(data)
                ]
            else:
                # Primitive value - return as-is
                return data
        finally:
            # Remove from visited set when done processing this object
            if isinstance(data, (dict, list)):
                visited.discard(data_id)

    def clean_credentials(
        self, data: Union[Dict, List, str, Any]
    ) -> Union[Dict, List, Any]:
        """
        Clean credentials from data structure.

        Args:
            data: Data structure to clean (dict, list, or primitive)

        Returns:
            Cleaned data structure with credentials masked or removed
        """
        if data is None:
            return None

        # Handle dictionaries (headers, payload objects)
        if isinstance(data, dict):
            return self._clean_dict_recursive(data)

        # Handle lists (arrays in JSON)
        if isinstance(data, list):
            return self._clean_dict_recursive(data)

        # For primitive types, return as-is (no cleaning needed)
        return data

    def clean_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Clean credentials from HTTP headers.

        SECURITY: Validates input type to prevent type confusion attacks.

        Args:
            headers: Dictionary of HTTP headers

        Returns:
            Dictionary with credential headers masked or removed
        """
        # SECURITY: Validate input type to prevent type confusion attacks
        if headers is None:
            return {}
        if not isinstance(headers, dict):
            return {}

        cleaned = {}
        for key, value in headers.items():
            if self._is_credential_field(key):
                if self.mode == "mask":
                    cleaned[key] = self.MASK_VALUE
                # else: remove mode - don't add to cleaned dict
            else:
                cleaned[key] = value

        return cleaned

    def clean_query_params(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Clean credentials from query parameters.

        SECURITY: Validates input type to prevent type confusion attacks.

        Args:
            query_params: Dictionary of query parameters

        Returns:
            Dictionary with credential parameters masked or removed
        """
        # SECURITY: Validate input type to prevent type confusion attacks
        if query_params is None:
            return {}
        if not isinstance(query_params, dict):
            return {}

        cleaned = {}
        for key, value in query_params.items():
            if self._is_credential_field(key):
                if self.mode == "mask":
                    cleaned[key] = self.MASK_VALUE
                # else: remove mode - don't add to cleaned dict
            else:
                cleaned[key] = value

        return cleaned
