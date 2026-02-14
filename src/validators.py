import hmac
import hashlib
import base64
import json
import time
import re
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)


class BaseValidator(ABC):
    """Base class for webhook validators."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize validator with configuration.

        Args:
            config: The webhook configuration

        Raises:
            TypeError: If config is not a dictionary
        """
        # SECURITY: Validate config type to prevent type confusion attacks
        if not isinstance(config, dict):
            raise TypeError(f"Config must be a dictionary, got {type(config).__name__}")
        self.config = config

    @abstractmethod
    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """
        Validate the webhook request.

        Args:
            headers: Request headers
            body: Raw request body

        Returns:
            Tuple of (is_valid, message)
        """
        pass


class AuthorizationValidator(BaseValidator):
    """Validates Authorization header."""

    def _validate_header_format(self, header_value: str) -> Tuple[bool, str]:
        """
        Validate header format to prevent header injection attacks.

        Args:
            header_value: The header value to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not header_value:
            return True, ""

        # Reject headers with newlines, carriage returns, or null bytes (header injection)
        dangerous_chars = ["\n", "\r", "\0"]
        for char in dangerous_chars:
            if char in header_value:
                return False, f"Invalid header format: contains forbidden character"

        # Reject headers that are too long (DoS protection)
        MAX_HEADER_LENGTH = 8192  # Standard HTTP header limit
        if len(header_value) > MAX_HEADER_LENGTH:
            return (
                False,
                f"Header too long: {len(header_value)} characters (max: {MAX_HEADER_LENGTH})",
            )

        return True, ""

    def _extract_bearer_token(self, auth_header: str) -> Tuple[bool, str, str]:
        """
        Extract Bearer token from authorization header with strict format validation.

        Args:
            auth_header: The authorization header value

        Returns:
            Tuple of (is_valid, token, error_message)
        """
        # Strip leading/trailing whitespace from entire header
        auth_header = auth_header.strip()

        # Must start with "Bearer " (case-sensitive, with exactly one space)
        if not auth_header.startswith("Bearer "):
            return False, "", "Invalid Bearer token format: must start with 'Bearer '"

        # Check that there's exactly one space after "Bearer" (not multiple spaces)
        # "Bearer " is 7 characters, so check character at index 6
        if len(auth_header) > 7 and auth_header[6] != " ":
            # This shouldn't happen if startswith worked, but double-check
            return False, "", "Invalid Bearer token format: must start with 'Bearer '"

        # Extract token part (everything after "Bearer ")
        token = auth_header[7:]  # "Bearer " is 7 characters

        # Token cannot be empty
        if not token:
            return False, "", "Invalid Bearer token format: token cannot be empty"

        # Token cannot contain only whitespace
        if not token.strip():
            return (
                False,
                "",
                "Invalid Bearer token format: token cannot be whitespace only",
            )

        # Check for multiple spaces at the start (after "Bearer ")
        # This prevents "Bearer  token" (double space) from being accepted
        if token.startswith(" "):
            return (
                False,
                "",
                "Invalid Bearer token format: token cannot start with whitespace",
            )

        # Normalize token (strip only trailing whitespace, preserve leading and internal spaces)
        # This ensures exact token matching while allowing trailing whitespace to be normalized
        token = token.rstrip()

        return True, token, ""

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate authorization header using constant-time comparison."""
        expected_auth = self.config.get("authorization", "")

        # SECURITY: Handle non-string authorization config (type confusion)
        if not isinstance(expected_auth, str):
            # Non-string config means no authorization required
            return True, "No authorization required"

        # SECURITY: Normalize and check if authorization is empty/whitespace-only
        expected_auth = expected_auth.strip()
        if not expected_auth:
            return True, "No authorization required"

        # SECURITY: Handle None header values (type confusion attack)
        authorization_header = headers.get("authorization", "")
        if authorization_header is None:
            # None header value means missing header
            return False, "Unauthorized"

        # SECURITY: Ensure header value is a string (type confusion attack)
        if not isinstance(authorization_header, str):
            return False, "Unauthorized"

        # Validate header format to prevent header injection
        is_valid_format, format_error = self._validate_header_format(
            authorization_header
        )
        if not is_valid_format:
            return False, format_error

        # Normalize header value (strip whitespace)
        authorization_header = authorization_header.strip()

        # Check if expected auth is a Bearer token
        if expected_auth.startswith("Bearer "):
            # Strictly validate Bearer token format for received header
            is_valid_format, received_token, format_error = self._extract_bearer_token(
                authorization_header
            )
            if not is_valid_format:
                return False, format_error

            # Extract expected token (everything after "Bearer ")
            # Only strip trailing whitespace to match the normalization of received token
            expected_token = expected_auth[7:].rstrip()

            # Use constant-time comparison to prevent timing attacks
            # Compare only the token parts, not the "Bearer " prefix
            if not hmac.compare_digest(
                expected_token.encode("utf-8"), received_token.encode("utf-8")
            ):
                return False, "Unauthorized"
        else:
            # For non-Bearer tokens, use constant-time comparison
            # Compare the full normalized strings
            if not hmac.compare_digest(
                expected_auth.encode("utf-8"), authorization_header.encode("utf-8")
            ):
                return False, "Unauthorized"

        return True, "Valid authorization"


class BasicAuthValidator(BaseValidator):
    """Validates HTTP Basic Authentication."""

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate HTTP Basic Authentication."""
        basic_auth_config = self.config.get("basic_auth", {})

        if not basic_auth_config:
            return True, "No basic auth required"

        auth_header = headers.get("authorization", "")

        if not auth_header:
            return False, "Missing Authorization header"

        # Validate Basic prefix format strictly
        # Must start with exactly "Basic " (case-sensitive, single space)
        if not auth_header.startswith("Basic "):
            return False, "Basic authentication required"

        # Additional check: ensure it's exactly "Basic " followed by base64 (no tabs, newlines, etc.)
        if len(auth_header) > 6:
            # Check for invalid whitespace characters after "Basic"
            if auth_header[6:7] in ["\t", "\n", "\r"]:
                return False, "Invalid Basic authentication format"
            # Check for double space
            if len(auth_header) > 7 and auth_header[6:8] == "  ":
                return False, "Invalid Basic authentication format"

        # SECURITY: Check that there's content after "Basic "
        if len(auth_header) <= 6 or (len(auth_header) == 6 and auth_header == "Basic"):
            return False, "Invalid Basic authentication format: missing credentials"

        try:
            # Extract and decode base64 credentials
            split_result = auth_header.split(" ", 1)
            if len(split_result) < 2 or not split_result[1]:
                return False, "Invalid Basic authentication format: missing credentials"
            encoded_credentials = split_result[1]

            # Strip whitespace from base64 string and validate format
            # Base64 should not contain whitespace (RFC 4648)
            encoded_credentials_stripped = encoded_credentials.strip()
            if encoded_credentials != encoded_credentials_stripped:
                return False, "Invalid base64 encoding: whitespace not allowed"

            # Validate base64 format (only alphanumeric, +, /, and = for padding)
            if not re.match(r"^[A-Za-z0-9+/]*={0,2}$", encoded_credentials_stripped):
                return False, "Invalid base64 encoding format"

            decoded_bytes = base64.b64decode(encoded_credentials_stripped)
            try:
                decoded_str = decoded_bytes.decode("utf-8")
            except UnicodeDecodeError:
                # Try other common encodings as fallback
                try:
                    decoded_str = decoded_bytes.decode("latin-1")
                except UnicodeDecodeError:
                    return (
                        False,
                        "Invalid UTF-8 encoding in Authorization header credentials",
                    )

            # Split username and password
            if ":" not in decoded_str:
                return False, "Invalid basic auth format"

            username, password = decoded_str.split(":", 1)

            # Get expected credentials
            expected_username = basic_auth_config.get("username")
            expected_password = basic_auth_config.get("password")

            # SECURITY: Validate config types to prevent type confusion attacks
            if not expected_username or not expected_password:
                return False, "Basic auth credentials not configured"

            # SECURITY: Ensure username and password are strings (prevent type confusion)
            if not isinstance(expected_username, str) or not isinstance(
                expected_password, str
            ):
                return False, "Basic auth credentials not configured"

            # Validate credentials using constant-time comparison for both username and password
            # This prevents timing attacks that could enumerate valid usernames
            # Encode to bytes for consistent comparison, especially with unicode
            username_match = hmac.compare_digest(
                username.encode("utf-8"), expected_username.encode("utf-8")
            )
            password_match = hmac.compare_digest(
                password.encode("utf-8"), expected_password.encode("utf-8")
            )

            if username_match and password_match:
                return True, "Valid basic authentication"
            else:
                return False, "Invalid credentials"

        except base64.binascii.Error:
            return False, "Invalid base64 encoding in Authorization header"
        except UnicodeDecodeError:
            return False, "Invalid UTF-8 encoding in credentials"
        except Exception as e:
            # SECURITY: Sanitize exception messages to prevent information disclosure
            # Log detailed error server-side only (if logging is available)
            # Return generic error to client
            from src.utils import sanitize_error_message

            return False, sanitize_error_message(e, "basic authentication")


class JWTValidator(BaseValidator):
    """Validates JSON Web Tokens (JWT)."""

    # Whitelist of allowed JWT algorithms (strong algorithms only)
    # Reject "none" and weak algorithms to prevent algorithm confusion attacks
    ALLOWED_ALGORITHMS = {
        "HS256",  # HMAC with SHA-256
        "HS384",  # HMAC with SHA-384
        "HS512",  # HMAC with SHA-512
        "RS256",  # RSA with SHA-256
        "RS384",  # RSA with SHA-384
        "RS512",  # RSA with SHA-512
        "ES256",  # ECDSA with SHA-256
        "ES384",  # ECDSA with SHA-384
        "ES512",  # ECDSA with SHA-512
        "PS256",  # RSASSA-PSS with SHA-256
        "PS384",  # RSASSA-PSS with SHA-384
        "PS512",  # RSASSA-PSS with SHA-512
    }

    # Explicitly blocked algorithms (security risks)
    BLOCKED_ALGORITHMS = {
        "none",  # No signature (critical security risk)
        "HS1",  # Weak HMAC
        "MD5",  # Weak hash
    }

    def _validate_algorithm(self, algorithm: str) -> str:
        """
        Validate JWT algorithm to prevent algorithm confusion attacks.

        This function:
        - Whitelists only strong, secure algorithms
        - Explicitly blocks "none" algorithm
        - Blocks weak/deprecated algorithms
        - Normalizes algorithm name (uppercase)

        Args:
            algorithm: Algorithm name from configuration

        Returns:
            Validated algorithm name (normalized)

        Raises:
            ValueError: If algorithm is invalid, blocked, or not whitelisted
        """
        if not algorithm or not isinstance(algorithm, str):
            raise ValueError("JWT algorithm must be a non-empty string")

        # Normalize to uppercase for comparison
        algorithm_normalized = algorithm.strip().upper()

        if not algorithm_normalized:
            raise ValueError("JWT algorithm cannot be empty")

        # Explicitly block dangerous algorithms FIRST (check normalized version)
        # Convert blocked algorithms to uppercase for comparison
        blocked_normalized = {alg.upper() for alg in self.BLOCKED_ALGORITHMS}
        if algorithm_normalized in blocked_normalized:
            raise ValueError(
                f"JWT algorithm '{algorithm}' is explicitly blocked for security reasons. "
                f"The 'none' algorithm and weak algorithms are not allowed."
            )

        # Check if algorithm is in whitelist
        if algorithm_normalized not in self.ALLOWED_ALGORITHMS:
            raise ValueError(
                f"JWT algorithm '{algorithm}' is not in the allowed algorithms whitelist. "
                f"Allowed algorithms: {', '.join(sorted(self.ALLOWED_ALGORITHMS))}"
            )

        return algorithm_normalized

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate JWT token."""
        jwt_config = self.config.get("jwt", {})

        if not jwt_config:
            return True, "No JWT validation required"

        # Import here to avoid import errors if PyJWT is not installed
        try:
            import jwt
        except ImportError:
            return False, "PyJWT library not installed"

        # Validate secret is present and not empty
        secret = jwt_config.get("secret")
        if not secret or (isinstance(secret, str) and not secret.strip()):
            return False, "JWT secret is required and cannot be empty"

        auth_header = headers.get("authorization", "")

        if not auth_header:
            return False, "Missing Authorization header"

        if not auth_header.startswith("Bearer "):
            return False, "JWT Bearer token required"

        try:
            token = auth_header.split(" ", 1)[1]

            # Get algorithm from config and validate it
            raw_algorithm = jwt_config.get("algorithm", "HS256")
            try:
                validated_algorithm = self._validate_algorithm(raw_algorithm)
            except ValueError as e:
                # Algorithm validation failed - this is a configuration error
                return False, f"JWT algorithm validation failed: {str(e)}"

            # Prepare validation options
            options = {
                "verify_exp": jwt_config.get("verify_exp", True),
                "verify_aud": bool(jwt_config.get("audience")),
                "verify_iss": bool(jwt_config.get("issuer")),
            }

            # Decode and validate with validated algorithm
            # Use list with single algorithm to prevent algorithm confusion
            # Secret was already validated above (not empty)
            jwt.decode(
                token,
                key=secret,  # Use validated secret
                algorithms=[validated_algorithm],  # Use validated algorithm only
                issuer=jwt_config.get("issuer"),
                audience=jwt_config.get("audience"),
                options=options,
            )

            return True, "Valid JWT"

        except jwt.ExpiredSignatureError:
            return False, "JWT token expired"
        except jwt.InvalidIssuerError:
            return False, "Invalid JWT issuer"
        except jwt.InvalidAudienceError:
            return False, "Invalid JWT audience"
        except jwt.InvalidAlgorithmError:
            return False, "Invalid JWT algorithm"
        except jwt.InvalidSignatureError:
            return False, "Invalid JWT signature"
        except jwt.MissingRequiredClaimError as e:
            return False, f"JWT missing required claim: {str(e)}"
        except jwt.DecodeError:
            return False, "Invalid JWT token format"
        except Exception:
            # SECURITY: Don't leak exception details that may reveal token structure
            return False, "JWT validation failed"


class HMACValidator(BaseValidator):
    """Validates HMAC signature."""

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate HMAC signature."""
        hmac_config = self.config.get("hmac", {})

        if not hmac_config:
            return True, "No HMAC validation required"

        secret = hmac_config.get("secret")
        header_name = hmac_config.get("header", "X-HMAC-Signature")
        algorithm = hmac_config.get("algorithm", "sha256")

        if not secret:
            return False, "HMAC secret not configured"

        # Normalize algorithm to lowercase for case-insensitive comparison
        algorithm = algorithm.lower()

        # Validate algorithm before processing signature
        if algorithm == "sha256":
            hash_func = hashlib.sha256
        elif algorithm == "sha1":
            hash_func = hashlib.sha1
        elif algorithm == "sha512":
            hash_func = hashlib.sha512
        else:
            return False, f"Unsupported HMAC algorithm: {algorithm}"

        received_signature = headers.get(header_name.lower(), "")

        if not received_signature:
            return False, f"Missing {header_name} header"

        # Validate signature format: must be hex characters only
        # This prevents Unicode injection and ensures hmac.compare_digest works correctly
        if not re.match(r"^[0-9a-fA-F]+$", received_signature.split("=", 1)[-1]):
            return False, "Invalid HMAC signature format (must be hexadecimal)"

        hmac_obj = hmac.new(secret.encode(), body, hash_func)
        computed_signature = hmac_obj.hexdigest()

        # Support both hex and sha256= prefix formats
        # Extract signature after = if prefix exists
        if received_signature.startswith(f"{algorithm}="):
            received_signature = received_signature.split("=", 1)[1]

        # Validate extracted signature is still hex
        if not re.match(r"^[0-9a-fA-F]+$", received_signature):
            return False, "Invalid HMAC signature format (must be hexadecimal)"

        # Normalize case for comparison (signatures may be submitted in uppercase)
        if not hmac.compare_digest(computed_signature.lower(), received_signature.lower()):
            return False, "Invalid HMAC signature"

        return True, "Valid HMAC signature"


class IPWhitelistValidator(BaseValidator):
    """Validates IP address against whitelist."""

    def __init__(self, config: Dict[str, Any], request=None):
        """
        Initialize IP whitelist validator.

        Args:
            config: The webhook configuration
            request: Optional FastAPI Request object for getting actual client IP
        """
        super().__init__(config)
        self.request = request

    def _get_client_ip(self, headers: Dict[str, str]) -> Tuple[str, bool]:
        """
        Get client IP address with security considerations.

        Security: Only trust X-Forwarded-For from trusted proxies to prevent IP spoofing.
        Uses request.client.host as primary source, only falls back to headers if:
        1. Request object is available
        2. Proxy IP is in trusted_proxies list (if configured)

        Args:
            headers: Request headers

        Returns:
            Tuple of (client_ip, is_from_trusted_proxy)
        """
        # Get trusted proxy IPs from config (if behind a reverse proxy)
        trusted_proxies = self.config.get("trusted_proxies", [])

        # If we have the Request object, use it as primary source (most secure)
        if self.request and hasattr(self.request, "client") and self.request.client:
            # Safely get client.host (may not exist or be empty)
            try:
                actual_client_ip = getattr(self.request.client, "host", None)
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

        # SECURITY: If no Request object or no valid client IP, we cannot trust headers
        # This prevents IP spoofing attacks via X-Forwarded-For when Request object is unavailable
        # In production, Request object should always be available
        # For backward compatibility, we return empty string which will cause validation to fail
        # This is more secure than trusting potentially spoofed headers
        return "", False

    def _normalize_ip(self, ip_str: str) -> str:
        """
        Normalize IP address for consistent comparison.

        This function:
        - Normalizes IPv6 addresses (compressed vs full form, case)
        - Normalizes IPv4 addresses (removes leading zeros)
        - Ensures consistent format for whitelist comparison

        Args:
            ip_str: IP address string to normalize

        Returns:
            Normalized IP address string

        Raises:
            ValueError: If IP address is invalid
        """
        import ipaddress

        try:
            # Parse and normalize IP address
            ip_obj = ipaddress.ip_address(ip_str.strip())
            # Return string representation (normalized)
            return str(ip_obj)
        except ValueError:
            raise ValueError(f"Invalid IP address format: {ip_str}")

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate IP address against whitelist."""
        ip_whitelist = self.config.get("ip_whitelist", [])

        if not ip_whitelist:
            return True, "No IP whitelist configured"

        # Get client IP with security validation
        client_ip, is_from_trusted_proxy = self._get_client_ip(headers)

        if not client_ip:
            return False, "Could not determine client IP"

        # Normalize client IP for consistent comparison
        try:
            normalized_client_ip = self._normalize_ip(client_ip)
        except ValueError as e:
            return False, str(e)

        # Normalize all whitelist IPs for consistent comparison
        normalized_whitelist = []
        for whitelist_ip in ip_whitelist:
            if not whitelist_ip or not isinstance(whitelist_ip, str):
                continue
            try:
                normalized_whitelist.append(self._normalize_ip(whitelist_ip))
            except ValueError:
                # Invalid IP in whitelist - skip it
                continue

        if not normalized_whitelist:
            return False, "IP whitelist contains no valid IP addresses"

        # Check if normalized client IP is in normalized whitelist
        if normalized_client_ip not in normalized_whitelist:
            # Log IP spoofing attempt if using untrusted headers
            if not is_from_trusted_proxy and (
                headers.get("x-forwarded-for") or headers.get("x-real-ip")
            ):
                logger.warning(
                    f"SECURITY: IP whitelist check failed for {normalized_client_ip} (may be spoofed via X-Forwarded-For)"
                )
            return False, f"IP {normalized_client_ip} not in whitelist"

        return True, "Valid IP address"


class RateLimitValidator(BaseValidator):
    """Validates request against rate limits."""

    def __init__(self, config: Dict[str, Any], webhook_id: str):
        """
        Initialize rate limit validator.

        Args:
            config: The webhook configuration
            webhook_id: The webhook identifier for tracking
        """
        super().__init__(config)
        self.webhook_id = webhook_id

        # Import here to avoid circular dependency
        from src.rate_limiter import rate_limiter

        self.rate_limiter = rate_limiter

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate request against rate limit."""
        rate_limit_config = self.config.get("rate_limit", {})

        if not rate_limit_config:
            return True, "No rate limit configured"

        max_requests = rate_limit_config.get("max_requests", 100)
        window_seconds = rate_limit_config.get("window_seconds", 60)

        is_allowed, message = await self.rate_limiter.is_allowed(
            self.webhook_id, max_requests, window_seconds
        )

        return is_allowed, message


class JsonSchemaValidator(BaseValidator):
    """Validates request body against a JSON schema."""

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate request body against JSON schema."""
        schema = self.config.get("json_schema", {})

        if not schema:
            return True, "No JSON schema configured"

        # Import here to avoid import errors if jsonschema is not installed
        try:
            import jsonschema
            from jsonschema import validate
        except ImportError:
            return False, "jsonschema library not installed"

        try:
            # Parse body as JSON
            payload = json.loads(body)
        except json.JSONDecodeError:
            return False, "Invalid JSON body"
        except Exception as e:
            # SECURITY: Catch any other exceptions during JSON parsing and sanitize
            from src.utils import sanitize_error_message

            return False, sanitize_error_message(e, "JSON parsing")

        try:
            # SECURITY: Disable remote reference resolution to prevent SSRF attacks
            # Use a registry that blocks remote references
            try:
                from referencing import Registry

                # Create an empty registry that blocks all remote references (prevents SSRF)
                registry = Registry()

                # Validate with registry that blocks remote references
                validate(instance=payload, schema=schema, registry=registry)
            except (ImportError, TypeError):
                # Fallback: If registry parameter not supported, use standard validate
                # Note: This may allow remote references in older jsonschema versions
                # But schema comes from config (not user input), so risk is lower
                validate(instance=payload, schema=schema)

            return True, "Valid JSON schema"
        except jsonschema.exceptions.ValidationError as e:
            # SECURITY: Sanitize validation error messages
            # e.message may contain field names, but shouldn't expose full schema structure
            return False, "JSON schema validation failed"
        except jsonschema.exceptions.SchemaError as e:
            # SECURITY: Sanitize schema error messages
            return False, "Invalid JSON schema configuration"
        except Exception as e:
            # SECURITY: Sanitize generic exception messages to prevent information disclosure
            from src.utils import sanitize_error_message

            return False, sanitize_error_message(e, "JSON schema validation")


class QueryParameterAuthValidator(BaseValidator):
    """Validates API key authentication via query parameters."""

    # Maximum length for parameter names and values to prevent DoS
    MAX_PARAM_NAME_LENGTH = 100
    MAX_PARAM_VALUE_LENGTH = 1000

    @staticmethod
    def _validate_parameter_name(name: str) -> Tuple[bool, str]:
        """
        Validate query parameter name format and length.

        Args:
            name: Parameter name to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not name or not isinstance(name, str):
            return False, "Parameter name must be a non-empty string"

        # Check length
        if len(name) > QueryParameterAuthValidator.MAX_PARAM_NAME_LENGTH:
            return (
                False,
                f"Parameter name too long: {len(name)} characters (max: {QueryParameterAuthValidator.MAX_PARAM_NAME_LENGTH})",
            )

        # Check for null bytes and control characters
        if "\x00" in name:
            return False, "Parameter name cannot contain null bytes"

        # Check for dangerous control characters (newline, carriage return, tab)
        dangerous_chars = ["\n", "\r", "\t"]
        for char in dangerous_chars:
            if char in name:
                return (
                    False,
                    f"Parameter name cannot contain control character: {repr(char)}",
                )

        # Validate format: alphanumeric, underscore, hyphen, dot only
        # This prevents injection via special characters
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", name):
            return (
                False,
                "Parameter name contains invalid characters. Only alphanumeric, underscore, hyphen, and dot are allowed",
            )

        return True, ""

    @staticmethod
    def _sanitize_parameter_value(value: str) -> Tuple[str, bool]:
        """
        Sanitize query parameter value by removing control characters and limiting length.

        Args:
            value: Parameter value to sanitize

        Returns:
            Tuple of (sanitized_value, is_valid)
        """
        if not isinstance(value, str):
            return "", False

        # Check length
        if len(value) > QueryParameterAuthValidator.MAX_PARAM_VALUE_LENGTH:
            return "", False

        # Remove only dangerous control characters, preserve valid unicode
        # Block: null bytes, newlines, carriage returns, tabs, and C0/C1 control chars
        # Allow: all printable unicode including non-ASCII characters
        dangerous_control_chars = set(chr(i) for i in range(32) if i not in (32,))  # C0 controls except space
        dangerous_control_chars.update(chr(i) for i in range(127, 160))  # DEL and C1 controls

        sanitized = "".join(char for char in value if char not in dangerous_control_chars)

        return sanitized, True

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate API key from query parameters."""
        query_auth_config = self.config.get("query_auth", {})

        if not query_auth_config:
            return True, "No query parameter auth required"

        parameter_name = query_auth_config.get("parameter_name", "api_key")
        expected_key = query_auth_config.get("api_key")
        case_sensitive = query_auth_config.get("case_sensitive", False)

        if not expected_key:
            return False, "Query auth API key not configured"

        # Note: Query parameters need to be passed from the request
        # Since we only have headers and body here, we need to get query params
        # from the request object. This will be handled in webhook.py

        return True, "Query parameter auth validation (requires request object)"

    @staticmethod
    def validate_query_params(
        query_params: Dict[str, str], config: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Validate query parameters (static method to be called with request query params).

        Args:
            query_params: Dictionary of query parameters from request
            config: Webhook configuration

        Returns:
            Tuple of (is_valid, message)
        """
        query_auth_config = config.get("query_auth")

        # If query_auth is not in config at all, no auth required
        if query_auth_config is None:
            return True, "No query parameter auth required"

        # If query_auth exists but is empty dict or api_key is not set, it's a configuration error
        if not query_auth_config or "api_key" not in query_auth_config:
            return False, "Query auth API key not configured"

        parameter_name = query_auth_config.get("parameter_name", "api_key")
        expected_key = query_auth_config.get("api_key")
        case_sensitive = query_auth_config.get("case_sensitive", False)

        # SECURITY: Validate api_key type to prevent type confusion attacks
        if not isinstance(expected_key, str):
            return False, "Query auth API key must be a string"

        # Check if api_key is configured (empty string is not valid)
        if expected_key == "":
            return False, "Query auth API key not configured"

        # Validate parameter name from config (prevent injection via config)
        is_valid_name, name_error = (
            QueryParameterAuthValidator._validate_parameter_name(parameter_name)
        )
        if not is_valid_name:
            return False, f"Invalid parameter name configuration: {name_error}"

        # Get the API key from query parameters
        received_key = query_params.get(parameter_name)

        # SECURITY: Check if parameter is missing (None) or invalid type
        if received_key is None:
            return False, f"Missing required query parameter: {parameter_name}"

        # SECURITY: Validate and sanitize received parameter value
        # Check type first (before sanitization) to provide clear error message
        if not isinstance(received_key, str):
            return False, f"Invalid query parameter value type for: {parameter_name}"

        # Sanitize parameter value (remove control characters, limit length)
        sanitized_key, is_valid_value = (
            QueryParameterAuthValidator._sanitize_parameter_value(received_key)
        )
        if not is_valid_value:
            return (
                False,
                f"Invalid query parameter value for: {parameter_name} (too long or contains invalid characters)",
            )

        # Check if sanitized value is empty
        if not sanitized_key or sanitized_key.strip() == "":
            return False, f"Invalid API key in query parameter: {parameter_name}"

        # Validate key with constant-time comparison (use sanitized value)
        if case_sensitive:
            is_valid = hmac.compare_digest(
                sanitized_key.encode("utf-8"), expected_key.encode("utf-8")
            )
        else:
            is_valid = hmac.compare_digest(
                sanitized_key.lower().encode("utf-8"),
                expected_key.lower().encode("utf-8"),
            )

        if not is_valid:
            return False, f"Invalid API key in query parameter: {parameter_name}"

        return True, "Valid query parameter authentication"


class HeaderAuthValidator(BaseValidator):
    """Validates API key authentication via custom headers."""

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate API key from custom header."""
        header_auth_config = self.config.get("header_auth")

        # If header_auth is not in config at all, no auth required
        if header_auth_config is None:
            return True, "No header auth required"

        # If header_auth exists but is empty dict or api_key is not set, it's a configuration error
        if not header_auth_config or "api_key" not in header_auth_config:
            return False, "Header auth API key not configured"

        header_name = header_auth_config.get("header_name", "X-API-Key")
        expected_key = header_auth_config.get("api_key")
        case_sensitive = header_auth_config.get("case_sensitive", False)

        # SECURITY: Validate header_name type to prevent type confusion attacks
        if not isinstance(header_name, str):
            return False, "Header auth header_name must be a string"

        # SECURITY: Validate api_key type to prevent type confusion attacks
        if not isinstance(expected_key, str):
            return False, "Header auth API key must be a string"

        # Check if api_key is configured (empty string is not valid)
        if expected_key == "" or not expected_key.strip():
            return False, "Header auth API key not configured"

        # Get the API key from headers (case-insensitive header lookup)
        header_name_lower = header_name.lower()
        received_key = None
        header_found = False

        # Try exact match first
        if header_name in headers:
            received_key = headers[header_name]
            header_found = True
        # Try case-insensitive lookup
        elif header_name_lower in headers:
            received_key = headers[header_name_lower]
            header_found = True
        else:
            # Check all headers case-insensitively
            for key, value in headers.items():
                if key.lower() == header_name_lower:
                    received_key = value
                    header_found = True
                    break

        if not header_found:
            return False, f"Missing required header: {header_name}"

        # SECURITY: Validate received_key type to prevent type confusion attacks
        if not isinstance(received_key, str):
            return False, f"Invalid API key type in header: {header_name}"

        # Check if header value is empty (header exists but value is empty)
        if received_key == "" or not received_key.strip():
            return False, f"Invalid API key in header: {header_name}"

        # Validate key with constant-time comparison
        if case_sensitive:
            is_valid = hmac.compare_digest(
                received_key.encode("utf-8"), expected_key.encode("utf-8")
            )
        else:
            is_valid = hmac.compare_digest(
                received_key.lower().encode("utf-8"),
                expected_key.lower().encode("utf-8"),
            )

        if not is_valid:
            return False, f"Invalid API key in header: {header_name}"

        return True, "Valid header authentication"


class OAuth2Validator(BaseValidator):
    """Validates OAuth 2.0 access tokens."""

    def _validate_introspection_endpoint(self, url: str) -> str:
        """
        Validate introspection endpoint URL to prevent SSRF attacks.

        This function:
        - Only allows http:// and https:// schemes
        - Blocks private IP ranges (RFC 1918, localhost, link-local)
        - Blocks file://, gopher://, and other dangerous schemes
        - Blocks cloud metadata endpoints
        - Validates URL format

        Args:
            url: URL to validate

        Returns:
            Validated URL string

        Raises:
            ValueError: If URL is invalid or poses SSRF risk
        """
        if not url or not isinstance(url, str):
            raise ValueError("Introspection endpoint URL must be a non-empty string")

        url = url.strip()
        if not url:
            raise ValueError("Introspection endpoint URL cannot be empty")

        # Parse URL
        from urllib.parse import urlparse
        import ipaddress

        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid introspection endpoint URL format: {str(e)}")

        # Only allow http and https schemes
        allowed_schemes = {"http", "https"}
        if parsed.scheme.lower() not in allowed_schemes:
            raise ValueError(
                f"Introspection endpoint URL scheme '{parsed.scheme}' is not allowed. "
                f"Only http:// and https:// are permitted."
            )

        # Block URLs without hostname
        if not parsed.netloc:
            raise ValueError("Introspection endpoint URL must include a hostname")

        # Extract hostname
        netloc = parsed.netloc
        if netloc.startswith("["):
            # IPv6 address
            end_bracket = netloc.find("]")
            if end_bracket != -1:
                hostname = netloc[1:end_bracket]
            else:
                raise ValueError(
                    "Invalid IPv6 address format in introspection endpoint URL"
                )
        else:
            hostname = netloc.split(":")[0]

        # Block localhost and variations
        # SECURITY: This set is used for validation to BLOCK localhost access, not for binding
        localhost_variants = {
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "[::1]",
            "127.1",
            "127.0.1",
            "127.000.000.001",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "2130706433",
            "0x7f000001",
        }  # nosec B104
        if hostname.lower() in localhost_variants:
            raise ValueError(
                f"Access to localhost in introspection endpoint is not allowed for security reasons (SSRF prevention)"
            )

        # Block private IP ranges
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback or ip.is_private or ip.is_link_local:
                raise ValueError(
                    f"Access to private/loopback IP '{hostname}' in introspection endpoint is not allowed for security reasons (SSRF prevention)"
                )
        except ValueError:
            # Not an IP address, continue with hostname checks
            pass

        # Block cloud metadata endpoints
        dangerous_hostnames = {
            "metadata.google.internal",
            "169.254.169.254",
            "metadata",
            "instance-data",
            "instance-data.ecs",
            "ecs-metadata",
            "100.100.100.200",
        }
        if hostname.lower() in dangerous_hostnames:
            raise ValueError(
                f"Access to metadata service '{hostname}' in introspection endpoint is not allowed for security reasons (SSRF prevention)"
            )

        return url

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate OAuth 2.0 access token."""
        oauth2_config = self.config.get("oauth2", {})

        if not oauth2_config:
            return True, "No OAuth 2.0 validation required"

        token_type = oauth2_config.get("token_type", "Bearer")
        introspection_endpoint = oauth2_config.get("introspection_endpoint")
        client_id = oauth2_config.get("client_id")
        client_secret = oauth2_config.get("client_secret")
        required_scope = oauth2_config.get("required_scope", [])
        validate_token = oauth2_config.get("validate_token", True)

        # Validate introspection endpoint URL to prevent SSRF
        if introspection_endpoint:
            try:
                introspection_endpoint = self._validate_introspection_endpoint(
                    introspection_endpoint
                )
            except ValueError as e:
                return False, f"Invalid OAuth 2.0 introspection endpoint: {str(e)}"

        # Get token from Authorization header
        auth_header = headers.get("authorization", "")

        if not auth_header:
            return False, "Missing Authorization header"

        # Validate header format to prevent header injection
        if "\n" in auth_header or "\r" in auth_header:
            return False, "Invalid Authorization header format (newlines not allowed)"

        # Extract token (support Bearer format)
        if not auth_header.startswith(f"{token_type} "):
            return False, f"OAuth 2.0 {token_type} token required"

        token = auth_header.split(" ", 1)[1].strip()

        if not token:
            return False, "Empty OAuth 2.0 token"

        # If token introspection is configured, validate via endpoint
        if introspection_endpoint and validate_token:
            try:
                import httpx

                # Prepare introspection request
                data = {"token": token, "token_type_hint": "access_token"}

                # Add client credentials if provided
                auth = None
                if client_id and client_secret:
                    auth = (client_id, client_secret)

                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        introspection_endpoint, data=data, auth=auth, timeout=5.0
                    )
                    response.raise_for_status()
                    introspection_result = response.json()

                # Check if token is active
                if not introspection_result.get("active", False):
                    return False, "OAuth 2.0 token is not active"

                # Validate scope if required
                if required_scope:
                    token_scope = introspection_result.get("scope", "")
                    if isinstance(token_scope, str):
                        token_scopes = token_scope.split()
                    else:
                        token_scopes = token_scope

                    # Check if all required scopes are present
                    missing_scopes = set(required_scope) - set(token_scopes)
                    if missing_scopes:
                        # SECURITY: Don't list specific missing scopes to prevent enumeration
                        return (
                            False,
                            "OAuth 2.0 token missing required scopes",
                        )

                return True, "Valid OAuth 2.0 token"

            except httpx.HTTPStatusError as e:
                return (
                    False,
                    f"OAuth 2.0 token introspection failed: HTTP {e.response.status_code}",
                )
            except httpx.RequestError as e:
                return False, f"OAuth 2.0 token introspection network error: {str(e)}"
            except Exception as e:
                return False, f"OAuth 2.0 token introspection error: {str(e)}"

        # If JWT token validation is enabled, try to validate as JWT
        jwt_secret = oauth2_config.get("jwt_secret")
        if jwt_secret and not introspection_endpoint:
            # Validate JWT secret is not empty
            if not jwt_secret or (
                isinstance(jwt_secret, str) and not jwt_secret.strip()
            ):
                return False, "OAuth 2.0 JWT secret is required and cannot be empty"

            # Validate and normalize JWT algorithms
            jwt_algorithms = oauth2_config.get("jwt_algorithms", ["HS256", "RS256"])
            if not isinstance(jwt_algorithms, list) or len(jwt_algorithms) == 0:
                return False, "OAuth 2.0 JWT algorithms must be a non-empty list"

            # Whitelist of allowed algorithms (strong algorithms only)
            allowed_algorithms = {
                "HS256",
                "HS384",
                "HS512",
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512",
                "PS256",
                "PS384",
                "PS512",
            }

            # Blocked algorithms
            blocked_algorithms = {"none"}

            # Validate each algorithm
            validated_algorithms = []
            for alg in jwt_algorithms:
                if not isinstance(alg, str):
                    return (
                        False,
                        f"OAuth 2.0 JWT algorithm must be a string, got {type(alg)}",
                    )

                alg_normalized = alg.strip().upper()
                if not alg_normalized:
                    return False, "OAuth 2.0 JWT algorithm cannot be empty"

                if alg_normalized in blocked_algorithms:
                    return (
                        False,
                        f"OAuth 2.0 JWT algorithm '{alg}' is explicitly blocked for security reasons",
                    )

                if alg_normalized not in allowed_algorithms:
                    return (
                        False,
                        f"OAuth 2.0 JWT algorithm '{alg}' is not in the allowed algorithms whitelist",
                    )

                validated_algorithms.append(alg_normalized)

            try:
                import jwt

                # Decode and validate JWT token
                decode_options = {
                    "verify_signature": True,
                    "verify_exp": oauth2_config.get("verify_exp", True),
                }

                # Prepare audience and issuer for validation
                audience = oauth2_config.get("audience")
                issuer = oauth2_config.get("issuer")

                if audience:
                    decode_options["verify_aud"] = True
                if issuer:
                    decode_options["verify_iss"] = True

                decoded = jwt.decode(
                    token,
                    key=jwt_secret,
                    algorithms=validated_algorithms,  # Use validated algorithms only
                    audience=audience,
                    issuer=issuer,
                    options=decode_options,
                )

                # Validate scope if required
                if required_scope:
                    token_scope = decoded.get("scope", "")
                    if isinstance(token_scope, str):
                        token_scopes = token_scope.split()
                    else:
                        token_scopes = token_scope

                    missing_scopes = set(required_scope) - set(token_scopes)
                    if missing_scopes:
                        # SECURITY: Don't list specific missing scopes to prevent enumeration
                        return (
                            False,
                            "OAuth 2.0 token missing required scopes",
                        )

                return True, "Valid OAuth 2.0 JWT token"

            except jwt.ExpiredSignatureError:
                return False, "OAuth 2.0 token expired"
            except jwt.InvalidAudienceError:
                return False, "OAuth 2.0 token audience mismatch"
            except jwt.InvalidIssuerError:
                return False, "OAuth 2.0 token issuer mismatch"
            except jwt.InvalidTokenError as e:
                return False, f"Invalid OAuth 2.0 JWT token: {str(e)}"
            except ImportError:
                return False, "PyJWT library not installed for JWT token validation"
            except Exception as e:
                return False, f"OAuth 2.0 JWT validation error: {str(e)}"

        # If no validation method is configured, just check token presence
        if not validate_token:
            return True, "OAuth 2.0 token present (validation disabled)"

        return (
            False,
            "OAuth 2.0 validation not properly configured (missing introspection_endpoint or jwt_secret)",
        )


class DigestAuthValidator(BaseValidator):
    """Validates HTTP Digest Authentication (RFC 7616)."""

    def __init__(self, config: Dict[str, Any], request=None):
        """
        Initialize Digest Auth validator.

        Args:
            config: The webhook configuration
            request: Optional FastAPI Request object for getting HTTP method
        """
        super().__init__(config)
        self.request = request

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate HTTP Digest Authentication."""
        digest_auth_config = self.config.get("digest_auth")

        # If digest_auth is not in config at all, skip validation
        if digest_auth_config is None:
            return True, "No digest auth required"

        # If digest_auth exists but is empty dict or missing credentials, fail
        username = digest_auth_config.get("username") if digest_auth_config else None
        password = digest_auth_config.get("password") if digest_auth_config else None
        realm = (
            digest_auth_config.get("realm", "Webhook API")
            if digest_auth_config
            else "Webhook API"
        )
        algorithm = (
            digest_auth_config.get("algorithm", "MD5") if digest_auth_config else "MD5"
        )
        qop = digest_auth_config.get("qop", "auth") if digest_auth_config else "auth"

        # Check if credentials are configured (empty string is not valid)
        # SECURITY: This checks if password is empty (validation), not a hardcoded password
        empty_string = ""  # nosec B105
        if (
            username is None
            or password is None
            or username == empty_string
            or password == empty_string
        ):
            return False, "Digest auth credentials not configured"

        # Get Authorization header
        auth_header = headers.get("authorization", "")

        if not auth_header:
            return False, "Missing Authorization header"

        if not auth_header.startswith("Digest "):
            return False, "Digest authentication required"

        try:
            # Parse Digest header
            digest_params = self._parse_digest_header(auth_header)

            # Validate required parameters
            required_params = ["username", "realm", "nonce", "uri", "response"]
            for param in required_params:
                if param not in digest_params:
                    return False, f"Missing required Digest parameter: {param}"

            # Validate username
            if digest_params["username"] != username:
                return False, "Invalid digest auth username"

            # Validate realm
            if digest_params.get("realm") != realm:
                return False, "Invalid digest auth realm"

            # Compute expected response
            # NOTE: MD5 is required by HTTP Digest Authentication (RFC 7616) specification.
            # While MD5 is cryptographically weak, it's part of the standard protocol.
            # Modern applications should prefer stronger auth methods (e.g., Bearer tokens, OAuth2).
            # HA1 = MD5(username:realm:password)
            ha1 = hashlib.md5(
                f"{username}:{realm}:{password}".encode()
            ).hexdigest()  # nosec B324

            # HA2 = MD5(method:uri) for qop="auth"
            # Get HTTP method from request, default to POST for webhooks
            method = "POST"
            if self.request and hasattr(self.request, "method"):
                method = self.request.method.upper()
            uri = digest_params.get("uri", "/")
            ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()  # nosec B324

            # Response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
            nonce = digest_params.get("nonce", "")
            nc = digest_params.get("nc", "00000001")
            cnonce = digest_params.get("cnonce", "")

            if qop == "auth" and cnonce:
                response_str = f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"
            else:
                # No qop
                response_str = f"{ha1}:{nonce}:{ha2}"

            expected_response = hashlib.md5(
                response_str.encode()
            ).hexdigest()  # nosec B324

            # Compare responses (constant-time)
            received_response = digest_params.get("response", "")
            if not hmac.compare_digest(
                received_response.lower(), expected_response.lower()
            ):
                return False, "Invalid digest auth response"

            # Validate algorithm if specified
            if "algorithm" in digest_params:
                if digest_params["algorithm"].upper() != algorithm.upper():
                    return (
                        False,
                        f"Invalid digest auth algorithm: {digest_params['algorithm']}",
                    )

            return True, "Valid digest authentication"

        except Exception as e:
            # SECURITY: Sanitize exception messages to prevent information disclosure
            from src.utils import sanitize_error_message

            return False, sanitize_error_message(e, "Digest auth validation")

    @staticmethod
    def _parse_digest_header(auth_header: str) -> Dict[str, str]:
        """Parse Digest Authorization header into parameters."""
        # Remove "Digest " prefix
        digest_str = auth_header[7:].strip()

        params = {}
        # Parse key="value" pairs
        pattern = r'(\w+)=["\']?([^,"\']+)["\']?'
        matches = re.findall(pattern, digest_str)

        for key, value in matches:
            params[key.lower()] = value.strip("\"'")

        return params


class OAuth1NonceTracker:
    """Tracks OAuth 1.0 nonces to prevent replay attacks."""

    # Maximum number of nonces to store to prevent unbounded memory growth
    MAX_NONCES = 100_000

    def __init__(self, max_age_seconds: int = 600):
        """
        Initialize nonce tracker.

        Args:
            max_age_seconds: Maximum age of nonces to keep (default: 600 = 10 minutes)
        """
        self.nonces: Dict[str, float] = {}  # nonce -> expiration_time
        self._lock: Optional[asyncio.Lock] = (
            None  # Lazy initialization to avoid event loop requirement
        )
        self.max_age_seconds = max_age_seconds
        self._last_cleanup = time.time()
        self._cleanup_interval = 60  # Cleanup every 60 seconds

    def _get_lock(self) -> asyncio.Lock:
        """Get or create the async lock (lazy initialization)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    @property
    def lock(self) -> asyncio.Lock:
        """Property to access lock (for backward compatibility)."""
        return self._get_lock()

    async def check_and_store_nonce(
        self, nonce: str, timestamp: int, timestamp_window: int
    ) -> Tuple[bool, str]:
        """
        Check if nonce has been used before and store it if valid.

        Args:
            nonce: The nonce to check
            timestamp: The OAuth timestamp
            timestamp_window: The timestamp window in seconds

        Returns:
            Tuple of (is_valid, error_message)
        """
        async with self.lock:
            # Periodic cleanup of expired nonces
            current_time = time.time()
            if current_time - self._last_cleanup > self._cleanup_interval:
                self._cleanup_expired_nonces(current_time)
                self._last_cleanup = current_time

            # Check if nonce already exists
            if nonce in self.nonces:
                expiration = self.nonces[nonce]
                if current_time < expiration:
                    return (
                        False,
                        "OAuth 1.0 nonce has already been used (replay attack detected)",
                    )
                else:
                    # Expired nonce, remove it
                    del self.nonces[nonce]

            # SECURITY: Enforce maximum nonce storage to prevent memory exhaustion
            if len(self.nonces) >= self.MAX_NONCES:
                # Force cleanup before rejecting
                self._cleanup_expired_nonces(current_time)
                if len(self.nonces) >= self.MAX_NONCES:
                    logger.warning(
                        "OAuth1 nonce tracker full (%d nonces), rejecting request",
                        len(self.nonces),
                    )
                    return False, "Server nonce storage full, please retry later"

            # Calculate expiration time: timestamp + window + buffer
            # Use timestamp from request, not current time, to prevent clock skew issues
            expiration_time = (
                timestamp + timestamp_window + 60
            )  # Add 60s buffer for clock skew

            # Store nonce with expiration
            self.nonces[nonce] = expiration_time

            return True, "Nonce is valid"

    def _cleanup_expired_nonces(self, current_time: float):
        """Remove expired nonces from memory."""
        expired_nonces = [
            nonce
            for nonce, expiration in self.nonces.items()
            if current_time >= expiration
        ]
        for nonce in expired_nonces:
            del self.nonces[nonce]

    async def get_stats(self) -> Dict[str, Any]:
        """Get statistics about nonce tracker."""
        async with self.lock:
            return {
                "total_nonces": len(self.nonces),
                "max_age_seconds": self.max_age_seconds,
            }

    async def clear(self):
        """Clear all nonces (useful for testing)."""
        async with self.lock:
            self.nonces.clear()
            self._last_cleanup = time.time()


# Global nonce tracker instance
_oauth1_nonce_tracker = OAuth1NonceTracker()


class OAuth1Validator(BaseValidator):
    """Validates OAuth 1.0 signatures (RFC 5849)."""

    def __init__(self, config: Dict[str, Any], request=None):
        """
        Initialize OAuth 1.0 validator.

        Args:
            config: The webhook configuration
            request: Optional FastAPI Request object for getting HTTP method and URI
        """
        super().__init__(config)
        self.request = request

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate OAuth 1.0 signature."""
        oauth1_config = self.config.get("oauth1")

        # If oauth1 is not in config at all, skip validation
        if oauth1_config is None:
            return True, "No OAuth 1.0 validation required"

        consumer_key = oauth1_config.get("consumer_key")
        consumer_secret = oauth1_config.get("consumer_secret")
        token_secret_config = oauth1_config.get(
            "token_secret", ""
        )  # Token secret from config (if provided)
        signature_method = oauth1_config.get("signature_method", "HMAC-SHA1")
        verify_timestamp = oauth1_config.get("verify_timestamp", True)
        timestamp_window = oauth1_config.get("timestamp_window", 300)

        if not consumer_key or not consumer_secret:
            return False, "OAuth 1.0 consumer credentials not configured"

        # Get Authorization header
        auth_header = headers.get("authorization", "")

        if not auth_header:
            return False, "Missing Authorization header"

        if not auth_header.startswith("OAuth "):
            return False, "OAuth 1.0 authentication required"

        try:
            # Parse OAuth parameters from Authorization header
            oauth_params = self._parse_oauth_header(auth_header)

            # Validate required parameters
            required_params = [
                "oauth_consumer_key",
                "oauth_signature_method",
                "oauth_signature",
            ]
            for param in required_params:
                if param not in oauth_params:
                    return False, f"Missing required OAuth 1.0 parameter: {param}"

            # Validate consumer key
            if oauth_params["oauth_consumer_key"] != consumer_key:
                return False, "Invalid OAuth 1.0 consumer key"

            # Validate signature method
            if (
                oauth_params["oauth_signature_method"].upper()
                != signature_method.upper()
            ):
                return (
                    False,
                    f"Invalid OAuth 1.0 signature method: {oauth_params['oauth_signature_method']}",
                )

            # Validate timestamp if enabled
            timestamp = None
            if verify_timestamp and "oauth_timestamp" in oauth_params:
                try:
                    timestamp = int(oauth_params["oauth_timestamp"])
                    current_time = int(time.time())
                    time_diff = abs(current_time - timestamp)

                    if time_diff > timestamp_window:
                        return (
                            False,
                            f"OAuth 1.0 timestamp out of window (diff: {time_diff}s, max: {timestamp_window}s)",
                        )
                except (ValueError, TypeError):
                    return False, "Invalid OAuth 1.0 timestamp"

            # Validate and track nonce to prevent replay attacks
            verify_nonce = oauth1_config.get("verify_nonce", True)
            if verify_nonce:
                if "oauth_nonce" not in oauth_params:
                    return False, "Missing required OAuth 1.0 parameter: oauth_nonce"

                nonce = oauth_params["oauth_nonce"]

                # Validate nonce format (should be non-empty string)
                if not nonce or not isinstance(nonce, str) or not nonce.strip():
                    return False, "Invalid OAuth 1.0 nonce format"

                # Use timestamp for nonce expiration (if available)
                if timestamp is None:
                    # If timestamp validation is disabled, use current time
                    timestamp = int(time.time())

                # Check and store nonce
                is_valid_nonce, nonce_message = (
                    await _oauth1_nonce_tracker.check_and_store_nonce(
                        nonce, timestamp, timestamp_window
                    )
                )

                if not is_valid_nonce:
                    return False, nonce_message

            # Get request URI and method from request object
            request_uri = "/"
            http_method = "POST"  # Default for webhooks
            if self.request:
                # Get method from request
                if hasattr(self.request, "method"):
                    http_method = self.request.method.upper()
                # Get URI from request
                if hasattr(self.request, "scope"):
                    # FastAPI Request object or mock - get path from scope
                    if isinstance(self.request.scope, dict):
                        request_uri = self.request.scope.get("path", "/")
                    elif hasattr(self.request.scope, "get"):
                        request_uri = self.request.scope.get("path", "/")
                elif hasattr(self.request, "url"):
                    request_uri = str(self.request.url.path)

            # Get token secret from config (if provided)
            # Note: oauth_token_secret is not a standard OAuth 1.0 parameter in the header
            # It's typically used during token exchange, not in webhook requests
            # For webhooks, token_secret can be configured if needed
            token_secret = token_secret_config

            # For PLAINTEXT, signature is just the signing key (no base string needed)
            if signature_method.upper() == "PLAINTEXT":
                from urllib.parse import quote

                computed_signature = (
                    f"{quote(consumer_secret, safe='')}&{quote(token_secret, safe='')}"
                )
            else:
                # Build signature base string for HMAC-SHA1, etc.
                base_string = self._build_signature_base_string(
                    http_method, request_uri, oauth_params, body
                )

                # Compute signature
                computed_signature = self._compute_signature(
                    base_string, consumer_secret, token_secret, signature_method
                )

            # Compare signatures (constant-time)
            # Encode both to bytes for consistent length comparison
            received_signature = oauth_params["oauth_signature"]
            if not hmac.compare_digest(
                computed_signature.encode("utf-8"), received_signature.encode("utf-8")
            ):
                return False, "Invalid OAuth 1.0 signature"

            return True, "Valid OAuth 1.0 signature"

        except Exception as e:
            # SECURITY: Sanitize exception messages to prevent information disclosure
            from src.utils import sanitize_error_message

            return False, sanitize_error_message(e, "OAuth 1.0 validation")

    @staticmethod
    def _parse_oauth_header(auth_header: str) -> Dict[str, str]:
        """Parse OAuth Authorization header into parameters."""
        from urllib.parse import unquote

        # Remove "OAuth " prefix
        oauth_str = auth_header[6:].strip()

        params = {}
        # Parse key="value" pairs
        pattern = r'(\w+)="([^"]+)"'
        matches = re.findall(pattern, oauth_str)

        for key, value in matches:
            # URL-decode the value (OAuth params are URL-encoded in header)
            params[key] = unquote(value)

        return params

    @staticmethod
    def _build_signature_base_string(
        method: str, uri: str, oauth_params: Dict[str, str], body: bytes
    ) -> str:
        """Build OAuth 1.0 signature base string."""
        from urllib.parse import quote, urlparse

        # Normalize URI (scheme://host:port/path, no query/fragment)
        # For webhooks, URI is typically just the path
        if "://" in uri:
            parsed = urlparse(uri)
            normalized_uri = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        else:
            # If no scheme, assume it's just the path
            normalized_uri = uri.split("?")[0]

        # Collect all parameters (oauth_* params, excluding oauth_signature)
        all_params = {}
        for key, value in oauth_params.items():
            if key != "oauth_signature":
                all_params[key] = value

        # Add body parameters if present (for form-encoded body)
        if body:
            try:
                # Try UTF-8 first, fallback to latin-1 for form-encoded data
                try:
                    body_str = body.decode("utf-8")
                except UnicodeDecodeError:
                    # Form-encoded data often uses latin-1
                    try:
                        body_str = body.decode("latin-1")
                    except UnicodeDecodeError:
                        # Skip body parsing if encoding fails
                        body_str = None

                # Check if body looks like form-encoded data (contains & and =)
                # OAuth 1.0 spec allows form-encoded body parameters in signature base string
                if body_str and "&" in body_str and "=" in body_str:
                    from urllib.parse import parse_qs

                    body_params = parse_qs(body_str, keep_blank_values=True)
                    for key, values in body_params.items():
                        all_params[key] = values[0] if values else ""
            except (UnicodeDecodeError, ValueError):
                pass

        # Sort parameters by key, then by value
        sorted_params = sorted(all_params.items())

        # Percent-encode and join
        param_string = "&".join(
            [
                f"{quote(str(k), safe='')}={quote(str(v), safe='')}"
                for k, v in sorted_params
            ]
        )

        # Build base string: METHOD&URI&PARAMS
        base_string = f"{method.upper()}&{quote(normalized_uri, safe='')}&{quote(param_string, safe='')}"

        return base_string

    @staticmethod
    def _compute_signature(
        base_string: str, consumer_secret: str, token_secret: str, signature_method: str
    ) -> str:
        """Compute OAuth 1.0 signature."""
        from urllib.parse import quote

        method = signature_method.upper()

        if method == "HMAC-SHA1":
            # Signing key = consumer_secret&token_secret
            signing_key = (
                f"{quote(consumer_secret, safe='')}&{quote(token_secret, safe='')}"
            )

            # Compute HMAC-SHA1
            signature = hmac.new(
                signing_key.encode("utf-8"), base_string.encode("utf-8"), hashlib.sha1
            ).digest()

            # Base64 encode
            return base64.b64encode(signature).decode("utf-8")

        elif method == "PLAINTEXT":
            # PLAINTEXT: signing_key as-is (no base string needed, signature is the key itself)
            signing_key = (
                f"{quote(consumer_secret, safe='')}&{quote(token_secret, safe='')}"
            )
            return signing_key

        elif method == "RSA-SHA1":
            # RSA-SHA1 requires private key, not supported for validation
            raise ValueError(
                "RSA-SHA1 signature validation not supported (requires private key)"
            )

        else:
            raise ValueError(f"Unsupported OAuth 1.0 signature method: {method}")


class RecaptchaValidator(BaseValidator):
    """Validates Google reCAPTCHA token."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize reCAPTCHA validator.

        Args:
            config: The webhook configuration
        """
        super().__init__(config)
        self.recaptcha_config = config.get("recaptcha", {})
        self.secret_key = self.recaptcha_config.get("secret_key")
        self.version = self.recaptcha_config.get("version", "v3")  # v2 or v3
        self.token_source = self.recaptcha_config.get(
            "token_source", "header"
        )  # header or body
        self.token_field = self.recaptcha_config.get("token_field", "X-Recaptcha-Token")
        self.min_score = self.recaptcha_config.get("min_score", 0.5)  # For v3 only
        self.verify_url = "https://www.google.com/recaptcha/api/siteverify"

    def _extract_token(self, headers: Dict[str, str], body: bytes) -> Optional[str]:
        """Extract reCAPTCHA token from headers or body."""
        # SECURITY: "header" is a configuration value (token_source), not a hardcoded password
        header_source = "header"  # nosec B105
        if self.token_source == header_source:
            # Try both original case and lowercase
            token = headers.get(self.token_field.lower()) or headers.get(
                self.token_field
            )
            return token
        else:  # body
            try:
                # Try UTF-8 first, fallback to other encodings
                try:
                    decoded_body = body.decode("utf-8")
                except UnicodeDecodeError:
                    # Try latin-1 as fallback for JSON (less common but possible)
                    try:
                        decoded_body = body.decode("latin-1")
                    except UnicodeDecodeError:
                        return None

                payload = json.loads(decoded_body)
                if isinstance(payload, dict):
                    # Try common field names
                    token = (
                        payload.get("recaptcha_token")
                        or payload.get("recaptcha")
                        or payload.get("g-recaptcha-response")
                    )
                    return token
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        return None

    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate reCAPTCHA token."""
        if not self.recaptcha_config:
            return True, "No reCAPTCHA validation required"

        if not self.secret_key:
            return False, "reCAPTCHA secret key not configured"

        # Extract token
        token = self._extract_token(headers, body)
        if not token:
            return (
                False,
                f"Missing reCAPTCHA token (expected in {self.token_source}: {self.token_field})",
            )

        # Get client IP if available (recommended for v3)
        client_ip = (
            headers.get("x-forwarded-for", "").split(",")[0].strip()
            or headers.get("x-real-ip", "")
            or headers.get("remote-addr", "")
        )

        # Verify token with Google
        try:
            import httpx

            # Prepare verification request
            data = {"secret": self.secret_key, "response": token}

            # Add remote IP for v3 (recommended)
            if client_ip and self.version == "v3":
                data["remoteip"] = client_ip

            # Make async request to Google
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(self.verify_url, data=data)
                response.raise_for_status()
                result = response.json()

            # Check if verification was successful
            if not result.get("success", False):
                error_codes = result.get("error-codes", [])
                error_msg = (
                    ", ".join(error_codes) if error_codes else "Verification failed"
                )
                return False, f"reCAPTCHA verification failed: {error_msg}"

            # For v3, check score threshold
            if self.version == "v3":
                score = result.get("score", 0.0)
                if score < self.min_score:
                    return (
                        False,
                        f"reCAPTCHA score {score:.2f} below threshold {self.min_score}",
                    )

            # For v2, check if challenge was passed
            # (v2 doesn't return a score, just success/failure)

            return True, f"Valid reCAPTCHA token (score: {result.get('score', 'N/A')})"

        except ImportError:
            return False, "httpx library not installed"
        except httpx.HTTPError as e:
            # SECURITY: Sanitize HTTP error messages to prevent information disclosure
            from src.utils import sanitize_error_message

            return False, sanitize_error_message(e, "reCAPTCHA verification")
        except json.JSONDecodeError:
            return False, "Invalid response from reCAPTCHA service"
        except Exception as e:
            # SECURITY: Sanitize generic exception messages to prevent information disclosure
            from src.utils import sanitize_error_message

            return False, sanitize_error_message(e, "reCAPTCHA validation")
