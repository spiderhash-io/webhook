import hmac
import hashlib
import base64
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, Optional


class BaseValidator(ABC):
    """Base class for webhook validators."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize validator with configuration.
        
        Args:
            config: The webhook configuration
        """
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
    
    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate authorization header."""
        expected_auth = self.config.get("authorization", "")
        
        if not expected_auth:
            return True, "No authorization required"
        
        authorization_header = headers.get('authorization', '')
        
        if "Bearer" in expected_auth and not authorization_header.startswith("Bearer"):
            return False, "Unauthorized: Bearer token required"
        
        if authorization_header != expected_auth:
            return False, "Unauthorized"
        
        return True, "Valid authorization"


class BasicAuthValidator(BaseValidator):
    """Validates HTTP Basic Authentication."""
    
    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate HTTP Basic Authentication."""
        basic_auth_config = self.config.get("basic_auth", {})
        
        if not basic_auth_config:
            return True, "No basic auth required"
        
        auth_header = headers.get('authorization', '')
        
        if not auth_header:
            return False, "Missing Authorization header"
        
        if not auth_header.startswith('Basic '):
            return False, "Basic authentication required"
        
        try:
            # Extract and decode base64 credentials
            encoded_credentials = auth_header.split(' ', 1)[1]
            decoded_bytes = base64.b64decode(encoded_credentials)
            decoded_str = decoded_bytes.decode('utf-8')
            
            # Split username and password
            if ':' not in decoded_str:
                return False, "Invalid basic auth format"
            
            username, password = decoded_str.split(':', 1)
            
            # Get expected credentials
            expected_username = basic_auth_config.get('username')
            expected_password = basic_auth_config.get('password')
            
            if not expected_username or not expected_password:
                return False, "Basic auth credentials not configured"
            
            # Validate credentials (constant-time comparison for password)
            # Encode to bytes for consistent comparison, especially with unicode
            username_match = username == expected_username
            password_match = hmac.compare_digest(
                password.encode('utf-8'), 
                expected_password.encode('utf-8')
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
            return False, f"Invalid basic auth format: {str(e)}"


class JWTValidator(BaseValidator):
    """Validates JSON Web Tokens (JWT)."""
    
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
        
        auth_header = headers.get('authorization', '')
        
        if not auth_header:
            return False, "Missing Authorization header"
        
        if not auth_header.startswith('Bearer '):
            return False, "JWT Bearer token required"
        
        try:
            token = auth_header.split(' ', 1)[1]
            
            # Prepare validation options
            options = {
                'verify_exp': jwt_config.get('verify_exp', True),
                'verify_aud': bool(jwt_config.get('audience')),
                'verify_iss': bool(jwt_config.get('issuer')),
            }
            
            # Decode and validate
            jwt.decode(
                token,
                key=jwt_config.get('secret'),
                algorithms=[jwt_config.get('algorithm', 'HS256')],
                issuer=jwt_config.get('issuer'),
                audience=jwt_config.get('audience'),
                options=options
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
        except Exception as e:
            return False, f"JWT validation failed: {str(e)}"


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
        
        received_signature = headers.get(header_name.lower(), "")
        
        if not received_signature:
            return False, f"Missing {header_name} header"
        
        # Compute HMAC
        if algorithm == "sha256":
            hash_func = hashlib.sha256
        elif algorithm == "sha1":
            hash_func = hashlib.sha1
        elif algorithm == "sha512":
            hash_func = hashlib.sha512
        else:
            return False, f"Unsupported HMAC algorithm: {algorithm}"
        
        hmac_obj = hmac.new(secret.encode(), body, hash_func)
        computed_signature = hmac_obj.hexdigest()
        
        # Support both hex and sha256= prefix formats
        if received_signature.startswith(f"{algorithm}="):
            received_signature = received_signature.split("=", 1)[1]
        
        if not hmac.compare_digest(computed_signature, received_signature):
            return False, "Invalid HMAC signature"
        
        return True, "Valid HMAC signature"


class IPWhitelistValidator(BaseValidator):
    """Validates IP address against whitelist."""
    
    async def validate(self, headers: Dict[str, str], body: bytes) -> Tuple[bool, str]:
        """Validate IP address."""
        ip_whitelist = self.config.get("ip_whitelist", [])
        
        if not ip_whitelist:
            return True, "No IP whitelist configured"
        
        # Get client IP from headers (consider proxy headers)
        client_ip = (
            headers.get('x-forwarded-for', '').split(',')[0].strip() or
            headers.get('x-real-ip', '') or
            headers.get('remote-addr', '')
        )
        
        if not client_ip:
            return False, "Could not determine client IP"
        
        if client_ip not in ip_whitelist:
            return False, f"IP {client_ip} not in whitelist"
        
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
            self.webhook_id,
            max_requests,
            window_seconds
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
            import json
            import jsonschema
            from jsonschema import validate
        except ImportError:
            return False, "jsonschema library not installed"
        
        try:
            # Parse body as JSON
            payload = json.loads(body)
        except json.JSONDecodeError:
            return False, "Invalid JSON body"
        
        try:
            # Validate against schema
            validate(instance=payload, schema=schema)
            return True, "Valid JSON schema"
        except jsonschema.exceptions.ValidationError as e:
            return False, f"JSON schema validation failed: {e.message}"
        except jsonschema.exceptions.SchemaError as e:
            return False, f"Invalid JSON schema configuration: {e.message}"
        except Exception as e:
            return False, f"JSON schema validation error: {str(e)}"


class QueryParameterAuthValidator(BaseValidator):
    """Validates API key authentication via query parameters."""
    
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
    def validate_query_params(query_params: Dict[str, str], config: Dict[str, Any]) -> Tuple[bool, str]:
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
        
        # Check if api_key is configured (empty string is not valid)
        if expected_key == "":
            return False, "Query auth API key not configured"
        
        # Get the API key from query parameters
        received_key = query_params.get(parameter_name)
        
        # Check if parameter is missing or empty
        if received_key is None:
            return False, f"Missing required query parameter: {parameter_name}"
        
        if received_key == "":
            return False, f"Invalid API key in query parameter: {parameter_name}"
        
        # Validate key with constant-time comparison
        if case_sensitive:
            is_valid = hmac.compare_digest(received_key.encode('utf-8'), expected_key.encode('utf-8'))
        else:
            is_valid = hmac.compare_digest(
                received_key.lower().encode('utf-8'),
                expected_key.lower().encode('utf-8')
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
        
        # Check if api_key is configured (empty string is not valid)
        if expected_key == "":
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
        
        # Check if header value is empty (header exists but value is empty)
        if received_key == "":
            return False, f"Invalid API key in header: {header_name}"
        
        # Validate key with constant-time comparison
        if case_sensitive:
            is_valid = hmac.compare_digest(received_key.encode('utf-8'), expected_key.encode('utf-8'))
        else:
            is_valid = hmac.compare_digest(
                received_key.lower().encode('utf-8'),
                expected_key.lower().encode('utf-8')
            )
        
        if not is_valid:
            return False, f"Invalid API key in header: {header_name}"
        
        return True, "Valid header authentication"


class OAuth2Validator(BaseValidator):
    """Validates OAuth 2.0 access tokens."""
    
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
        
        # Get token from Authorization header
        auth_header = headers.get('authorization', '')
        
        if not auth_header:
            return False, "Missing Authorization header"
        
        # Extract token (support Bearer format)
        if not auth_header.startswith(f'{token_type} '):
            return False, f"OAuth 2.0 {token_type} token required"
        
        token = auth_header.split(' ', 1)[1].strip()
        
        if not token:
            return False, "Empty OAuth 2.0 token"
        
        # If token introspection is configured, validate via endpoint
        if introspection_endpoint and validate_token:
            try:
                import httpx
                
                # Prepare introspection request
                data = {
                    "token": token,
                    "token_type_hint": "access_token"
                }
                
                # Add client credentials if provided
                auth = None
                if client_id and client_secret:
                    auth = (client_id, client_secret)
                
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        introspection_endpoint,
                        data=data,
                        auth=auth,
                        timeout=10.0
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
                        return False, f"OAuth 2.0 token missing required scopes: {', '.join(missing_scopes)}"
                
                return True, "Valid OAuth 2.0 token"
                
            except httpx.HTTPStatusError as e:
                return False, f"OAuth 2.0 token introspection failed: HTTP {e.response.status_code}"
            except httpx.RequestError as e:
                return False, f"OAuth 2.0 token introspection network error: {str(e)}"
            except Exception as e:
                return False, f"OAuth 2.0 token introspection error: {str(e)}"
        
        # If JWT token validation is enabled, try to validate as JWT
        jwt_secret = oauth2_config.get("jwt_secret")
        if jwt_secret and not introspection_endpoint:
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
                    algorithms=oauth2_config.get("jwt_algorithms", ["HS256", "RS256"]),
                    audience=audience,
                    issuer=issuer,
                    options=decode_options
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
                        return False, f"OAuth 2.0 token missing required scopes: {', '.join(missing_scopes)}"
                
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
        
        return False, "OAuth 2.0 validation not properly configured (missing introspection_endpoint or jwt_secret)"


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
        self.token_source = self.recaptcha_config.get("token_source", "header")  # header or body
        self.token_field = self.recaptcha_config.get("token_field", "X-Recaptcha-Token")
        self.min_score = self.recaptcha_config.get("min_score", 0.5)  # For v3 only
        self.verify_url = "https://www.google.com/recaptcha/api/siteverify"
    
    def _extract_token(self, headers: Dict[str, str], body: bytes) -> Optional[str]:
        """Extract reCAPTCHA token from headers or body."""
        if self.token_source == "header":
            # Try both original case and lowercase
            token = headers.get(self.token_field.lower()) or headers.get(self.token_field)
            return token
        else:  # body
            try:
                payload = json.loads(body.decode('utf-8'))
                if isinstance(payload, dict):
                    # Try common field names
                    token = payload.get("recaptcha_token") or payload.get("recaptcha") or payload.get("g-recaptcha-response")
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
            return False, f"Missing reCAPTCHA token (expected in {self.token_source}: {self.token_field})"
        
        # Get client IP if available (recommended for v3)
        client_ip = (
            headers.get('x-forwarded-for', '').split(',')[0].strip() or
            headers.get('x-real-ip', '') or
            headers.get('remote-addr', '')
        )
        
        # Verify token with Google
        try:
            import httpx
            
            # Prepare verification request
            data = {
                "secret": self.secret_key,
                "response": token
            }
            
            # Add remote IP for v3 (recommended)
            if client_ip and self.version == "v3":
                data["remoteip"] = client_ip
            
            # Make async request to Google
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(self.verify_url, data=data)
                response.raise_for_status()
                result = response.json()
            
            # Check if verification was successful
            if not result.get("success", False):
                error_codes = result.get("error-codes", [])
                error_msg = ", ".join(error_codes) if error_codes else "Verification failed"
                return False, f"reCAPTCHA verification failed: {error_msg}"
            
            # For v3, check score threshold
            if self.version == "v3":
                score = result.get("score", 0.0)
                if score < self.min_score:
                    return False, f"reCAPTCHA score {score:.2f} below threshold {self.min_score}"
            
            # For v2, check if challenge was passed
            # (v2 doesn't return a score, just success/failure)
            
            return True, f"Valid reCAPTCHA token (score: {result.get('score', 'N/A')})"
            
        except ImportError:
            return False, "httpx library not installed"
        except httpx.HTTPError as e:
            return False, f"Failed to verify reCAPTCHA token: {str(e)}"
        except json.JSONDecodeError:
            return False, "Invalid response from reCAPTCHA service"
        except Exception as e:
            return False, f"reCAPTCHA validation error: {str(e)}"
