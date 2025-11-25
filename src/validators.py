import hmac
import hashlib
import base64
from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple


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
