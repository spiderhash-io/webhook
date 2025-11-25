import hmac
import hashlib
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

