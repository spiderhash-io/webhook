"""
Tests for OAuth 1.0 Authentication validator.
Includes security edge cases and comprehensive validation.
"""
import pytest
import hmac
import hashlib
import base64
import time
from urllib.parse import quote
from src.validators import OAuth1Validator


def generate_oauth1_signature(
    method: str,
    uri: str,
    consumer_secret: str,
    token_secret: str,
    oauth_params: dict,
    body: bytes = b""
) -> str:
    """Helper function to generate valid OAuth 1.0 HMAC-SHA1 signature."""
    from urllib.parse import urlparse
    
    # Build signature base string (matching validator logic)
    # Normalize URI
    if '://' in uri:
        parsed = urlparse(uri)
        normalized_uri = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    else:
        normalized_uri = uri.split('?')[0]
    
    # Collect all parameters (excluding oauth_signature)
    all_params = {k: v for k, v in oauth_params.items() if k != 'oauth_signature'}
    
    # Sort parameters
    sorted_params = sorted(all_params.items())
    
    # Percent-encode and join
    param_string = '&'.join([f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in sorted_params])
    
    # Build base string: METHOD&URI&PARAMS
    base_string = f"{method.upper()}&{quote(normalized_uri, safe='')}&{quote(param_string, safe='')}"
    
    # Signing key
    signing_key = f"{quote(consumer_secret, safe='')}&{quote(token_secret, safe='')}"
    
    # Compute HMAC-SHA1
    signature = hmac.new(
        signing_key.encode('utf-8'),
        base_string.encode('utf-8'),
        hashlib.sha1
    ).digest()
    
    # Base64 encode
    return base64.b64encode(signature).decode('utf-8')


class TestOAuth1:
    """Test suite for OAuth 1.0 Authentication."""
    
    @pytest.mark.asyncio
    async def test_oauth1_no_config(self):
        """Test that validation passes when no OAuth 1.0 is configured."""
        config = {}
        validator = OAuth1Validator(config)
        
        headers = {}
        body = b"test"
        
        is_valid, message = await validator.validate(headers, body)
        assert is_valid is True
        assert "No OAuth 1.0 validation required" in message
    
    @pytest.mark.asyncio
    async def test_oauth1_missing_authorization_header(self):
        """Test validation when Authorization header is missing."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret"
            }
        }
        
        headers = {}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Missing Authorization header" in message
    
    @pytest.mark.asyncio
    async def test_oauth1_wrong_scheme(self):
        """Test validation with wrong authentication scheme."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret"
            }
        }
        
        headers = {"authorization": "Bearer token"}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "OAuth 1.0 authentication required" in message
    
    @pytest.mark.asyncio
    async def test_oauth1_valid_signature(self):
        """Test validation with valid signature."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "HMAC-SHA1"
            },
            "_request": type('obj', (object,), {
                'scope': {'path': '/webhook/test'}
            })()
        }
        
        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""
        
        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123",
            "oauth_version": "1.0"
        }
        
        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature
        
        # Build Authorization header
        auth_parts = [f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()]
        auth_header = "OAuth " + ", ".join(auth_parts)
        
        headers = {"authorization": auth_header}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True
        assert "Valid OAuth 1.0 signature" in message
    
    @pytest.mark.asyncio
    async def test_oauth1_invalid_consumer_key(self):
        """Test validation with invalid consumer key."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret"
            },
            "_request": type('obj', (object,), {
                'scope': {'path': '/webhook/test'}
            })()
        }
        
        uri = "/webhook/test"
        method = "POST"
        consumer_secret = "consumer_secret"
        token_secret = ""
        
        oauth_params = {
            "oauth_consumer_key": "wrong_key",
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123"
        }
        
        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature
        
        auth_parts = [f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()]
        auth_header = "OAuth " + ", ".join(auth_parts)
        
        headers = {"authorization": auth_header}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid OAuth 1.0 consumer key" in message
    
    @pytest.mark.asyncio
    async def test_oauth1_invalid_signature(self):
        """Test validation with invalid signature."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret"
            },
            "_request": type('obj', (object,), {
                'scope': {'path': '/webhook/test'}
            })()
        }
        
        uri = "/webhook/test"
        consumer_key = "consumer_key"
        
        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123",
            "oauth_signature": "invalid_signature"
        }
        
        auth_parts = [f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()]
        auth_header = "OAuth " + ", ".join(auth_parts)
        
        headers = {"authorization": auth_header}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid OAuth 1.0 signature" in message
    
    @pytest.mark.asyncio
    async def test_oauth1_missing_required_parameter(self):
        """Test validation when required parameter is missing."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret"
            }
        }
        
        # Missing oauth_signature
        auth_header = 'OAuth oauth_consumer_key="consumer_key", oauth_signature_method="HMAC-SHA1"'
        
        headers = {"authorization": auth_header}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Missing required OAuth 1.0 parameter" in message
    
    @pytest.mark.asyncio
    async def test_oauth1_timestamp_validation(self):
        """Test timestamp validation."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "verify_timestamp": True,
                "timestamp_window": 300
            },
            "_request": type('obj', (object,), {
                'scope': {'path': '/webhook/test'}
            })()
        }
        
        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""
        
        # Timestamp too old (1 hour ago)
        old_timestamp = str(int(time.time()) - 3600)
        
        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": old_timestamp,
            "oauth_nonce": "nonce123"
        }
        
        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature
        
        auth_parts = [f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()]
        auth_header = "OAuth " + ", ".join(auth_parts)
        
        headers = {"authorization": auth_header}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "timestamp out of window" in message.lower()
    
    @pytest.mark.asyncio
    async def test_oauth1_timestamp_validation_disabled(self):
        """Test when timestamp validation is disabled."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "verify_timestamp": False
            },
            "_request": type('obj', (object,), {
                'scope': {'path': '/webhook/test'}
            })()
        }
        
        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""
        
        # Old timestamp (should be accepted when validation is disabled)
        old_timestamp = str(int(time.time()) - 3600)
        
        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": old_timestamp,
            "oauth_nonce": "nonce123"
        }
        
        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature
        
        auth_parts = [f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()]
        auth_header = "OAuth " + ", ".join(auth_parts)
        
        headers = {"authorization": auth_header}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_oauth1_plaintext_signature(self):
        """Test PLAINTEXT signature method."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "PLAINTEXT"
            },
            "_request": type('obj', (object,), {
                'scope': {'path': '/webhook/test'}
            })()
        }
        
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""
        
        # PLAINTEXT signature is just the signing key
        signing_key = f"{quote(consumer_secret, safe='')}&{quote(token_secret, safe='')}"
        
        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "PLAINTEXT",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123",
            "oauth_signature": signing_key
        }
        
        auth_parts = [f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()]
        auth_header = "OAuth " + ", ".join(auth_parts)
        
        headers = {"authorization": auth_header}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_oauth1_invalid_signature_method(self):
        """Test validation with invalid signature method."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "HMAC-SHA1"
            }
        }
        
        oauth_params = {
            "oauth_consumer_key": "consumer_key",
            "oauth_signature_method": "RSA-SHA1",
            "oauth_signature": "signature"
        }
        
        auth_parts = [f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()]
        auth_header = "OAuth " + ", ".join(auth_parts)
        
        headers = {"authorization": auth_header}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid OAuth 1.0 signature method" in message
    
    @pytest.mark.asyncio
    async def test_oauth1_missing_consumer_key_config(self):
        """Test validation when consumer_key is not configured."""
        config = {
            "oauth1": {
                "consumer_secret": "consumer_secret"
            }
        }
        
        headers = {"authorization": "OAuth oauth_consumer_key=\"key\""}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "OAuth 1.0 consumer credentials not configured" in message
    
    @pytest.mark.asyncio
    async def test_oauth1_missing_consumer_secret_config(self):
        """Test validation when consumer_secret is not configured."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key"
            }
        }
        
        headers = {"authorization": "OAuth oauth_consumer_key=\"key\""}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "OAuth 1.0 consumer credentials not configured" in message
    
    @pytest.mark.asyncio
    async def test_oauth1_with_token_secret(self):
        """Test validation with token secret (token secret comes from config, not header)."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "token_secret": "token_secret",  # Token secret in config
                "signature_method": "HMAC-SHA1"
            },
            "_request": type('obj', (object,), {
                'scope': {'path': '/webhook/test'}
            })()
        }
        
        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = "token_secret"  # From config
        
        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_token": "token",
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123"
        }
        
        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature
        
        auth_parts = [f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()]
        auth_header = "OAuth " + ", ".join(auth_parts)
        
        headers = {"authorization": auth_header}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_oauth1_malformed_header(self):
        """Test validation with malformed Authorization header."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret"
            }
        }
        
        headers = {"authorization": "OAuth invalid_format"}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_oauth1_sql_injection_attempt(self):
        """Test that SQL injection attempts are handled safely."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret"
            }
        }
        
        # Attempt SQL injection in consumer key
        oauth_params = {
            "oauth_consumer_key": "consumer_key'; DROP TABLE users; --",
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_signature": "signature"
        }
        
        auth_parts = [f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()]
        auth_header = "OAuth " + ", ".join(auth_parts)
        
        headers = {"authorization": auth_header}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid OAuth 1.0 consumer key" in message
    
    @pytest.mark.asyncio
    async def test_oauth1_timing_attack_resistance(self):
        """Test that validation uses constant-time comparison to resist timing attacks."""
        import time
        
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "signature_method": "HMAC-SHA1",
                "verify_timestamp": False
            },
            "_request": type('obj', (object,), {
                'scope': {'path': '/webhook/test'}
            })()
        }
        
        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""
        
        # Correct signature
        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": "nonce123"
        }
        correct_signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = correct_signature
        
        auth_parts = [f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()]
        correct_header = "OAuth " + ", ".join(auth_parts)
        
        # Wrong signature (first character different)
        wrong_signature = "x" + correct_signature[1:] if len(correct_signature) > 1 else "x"
        oauth_params["oauth_signature"] = wrong_signature
        auth_parts = [f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()]
        wrong_header = "OAuth " + ", ".join(auth_parts)
        
        validator = OAuth1Validator(config)
        
        # Measure time for correct signature
        correct_times = []
        for _ in range(10):
            start = time.perf_counter()
            await validator.validate({"authorization": correct_header}, body=b"test")
            correct_times.append(time.perf_counter() - start)
        correct_time = sum(correct_times) / len(correct_times)
        
        # Measure time for wrong signature
        wrong_times = []
        for _ in range(10):
            start = time.perf_counter()
            await validator.validate({"authorization": wrong_header}, body=b"test")
            wrong_times.append(time.perf_counter() - start)
        wrong_time = sum(wrong_times) / len(wrong_times)
        
        # Times should be similar (within reasonable margin)
        time_diff_ratio = abs(correct_time - wrong_time) / max(correct_time, wrong_time, 0.000001)
        
        # Allow up to 70% difference due to system noise
        assert time_diff_ratio < 0.7, f"Timing attack vulnerability detected: {time_diff_ratio:.2%}"
    
    @pytest.mark.asyncio
    async def test_oauth1_empty_config(self):
        """Test validation when oauth1 config exists but is empty."""
        config = {
            "oauth1": {}
        }
        
        headers = {"authorization": "OAuth oauth_consumer_key=\"key\""}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "OAuth 1.0 consumer credentials not configured" in message
    
    @pytest.mark.asyncio
    async def test_oauth1_invalid_timestamp_format(self):
        """Test validation with invalid timestamp format."""
        config = {
            "oauth1": {
                "consumer_key": "consumer_key",
                "consumer_secret": "consumer_secret",
                "verify_timestamp": True
            },
            "_request": type('obj', (object,), {
                'scope': {'path': '/webhook/test'}
            })()
        }
        
        uri = "/webhook/test"
        method = "POST"
        consumer_key = "consumer_key"
        consumer_secret = "consumer_secret"
        token_secret = ""
        
        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": "not_a_number",
            "oauth_nonce": "nonce123"
        }
        
        signature = generate_oauth1_signature(
            method, uri, consumer_secret, token_secret, oauth_params
        )
        oauth_params["oauth_signature"] = signature
        
        auth_parts = [f'{k}="{quote(str(v), safe="")}"' for k, v in oauth_params.items()]
        auth_header = "OAuth " + ", ".join(auth_parts)
        
        headers = {"authorization": auth_header}
        
        validator = OAuth1Validator(config)
        is_valid, message = await validator.validate(headers, body=b"test")
        assert is_valid is False
        assert "Invalid OAuth 1.0 timestamp" in message

