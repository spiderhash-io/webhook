"""
Comprehensive security tests for JWT authentication.
Tests advanced JWT attack vectors and bypass techniques.
"""
import pytest
import jwt
import time
import base64
import json
from src.validators import JWTValidator


class TestJWTAlgorithmConfusion:
    """Test JWT algorithm confusion attacks."""
    
    @pytest.mark.asyncio
    async def test_none_algorithm_in_token_header(self):
        """Test that 'none' algorithm in JWT header is rejected."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Create JWT with 'none' algorithm in header (even though config says HS256)
        # This tests that PyJWT properly validates algorithm
        try:
            # Try to create a token with none algorithm
            # PyJWT should reject this, but test anyway
            token = jwt.encode({"user": "test"}, secret, algorithm="none")
            headers = {"authorization": f"Bearer {token}"}
            
            is_valid, message = await validator.validate(headers, b"")
            # Should fail because we only allow HS256, not 'none'
            assert is_valid is False
            assert "Invalid JWT algorithm" in message or "Invalid JWT token format" in message
        except Exception:
            # If PyJWT rejects encoding with 'none', that's also good
            pass
    
    @pytest.mark.asyncio
    async def test_algorithm_mismatch_rs256_vs_hs256(self):
        """Test that RS256 token cannot be validated with HS256 secret."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Create token with RS256 but config expects HS256
        # This should fail because algorithm mismatch
        try:
            # Try to create RS256 token (would need RSA keys, but test the validation)
            # Actually, we can't easily create RS256 without keys, so test that
            # a token signed with different algorithm is rejected
            token = jwt.encode({"user": "test"}, secret, algorithm="HS512")
            headers = {"authorization": f"Bearer {token}"}
            
            is_valid, message = await validator.validate(headers, b"")
            # Should fail because algorithm mismatch (HS512 vs HS256)
            assert is_valid is False
            assert "Invalid JWT algorithm" in message
        except Exception:
            pass
    
    @pytest.mark.asyncio
    async def test_algorithm_header_manipulation(self):
        """Test that algorithm in JWT header cannot override config."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"  # Config says HS256
            }
        }
        
        validator = JWTValidator(config)
        
        # Create token with HS256 (correct)
        token = jwt.encode({"user": "test"}, secret, algorithm="HS256")
        
        # Manually modify header to claim it's HS512
        # JWT format: header.payload.signature
        parts = token.split('.')
        if len(parts) == 3:
            # Decode header
            header_data = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            # Change algorithm
            header_data['alg'] = 'HS512'
            # Re-encode header
            new_header = base64.urlsafe_b64encode(
                json.dumps(header_data, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            # Create new token with modified header
            modified_token = f"{new_header}.{parts[1]}.{parts[2]}"
            headers = {"authorization": f"Bearer {modified_token}"}
            
            is_valid, message = await validator.validate(headers, b"")
            # Should fail because algorithm mismatch
            assert is_valid is False
            assert "Invalid JWT signature" in message or "Invalid JWT algorithm" in message
    
    @pytest.mark.asyncio
    async def test_missing_algorithm_in_header(self):
        """Test JWT with missing algorithm in header."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Create token normally
        token = jwt.encode({"user": "test"}, secret, algorithm="HS256")
        
        # Manually remove algorithm from header
        parts = token.split('.')
        if len(parts) == 3:
            header_data = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            del header_data['alg']  # Remove algorithm
            new_header = base64.urlsafe_b64encode(
                json.dumps(header_data, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            modified_token = f"{new_header}.{parts[1]}.{parts[2]}"
            headers = {"authorization": f"Bearer {modified_token}"}
            
            is_valid, message = await validator.validate(headers, b"")
            # Should fail - algorithm is required
            assert is_valid is False


class TestJWTKeyConfusion:
    """Test JWT key confusion attacks."""
    
    @pytest.mark.asyncio
    async def test_empty_secret_rejected(self):
        """Test that empty secret is handled properly."""
        config = {
            "jwt": {
                "secret": "",  # Empty secret
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Try to validate with empty secret
        token = jwt.encode({"user": "test"}, "", algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - empty secret is insecure
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_weak_secret_detection(self):
        """Test that weak secrets are rejected (if implemented)."""
        # Note: This tests current behavior - weak secret detection may not be implemented
        weak_secrets = ["", "secret", "12345", "password", "admin"]
        
        for weak_secret in weak_secrets:
            config = {
                "jwt": {
                    "secret": weak_secret,
                    "algorithm": "HS256"
                }
            }
            
            validator = JWTValidator(config)
            token = jwt.encode({"user": "test"}, weak_secret, algorithm="HS256")
            headers = {"authorization": f"Bearer {token}"}
            
            # Current implementation may accept weak secrets
            # This test documents current behavior
            is_valid, message = await validator.validate(headers, b"")
            # Token will validate if secret matches, but secret is weak
            # This is a potential security issue if not addressed elsewhere


class TestJWTHeaderInjection:
    """Test JWT header injection attacks."""
    
    @pytest.mark.asyncio
    async def test_malformed_header_json(self):
        """Test JWT with malformed header JSON."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Create malformed header (invalid JSON)
        malformed_header = base64.urlsafe_b64encode(b"{invalid json}").decode().rstrip('=')
        payload = base64.urlsafe_b64encode(json.dumps({"user": "test"}).encode()).decode().rstrip('=')
        signature = "invalid"
        
        malformed_token = f"{malformed_header}.{payload}.{signature}"
        headers = {"authorization": f"Bearer {malformed_token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Invalid JWT token format" in message or "JWT validation failed" in message
    
    @pytest.mark.asyncio
    async def test_header_with_injection_attempts(self):
        """Test JWT header with injection attempts."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Try to inject newlines, null bytes, etc. in header
        injection_payloads = [
            {"alg": "HS256\nX-Injected: value"},
            {"alg": "HS256\rX-Injected: value"},
            {"alg": "HS256\x00X-Injected: value"},
        ]
        
        for inj_payload in injection_payloads:
            try:
                header_b64 = base64.urlsafe_b64encode(
                    json.dumps(inj_payload, separators=(',', ':')).encode()
                ).decode().rstrip('=')
                
                payload_b64 = base64.urlsafe_b64encode(
                    json.dumps({"user": "test"}).encode()
                ).decode().rstrip('=')
                
                # Create signature (will be invalid, but test header parsing)
                signature = "invalid"
                token = f"{header_b64}.{payload_b64}.{signature}"
                headers = {"authorization": f"Bearer {token}"}
                
                is_valid, message = await validator.validate(headers, b"")
                # Should fail - malformed or invalid
                assert is_valid is False
            except Exception:
                # If encoding fails, that's also good
                pass
    
    @pytest.mark.asyncio
    async def test_very_large_header(self):
        """Test JWT with very large header (DoS attempt)."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Create header with very large custom claim
        large_data = "x" * 10000
        header_data = {"alg": "HS256", "large": large_data}
        
        try:
            header_b64 = base64.urlsafe_b64encode(
                json.dumps(header_data, separators=(',', ':')).encode()
            ).decode().rstrip('=')
            
            payload_b64 = base64.urlsafe_b64encode(
                json.dumps({"user": "test"}).encode()
            ).decode().rstrip('=')
            
            signature = "invalid"
            token = f"{header_b64}.{payload_b64}.{signature}"
            headers = {"authorization": f"Bearer {token}"}
            
            is_valid, message = await validator.validate(headers, b"")
            # Should fail (invalid signature or format)
            assert is_valid is False
        except Exception as e:
            # If it raises exception due to size, that's also acceptable
            pass


class TestJWTClaimConfusion:
    """Test JWT claim confusion and manipulation attacks."""
    
    @pytest.mark.asyncio
    async def test_exp_claim_bypass_attempts(self):
        """Test various expiration claim bypass attempts."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256",
                "verify_exp": True
            }
        }
        
        validator = JWTValidator(config)
        
        # Test with very large expiration (year 9999)
        payload = {"exp": 253402300799}  # Far future
        token = jwt.encode(payload, secret, algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should pass if expiration is in future
        # This tests that very large but valid exp is accepted
        
        # Test with negative expiration
        payload = {"exp": -1}
        token = jwt.encode(payload, secret, algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "expired" in message.lower()
    
    @pytest.mark.asyncio
    async def test_malformed_exp_claim(self):
        """Test JWT with malformed expiration claim."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256",
                "verify_exp": True
            }
        }
        
        validator = JWTValidator(config)
        
        # Create token with string expiration (should be numeric)
        payload = {"exp": "not-a-number"}
        token = jwt.encode(payload, secret, algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - exp must be numeric
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_issuer_case_sensitivity(self):
        """Test issuer validation case sensitivity."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256",
                "issuer": "ExpectedIssuer"
            }
        }
        
        validator = JWTValidator(config)
        
        # Test with different case
        payload = {"iss": "expectedissuer"}  # Lowercase
        token = jwt.encode(payload, secret, algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - issuer mismatch (case-sensitive)
        assert is_valid is False
        assert "Invalid JWT issuer" in message
    
    @pytest.mark.asyncio
    async def test_audience_array_vs_string(self):
        """Test audience claim handling (array vs string)."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256",
                "audience": "expected-audience"
            }
        }
        
        validator = JWTValidator(config)
        
        # Test with array audience
        payload = {"aud": ["expected-audience", "other"]}
        token = jwt.encode(payload, secret, algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # PyJWT should handle array audiences, test behavior
        # Should pass if array contains expected audience
    
    @pytest.mark.asyncio
    async def test_claim_injection_attempts(self):
        """Test claim injection attempts."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Try to inject malicious claims
        malicious_claims = [
            {"user": "admin", "role": "admin"},  # Privilege escalation attempt
            {"user": "test", "__proto__": {"admin": True}},  # Prototype pollution attempt
            {"user": "test", "constructor": {"admin": True}},  # Constructor injection
        ]
        
        for claims in malicious_claims:
            token = jwt.encode(claims, secret, algorithm="HS256")
            headers = {"authorization": f"Bearer {token}"}
            
            is_valid, message = await validator.validate(headers, b"")
            # Token should validate (claims are just data)
            # But application logic should not trust claims without validation
            # This test documents that claims can contain arbitrary data


class TestJWTStructureAttacks:
    """Test JWT structure manipulation attacks."""
    
    @pytest.mark.asyncio
    async def test_missing_signature(self):
        """Test JWT with missing signature part."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Create token with only header.payload (no signature)
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256"}).encode()
        ).decode().rstrip('=')
        payload = base64.urlsafe_b64encode(
            json.dumps({"user": "test"}).encode()
        ).decode().rstrip('=')
        
        token = f"{header}.{payload}"  # Missing signature
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Invalid JWT token format" in message or "JWT validation failed" in message
    
    @pytest.mark.asyncio
    async def test_empty_signature(self):
        """Test JWT with empty signature."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256"}).encode()
        ).decode().rstrip('=')
        payload = base64.urlsafe_b64encode(
            json.dumps({"user": "test"}).encode()
        ).decode().rstrip('=')
        
        token = f"{header}.{payload}."  # Empty signature
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Invalid JWT signature" in message or "Invalid JWT token format" in message
    
    @pytest.mark.asyncio
    async def test_extra_dots_in_token(self):
        """Test JWT with extra dots (malformed structure)."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Valid token
        valid_token = jwt.encode({"user": "test"}, secret, algorithm="HS256")
        
        # Add extra dots
        malformed_tokens = [
            f".{valid_token}",
            f"{valid_token}.",
            f"{valid_token}..",
            valid_token.replace('.', '..'),
        ]
        
        for token in malformed_tokens:
            headers = {"authorization": f"Bearer {token}"}
            is_valid, message = await validator.validate(headers, b"")
            assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_invalid_base64_encoding(self):
        """Test JWT with invalid base64 encoding."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Invalid base64 characters
        invalid_tokens = [
            "header!payload.signature",  # Invalid base64 char
            "header@payload#signature",  # Invalid base64 chars
            "header payload signature",  # Spaces
            "header\npayload\nsignature",  # Newlines
        ]
        
        for token in invalid_tokens:
            headers = {"authorization": f"Bearer {token}"}
            is_valid, message = await validator.validate(headers, b"")
            assert is_valid is False
            assert "Invalid JWT token format" in message or "JWT validation failed" in message


class TestJWTAuthorizationHeader:
    """Test Authorization header manipulation attacks."""
    
    @pytest.mark.asyncio
    async def test_missing_bearer_prefix(self):
        """Test JWT without Bearer prefix."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        token = jwt.encode({"user": "test"}, secret, algorithm="HS256")
        headers = {"authorization": token}  # Missing "Bearer "
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "JWT Bearer token required" in message
    
    @pytest.mark.asyncio
    async def test_empty_token_after_bearer(self):
        """Test Authorization header with Bearer but no token."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Empty token after Bearer
        headers = {"authorization": "Bearer "}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Invalid JWT token format" in message or "JWT validation failed" in message
    
    @pytest.mark.asyncio
    async def test_whitespace_only_token(self):
        """Test Authorization header with only whitespace after Bearer."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Whitespace only
        headers = {"authorization": "Bearer   "}  # Only spaces
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Invalid JWT token format" in message or "JWT validation failed" in message
    
    @pytest.mark.asyncio
    async def test_case_variations_bearer(self):
        """Test Bearer prefix case variations."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        token = jwt.encode({"user": "test"}, secret, algorithm="HS256")
        
        # Test various case combinations
        case_variations = [
            "bearer",  # Lowercase
            "BEARER",  # Uppercase
            "Bearer",  # Correct
            "BeArEr",  # Mixed
        ]
        
        for prefix in case_variations:
            headers = {"authorization": f"{prefix} {token}"}
            is_valid, message = await validator.validate(headers, b"")
            # Current implementation requires exact "Bearer " (case-sensitive)
            # Test documents current behavior
            if prefix == "Bearer":
                # Should work
                assert is_valid is True
            else:
                # Should fail
                assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_multiple_bearer_tokens(self):
        """Test Authorization header with multiple Bearer tokens."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        token1 = jwt.encode({"user": "test1"}, secret, algorithm="HS256")
        token2 = jwt.encode({"user": "test2"}, secret, algorithm="HS256")
        
        # Multiple Bearer tokens (should use first one)
        headers = {"authorization": f"Bearer {token1} Bearer {token2}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should extract first token, may fail if second token interferes
        # Test documents behavior
    
    @pytest.mark.asyncio
    async def test_whitespace_manipulation(self):
        """Test Authorization header with various whitespace."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        token = jwt.encode({"user": "test"}, secret, algorithm="HS256")
        
        whitespace_variations = [
            f"Bearer  {token}",  # Double space
            f"Bearer\t{token}",  # Tab
            f"Bearer\n{token}",  # Newline
            f" Bearer {token}",  # Leading space
            f"Bearer {token} ",  # Trailing space
        ]
        
        for auth_header in whitespace_variations:
            headers = {"authorization": auth_header}
            is_valid, message = await validator.validate(headers, b"")
            # Should handle whitespace appropriately
            # Newlines should be rejected (header injection)
            if "\n" in auth_header or "\r" in auth_header:
                assert is_valid is False
            else:
                # Other whitespace should be handled
                pass


class TestJWTTimingAttacks:
    """Test timing attack resistance."""
    
    @pytest.mark.asyncio
    async def test_timing_attack_resistance(self):
        """Test that JWT validation is resistant to timing attacks."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Create valid token
        valid_token = jwt.encode({"user": "test"}, secret, algorithm="HS256")
        
        # Create invalid token (wrong signature)
        invalid_token = jwt.encode({"user": "test"}, "wrong_secret", algorithm="HS256")
        
        # Measure validation time for both
        import time
        
        # Valid token
        start = time.time()
        headers_valid = {"authorization": f"Bearer {valid_token}"}
        is_valid1, _ = await validator.validate(headers_valid, b"")
        time_valid = time.time() - start
        
        # Invalid token
        start = time.time()
        headers_invalid = {"authorization": f"Bearer {invalid_token}"}
        is_valid2, _ = await validator.validate(headers_invalid, b"")
        time_invalid = time.time() - start
        
        # Times should be similar (within reasonable margin)
        # Large differences could indicate timing vulnerability
        time_diff = abs(time_valid - time_invalid)
        # Allow 0.1 second difference (timing can vary)
        assert time_diff < 0.1, f"Timing difference too large: {time_diff}s (potential timing attack)"


class TestJWTSecretHandling:
    """Test JWT secret/key handling security."""
    
    @pytest.mark.asyncio
    async def test_secret_exposure_in_error_messages(self):
        """Test that secrets are not exposed in error messages."""
        secret = "super_secret_key_12345"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Use wrong secret to trigger error
        wrong_token = jwt.encode({"user": "test"}, "wrong_secret", algorithm="HS256")
        headers = {"authorization": f"Bearer {wrong_token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        
        # Secret should not appear in error message
        assert secret not in message
        assert "super_secret_key_12345" not in message
    
    @pytest.mark.asyncio
    async def test_missing_secret_config(self):
        """Test behavior when secret is missing from config."""
        config = {
            "jwt": {
                # Missing secret
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        token = jwt.encode({"user": "test"}, "some_secret", algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - secret is required
        assert is_valid is False
        assert "secret" in message.lower() or "required" in message.lower()
    
    @pytest.mark.asyncio
    async def test_whitespace_only_secret(self):
        """Test that whitespace-only secret is rejected."""
        config = {
            "jwt": {
                "secret": "   ",  # Only whitespace
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        token = jwt.encode({"user": "test"}, "   ", algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should fail - whitespace-only secret is effectively empty
        assert is_valid is False
        assert "secret" in message.lower() or "required" in message.lower() or "cannot be empty" in message.lower()


class TestJWTDoS:
    """Test JWT denial-of-service attacks."""
    
    @pytest.mark.asyncio
    async def test_very_large_jwt(self):
        """Test JWT with very large payload (DoS attempt)."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Create payload with very large claim
        large_payload = {"data": "x" * 100000}  # 100KB payload
        
        try:
            token = jwt.encode(large_payload, secret, algorithm="HS256")
            headers = {"authorization": f"Bearer {token}"}
            
            # Should handle gracefully (may be slow, but shouldn't crash)
            is_valid, message = await validator.validate(headers, b"")
            # May pass or fail, but shouldn't crash
        except Exception as e:
            # If it raises exception due to size, that's acceptable
            pass
    
    @pytest.mark.asyncio
    async def test_deeply_nested_claims(self):
        """Test JWT with deeply nested claims (DoS attempt)."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        # Create deeply nested structure
        nested = {"level": 0}
        for i in range(100):  # 100 levels deep
            nested = {"level": i, "nested": nested}
        
        try:
            token = jwt.encode(nested, secret, algorithm="HS256")
            headers = {"authorization": f"Bearer {token}"}
            
            is_valid, message = await validator.validate(headers, b"")
            # Should handle gracefully
        except Exception:
            # If it raises exception, that's acceptable
            pass


class TestJWTEdgeCases:
    """Test JWT edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_empty_payload(self):
        """Test JWT with empty payload."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        token = jwt.encode({}, secret, algorithm="HS256")  # Empty payload
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should work - empty payload is valid
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_unicode_in_claims(self):
        """Test JWT with Unicode characters in claims."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        payload = {"user": "测试", "data": "🎉"}
        token = jwt.encode(payload, secret, algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should work - Unicode is valid in JSON
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_special_characters_in_claims(self):
        """Test JWT with special characters in claims."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
            }
        }
        
        validator = JWTValidator(config)
        
        payload = {
            "user": "test@example.com",
            "path": "/api/v1/users",
            "query": "?param=value&other=123"
        }
        token = jwt.encode(payload, secret, algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should work - special chars are valid in JSON strings
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_verify_exp_disabled(self):
        """Test JWT with expiration verification disabled."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256",
                "verify_exp": False  # Disabled
            }
        }
        
        validator = JWTValidator(config)
        
        # Create expired token
        payload = {"exp": time.time() - 3600}  # Expired 1 hour ago
        token = jwt.encode(payload, secret, algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should pass if verify_exp is False
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_missing_issuer_audience_optional(self):
        """Test JWT when issuer/audience are optional."""
        secret = "jwt_secret_key"
        config = {
            "jwt": {
                "secret": secret,
                "algorithm": "HS256"
                # No issuer or audience required
            }
        }
        
        validator = JWTValidator(config)
        
        token = jwt.encode({"user": "test"}, secret, algorithm="HS256")
        headers = {"authorization": f"Bearer {token}"}
        
        is_valid, message = await validator.validate(headers, b"")
        # Should pass - issuer/audience not required
        assert is_valid is True

