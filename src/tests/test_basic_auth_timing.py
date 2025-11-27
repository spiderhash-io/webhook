"""
Security tests for BasicAuthValidator timing attack prevention.
Tests constant-time comparison for both username and password to prevent timing-based attacks.
"""
import pytest
import base64
import time
import statistics
from src.validators import BasicAuthValidator


class TestBasicAuthTiming:
    """Test suite for BasicAuthValidator timing attack prevention."""
    
    @pytest.mark.asyncio
    async def test_basic_auth_valid_credentials(self):
        """Test that valid basic auth credentials are accepted."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        validator = BasicAuthValidator(config)
        
        credentials = "admin:secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is True
        assert "Valid basic authentication" in message
    
    @pytest.mark.asyncio
    async def test_basic_auth_invalid_username(self):
        """Test that invalid username is rejected."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        validator = BasicAuthValidator(config)
        
        credentials = "wronguser:secret123"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Invalid credentials" in message
    
    @pytest.mark.asyncio
    async def test_basic_auth_invalid_password(self):
        """Test that invalid password is rejected."""
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        validator = BasicAuthValidator(config)
        
        credentials = "admin:wrongpass"
        encoded = base64.b64encode(credentials.encode()).decode()
        headers = {"authorization": f"Basic {encoded}"}
        
        is_valid, message = await validator.validate(headers, b"")
        assert is_valid is False
        assert "Invalid credentials" in message
    
    @pytest.mark.asyncio
    async def test_basic_auth_username_timing_attack_resistance(self):
        """
        Test that username timing attacks are prevented by using constant-time comparison.
        
        This test measures the time taken to validate usernames and ensures
        that valid and invalid usernames take approximately the same time,
        preventing timing-based username enumeration.
        """
        config = {
            "basic_auth": {
                "username": "a" * 100,  # Long username for better timing measurement
                "password": "secret123"
            }
        }
        validator = BasicAuthValidator(config)
        
        valid_username = "a" * 100
        invalid_username_early = "b" + "a" * 99  # Wrong first char
        invalid_username_late = "a" * 99 + "b"  # Wrong last char
        invalid_username_wrong_length = "a" * 99  # Wrong length
        
        # Measure validation times
        iterations = 100
        valid_times = []
        invalid_early_times = []
        invalid_late_times = []
        invalid_length_times = []
        
        for _ in range(iterations):
            # Valid username
            credentials = f"{valid_username}:secret123"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            valid_times.append(time.perf_counter() - start)
            
            # Invalid username (early mismatch)
            credentials = f"{invalid_username_early}:secret123"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            invalid_early_times.append(time.perf_counter() - start)
            
            # Invalid username (late mismatch)
            credentials = f"{invalid_username_late}:secret123"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            invalid_late_times.append(time.perf_counter() - start)
            
            # Invalid username (wrong length)
            credentials = f"{invalid_username_wrong_length}:secret123"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            invalid_length_times.append(time.perf_counter() - start)
        
        # Calculate average times
        avg_valid = statistics.mean(valid_times)
        avg_invalid_early = statistics.mean(invalid_early_times)
        avg_invalid_late = statistics.mean(invalid_late_times)
        avg_invalid_length = statistics.mean(invalid_length_times)
        
        # All times should be similar (within reasonable variance)
        # Allow 20% variance to account for system noise
        max_time = max(avg_valid, avg_invalid_early, avg_invalid_late, avg_invalid_length)
        min_time = min(avg_valid, avg_invalid_early, avg_invalid_late, avg_invalid_length)
        
        # The difference should be small relative to the average
        time_diff_ratio = (max_time - min_time) / max_time if max_time > 0 else 0
        
        # Assert that timing difference is less than 20% (indicating constant-time comparison)
        assert time_diff_ratio < 0.20, (
            f"Username timing attack vulnerability detected! "
            f"Time difference ratio: {time_diff_ratio:.2%}, "
            f"Valid: {avg_valid*1000:.3f}ms, "
            f"Invalid (early): {avg_invalid_early*1000:.3f}ms, "
            f"Invalid (late): {avg_invalid_late*1000:.3f}ms, "
            f"Invalid (length): {avg_invalid_length*1000:.3f}ms"
        )
    
    @pytest.mark.asyncio
    async def test_basic_auth_password_timing_attack_resistance(self):
        """
        Test that password timing attacks are prevented (verify existing protection).
        """
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "a" * 100  # Long password for better timing measurement
            }
        }
        validator = BasicAuthValidator(config)
        
        valid_password = "a" * 100
        invalid_password_early = "b" + "a" * 99  # Wrong first char
        invalid_password_late = "a" * 99 + "b"  # Wrong last char
        
        # Measure validation times
        iterations = 100
        valid_times = []
        invalid_early_times = []
        invalid_late_times = []
        
        for _ in range(iterations):
            # Valid password
            credentials = f"admin:{valid_password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            valid_times.append(time.perf_counter() - start)
            
            # Invalid password (early mismatch)
            credentials = f"admin:{invalid_password_early}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            invalid_early_times.append(time.perf_counter() - start)
            
            # Invalid password (late mismatch)
            credentials = f"admin:{invalid_password_late}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            invalid_late_times.append(time.perf_counter() - start)
        
        # Calculate average times
        avg_valid = statistics.mean(valid_times)
        avg_invalid_early = statistics.mean(invalid_early_times)
        avg_invalid_late = statistics.mean(invalid_late_times)
        
        # All times should be similar
        max_time = max(avg_valid, avg_invalid_early, avg_invalid_late)
        min_time = min(avg_valid, avg_invalid_early, avg_invalid_late)
        time_diff_ratio = (max_time - min_time) / max_time if max_time > 0 else 0
        
        # Assert constant-time comparison
        assert time_diff_ratio < 0.20, (
            f"Password timing attack vulnerability detected! "
            f"Time difference ratio: {time_diff_ratio:.2%}"
        )
    
    @pytest.mark.asyncio
    async def test_basic_auth_both_credentials_timing(self):
        """
        Test timing when both username and password are wrong vs when only one is wrong.
        All should take similar time to prevent enumeration.
        """
        config = {
            "basic_auth": {
                "username": "admin",
                "password": "secret123"
            }
        }
        validator = BasicAuthValidator(config)
        
        iterations = 50
        both_wrong_times = []
        username_wrong_times = []
        password_wrong_times = []
        both_correct_times = []
        
        for _ in range(iterations):
            # Both wrong
            credentials = "wronguser:wrongpass"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            both_wrong_times.append(time.perf_counter() - start)
            
            # Username wrong
            credentials = "wronguser:secret123"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            username_wrong_times.append(time.perf_counter() - start)
            
            # Password wrong
            credentials = "admin:wrongpass"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            password_wrong_times.append(time.perf_counter() - start)
            
            # Both correct
            credentials = "admin:secret123"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            both_correct_times.append(time.perf_counter() - start)
        
        # Calculate averages
        avg_both_wrong = statistics.mean(both_wrong_times)
        avg_username_wrong = statistics.mean(username_wrong_times)
        avg_password_wrong = statistics.mean(password_wrong_times)
        avg_both_correct = statistics.mean(both_correct_times)
        
        # All should be similar (within 20%)
        max_time = max(avg_both_wrong, avg_username_wrong, avg_password_wrong, avg_both_correct)
        min_time = min(avg_both_wrong, avg_username_wrong, avg_password_wrong, avg_both_correct)
        time_diff_ratio = (max_time - min_time) / max_time if max_time > 0 else 0
        
        assert time_diff_ratio < 0.20, (
            f"Timing attack vulnerability: different failure modes have different timings! "
            f"Time difference ratio: {time_diff_ratio:.2%}, "
            f"Both wrong: {avg_both_wrong*1000:.3f}ms, "
            f"Username wrong: {avg_username_wrong*1000:.3f}ms, "
            f"Password wrong: {avg_password_wrong*1000:.3f}ms, "
            f"Both correct: {avg_both_correct*1000:.3f}ms"
        )
    
    @pytest.mark.asyncio
    async def test_basic_auth_unicode_username_timing(self):
        """Test timing attack resistance with Unicode usernames."""
        config = {
            "basic_auth": {
                "username": "用户" * 50,  # Unicode username
                "password": "secret123"
            }
        }
        validator = BasicAuthValidator(config)
        
        valid_username = "用户" * 50
        invalid_username = "用户" * 49 + "X"
        
        iterations = 50
        valid_times = []
        invalid_times = []
        
        for _ in range(iterations):
            # Valid
            credentials = f"{valid_username}:secret123"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            valid_times.append(time.perf_counter() - start)
            
            # Invalid
            credentials = f"{invalid_username}:secret123"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            invalid_times.append(time.perf_counter() - start)
        
        avg_valid = statistics.mean(valid_times)
        avg_invalid = statistics.mean(invalid_times)
        time_diff_ratio = abs(avg_valid - avg_invalid) / max(avg_valid, avg_invalid) if max(avg_valid, avg_invalid) > 0 else 0
        
        assert time_diff_ratio < 0.20, f"Unicode username timing attack vulnerability: {time_diff_ratio:.2%}"
    
    @pytest.mark.asyncio
    async def test_basic_auth_case_sensitivity_timing(self):
        """Test that case-sensitive comparisons are constant-time."""
        config = {
            "basic_auth": {
                "username": "Admin",
                "password": "Secret123"
            }
        }
        validator = BasicAuthValidator(config)
        
        iterations = 50
        correct_case_times = []
        wrong_case_times = []
        
        for _ in range(iterations):
            # Correct case
            credentials = "Admin:Secret123"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            correct_case_times.append(time.perf_counter() - start)
            
            # Wrong case
            credentials = "admin:secret123"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {"authorization": f"Basic {encoded}"}
            start = time.perf_counter()
            await validator.validate(headers, b"")
            wrong_case_times.append(time.perf_counter() - start)
        
        avg_correct = statistics.mean(correct_case_times)
        avg_wrong = statistics.mean(wrong_case_times)
        time_diff_ratio = abs(avg_correct - avg_wrong) / max(avg_correct, avg_wrong) if max(avg_correct, avg_wrong) > 0 else 0
        
        assert time_diff_ratio < 0.20, f"Case sensitivity timing attack: {time_diff_ratio:.2%}"

