import pytest
import os
import asyncio

def pytest_configure(config):
    """Set up test environment variables before any tests run."""
    # Use the docker-compose Redis port
    os.environ["REDIS_HOST"] = "localhost"
    os.environ["REDIS_PORT"] = "6380"


@pytest.fixture(autouse=True)
def clear_oauth1_nonce_tracker():
    """Clear OAuth 1.0 nonce tracker before and after each test to prevent test interference."""
    from src.validators import _oauth1_nonce_tracker
    
    # Clear before test - directly clear the nonces dict (safe for sequential tests)
    _oauth1_nonce_tracker.nonces.clear()
    
    yield
    
    # Clear after test
    _oauth1_nonce_tracker.nonces.clear()

