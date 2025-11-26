import pytest
import os

def pytest_configure(config):
    """Set up test environment variables before any tests run."""
    # Use the docker-compose Redis port
    os.environ["REDIS_HOST"] = "localhost"
    os.environ["REDIS_PORT"] = "6380"

