"""
Pytest configuration for test suite.
Excludes performance tests by default.
"""
import pytest
import sys


def pytest_configure(config):
    """Configure pytest to exclude performance tests by default."""
    # Add performance marker if not already defined
    config.addinivalue_line(
        "markers", "performance: Performance/load tests (deselect with '-m \"not performance\"')"
    )
    config.addinivalue_line(
        "markers", "slow: Slow tests that should not run by default (deselect with '-m \"not slow\"')"
    )


def pytest_collection_modifyitems(config, items):
    """Automatically exclude performance test files from collection."""
    # Files to exclude (standalone performance test scripts)
    performance_files = [
        'performance_test_single.py',
        'performance_test_multi_instance.py',
        'performance_test_redis.py',
    ]
    
    # Remove performance test files from collection
    items[:] = [
        item for item in items
        if not any(perf_file in str(item.fspath) for perf_file in performance_files)
    ]

