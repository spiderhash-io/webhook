"""
Security tests for Task Manager - DoS, resource exhaustion, race conditions, and configuration attacks.

These tests verify that the Task Manager properly prevents:
- DoS via task exhaustion (filling semaphore)
- Memory leaks from tasks not being cleaned up
- Race conditions in task tracking
- Configuration injection via environment variables
- Integer overflow in metrics
- Timeout bypass attempts
- Task reference errors
"""
import pytest
import asyncio
import os
import time
from unittest.mock import patch
from src.webhook import TaskManager, task_manager


class TestTaskManagerSecurity:
    """Security-focused tests for Task Manager."""
    
    @pytest.fixture
    def small_task_manager(self):
        """Create a task manager with small limit for testing."""
        return TaskManager(max_concurrent_tasks=5, task_timeout=1.0)
    
    @pytest.mark.asyncio
    async def test_dos_task_exhaustion_semaphore_fill(self, small_task_manager):
        """Test that semaphore prevents DoS via task exhaustion."""
        # Create tasks to fill the semaphore
        async def long_task():
            await asyncio.sleep(0.5)  # Long-running task
        
        tasks = []
        # Fill up to limit
        for i in range(5):
            task = await small_task_manager.create_task(long_task())
            tasks.append(task)
        
        # Verify we're at limit
        metrics = small_task_manager.get_metrics()
        assert metrics["active_tasks"] == 5
        assert metrics["queue_usage_percent"] == 100.0
        
        # Additional tasks should wait (semaphore blocks)
        # This prevents DoS by limiting concurrent tasks
        start_time = time.time()
        extra_task = await small_task_manager.create_task(long_task())
        elapsed = time.time() - start_time
        
        # Should have waited for a slot (at least 0.4 seconds if tasks take 0.5s)
        assert elapsed >= 0.3, "Semaphore should block when limit reached"
        
        # Clean up
        await asyncio.gather(*tasks, extra_task, return_exceptions=True)
    
    @pytest.mark.asyncio
    async def test_memory_leak_prevention_task_cleanup(self, small_task_manager):
        """Test that completed tasks are properly cleaned up to prevent memory leaks."""
        async def quick_task():
            await asyncio.sleep(0.01)
            return "done"
        
        # Create many tasks
        tasks = []
        for i in range(20):
            task = await small_task_manager.create_task(quick_task())
            tasks.append(task)
        
        # Wait for all to complete
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Give time for cleanup
        await asyncio.sleep(0.1)
        
        metrics = small_task_manager.get_metrics()
        # Active tasks should be cleaned up (not accumulate)
        assert metrics["active_tasks"] <= 5, "Completed tasks should be cleaned up"
        assert metrics["total_tasks_completed"] == 20, "All tasks should be tracked"
    
    @pytest.mark.asyncio
    async def test_race_condition_task_tracking(self, small_task_manager):
        """Test that task tracking is thread-safe (no race conditions)."""
        async def quick_task():
            await asyncio.sleep(0.01)
            return "done"
        
        # Create many tasks concurrently
        async def create_task():
            return await small_task_manager.create_task(quick_task())
        
        # Create 50 tasks concurrently (stress test)
        tasks = await asyncio.gather(*[create_task() for _ in range(50)], return_exceptions=True)
        
        # Wait for all to complete
        await asyncio.gather(*[t for t in tasks if isinstance(t, asyncio.Task)], return_exceptions=True)
        
        await asyncio.sleep(0.1)
        
        metrics = small_task_manager.get_metrics()
        # Metrics should be consistent (no race conditions)
        assert metrics["total_tasks_created"] == 50, "All tasks should be tracked"
        assert metrics["total_tasks_completed"] == 50, "All tasks should complete"
        # Active tasks should be cleaned up
        assert metrics["active_tasks"] <= 5, "No task accumulation from race conditions"
    
    @pytest.mark.asyncio
    async def test_configuration_injection_environment_variables(self):
        """Test that environment variable configuration is validated."""
        # Test with malicious environment variable values - should be rejected
        with patch.dict(os.environ, {"MAX_CONCURRENT_TASKS": "-1"}):
            # Should reject negative values
            with pytest.raises(ValueError, match="must be >= 1"):
                TaskManager(max_concurrent_tasks=int(os.getenv("MAX_CONCURRENT_TASKS", "100")))
        
        with patch.dict(os.environ, {"MAX_CONCURRENT_TASKS": "0"}):
            # Should reject zero values
            with pytest.raises(ValueError, match="must be >= 1"):
                TaskManager(max_concurrent_tasks=int(os.getenv("MAX_CONCURRENT_TASKS", "100")))
        
        with patch.dict(os.environ, {"TASK_TIMEOUT": "-1.0"}):
            # Should reject negative timeout values
            with pytest.raises(ValueError, match="must be >= 0.1"):
                TaskManager(task_timeout=float(os.getenv("TASK_TIMEOUT", "300.0")))
        
        # Test with extremely large values
        with patch.dict(os.environ, {"MAX_CONCURRENT_TASKS": "100000"}):
            # Should reject values exceeding security limit
            with pytest.raises(ValueError, match="exceeds security limit"):
                TaskManager(max_concurrent_tasks=int(os.getenv("MAX_CONCURRENT_TASKS", "100")))
        
        with patch.dict(os.environ, {"TASK_TIMEOUT": "100000.0"}):
            # Should reject timeout values exceeding security limit
            with pytest.raises(ValueError, match="exceeds security limit"):
                TaskManager(task_timeout=float(os.getenv("TASK_TIMEOUT", "300.0")))
    
    @pytest.mark.asyncio
    async def test_integer_overflow_metrics_calculation(self, small_task_manager):
        """Test that metrics calculations don't overflow."""
        # Create many tasks to test counter overflow
        async def quick_task():
            await asyncio.sleep(0.001)
        
        # Create 1000 tasks (test counter doesn't overflow)
        tasks = []
        for i in range(1000):
            task = await small_task_manager.create_task(quick_task())
            tasks.append(task)
        
        # Wait for all
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.sleep(0.1)
        
        metrics = small_task_manager.get_metrics()
        # Counters should handle large numbers (Python ints are arbitrary precision)
        assert metrics["total_tasks_created"] == 1000
        assert metrics["total_tasks_completed"] == 1000
        assert isinstance(metrics["total_tasks_created"], int)
        assert isinstance(metrics["total_tasks_completed"], int)
    
    @pytest.mark.asyncio
    async def test_timeout_bypass_attempts(self, small_task_manager):
        """Test that timeout cannot be bypassed."""
        # Attempt to bypass timeout with extremely large value - should be rejected
        async def slow_task():
            await asyncio.sleep(10.0)
        
        # Try to set timeout to very large value - should raise ValueError
        with pytest.raises(ValueError, match="exceeds security limit"):
            await small_task_manager.create_task(slow_task(), timeout=1000000.0)
    
    @pytest.mark.asyncio
    async def test_task_reference_error_bug(self, small_task_manager):
        """Test for the bug where task_wrapper references 'task' before it's defined."""
        # This test documents a potential bug: task_wrapper() references 'task' on line 74
        # but 'task' is defined on line 81. This could cause NameError.
        
        async def test_task():
            await asyncio.sleep(0.01)
            return "success"
        
        # This should work (task is defined before wrapper executes)
        # But the closure references task before it exists in the closure scope
        task = await small_task_manager.create_task(test_task())
        
        # Should complete without NameError
        result = await task
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_semaphore_release_on_exception(self, small_task_manager):
        """Test that semaphore is released even when task raises exception."""
        async def failing_task():
            raise ValueError("Task failed")
        
        # Create task that will fail
        task = await small_task_manager.create_task(failing_task())
        
        try:
            await task
        except Exception:
            pass  # Expected
        
        # Semaphore should be released (allowing new tasks)
        await asyncio.sleep(0.01)
        
        # Should be able to create new tasks
        async def success_task():
            return "success"
        
        task2 = await small_task_manager.create_task(success_task())
        result = await task2
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_semaphore_release_on_timeout(self, small_task_manager):
        """Test that semaphore is released when task times out."""
        async def slow_task():
            await asyncio.sleep(10.0)  # Longer than timeout
        
        # Create task that will timeout
        task = await small_task_manager.create_task(slow_task(), timeout=0.1)
        
        try:
            await task
        except Exception:
            pass  # Expected timeout
        
        # Semaphore should be released
        await asyncio.sleep(0.01)
        
        # Should be able to create new tasks
        async def success_task():
            return "success"
        
        task2 = await small_task_manager.create_task(success_task())
        result = await task2
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_division_by_zero_metrics(self):
        """Test that metrics calculation handles division by zero."""
        # Create manager with max_concurrent_tasks=0 (edge case) - should be rejected
        with pytest.raises(ValueError, match="must be >= 1"):
            TaskManager(max_concurrent_tasks=0, task_timeout=1.0)
        
        # Test with valid minimum value
        manager = TaskManager(max_concurrent_tasks=1, task_timeout=1.0)
        metrics = manager.get_metrics()
        # Should handle division correctly
        assert "queue_usage_percent" in metrics
        assert metrics["queue_usage_percent"] == 0.0  # No active tasks
    
    @pytest.mark.asyncio
    async def test_concurrent_metrics_access(self, small_task_manager):
        """Test that metrics can be accessed concurrently without race conditions."""
        async def task():
            await asyncio.sleep(0.01)
        
        async def get_metrics():
            return small_task_manager.get_metrics()
        
        # Create tasks and read metrics concurrently
        tasks = [small_task_manager.create_task(task()) for _ in range(10)]
        metrics_reads = [get_metrics() for _ in range(10)]
        
        # Both should complete without errors
        await asyncio.gather(*tasks, *metrics_reads, return_exceptions=True)
        
        # Metrics should be consistent
        final_metrics = small_task_manager.get_metrics()
        assert final_metrics["total_tasks_created"] == 10
    
    @pytest.mark.asyncio
    async def test_task_cleanup_periodic_trigger(self, small_task_manager):
        """Test that periodic cleanup is triggered correctly."""
        async def quick_task():
            await asyncio.sleep(0.01)
        
        # Create tasks in batches to trigger periodic cleanup (every 10 tasks)
        for batch in range(3):
            tasks = []
            for i in range(10):
                task = await small_task_manager.create_task(quick_task())
                tasks.append(task)
            
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(0.01)
        
        # Cleanup should have been triggered multiple times
        metrics = small_task_manager.get_metrics()
        assert metrics["total_tasks_created"] == 30
        assert metrics["active_tasks"] <= 5  # Should be cleaned up
    
    @pytest.mark.asyncio
    async def test_extremely_large_timeout_value(self, small_task_manager):
        """Test handling of extremely large timeout values."""
        async def quick_task():
            await asyncio.sleep(0.01)
        
        # Test with very large timeout (potential DoS) - should be rejected
        with pytest.raises(ValueError, match="exceeds security limit"):
            await small_task_manager.create_task(quick_task(), timeout=1e10)
    
    @pytest.mark.asyncio
    async def test_zero_timeout_handling(self, small_task_manager):
        """Test handling of zero timeout."""
        async def quick_task():
            await asyncio.sleep(0.01)
        
        # Test with zero timeout - should be rejected
        with pytest.raises(ValueError, match="must be >= 0.1"):
            await small_task_manager.create_task(quick_task(), timeout=0.0)
        
        # Test with minimum valid timeout
        task = await small_task_manager.create_task(quick_task(), timeout=0.1)
        start_time = time.time()
        await task
        elapsed = time.time() - start_time
        # Should complete quickly
        assert elapsed < 0.2

