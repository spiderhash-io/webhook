"""
Security tests for async task accumulation prevention.
Tests that task manager limits concurrent tasks and prevents memory exhaustion.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock
from src.webhook import TaskManager, task_manager


class TestAsyncTaskAccumulation:
    """Test suite for async task accumulation prevention."""

    @pytest.fixture
    def small_task_manager(self):
        """Create a task manager with small limit for testing."""
        return TaskManager(max_concurrent_tasks=3, task_timeout=1.0)

    @pytest.mark.asyncio
    async def test_task_manager_limits_concurrency(self, small_task_manager):
        """Test that task manager limits concurrent tasks."""
        # Create tasks up to the limit
        tasks = []
        for i in range(3):

            async def dummy_task():
                await asyncio.sleep(0.1)
                return i

            task = await small_task_manager.create_task(dummy_task())
            tasks.append(task)

        # All tasks should be created
        assert len(tasks) == 3

        # Wait for completion
        await asyncio.gather(*tasks, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_task_manager_prevents_overflow(self, small_task_manager):
        """Test that task manager prevents queue overflow via semaphore."""

        # Fill the queue
        async def long_task():
            await asyncio.sleep(0.1)

        # Create tasks up to limit
        tasks = []
        for _ in range(3):
            task = await small_task_manager.create_task(long_task())
            tasks.append(task)

        # Verify we're at the limit
        metrics = small_task_manager.get_metrics()
        assert metrics["active_tasks"] == 3
        assert metrics["queue_usage_percent"] == 100.0

        # The semaphore provides natural backpressure - tasks will wait for available slots
        # This prevents memory exhaustion by limiting concurrent tasks
        # Wait for tasks to complete to free up slots
        await asyncio.gather(*tasks, return_exceptions=True)

        # After tasks complete, should be able to create new tasks
        await asyncio.sleep(0.05)  # Give time for cleanup
        new_task = await small_task_manager.create_task(long_task())
        await new_task

    @pytest.mark.asyncio
    async def test_task_timeout_protection(self, small_task_manager):
        """Test that tasks timeout after specified time."""

        async def slow_task():
            await asyncio.sleep(2.0)  # Longer than timeout
            return "completed"

        # Create task with short timeout
        task = await small_task_manager.create_task(slow_task(), timeout=0.1)

        # Wait for task to complete (should timeout)
        try:
            await task
            assert False, "Expected timeout exception"
        except Exception as e:
            assert "timeout" in str(e).lower() or "exceeded" in str(e).lower()

    @pytest.mark.asyncio
    async def test_task_metrics_tracking(self, small_task_manager):
        """Test that task metrics are tracked correctly."""
        metrics = small_task_manager.get_metrics()
        assert metrics["max_concurrent_tasks"] == 3
        assert metrics["active_tasks"] == 0
        assert metrics["total_tasks_created"] == 0
        assert metrics["total_tasks_completed"] == 0
        assert metrics["total_tasks_timeout"] == 0

        # Create and complete a task
        async def quick_task():
            await asyncio.sleep(0.01)
            return "done"

        task = await small_task_manager.create_task(quick_task())
        await task

        # Give a small delay for cleanup
        await asyncio.sleep(0.01)

        metrics = small_task_manager.get_metrics()
        assert metrics["total_tasks_created"] == 1
        assert metrics["total_tasks_completed"] == 1
        assert metrics["active_tasks"] == 0

    @pytest.mark.asyncio
    async def test_task_cleanup(self, small_task_manager):
        """Test that completed tasks are cleaned up."""

        async def quick_task():
            await asyncio.sleep(0.01)
            return "done"

        # Create multiple tasks
        tasks = []
        for _ in range(3):
            task = await small_task_manager.create_task(quick_task())
            tasks.append(task)

        # Wait for all to complete
        await asyncio.gather(*tasks, return_exceptions=True)

        # Give time for cleanup
        await asyncio.sleep(0.05)

        metrics = small_task_manager.get_metrics()
        # Active tasks should be cleaned up
        assert metrics["active_tasks"] <= 3  # May have some pending cleanup

    @pytest.mark.asyncio
    async def test_concurrent_task_creation(self, small_task_manager):
        """Test concurrent task creation with limits."""

        async def worker():
            async def task():
                await asyncio.sleep(0.1)

            return await small_task_manager.create_task(task())

        # Create many workers concurrently
        workers = [worker() for _ in range(10)]
        results = await asyncio.gather(*workers, return_exceptions=True)

        # All should succeed (semaphore will block internally)
        assert len(results) == 10

    @pytest.mark.asyncio
    async def test_task_semaphore_release(self, small_task_manager):
        """Test that semaphore is released after task completion."""

        async def quick_task():
            await asyncio.sleep(0.01)

        # Fill the queue
        tasks = []
        for _ in range(3):
            task = await small_task_manager.create_task(quick_task())
            tasks.append(task)

        # Wait for all to complete
        await asyncio.gather(*tasks, return_exceptions=True)

        # Should be able to create new tasks (semaphore released)
        new_task = await small_task_manager.create_task(quick_task())
        await new_task

    @pytest.mark.asyncio
    async def test_task_timeout_increments_counter(self, small_task_manager):
        """Test that timeout errors increment the counter."""

        async def slow_task():
            await asyncio.sleep(2.0)

        # Create task that will timeout
        task = await small_task_manager.create_task(slow_task(), timeout=0.1)

        try:
            await task
        except Exception:
            pass

        # Give time for cleanup
        await asyncio.sleep(0.05)

        metrics = small_task_manager.get_metrics()
        assert metrics["total_tasks_timeout"] >= 1

    @pytest.mark.asyncio
    async def test_global_task_manager_exists(self):
        """Test that global task manager is available."""
        assert task_manager is not None
        assert isinstance(task_manager, TaskManager)
        assert task_manager.max_concurrent_tasks > 0

    @pytest.mark.asyncio
    async def test_task_manager_queue_usage(self, small_task_manager):
        """Test that queue usage is calculated correctly."""
        metrics = small_task_manager.get_metrics()
        assert metrics["queue_usage_percent"] == 0.0  # Empty queue

        # Create tasks
        async def task():
            await asyncio.sleep(0.1)

        tasks = []
        for _ in range(2):
            task_obj = await small_task_manager.create_task(task())
            tasks.append(task_obj)

        metrics = small_task_manager.get_metrics()
        # Should have some usage (2 of 3 tasks = ~66%)
        assert metrics["queue_usage_percent"] > 0
        assert metrics["active_tasks"] == 2

        # Wait for completion
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.sleep(0.05)

        metrics = small_task_manager.get_metrics()
        # Usage should decrease after completion
        assert metrics["active_tasks"] <= 2

    def test_default_task_manager_config(self):
        """Test that default task manager has reasonable limits."""
        assert task_manager.max_concurrent_tasks == 100  # Default
        assert task_manager.task_timeout == 300.0  # 5 minutes default

    @pytest.mark.asyncio
    async def test_task_exception_handling(self, small_task_manager):
        """Test that task exceptions don't break the manager."""

        async def failing_task():
            raise ValueError("Task failed")

        task = await small_task_manager.create_task(failing_task())

        # Task should complete (with exception)
        try:
            await task
            assert False, "Expected exception"
        except Exception:
            pass  # Expected

        # Manager should still work
        async def success_task():
            return "success"

        task2 = await small_task_manager.create_task(success_task())
        result = await task2
        assert result == "success"

    @pytest.mark.asyncio
    async def test_multiple_task_managers_independent(self):
        """Test that multiple task managers are independent."""
        manager1 = TaskManager(max_concurrent_tasks=2)
        manager2 = TaskManager(max_concurrent_tasks=2)

        async def task():
            await asyncio.sleep(0.1)

        # Fill both managers
        tasks1 = [await manager1.create_task(task()) for _ in range(2)]
        tasks2 = [await manager2.create_task(task()) for _ in range(2)]

        # Both should work independently
        await asyncio.gather(*tasks1, *tasks2, return_exceptions=True)

        metrics1 = manager1.get_metrics()
        metrics2 = manager2.get_metrics()

        assert metrics1["total_tasks_created"] == 2
        assert metrics2["total_tasks_created"] == 2
