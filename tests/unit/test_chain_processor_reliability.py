import pytest
import asyncio
from unittest.mock import MagicMock, patch
from src.chain_processor import ChainProcessor, ChainResult
from src.modules.base import BaseModule


class HangingModule(BaseModule):
    """Mock module that hangs."""

    async def process(self, payload, headers):
        await asyncio.sleep(100)  # Hang for a long time


class FastModule(BaseModule):
    """Mock module that is fast."""

    async def process(self, payload, headers):
        pass


@pytest.mark.asyncio
async def test_parallel_execution_hang_reproduction():
    """Reproduce the issue where parallel execution hangs indefinitely."""
    mock_webhook_config = {"data_type": "json"}
    chain = ["hanging", "fast"]

    with patch("src.chain_processor.ModuleRegistry") as mock_registry:
        mock_hanging_class = MagicMock()
        mock_hanging_class.return_value = HangingModule({})

        mock_fast_class = MagicMock()
        mock_fast_class.return_value = FastModule({})

        mock_registry.get.side_effect = [mock_hanging_class, mock_fast_class]

        processor = ChainProcessor(
            chain=chain,
            chain_config={"execution": "parallel"},
            webhook_config=mock_webhook_config,
        )

        # This should hang if no timeout is implemented
        # We use wait_for here to detect the hang in the test
        try:
            await asyncio.wait_for(processor.execute({}, {}), timeout=1.0)
            pytest.fail("Should have timed out")
        except asyncio.TimeoutError:
            # This confirms it hangs indefinitely (or at least > 1s)
            pass


class FailingModule(BaseModule):
    """Mock module that fails quickly."""

    async def process(self, payload, headers):
        await asyncio.sleep(0.1)
        raise Exception("Quick failure")


@pytest.mark.asyncio
async def test_parallel_execution_cancel_on_failure():
    """
    Test that parallel execution cancels remaining tasks when one fails
    and continue_on_error=False.
    """
    mock_webhook_config = {"data_type": "json"}
    chain = ["failing", "hanging"]

    with patch("src.chain_processor.ModuleRegistry") as mock_registry:
        mock_failing_class = MagicMock()
        mock_failing_class.return_value = FailingModule({})

        mock_hanging_class = MagicMock()
        mock_hanging_class.return_value = HangingModule({})

        mock_registry.get.side_effect = [mock_failing_class, mock_hanging_class]

        # Configure continue_on_error=False
        processor = ChainProcessor(
            chain=chain,
            chain_config={"execution": "parallel", "continue_on_error": False},
            webhook_config=mock_webhook_config,
        )

        start_time = asyncio.get_event_loop().time()
        results = await processor.execute({}, {})
        end_time = asyncio.get_event_loop().time()

        duration = end_time - start_time

        # Should complete quickly (not wait for hanging module)
        assert duration < 1.0, f"Execution took too long: {duration}s"
        assert len(results) == 2

        # Failing module should have failed
        assert results[0].module_name == "failing"
        assert not results[0].success
        assert "Quick failure" in str(results[0].error)

        # Hanging module should have been cancelled
        assert results[1].module_name == "hanging"
        assert not results[1].success
        assert (
            "timed out" in str(results[1].error).lower()
            or "cancelled" in str(results[1].error).lower()
        )
    """
    Test that parallel execution respects the timeout configuration.
    """
    mock_webhook_config = {"data_type": "json"}
    chain = ["hanging", "fast"]

    with patch("src.chain_processor.ModuleRegistry") as mock_registry:
        mock_hanging_class = MagicMock()
        mock_hanging_class.return_value = HangingModule({})

        mock_fast_class = MagicMock()
        mock_fast_class.return_value = FastModule({})

        mock_registry.get.side_effect = [mock_hanging_class, mock_fast_class]

        # Configure a short timeout
        processor = ChainProcessor(
            chain=chain,
            chain_config={
                "execution": "parallel",
                "timeout": 0.5,  # 0.5 seconds timeout
            },
            webhook_config=mock_webhook_config,
        )

        # Execute - this should now return within 0.5 seconds and have a timeout error in results
        results = await processor.execute({}, {})

        assert len(results) == 2
        # One should have failed due to timeout
        assert any(not r.success for r in results)

        timeout_found = False
        for r in results:
            if r.error and "timed out" in str(r.error).lower():
                timeout_found = True
                break
        assert timeout_found, f"No timeout error found in results: {results}"
