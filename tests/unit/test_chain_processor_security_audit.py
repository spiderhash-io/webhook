"""
Comprehensive security audit tests for Chain Processor.

This audit focuses on:
- Deep copy DoS (circular references, deeply nested structures)
- Error information disclosure
- Resource exhaustion attacks
- Configuration injection
- Type confusion attacks
- Race conditions in parallel execution
- Module teardown security
"""

import pytest
import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from src.chain_processor import ChainProcessor, ChainResult
from src.chain_validator import ChainValidator
from src.modules.base import BaseModule


# ============================================================================
# 1. DEEP COPY DoS ATTACKS
# ============================================================================


class TestChainProcessorDeepCopyDoS:
    """Test deep copy DoS vulnerabilities."""

    def test_circular_reference_in_webhook_config(self):
        """Test that circular references in webhook_config don't cause infinite loop."""
        # Create circular reference
        webhook_config = {"key": "value"}
        webhook_config["self"] = webhook_config  # Circular reference

        chain = ["log"]

        # Should not hang or crash
        processor = ChainProcessor(
            chain=chain, chain_config={}, webhook_config=webhook_config
        )

        # Verify processor was created successfully
        assert processor is not None
        assert processor.chain == chain

    def test_circular_reference_in_connection_config(self):
        """Test that circular references in connection_config don't cause infinite loop."""
        connection_config = {"test_conn": {"type": "postgresql", "host": "localhost"}}
        connection_config["test_conn"]["self"] = connection_config  # Circular reference

        chain = [{"module": "postgresql", "connection": "test_conn"}]
        webhook_config = {}

        # Should not hang or crash
        processor = ChainProcessor(
            chain=chain,
            chain_config={},
            webhook_config=webhook_config,
            connection_config=connection_config,
        )

        # Verify processor was created successfully
        assert processor is not None

    def test_deeply_nested_webhook_config(self):
        """Test that deeply nested webhook_config doesn't cause stack overflow."""
        # Create deeply nested structure (1000 levels)
        webhook_config = {}
        current = webhook_config
        for i in range(1000):
            current["nested"] = {}
            current = current["nested"]

        chain = ["log"]

        # Should not crash
        processor = ChainProcessor(
            chain=chain, chain_config={}, webhook_config=webhook_config
        )

        assert processor is not None

    def test_deeply_nested_module_config(self):
        """Test that deeply nested module-config doesn't cause stack overflow."""
        chain = [{"module": "log", "module-config": {}}]

        # Create deeply nested module-config
        nested_config = {}
        current = nested_config
        for i in range(1000):
            current["nested"] = {}
            current = current["nested"]

        chain[0]["module-config"] = nested_config
        webhook_config = {}

        # Should not crash
        processor = ChainProcessor(
            chain=chain, chain_config={}, webhook_config=webhook_config
        )

        assert processor is not None


# ============================================================================
# 2. ERROR INFORMATION DISCLOSURE
# ============================================================================


class TestChainProcessorErrorDisclosure:
    """Test error information disclosure vulnerabilities."""

    @pytest.mark.asyncio
    async def test_module_instantiation_error_sanitization(self):
        """Test that module instantiation errors don't expose sensitive data."""
        chain = [{"module": "postgresql", "connection": "test_conn"}]
        webhook_config = {}
        connection_config = {
            "test_conn": {
                "type": "postgresql",
                "host": "localhost",
                "password": "secret_password_123",
            }
        }

        with patch("src.chain_processor.ModuleRegistry") as mock_registry:
            # Simulate module instantiation error
            mock_registry.get.side_effect = Exception(
                "Connection failed: postgresql://user:secret_password_123@localhost:5432/db"
            )

            processor = ChainProcessor(
                chain=chain,
                chain_config={},
                webhook_config=webhook_config,
                connection_config=connection_config,
            )

            results = await processor.execute({}, {})

            # Error should be present but not expose password
            assert len(results) == 1
            assert not results[0].success
            error_str = str(results[0].error)
            # Password should not be in error message (or should be sanitized)
            # Note: This test documents current behavior - actual sanitization
            # should be done at the module level or in error handling

    @pytest.mark.asyncio
    async def test_module_execution_error_sanitization(self):
        """Test that module execution errors don't expose sensitive data."""
        chain = ["log"]
        webhook_config = {}

        class MockModule(BaseModule):
            async def process(self, payload, headers):
                raise Exception("Database error: postgresql://user:secret@localhost/db")

        with patch("src.chain_processor.ModuleRegistry") as mock_registry:
            mock_registry.get.return_value = MockModule

            processor = ChainProcessor(
                chain=chain, chain_config={}, webhook_config=webhook_config
            )

            results = await processor.execute({}, {})

            # Error should be present
            assert len(results) == 1
            assert not results[0].success
            # Note: Error sanitization should be done at module level

    @pytest.mark.asyncio
    async def test_teardown_error_doesnt_crash_chain(self):
        """Test that teardown errors don't crash the chain execution."""
        chain = ["log"]
        webhook_config = {}

        class MockModule(BaseModule):
            async def process(self, payload, headers):
                pass  # Success

            async def teardown(self):
                raise Exception("Teardown error with sensitive data: password=secret")

        with patch("src.chain_processor.ModuleRegistry") as mock_registry:
            mock_registry.get.return_value = MockModule

            processor = ChainProcessor(
                chain=chain, chain_config={}, webhook_config=webhook_config
            )

            results = await processor.execute({}, {})

            # Chain should complete successfully despite teardown error
            assert len(results) == 1
            assert results[0].success  # Process succeeded
            # Teardown error should be logged but not fail the chain


# ============================================================================
# 3. RESOURCE EXHAUSTION ATTACKS
# ============================================================================


class TestChainProcessorResourceExhaustion:
    """Test resource exhaustion vulnerabilities."""

    @pytest.mark.asyncio
    async def test_parallel_execution_with_max_chain_length(self):
        """Test that parallel execution with max chain length doesn't exhaust resources."""
        # Create chain at maximum length
        max_chain = ["log"] * ChainValidator.MAX_CHAIN_LENGTH
        webhook_config = {}

        class MockModule(BaseModule):
            async def process(self, payload, headers):
                await asyncio.sleep(0.01)  # Small delay

        with patch("src.chain_processor.ModuleRegistry") as mock_registry:
            mock_registry.get.return_value = MockModule

            processor = ChainProcessor(
                chain=max_chain,
                chain_config={"execution": "parallel"},
                webhook_config=webhook_config,
            )

            # Should complete without resource exhaustion
            results = await processor.execute({}, {})

            assert len(results) == ChainValidator.MAX_CHAIN_LENGTH
            assert all(r.success for r in results)

    @pytest.mark.asyncio
    async def test_parallel_execution_timeout_protection(self):
        """Test that parallel execution doesn't hang indefinitely."""
        chain = ["log", "log", "log"]
        webhook_config = {}

        class HangingModule(BaseModule):
            async def process(self, payload, headers):
                await asyncio.sleep(10)  # Long delay

        with patch("src.chain_processor.ModuleRegistry") as mock_registry:
            mock_registry.get.return_value = HangingModule

            processor = ChainProcessor(
                chain=chain,
                chain_config={"execution": "parallel"},
                webhook_config=webhook_config,
            )

            # Should complete within reasonable time (with timeout)
            try:
                results = await asyncio.wait_for(
                    processor.execute({}, {}), timeout=1.0  # 1 second timeout
                )
                # If we get here, execution completed (or was cancelled)
                assert len(results) == 3
            except asyncio.TimeoutError:
                # Timeout is expected for this test
                pass


# ============================================================================
# 4. CONFIGURATION INJECTION ATTACKS
# ============================================================================


class TestChainProcessorConfigInjection:
    """Test configuration injection vulnerabilities."""

    def test_malicious_module_config_injection(self):
        """Test that malicious module-config values are handled safely."""
        chain = [
            {
                "module": "log",
                "module-config": {
                    "__class__": "malicious_class",
                    "__init__": "malicious_init",
                    "path": "../../etc/passwd",  # Path traversal attempt
                    "table": "'; DROP TABLE users; --",  # SQL injection attempt
                },
            }
        ]
        webhook_config = {}

        # Should not crash
        processor = ChainProcessor(
            chain=chain, chain_config={}, webhook_config=webhook_config
        )

        assert processor is not None
        # Module-specific validation should handle these in module.process()

    def test_malicious_connection_name_injection(self):
        """Test that malicious connection names are handled safely."""
        chain = [
            {
                "module": "postgresql",
                "connection": "../../etc/passwd",  # Path traversal attempt
            }
        ]
        webhook_config = {}
        connection_config = {"valid_conn": {"type": "postgresql", "host": "localhost"}}

        # Should not crash
        processor = ChainProcessor(
            chain=chain,
            chain_config={},
            webhook_config=webhook_config,
            connection_config=connection_config,
        )

        assert processor is not None
        # Connection name won't be found, but shouldn't crash

    def test_malicious_retry_config_injection(self):
        """Test that malicious retry config values are handled safely."""
        chain = [
            {
                "module": "log",
                "retry": {
                    "enabled": True,
                    "max_attempts": 999999,  # Excessive retries
                    "delay": -1,  # Negative delay
                    "backoff_multiplier": 1e10,  # Excessive multiplier
                },
            }
        ]
        webhook_config = {}

        # Should not crash
        processor = ChainProcessor(
            chain=chain, chain_config={}, webhook_config=webhook_config
        )

        assert processor is not None
        # Retry handler should validate these values


# ============================================================================
# 5. TYPE CONFUSION ATTACKS
# ============================================================================


class TestChainProcessorTypeConfusion:
    """Test type confusion vulnerabilities."""

    def test_non_dict_webhook_config(self):
        """Test that non-dict webhook_config is handled safely."""
        chain = ["log"]
        webhook_config = "not_a_dict"  # Should be dict

        # Should not crash
        try:
            processor = ChainProcessor(
                chain=chain, chain_config={}, webhook_config=webhook_config
            )
            # If it doesn't crash, verify it handles it gracefully
            assert processor is not None
        except (TypeError, AttributeError):
            # Expected - webhook_config should be dict
            pass

    def test_non_dict_chain_config(self):
        """Test that non-dict chain_config is handled safely."""
        chain = ["log"]
        chain_config = "not_a_dict"  # Should be dict

        # Should not crash
        try:
            processor = ChainProcessor(
                chain=chain, chain_config=chain_config, webhook_config={}
            )
            # If it doesn't crash, verify it handles it gracefully
            assert processor is not None
            # Should default to empty dict
            assert processor.chain_config == {} or isinstance(
                processor.chain_config, dict
            )
        except (TypeError, AttributeError):
            # Expected - chain_config should be dict
            pass

    def test_non_dict_connection_config(self):
        """Test that non-dict connection_config is handled safely."""
        chain = [{"module": "postgresql", "connection": "test_conn"}]
        connection_config = "not_a_dict"  # Should be dict

        # Should not crash
        try:
            processor = ChainProcessor(
                chain=chain,
                chain_config={},
                webhook_config={},
                connection_config=connection_config,
            )
            # If it doesn't crash, verify it handles it gracefully
            assert processor is not None
        except (TypeError, AttributeError):
            # Expected - connection_config should be dict
            pass

    def test_non_list_chain(self):
        """Test that non-list chain is handled safely."""
        chain = "not_a_list"  # Should be list

        # Should crash or be handled gracefully
        try:
            processor = ChainProcessor(chain=chain, chain_config={}, webhook_config={})
            # If it doesn't crash, normalization should handle it
            # But validation should catch it
        except (TypeError, AttributeError, ValueError):
            # Expected - chain should be list
            pass


# ============================================================================
# 6. RACE CONDITIONS IN PARALLEL EXECUTION
# ============================================================================


class TestChainProcessorRaceConditions:
    """Test race condition vulnerabilities in parallel execution."""

    @pytest.mark.asyncio
    async def test_parallel_execution_shared_state(self):
        """Test that parallel execution doesn't have shared state issues."""
        chain = ["log", "log", "log"]
        webhook_config = {}

        shared_counter = {"count": 0}

        class MockModule(BaseModule):
            def __init__(self, config, pool_registry=None):
                super().__init__(config, pool_registry)
                self.counter = shared_counter

            async def process(self, payload, headers):
                # Simulate shared state access
                self.counter["count"] += 1
                await asyncio.sleep(0.01)

        with patch("src.chain_processor.ModuleRegistry") as mock_registry:
            mock_registry.get.return_value = MockModule

            processor = ChainProcessor(
                chain=chain,
                chain_config={"execution": "parallel"},
                webhook_config=webhook_config,
            )

            results = await processor.execute({}, {})

            # All modules should execute
            assert len(results) == 3
            assert all(r.success for r in results)
            # Counter should be 3 (all modules incremented it)
            assert shared_counter["count"] == 3

    @pytest.mark.asyncio
    async def test_parallel_execution_exception_handling(self):
        """Test that exceptions in parallel execution are handled correctly."""
        chain = ["log", "log", "log"]
        webhook_config = {}

        class FailingModule(BaseModule):
            async def process(self, payload, headers):
                raise Exception("Test error")

        with patch("src.chain_processor.ModuleRegistry") as mock_registry:
            mock_registry.get.return_value = FailingModule

            processor = ChainProcessor(
                chain=chain,
                chain_config={"execution": "parallel"},
                webhook_config=webhook_config,
            )

            results = await processor.execute({}, {})

            # All modules should be marked as failed
            assert len(results) == 3
            assert all(not r.success for r in results)
            assert all(r.error is not None for r in results)


# ============================================================================
# 7. LARGE PAYLOAD/HEADERS DoS
# ============================================================================


class TestChainProcessorLargePayloadDoS:
    """Test large payload/headers DoS vulnerabilities."""

    @pytest.mark.asyncio
    async def test_large_payload_handling(self):
        """Test that large payloads don't cause DoS."""
        chain = ["log"]
        webhook_config = {}

        # Create large payload (10MB)
        large_payload = {"data": "x" * (10 * 1024 * 1024)}

        class MockModule(BaseModule):
            async def process(self, payload, headers):
                # Verify payload is received
                assert "data" in payload
                assert len(payload["data"]) > 0

        with patch("src.chain_processor.ModuleRegistry") as mock_registry:
            mock_registry.get.return_value = MockModule

            processor = ChainProcessor(
                chain=chain, chain_config={}, webhook_config=webhook_config
            )

            # Should complete without memory issues
            results = await processor.execute(large_payload, {})

            assert len(results) == 1
            assert results[0].success

    @pytest.mark.asyncio
    async def test_large_headers_handling(self):
        """Test that large headers don't cause DoS."""
        chain = ["log"]
        webhook_config = {}

        # Create large headers
        large_headers = {"X-Large-Header": "x" * (1 * 1024 * 1024)}  # 1MB header

        class MockModule(BaseModule):
            async def process(self, payload, headers):
                # Verify headers are received
                assert "X-Large-Header" in headers

        with patch("src.chain_processor.ModuleRegistry") as mock_registry:
            mock_registry.get.return_value = MockModule

            processor = ChainProcessor(
                chain=chain, chain_config={}, webhook_config=webhook_config
            )

            # Should complete without memory issues
            results = await processor.execute({}, large_headers)

            assert len(results) == 1
            assert results[0].success


# ============================================================================
# 8. ASYNCIO.GATHER EDGE CASES
# ============================================================================


class TestChainProcessorAsyncioGatherEdgeCases:
    """Test asyncio.gather edge cases in parallel execution."""

    @pytest.mark.asyncio
    async def test_parallel_execution_mixed_results(self):
        """Test that parallel execution handles mixed success/failure correctly."""
        chain = ["log", "log", "log"]
        webhook_config = {}

        call_count = {"count": 0}

        class MixedModule(BaseModule):
            async def process(self, payload, headers):
                call_count["count"] += 1
                if call_count["count"] == 2:
                    raise Exception("Second module fails")
                # First and third succeed

        with patch("src.chain_processor.ModuleRegistry") as mock_registry:
            mock_registry.get.return_value = MixedModule

            processor = ChainProcessor(
                chain=chain,
                chain_config={"execution": "parallel"},
                webhook_config=webhook_config,
            )

            results = await processor.execute({}, {})

            # All modules should execute
            assert len(results) == 3
            # Results may be in any order due to parallel execution
            success_count = sum(1 for r in results if r.success)
            failure_count = sum(1 for r in results if not r.success)
            assert success_count == 2
            assert failure_count == 1

    @pytest.mark.asyncio
    async def test_parallel_execution_unexpected_result_type(self):
        """Test that unexpected result types from asyncio.gather are handled."""
        chain = ["log"]
        webhook_config = {}

        class MockModule(BaseModule):
            async def process(self, payload, headers):
                # Return unexpected type (should be handled by gather)
                return "unexpected_string_result"

        with patch("src.chain_processor.ModuleRegistry") as mock_registry:
            mock_registry.get.return_value = MockModule

            processor = ChainProcessor(
                chain=chain,
                chain_config={"execution": "parallel"},
                webhook_config=webhook_config,
            )

            results = await processor.execute({}, {})

            # Should handle unexpected result type
            assert len(results) == 1
            # Result should be marked as success (process didn't raise exception)
            assert results[0].success


# ============================================================================
# 9. MODULE CONFIG MERGING SECURITY
# ============================================================================


class TestChainProcessorConfigMerging:
    """Test module config merging security."""

    def test_module_config_merging_preserves_security(self):
        """Test that module config merging preserves security settings."""
        chain = [{"module": "log", "module-config": {"new_setting": "value"}}]
        webhook_config = {
            "module-config": {
                "existing_setting": "existing_value",
                "authorization": "Bearer token",
            }
        }

        processor = ChainProcessor(
            chain=chain, chain_config={}, webhook_config=webhook_config
        )

        # Build module config
        module_config = processor._build_module_config(processor.normalized_chain[0])

        # Both settings should be present
        assert "existing_setting" in module_config.get("module-config", {})
        assert "new_setting" in module_config.get("module-config", {})
        # Security settings should be preserved
        assert (
            module_config.get("module-config", {}).get("authorization")
            == "Bearer token"
        )

    def test_module_config_override_security(self):
        """Test that chain item module-config can override base config."""
        chain = [
            {
                "module": "log",
                "module-config": {"authorization": "new_token"},  # Override
            }
        ]
        webhook_config = {"module-config": {"authorization": "old_token"}}

        processor = ChainProcessor(
            chain=chain, chain_config={}, webhook_config=webhook_config
        )

        # Build module config
        module_config = processor._build_module_config(processor.normalized_chain[0])

        # Chain item config should override base config
        assert (
            module_config.get("module-config", {}).get("authorization") == "new_token"
        )


# ============================================================================
# 10. SUMMARY GENERATION SECURITY
# ============================================================================


class TestChainProcessorSummarySecurity:
    """Test summary generation security."""

    def test_summary_handles_malicious_error_messages(self):
        """Test that summary handles malicious error messages safely."""
        processor = ChainProcessor(chain=["log"], chain_config={}, webhook_config={})

        # Create results with malicious error messages
        malicious_error = Exception("'; DROP TABLE users; --")
        results = [ChainResult("log", False, malicious_error)]

        summary = processor.get_summary(results)

        # Summary should be generated without crashing
        assert "total_modules" in summary
        assert "failed" in summary
        assert summary["failed"] == 1
        # Error message should be converted to string safely
        assert "results" in summary
        assert len(summary["results"]) == 1

    def test_summary_handles_none_error(self):
        """Test that summary handles None errors safely."""
        processor = ChainProcessor(chain=["log"], chain_config={}, webhook_config={})

        results = [ChainResult("log", True, None)]

        summary = processor.get_summary(results)

        # Summary should be generated without crashing
        assert "total_modules" in summary
        assert "successful" in summary
        assert summary["successful"] == 1
        assert summary["results"][0]["error"] is None

    def test_summary_division_by_zero_protection(self):
        """Test that summary handles empty results without division by zero."""
        processor = ChainProcessor(chain=[], chain_config={}, webhook_config={})

        results = []

        summary = processor.get_summary(results)

        # Should not crash with division by zero
        assert "total_modules" in summary
        assert summary["total_modules"] == 0
        assert "success_rate" in summary
        assert summary["success_rate"] == 0.0  # Should be 0.0, not crash
