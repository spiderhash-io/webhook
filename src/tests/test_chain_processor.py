"""
Unit tests for chain processor.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from src.chain_processor import ChainProcessor, ChainResult
from src.modules.base import BaseModule


class MockModule(BaseModule):
    """Mock module for testing."""
    
    def __init__(self, config, pool_registry=None):
        super().__init__(config, pool_registry)
        self.process_called = False
        self.should_fail = False
        self.failure_count = 0
        self.max_failures = 0
    
    async def process(self, payload, headers):
        self.process_called = True
        if self.should_fail:
            self.failure_count += 1
            if self.failure_count <= self.max_failures:
                raise Exception(f"Mock module failure {self.failure_count}")


class TestChainProcessor:
    """Test chain processor."""
    
    @pytest.fixture
    def mock_webhook_config(self):
        """Create mock webhook config."""
        return {
            'data_type': 'json',
            'authorization': 'Bearer token'
        }
    
    @pytest.fixture
    def simple_chain(self):
        """Create simple chain configuration."""
        return ['log', 'save_to_disk']
    
    @pytest.fixture
    def detailed_chain(self):
        """Create detailed chain configuration."""
        return [
            {
                'module': 'log',
                'connection': 'local'
            },
            {
                'module': 'save_to_disk',
                'module-config': {'path': '/tmp'}
            }
        ]
    
    @pytest.mark.asyncio
    async def test_sequential_execution_success(self, mock_webhook_config, simple_chain):
        """Test successful sequential execution."""
        with patch('src.chain_processor.ModuleRegistry') as mock_registry:
            # Mock module classes
            mock_log_module = MagicMock()
            mock_log_module.return_value = MockModule({})
            
            mock_save_module = MagicMock()
            mock_save_module.return_value = MockModule({})
            
            mock_registry.get.side_effect = [mock_log_module, mock_save_module]
            
            processor = ChainProcessor(
                chain=simple_chain,
                chain_config={'execution': 'sequential'},
                webhook_config=mock_webhook_config
            )
            
            payload = {'key': 'value'}
            headers = {'Content-Type': 'application/json'}
            
            results = await processor.execute(payload, headers)
            
            assert len(results) == 2
            assert all(r.success for r in results)
            assert results[0].module_name == 'log'
            assert results[1].module_name == 'save_to_disk'
    
    @pytest.mark.asyncio
    async def test_parallel_execution_success(self, mock_webhook_config, simple_chain):
        """Test successful parallel execution."""
        with patch('src.chain_processor.ModuleRegistry') as mock_registry:
            # Mock module classes
            mock_log_module = MagicMock()
            mock_log_module.return_value = MockModule({})
            
            mock_save_module = MagicMock()
            mock_save_module.return_value = MockModule({})
            
            mock_registry.get.side_effect = [mock_log_module, mock_save_module]
            
            processor = ChainProcessor(
                chain=simple_chain,
                chain_config={'execution': 'parallel'},
                webhook_config=mock_webhook_config
            )
            
            payload = {'key': 'value'}
            headers = {'Content-Type': 'application/json'}
            
            results = await processor.execute(payload, headers)
            
            assert len(results) == 2
            assert all(r.success for r in results)
    
    @pytest.mark.asyncio
    async def test_sequential_execution_with_failure_continue(self, mock_webhook_config):
        """Test sequential execution with failure but continue_on_error=True."""
        chain = ['log', 'save_to_disk']
        
        with patch('src.chain_processor.ModuleRegistry') as mock_registry:
            # First module fails, second succeeds
            mock_log_module = MagicMock()
            failing_module = MockModule({})
            failing_module.should_fail = True
            failing_module.max_failures = 1
            mock_log_module.return_value = failing_module
            
            mock_save_module = MagicMock()
            mock_save_module.return_value = MockModule({})
            
            mock_registry.get.side_effect = [mock_log_module, mock_save_module]
            
            processor = ChainProcessor(
                chain=chain,
                chain_config={
                    'execution': 'sequential',
                    'continue_on_error': True
                },
                webhook_config=mock_webhook_config
            )
            
            payload = {'key': 'value'}
            headers = {'Content-Type': 'application/json'}
            
            results = await processor.execute(payload, headers)
            
            assert len(results) == 2
            assert not results[0].success  # First module failed
            assert results[1].success  # Second module succeeded
    
    @pytest.mark.asyncio
    async def test_sequential_execution_with_failure_stop(self, mock_webhook_config):
        """Test sequential execution with failure and continue_on_error=False."""
        chain = ['log', 'save_to_disk']
        
        with patch('src.chain_processor.ModuleRegistry') as mock_registry:
            # First module fails
            mock_log_module = MagicMock()
            failing_module = MockModule({})
            failing_module.should_fail = True
            failing_module.max_failures = 1
            mock_log_module.return_value = failing_module
            
            mock_save_module = MagicMock()
            mock_save_module.return_value = MockModule({})
            
            mock_registry.get.side_effect = [mock_log_module, mock_save_module]
            
            processor = ChainProcessor(
                chain=chain,
                chain_config={
                    'execution': 'sequential',
                    'continue_on_error': False
                },
                webhook_config=mock_webhook_config
            )
            
            payload = {'key': 'value'}
            headers = {'Content-Type': 'application/json'}
            
            results = await processor.execute(payload, headers)
            
            assert len(results) == 2
            assert not results[0].success  # First module failed
            assert not results[1].success  # Second module not executed
    
    @pytest.mark.asyncio
    async def test_parallel_execution_with_failure(self, mock_webhook_config):
        """Test parallel execution with one module failing."""
        chain = ['log', 'save_to_disk']
        
        with patch('src.chain_processor.ModuleRegistry') as mock_registry:
            # First module fails, second succeeds
            mock_log_module = MagicMock()
            failing_module = MockModule({})
            failing_module.should_fail = True
            failing_module.max_failures = 1
            mock_log_module.return_value = failing_module
            
            mock_save_module = MagicMock()
            mock_save_module.return_value = MockModule({})
            
            mock_registry.get.side_effect = [mock_log_module, mock_save_module]
            
            processor = ChainProcessor(
                chain=chain,
                chain_config={
                    'execution': 'parallel',
                    'continue_on_error': True
                },
                webhook_config=mock_webhook_config
            )
            
            payload = {'key': 'value'}
            headers = {'Content-Type': 'application/json'}
            
            results = await processor.execute(payload, headers)
            
            assert len(results) == 2
            assert not results[0].success  # First module failed
            assert results[1].success  # Second module succeeded
    
    @pytest.mark.asyncio
    async def test_module_instantiation_error(self, mock_webhook_config):
        """Test handling of module instantiation error."""
        chain = ['log']
        
        with patch('src.chain_processor.ModuleRegistry') as mock_registry:
            mock_registry.get.side_effect = KeyError("Module not found")
            
            processor = ChainProcessor(
                chain=chain,
                chain_config={'execution': 'sequential'},
                webhook_config=mock_webhook_config
            )
            
            payload = {'key': 'value'}
            headers = {'Content-Type': 'application/json'}
            
            results = await processor.execute(payload, headers)
            
            assert len(results) == 1
            assert not results[0].success
            assert results[0].error is not None
    
    @pytest.mark.asyncio
    async def test_build_module_config(self, mock_webhook_config, detailed_chain):
        """Test module configuration building."""
        processor = ChainProcessor(
            chain=detailed_chain,
            chain_config={},
            webhook_config=mock_webhook_config
        )
        
        # Test building config for first chain item
        config = processor._build_module_config(processor.normalized_chain[0])
        assert config['module'] == 'log'
        assert config['connection'] == 'local'
        assert config['data_type'] == 'json'  # From base config
    
    def test_get_summary(self):
        """Test execution summary generation."""
        results = [
            ChainResult('log', True),
            ChainResult('save_to_disk', False, Exception("Test error")),
            ChainResult('rabbitmq', True)
        ]
        
        processor = ChainProcessor(
            chain=['log', 'save_to_disk', 'rabbitmq'],
            chain_config={},
            webhook_config={}
        )
        
        summary = processor.get_summary(results)
        
        assert summary['total_modules'] == 3
        assert summary['successful'] == 2
        assert summary['failed'] == 1
        assert summary['success_rate'] == 2/3
        assert len(summary['results']) == 3

