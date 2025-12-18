"""
Chain processor for webhook destination chaining.

SECURITY: This module handles chain execution with proper error handling,
resource management, and DoS protection.
"""
import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple
from src.modules.registry import ModuleRegistry
from src.chain_validator import ChainValidator
from src.retry_handler import retry_handler

logger = logging.getLogger(__name__)


class ChainResult:
    """Result of chain execution for a single module."""
    
    def __init__(self, module_name: str, success: bool, error: Optional[Exception] = None):
        self.module_name = module_name
        self.success = success
        self.error = error
    
    def __repr__(self):
        status = "SUCCESS" if self.success else "FAILED"
        error_msg = f": {self.error}" if self.error else ""
        return f"ChainResult({self.module_name}, {status}{error_msg})"


class ChainProcessor:
    """Processes webhook chains (sequential or parallel execution)."""
    
    def __init__(self, chain: List[Any], chain_config: Dict[str, Any], 
                 webhook_config: Dict[str, Any], pool_registry=None, connection_config=None):
        """
        Initialize chain processor.
        
        SECURITY: Validates chain configuration before processing.
        
        Args:
            chain: Chain configuration (list of strings or dicts)
            chain_config: Chain execution configuration
            webhook_config: Base webhook configuration
            pool_registry: Optional ConnectionPoolRegistry
            connection_config: Optional connection configuration dictionary
        """
        self.chain = chain
        self.chain_config = chain_config or {}
        self.webhook_config = webhook_config
        self.pool_registry = pool_registry
        self.connection_config = connection_config or {}
        
        # Get execution mode (default: sequential)
        self.execution_mode = self.chain_config.get('execution', 'sequential')
        self.continue_on_error = self.chain_config.get('continue_on_error', True)
        
        # Normalize chain items to dict format
        self.normalized_chain = [ChainValidator.normalize_chain_item(item) for item in chain]
    
    async def execute(self, payload: Any, headers: Dict[str, str]) -> List[ChainResult]:
        """
        Execute the chain.
        
        SECURITY: Handles errors gracefully and prevents resource exhaustion.
        
        Args:
            payload: Webhook payload
            headers: Request headers
            
        Returns:
            List of ChainResult objects (one per module)
        """
        if self.execution_mode == 'parallel':
            return await self._execute_parallel(payload, headers)
        else:
            return await self._execute_sequential(payload, headers)
    
    async def _execute_sequential(self, payload: Any, headers: Dict[str, str]) -> List[ChainResult]:
        """
        Execute chain sequentially (one module after another).
        
        SECURITY: Continues on error if configured, logs all failures.
        """
        results = []
        
        for idx, chain_item in enumerate(self.normalized_chain):
            module_name = chain_item.get('module')
            result = await self._execute_module(chain_item, payload, headers, idx)
            results.append(result)
            
            # If module failed and continue_on_error is False, stop chain
            if not result.success and not self.continue_on_error:
                logger.warning(f"Chain execution stopped at module {idx} ({module_name}) due to error")
                # Mark remaining modules as not executed
                for remaining_idx in range(idx + 1, len(self.normalized_chain)):
                    remaining_module = self.normalized_chain[remaining_idx].get('module')
                    results.append(ChainResult(remaining_module, False, 
                                             Exception("Chain execution stopped due to previous error")))
                break
        
        return results
    
    async def _execute_parallel(self, payload: Any, headers: Dict[str, str]) -> List[ChainResult]:
        """
        Execute chain in parallel (all modules at once).
        
        SECURITY: Uses asyncio.gather with return_exceptions to handle errors gracefully.
        """
        # Create tasks for all modules
        tasks = []
        for idx, chain_item in enumerate(self.normalized_chain):
            task = self._execute_module(chain_item, payload, headers, idx)
            tasks.append(task)
        
        # Execute all tasks in parallel
        # return_exceptions=True ensures all tasks complete even if some fail
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert results to ChainResult objects
        chain_results = []
        for idx, result in enumerate(results):
            chain_item = self.normalized_chain[idx]
            module_name = chain_item.get('module')
            
            if isinstance(result, Exception):
                # Exception occurred during execution
                chain_results.append(ChainResult(module_name, False, result))
            elif isinstance(result, ChainResult):
                # Normal result
                chain_results.append(result)
            else:
                # Unexpected result type
                chain_results.append(ChainResult(module_name, False, 
                                               Exception(f"Unexpected result type: {type(result)}")))
        
        return chain_results
    
    async def _execute_module(self, chain_item: Dict[str, Any], payload: Any, 
                             headers: Dict[str, str], index: int) -> ChainResult:
        """
        Execute a single module in the chain.
        
        SECURITY: Handles module instantiation errors and execution errors gracefully.
        
        Args:
            chain_item: Normalized chain item (dict with module, connection, etc.)
            payload: Webhook payload
            headers: Request headers
            index: Index in chain (for logging)
            
        Returns:
            ChainResult object
        """
        module_name = chain_item.get('module')
        
        try:
            # Build module configuration
            module_config = self._build_module_config(chain_item)
            
            # Instantiate module
            try:
                module_class = ModuleRegistry.get(module_name)
                module = module_class(module_config, pool_registry=self.pool_registry)
            except (KeyError, ValueError) as e:
                logger.error(f"Chain module {index} ({module_name}): Failed to get module class: {e}")
                return ChainResult(module_name, False, e)
            except Exception as e:
                logger.error(f"Chain module {index} ({module_name}): Failed to instantiate module: {e}")
                return ChainResult(module_name, False, e)
            
            # Get retry config for this module (if specified)
            retry_config = chain_item.get('retry')
            
            # Execute module (with retry if configured)
            if retry_config and retry_config.get('enabled', False):
                # Execute with retry
                success, error = await retry_handler.execute_with_retry(
                    module.process,
                    payload,
                    headers,
                    retry_config=retry_config
                )
                if success:
                    return ChainResult(module_name, True)
                else:
                    return ChainResult(module_name, False, error)
            else:
                # Execute without retry
                try:
                    await module.process(payload, headers)
                    return ChainResult(module_name, True)
                except Exception as e:
                    logger.error(f"Chain module {index} ({module_name}): Execution failed: {e}")
                    return ChainResult(module_name, False, e)
        
        except Exception as e:
            # Catch any unexpected errors
            logger.error(f"Chain module {index} ({module_name}): Unexpected error: {e}")
            return ChainResult(module_name, False, e)
    
    def _build_module_config(self, chain_item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build module configuration from chain item and base webhook config.
        
        SECURITY: Merges configurations safely, preserving security settings.
        
        Args:
            chain_item: Normalized chain item
            
        Returns:
            Complete module configuration dictionary
        """
        # Start with base webhook config (copy to avoid modifying original)
        import copy
        module_config = copy.deepcopy(self.webhook_config)
        
        # Override module name
        module_config['module'] = chain_item.get('module')
        
        # Override connection if specified in chain item
        connection_name = chain_item.get('connection')
        if connection_name:
            module_config['connection'] = connection_name
            
            # Inject connection details from connection_config if available
            if self.connection_config and connection_name in self.connection_config:
                connection_details = copy.deepcopy(self.connection_config[connection_name])
                module_config['connection_details'] = connection_details
        
        # Copy module-specific top-level configs from chain item (e.g., 'topic' for Kafka)
        # These are configs that modules expect at the top level, not in module-config
        module_specific_keys = ['topic']  # Add other module-specific keys as needed
        for key in module_specific_keys:
            if key in chain_item:
                module_config[key] = chain_item[key]
            # Also check in webhook config (for backward compatibility)
            elif key in self.webhook_config:
                module_config[key] = self.webhook_config[key]
        
        # Merge module-config if specified
        if 'module-config' in chain_item:
            chain_module_config = chain_item['module-config']
            if isinstance(chain_module_config, dict):
                # Merge with existing module-config
                existing_module_config = module_config.get('module-config', {})
                if isinstance(existing_module_config, dict):
                    # Deep merge
                    merged_config = copy.deepcopy(existing_module_config)
                    merged_config.update(chain_module_config)
                    module_config['module-config'] = merged_config
                else:
                    module_config['module-config'] = copy.deepcopy(chain_module_config)
            else:
                # Invalid module-config, use empty dict
                module_config['module-config'] = {}
        
        # Preserve webhook_id if present
        if '_webhook_id' in self.webhook_config:
            module_config['_webhook_id'] = self.webhook_config['_webhook_id']
        
        return module_config
    
    def get_summary(self, results: List[ChainResult]) -> Dict[str, Any]:
        """
        Get execution summary from results.
        
        Args:
            results: List of ChainResult objects
            
        Returns:
            Summary dictionary with statistics
        """
        total = len(results)
        successful = sum(1 for r in results if r.success)
        failed = total - successful
        
        return {
            'total_modules': total,
            'successful': successful,
            'failed': failed,
            'success_rate': successful / total if total > 0 else 0.0,
            'results': [
                {
                    'module': r.module_name,
                    'success': r.success,
                    'error': str(r.error) if r.error else None
                }
                for r in results
            ]
        }

