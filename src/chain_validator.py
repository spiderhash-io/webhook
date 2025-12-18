"""
Chain configuration validator for webhook chaining feature.

SECURITY: This module validates chain configurations to prevent:
- DoS attacks via excessive chain length
- Invalid module references
- Malformed configuration structures
- Resource exhaustion attacks
"""
from typing import Any, Dict, List, Optional, Tuple
from src.modules.registry import ModuleRegistry


class ChainValidator:
    """Validates webhook chain configurations."""
    
    # Security limits to prevent DoS attacks
    MAX_CHAIN_LENGTH = 20  # Maximum allowed chain length (prevents DoS via excessive chains)
    MIN_CHAIN_LENGTH = 1  # Minimum chain length (must have at least 1 module)
    
    @staticmethod
    def validate_chain_config(config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validate chain configuration.
        
        SECURITY: Validates all aspects of chain configuration to prevent DoS and injection attacks.
        
        Args:
            config: Webhook configuration dictionary
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if chain exists
        chain = config.get('chain')
        if chain is None:
            # Chain is optional - if not present, module field should be used (backward compatibility)
            return True, None
        
        # SECURITY: Validate chain is a list
        if not isinstance(chain, list):
            return False, "Chain must be a list/array"
        
        # SECURITY: Validate chain length to prevent DoS
        chain_length = len(chain)
        if chain_length < ChainValidator.MIN_CHAIN_LENGTH:
            return False, f"Chain must contain at least {ChainValidator.MIN_CHAIN_LENGTH} module"
        
        if chain_length > ChainValidator.MAX_CHAIN_LENGTH:
            return False, f"Chain length {chain_length} exceeds security limit {ChainValidator.MAX_CHAIN_LENGTH}"
        
        # Validate each chain item
        for idx, item in enumerate(chain):
            is_valid, error = ChainValidator._validate_chain_item(item, idx)
            if not is_valid:
                return False, error
        
        # Validate chain-config if present
        chain_config = config.get('chain-config', {})
        if chain_config:
            is_valid, error = ChainValidator._validate_chain_execution_config(chain_config)
            if not is_valid:
                return False, error
        
        return True, None
    
    @staticmethod
    def _validate_chain_item(item: Any, index: int) -> Tuple[bool, Optional[str]]:
        """
        Validate a single chain item.
        
        SECURITY: Validates module name and configuration structure.
        
        Args:
            item: Chain item (string or dict)
            index: Index in chain (for error messages)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Chain item can be a string (simple format) or dict (detailed format)
        if isinstance(item, str):
            # Simple format: just module name
            module_name = item
            # SECURITY: Validate module name format
            if not module_name or not isinstance(module_name, str):
                return False, f"Chain item {index}: module name must be a non-empty string"
            
            # SECURITY: Validate module exists in registry
            try:
                ModuleRegistry.get(module_name)
            except (KeyError, ValueError) as e:
                return False, f"Chain item {index}: module '{module_name}' is not registered"
            
            return True, None
        
        elif isinstance(item, dict):
            # Detailed format: dict with module, connection, module-config, retry, etc.
            # SECURITY: Validate module field exists and is a string
            module_name = item.get('module')
            if not module_name:
                return False, f"Chain item {index}: missing required 'module' field"
            
            if not isinstance(module_name, str):
                return False, f"Chain item {index}: 'module' must be a string"
            
            # SECURITY: Validate module exists in registry
            try:
                ModuleRegistry.get(module_name)
            except (KeyError, ValueError) as e:
                return False, f"Chain item {index}: module '{module_name}' is not registered"
            
            # SECURITY: Validate connection field if present (must be string)
            connection = item.get('connection')
            if connection is not None and not isinstance(connection, str):
                return False, f"Chain item {index}: 'connection' must be a string if provided"
            
            # SECURITY: Validate topic field if present (must be string, used by Kafka module)
            topic = item.get('topic')
            if topic is not None and not isinstance(topic, str):
                return False, f"Chain item {index}: 'topic' must be a string if provided"
            
            # SECURITY: Validate module-config if present (must be dict)
            module_config = item.get('module-config')
            if module_config is not None and not isinstance(module_config, dict):
                return False, f"Chain item {index}: 'module-config' must be a dictionary if provided"
            
            # SECURITY: Validate retry config if present (must be dict)
            retry_config = item.get('retry')
            if retry_config is not None:
                if not isinstance(retry_config, dict):
                    return False, f"Chain item {index}: 'retry' must be a dictionary if provided"
                
                # Validate retry config structure (basic validation, detailed validation in retry_handler)
                if 'enabled' in retry_config and not isinstance(retry_config['enabled'], bool):
                    return False, f"Chain item {index}: 'retry.enabled' must be a boolean"
                
                if 'max_attempts' in retry_config:
                    max_attempts = retry_config['max_attempts']
                    if not isinstance(max_attempts, int) or max_attempts < 1:
                        return False, f"Chain item {index}: 'retry.max_attempts' must be a positive integer"
            
            # SECURITY: Reject unknown fields to prevent injection
            # Allow module-specific top-level configs (e.g., 'topic' for Kafka)
            allowed_fields = {'module', 'connection', 'module-config', 'retry', 'topic'}
            for field in item.keys():
                if field not in allowed_fields:
                    return False, f"Chain item {index}: unknown field '{field}' (allowed: {', '.join(allowed_fields)})"
            
            return True, None
        
        else:
            return False, f"Chain item {index}: must be a string or dictionary, got {type(item).__name__}"
    
    @staticmethod
    def _validate_chain_execution_config(chain_config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validate chain execution configuration.
        
        SECURITY: Validates execution mode and error handling settings.
        
        Args:
            chain_config: Chain execution configuration dictionary
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # SECURITY: Validate chain_config is a dict
        if not isinstance(chain_config, dict):
            return False, "chain-config must be a dictionary"
        
        # Validate execution mode
        execution = chain_config.get('execution', 'sequential')
        if not isinstance(execution, str):
            return False, "chain-config.execution must be a string"
        
        allowed_execution_modes = {'sequential', 'parallel'}
        if execution not in allowed_execution_modes:
            return False, f"chain-config.execution must be one of {allowed_execution_modes}, got '{execution}'"
        
        # Validate continue_on_error
        continue_on_error = chain_config.get('continue_on_error', True)
        if not isinstance(continue_on_error, bool):
            return False, "chain-config.continue_on_error must be a boolean"
        
        # SECURITY: Reject unknown fields to prevent injection
        allowed_fields = {'execution', 'continue_on_error'}
        for field in chain_config.keys():
            if field not in allowed_fields:
                return False, f"chain-config: unknown field '{field}' (allowed: {', '.join(allowed_fields)})"
        
        return True, None
    
    @staticmethod
    def normalize_chain_item(item: Any) -> Dict[str, Any]:
        """
        Normalize chain item to dict format.
        
        Converts string format to dict format for consistent processing.
        
        Args:
            item: Chain item (string or dict)
            
        Returns:
            Normalized chain item as dict
        """
        if isinstance(item, str):
            # Simple format: convert to dict
            return {
                'module': item
            }
        elif isinstance(item, dict):
            # Already in dict format, return as-is
            return item
        else:
            # Should not happen if validation passed, but handle gracefully
            raise ValueError(f"Invalid chain item type: {type(item).__name__}")
    
    @staticmethod
    def get_chain_modules(chain: List[Any]) -> List[str]:
        """
        Extract module names from chain.
        
        Args:
            chain: Chain configuration list
            
        Returns:
            List of module names
        """
        modules = []
        for item in chain:
            if isinstance(item, str):
                modules.append(item)
            elif isinstance(item, dict):
                module_name = item.get('module')
                if module_name:
                    modules.append(module_name)
        return modules

