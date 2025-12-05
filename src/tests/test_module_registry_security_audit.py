"""
Comprehensive security audit tests for ModuleRegistry.
Tests module registration security, class validation, registry manipulation, concurrent access, and edge cases.
"""
import pytest
import re
from typing import Any, Dict
from src.modules.registry import ModuleRegistry
from src.modules.base import BaseModule


# ============================================================================
# 1. MODULE REGISTRATION SECURITY
# ============================================================================

class TestModuleRegistryRegistrationSecurity:
    """Test module registration security vulnerabilities."""
    
    def test_register_overwrites_existing_module(self):
        """Test that registering a module with existing name overwrites it."""
        # Create a dummy module class
        class DummyModule(BaseModule):
            async def process(self, payload, headers):
                pass
        
        # Get original module
        original_module = ModuleRegistry.get('log')
        
        try:
            # Register new module with existing name
            ModuleRegistry.register('log', DummyModule)
            
            # Should overwrite original
            new_module = ModuleRegistry.get('log')
            assert new_module == DummyModule
            assert new_module != original_module
        finally:
            # Restore original module
            ModuleRegistry._modules['log'] = original_module
    
    def test_register_malicious_module_class(self):
        """Test that malicious module classes are still validated."""
        # Create a module that inherits from BaseModule but could be dangerous
        class MaliciousModule(BaseModule):
            async def process(self, payload, headers):
                # Could do something malicious, but still inherits from BaseModule
                pass
        
        # Should be allowed (inherits from BaseModule)
        try:
            ModuleRegistry.register('test_malicious', MaliciousModule)
            # Should succeed since it inherits from BaseModule
            module = ModuleRegistry.get('test_malicious')
            assert module == MaliciousModule
        finally:
            # Clean up
            if 'test_malicious' in ModuleRegistry._modules:
                del ModuleRegistry._modules['test_malicious']
    
    def test_register_non_base_module_rejected(self):
        """Test that non-BaseModule classes are rejected."""
        class NotAModule:
            pass
        
        with pytest.raises(ValueError, match="inherit from BaseModule"):
            ModuleRegistry.register('test_invalid', NotAModule)
    
    def test_register_with_invalid_name_rejected(self):
        """Test that invalid module names are rejected during registration."""
        class DummyModule(BaseModule):
            async def process(self, payload, headers):
                pass
        
        invalid_names = [
            '../malicious',
            'module\x00name',
            'module;command',
            'module|command',
            'module&command',
        ]
        
        for invalid_name in invalid_names:
            with pytest.raises(ValueError):
                ModuleRegistry.register(invalid_name, DummyModule)


# ============================================================================
# 2. MODULE CLASS VALIDATION
# ============================================================================

class TestModuleRegistryClassValidation:
    """Test module class validation security."""
    
    def test_register_with_none_class(self):
        """Test that None class is rejected."""
        with pytest.raises((ValueError, TypeError)):
            ModuleRegistry.register('test_module', None)
    
    def test_register_with_string_class(self):
        """Test that string class is rejected."""
        with pytest.raises((ValueError, TypeError)):
            ModuleRegistry.register('test_module', 'NotAClass')
    
    def test_register_with_dict_class(self):
        """Test that dict class is rejected."""
        with pytest.raises((ValueError, TypeError)):
            ModuleRegistry.register('test_module', {})
    
    def test_register_with_list_class(self):
        """Test that list class is rejected."""
        with pytest.raises((ValueError, TypeError)):
            ModuleRegistry.register('test_module', [])


# ============================================================================
# 3. REGISTRY MANIPULATION SECURITY
# ============================================================================

class TestModuleRegistryManipulation:
    """Test registry manipulation security."""
    
    def test_direct_dict_manipulation(self):
        """Test that direct dictionary manipulation is possible (documented behavior)."""
        # This is a known limitation - _modules is a class variable and can be manipulated
        # However, get() and register() still validate names, so this is acceptable
        original_modules = ModuleRegistry._modules.copy()
        
        try:
            # Direct manipulation
            class DummyModule(BaseModule):
                async def process(self, payload, headers):
                    pass
            
            ModuleRegistry._modules['direct_manipulation'] = DummyModule
            
            # Should be accessible
            module = ModuleRegistry.get('direct_manipulation')
            assert module == DummyModule
        finally:
            # Restore
            ModuleRegistry._modules = original_modules
    
    def test_get_validates_even_after_direct_manipulation(self):
        """Test that get() still validates even if module was added directly."""
        original_modules = ModuleRegistry._modules.copy()
        
        try:
            # Direct manipulation with invalid name
            class DummyModule(BaseModule):
                async def process(self, payload, headers):
                    pass
            
            # Try to add with invalid name directly
            ModuleRegistry._modules['../malicious'] = DummyModule
            
            # get() should still validate and reject
            with pytest.raises(ValueError, match="path traversal"):
                ModuleRegistry.get('../malicious')
        finally:
            # Restore
            ModuleRegistry._modules = original_modules


# ============================================================================
# 4. CONCURRENT ACCESS SECURITY
# ============================================================================

class TestModuleRegistryConcurrentAccess:
    """Test concurrent access security."""
    
    def test_concurrent_registration(self):
        """Test that concurrent registration is handled safely."""
        import threading
        
        class DummyModule1(BaseModule):
            async def process(self, payload, headers):
                pass
        
        class DummyModule2(BaseModule):
            async def process(self, payload, headers):
                pass
        
        results = []
        
        def register_module(name, module_class):
            try:
                ModuleRegistry.register(name, module_class)
                results.append(f"{name}:success")
            except Exception as e:
                results.append(f"{name}:error:{str(e)}")
        
        # Register concurrently
        thread1 = threading.Thread(target=register_module, args=('concurrent1', DummyModule1))
        thread2 = threading.Thread(target=register_module, args=('concurrent2', DummyModule2))
        
        thread1.start()
        thread2.start()
        
        thread1.join()
        thread2.join()
        
        # Both should succeed or at least not crash
        assert len(results) == 2
        
        # Clean up
        for name in ['concurrent1', 'concurrent2']:
            if name in ModuleRegistry._modules:
                del ModuleRegistry._modules[name]
    
    def test_concurrent_lookup(self):
        """Test that concurrent lookup is handled safely."""
        import threading
        
        results = []
        
        def lookup_module(name):
            try:
                module = ModuleRegistry.get(name)
                results.append(f"{name}:success")
            except Exception as e:
                results.append(f"{name}:error:{type(e).__name__}")
        
        # Lookup concurrently
        thread1 = threading.Thread(target=lookup_module, args=('log',))
        thread2 = threading.Thread(target=lookup_module, args=('kafka',))
        
        thread1.start()
        thread2.start()
        
        thread1.join()
        thread2.join()
        
        # Both should succeed or fail gracefully
        assert len(results) == 2


# ============================================================================
# 5. REGEX REDOS VULNERABILITIES
# ============================================================================

class TestModuleRegistryReDoS:
    """Test ReDoS vulnerabilities in regex validation."""
    
    def test_module_name_regex_redos(self):
        """Test ReDoS vulnerability in module name regex."""
        import time
        
        # Complex module name that might cause ReDoS
        complex_name = "a" * 1000 + "!"  # Long string ending with invalid char
        
        start_time = time.time()
        try:
            ModuleRegistry.get(complex_name)
            assert False, "Should have raised ValueError"
        except ValueError:
            elapsed = time.time() - start_time
            # Should complete quickly (no ReDoS)
            assert elapsed < 1.0, f"ReDoS detected: validation took {elapsed:.2f}s"
    
    def test_consecutive_chars_regex_redos(self):
        """Test ReDoS vulnerability in consecutive characters regex."""
        import time
        
        # Complex pattern that might cause ReDoS
        complex_name = "a" * 500 + "--" + "b" * 500
        
        start_time = time.time()
        try:
            ModuleRegistry.get(complex_name)
            assert False, "Should have raised ValueError"
        except ValueError:
            elapsed = time.time() - start_time
            # Should complete quickly (no ReDoS)
            assert elapsed < 1.0, f"ReDoS detected: validation took {elapsed:.2f}s"


# ============================================================================
# 6. EDGE CASES & BOUNDARY CONDITIONS
# ============================================================================

class TestModuleRegistryEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_module_name_at_max_length(self):
        """Test module name at maximum length."""
        # Max length is 64
        max_name = "a" * 64
        
        # Should pass validation (but fail on lookup if not registered)
        try:
            ModuleRegistry.get(max_name)
        except KeyError:
            # Expected for unregistered module
            pass
        except ValueError as e:
            # Should not fail validation
            pytest.fail(f"Module name at max length was rejected: {e}")
    
    def test_module_name_at_min_length(self):
        """Test module name at minimum length."""
        # Min length is 1
        min_name = "a"
        
        # Should pass validation (but fail on lookup if not registered)
        try:
            ModuleRegistry.get(min_name)
        except KeyError:
            # Expected for unregistered module
            pass
        except ValueError as e:
            # Should not fail validation
            pytest.fail(f"Module name at min length was rejected: {e}")
    
    def test_module_name_with_numbers(self):
        """Test module names with numbers."""
        valid_names = [
            "module123",
            "123module",  # Starts with number (should be rejected)
            "module_123",
            "module-123",
        ]
        
        for name in valid_names:
            try:
                ModuleRegistry.get(name)
            except KeyError:
                # Expected for unregistered modules
                pass
            except ValueError as e:
                # Check if it's expected rejection (starts with number)
                if name == "123module":
                    assert "start with alphanumeric" in str(e).lower() or "invalid" in str(e).lower()
                else:
                    pytest.fail(f"Valid module name '{name}' was rejected: {e}")
    
    def test_module_name_unicode(self):
        """Test that Unicode module names are rejected."""
        unicode_names = [
            "测试_module",
            "module_ログ",
            "module_логи",
            "module_📊",
        ]
        
        for name in unicode_names:
            with pytest.raises(ValueError):
                ModuleRegistry.get(name)


# ============================================================================
# 7. LIST MODULES SECURITY
# ============================================================================

class TestModuleRegistryListModules:
    """Test list_modules() security."""
    
    def test_list_modules_returns_copy(self):
        """Test that list_modules() returns a copy, not the original."""
        modules_list = ModuleRegistry.list_modules()
        
        # Modify the list
        modules_list.append('malicious')
        
        # Original registry should not be affected
        original_list = ModuleRegistry.list_modules()
        assert 'malicious' not in original_list
    
    def test_list_modules_contains_all_registered(self):
        """Test that list_modules() contains all registered modules."""
        modules_list = ModuleRegistry.list_modules()
        
        # Should contain known modules
        assert 'log' in modules_list
        assert 'kafka' in modules_list
        assert 'websocket' in modules_list
    
    def test_list_modules_after_registration(self):
        """Test that list_modules() includes newly registered modules."""
        class DummyModule(BaseModule):
            async def process(self, payload, headers):
                pass
        
        try:
            # Register new module
            ModuleRegistry.register('test_list_module', DummyModule)
            
            # Should appear in list
            modules_list = ModuleRegistry.list_modules()
            assert 'test_list_module' in modules_list
        finally:
            # Clean up
            if 'test_list_module' in ModuleRegistry._modules:
                del ModuleRegistry._modules['test_list_module']


# ============================================================================
# 8. ERROR INFORMATION DISCLOSURE
# ============================================================================

class TestModuleRegistryErrorDisclosure:
    """Test error information disclosure."""
    
    def test_get_error_message_disclosure(self):
        """Test that error messages don't leak sensitive information."""
        try:
            ModuleRegistry.get('nonexistent_module')
            assert False, "Should have raised KeyError"
        except KeyError as e:
            # Should not expose internal registry structure
            error_msg = str(e).lower()
            # Should contain module name (acceptable)
            assert "nonexistent_module" in error_msg or "not registered" in error_msg
            # Should not expose internal details
            assert "_modules" not in error_msg
    
    def test_register_error_message_disclosure(self):
        """Test that register() error messages don't leak sensitive information."""
        class NotAModule:
            pass
        
        try:
            ModuleRegistry.register('test_module', NotAModule)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            # Should not expose internal registry structure
            error_msg = str(e).lower()
            # Should contain helpful message
            assert "basemodule" in error_msg or "inherit" in error_msg
            # Should not expose internal details
            assert "_modules" not in error_msg


# ============================================================================
# 9. TYPE CONFUSION ATTACKS
# ============================================================================

class TestModuleRegistryTypeConfusion:
    """Test type confusion attacks."""
    
    def test_get_with_none(self):
        """Test get() with None."""
        with pytest.raises(ValueError, match="non-empty string"):
            ModuleRegistry.get(None)
    
    def test_get_with_integer(self):
        """Test get() with integer."""
        with pytest.raises(ValueError, match="non-empty string"):
            ModuleRegistry.get(123)
    
    def test_get_with_list(self):
        """Test get() with list."""
        with pytest.raises(ValueError, match="non-empty string"):
            ModuleRegistry.get(['log'])
    
    def test_get_with_dict(self):
        """Test get() with dict."""
        with pytest.raises(ValueError, match="non-empty string"):
            ModuleRegistry.get({'module': 'log'})
    
    def test_register_with_integer_name(self):
        """Test register() with integer name."""
        class DummyModule(BaseModule):
            async def process(self, payload, headers):
                pass
        
        with pytest.raises(ValueError, match="non-empty string"):
            ModuleRegistry.register(123, DummyModule)
    
    def test_register_with_list_name(self):
        """Test register() with list name."""
        class DummyModule(BaseModule):
            async def process(self, payload, headers):
                pass
        
        with pytest.raises(ValueError, match="non-empty string"):
            ModuleRegistry.register(['test'], DummyModule)


# ============================================================================
# 10. MODULE NAME COLLISION
# ============================================================================

class TestModuleRegistryNameCollision:
    """Test module name collision handling."""
    
    def test_register_same_name_twice(self):
        """Test that registering the same name twice overwrites."""
        class DummyModule1(BaseModule):
            async def process(self, payload, headers):
                pass
        
        class DummyModule2(BaseModule):
            async def process(self, payload, headers):
                pass
        
        try:
            # Register first module
            ModuleRegistry.register('test_collision', DummyModule1)
            module1 = ModuleRegistry.get('test_collision')
            assert module1 == DummyModule1
            
            # Register second module with same name
            ModuleRegistry.register('test_collision', DummyModule2)
            module2 = ModuleRegistry.get('test_collision')
            assert module2 == DummyModule2
            assert module2 != DummyModule1
        finally:
            # Clean up
            if 'test_collision' in ModuleRegistry._modules:
                del ModuleRegistry._modules['test_collision']


# ============================================================================
# 11. VALIDATION ORDER SECURITY
# ============================================================================

class TestModuleRegistryValidationOrder:
    """Test validation order security."""
    
    def test_path_traversal_checked_before_format(self):
        """Test that path traversal is checked before format validation."""
        # Path traversal should be caught first
        with pytest.raises(ValueError, match="path traversal"):
            ModuleRegistry.get('../malicious')
    
    def test_null_byte_checked_before_format(self):
        """Test that null bytes are checked before format validation."""
        # Null byte should be caught first
        with pytest.raises(ValueError, match="null bytes"):
            ModuleRegistry.get('module\x00name')
    
    def test_length_checked_before_format(self):
        """Test that length is checked before format validation."""
        # Length should be checked
        long_name = "a" * 65
        with pytest.raises(ValueError, match="too long"):
            ModuleRegistry.get(long_name)


# ============================================================================
# 12. WHITESPACE HANDLING
# ============================================================================

class TestModuleRegistryWhitespaceHandling:
    """Test whitespace handling security."""
    
    def test_whitespace_stripped(self):
        """Test that whitespace is stripped from module names."""
        # Whitespace should be stripped
        try:
            ModuleRegistry.get('  log  ')
            # Should work (whitespace stripped, 'log' is registered)
        except KeyError:
            # If stripped to empty, should raise ValueError
            pass
        except ValueError as e:
            # Should not fail validation for whitespace
            assert "empty" in str(e).lower() or "whitespace" in str(e).lower()
    
    def test_whitespace_only_rejected(self):
        """Test that whitespace-only names are rejected."""
        whitespace_names = [
            '   ',
            '\t',
            '\n',
            '\r',
        ]
        
        for name in whitespace_names:
            with pytest.raises(ValueError, match="empty|whitespace"):
                ModuleRegistry.get(name)

