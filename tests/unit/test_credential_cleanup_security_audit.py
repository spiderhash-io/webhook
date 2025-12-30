"""
Comprehensive security audit tests for CredentialCleaner class.

This audit focuses on:
- ReDoS (Regex Denial of Service) attacks
- Deep recursion DoS attacks
- Circular reference crashes
- Memory exhaustion via large payloads
- Configuration injection via custom_fields
- Pattern bypass attempts
- Type confusion attacks
- Information disclosure in error messages
- Incomplete redaction scenarios
- Edge cases with special characters, Unicode, control characters
"""
import pytest
import sys
import copy
from typing import Any, Dict, List
from src.utils import CredentialCleaner


# ============================================================================
# 1. ReDoS (Regex Denial of Service) ATTACKS
# ============================================================================

class TestCredentialCleanupReDoS:
    """Test ReDoS vulnerabilities in credential field pattern matching."""
    
    def test_redos_credential_pattern_matching(self):
        """Test that credential pattern matching doesn't suffer from ReDoS."""
        cleaner = CredentialCleaner()
        
        # ReDoS attack: Craft field names that could cause catastrophic backtracking
        # Pattern: r'.*password.*' could be vulnerable to ReDoS
        malicious_field_names = [
            'a' * 1000 + 'password',
            'password' + 'a' * 1000,
            'a' * 100 + 'password' + 'a' * 100,
            'p' * 1000 + 'assword',
        ]
        
        for field_name in malicious_field_names:
            # Should complete quickly, not hang
            import time
            start = time.time()
            result = cleaner._is_credential_field(field_name)
            elapsed = time.time() - start
            
            # Should complete in reasonable time (< 1 second)
            assert elapsed < 1.0, f"ReDoS detected: pattern matching took {elapsed}s for field '{field_name[:50]}...'"
            # Should correctly identify as credential field
            assert result is True
    
    def test_redos_x_header_pattern_matching(self):
        """Test that x-*-key pattern matching doesn't suffer from ReDoS."""
        cleaner = CredentialCleaner()
        
        # ReDoS attack on pattern: r'x-.*-key'
        malicious_field_names = [
            'x-' + 'a' * 1000 + '-key',
            'x-' + 'a' * 100 + '-b' * 100 + '-key',
        ]
        
        for field_name in malicious_field_names:
            import time
            start = time.time()
            result = cleaner._is_credential_field(field_name)
            elapsed = time.time() - start
            
            assert elapsed < 1.0, f"ReDoS detected: x-header pattern matching took {elapsed}s"
            assert result is True
    
    def test_redos_custom_fields_pattern_matching(self):
        """Test that custom fields don't introduce ReDoS vulnerabilities."""
        # Custom fields are added to set, not used in regex, so should be safe
        # But test to ensure no regex is applied to custom fields
        cleaner = CredentialCleaner(custom_fields=['a' * 1000 + 'password'])
        
        # Should match quickly
        import time
        start = time.time()
        result = cleaner._is_credential_field('a' * 1000 + 'password')
        elapsed = time.time() - start
        
        assert elapsed < 1.0, f"ReDoS detected in custom field matching"
        assert result is True


# ============================================================================
# 2. DEEP RECURSION DoS ATTACKS
# ============================================================================

class TestCredentialCleanupDeepRecursion:
    """Test deep recursion DoS vulnerabilities."""
    
    def test_deeply_nested_dict_recursion(self):
        """Test that deeply nested dictionaries don't cause stack overflow."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Create deeply nested structure (1000 levels)
        depth = 1000
        data = {'level': 0, 'password': 'secret'}
        current = data
        
        for i in range(1, depth):
            current['nested'] = {'level': i, 'password': f'secret{i}'}
            current = current['nested']
        
        # Should handle without stack overflow
        try:
            cleaned = cleaner.clean_credentials(data)
            # Verify credentials were masked at all levels
            current = cleaned
            for i in range(depth):
                if 'password' in current:
                    assert current['password'] == '***REDACTED***'
                if 'nested' in current:
                    current = current['nested']
        except RecursionError:
            pytest.fail("Deep recursion DoS: Stack overflow on deeply nested dict")
        except Exception as e:
            # Other exceptions are acceptable (e.g., memory issues)
            # But stack overflow should not occur
            assert "maximum recursion depth" not in str(e).lower()
    
    def test_deeply_nested_list_recursion(self):
        """Test that deeply nested lists don't cause stack overflow."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Create deeply nested list structure
        depth = 1000
        data = [{'password': 'secret0'}]
        current = data
        
        for i in range(1, depth):
            current.append([{'password': f'secret{i}'}])
            current = current[-1]
        
        try:
            cleaned = cleaner.clean_credentials(data)
            # Verify structure is preserved
            assert isinstance(cleaned, list)
        except RecursionError:
            pytest.fail("Deep recursion DoS: Stack overflow on deeply nested list")
        except Exception as e:
            assert "maximum recursion depth" not in str(e).lower()


# ============================================================================
# 3. CIRCULAR REFERENCE CRASHES
# ============================================================================

class TestCredentialCleanupCircularReferences:
    """Test circular reference handling."""
    
    def test_circular_reference_in_dict(self):
        """Test that circular references don't cause infinite loops."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Create circular reference
        data = {'password': 'secret', 'nested': {}}
        data['nested']['parent'] = data  # Circular reference
        
        # Should handle without infinite loop
        import time
        start = time.time()
        try:
            cleaned = cleaner.clean_credentials(data)
            elapsed = time.time() - start
            
            # Should complete quickly (< 5 seconds)
            assert elapsed < 5.0, "Circular reference caused infinite loop or excessive processing"
        except RecursionError:
            pytest.fail("Circular reference caused recursion error")
    
    def test_circular_reference_in_list(self):
        """Test that circular references in lists don't cause infinite loops."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Create circular reference in list
        data = [{'password': 'secret'}]
        data.append(data)  # List contains itself
        
        import time
        start = time.time()
        try:
            cleaned = cleaner.clean_credentials(data)
            elapsed = time.time() - start
            
            assert elapsed < 5.0, "Circular reference in list caused infinite loop"
        except RecursionError:
            pytest.fail("Circular reference in list caused recursion error")
    
    def test_complex_circular_reference(self):
        """Test complex circular reference scenarios."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Create complex circular structure
        data = {'a': {'password': 'secret1'}, 'b': {'password': 'secret2'}}
        data['a']['ref'] = data['b']
        data['b']['ref'] = data['a']
        data['c'] = data  # Top-level circular reference
        
        import time
        start = time.time()
        try:
            cleaned = cleaner.clean_credentials(data)
            elapsed = time.time() - start
            
            assert elapsed < 5.0, "Complex circular reference caused infinite loop"
        except RecursionError:
            pytest.fail("Complex circular reference caused recursion error")


# ============================================================================
# 4. MEMORY EXHAUSTION ATTACKS
# ============================================================================

class TestCredentialCleanupMemoryExhaustion:
    """Test memory exhaustion vulnerabilities."""
    
    def test_large_payload_handling(self):
        """Test that large payloads are handled without memory exhaustion."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Create large payload (10MB of data)
        large_data = {
            'password': 'secret',
            'large_field': 'x' * (10 * 1024 * 1024),  # 10MB string
            'many_fields': {f'field_{i}': f'value_{i}' for i in range(10000)}
        }
        
        try:
            cleaned = cleaner.clean_credentials(large_data)
            # Verify password was masked
            assert cleaned['password'] == '***REDACTED***'
            # Verify large field is preserved
            assert len(cleaned['large_field']) == 10 * 1024 * 1024
        except MemoryError:
            pytest.fail("Memory exhaustion: Large payload caused memory error")
        except Exception as e:
            # Other exceptions might be acceptable, but memory errors are not
            assert "memory" not in str(e).lower() or "cannot allocate" not in str(e).lower()
    
    def test_many_credential_fields(self):
        """Test that many credential fields don't cause memory issues."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Create payload with many credential fields
        data = {f'password_{i}': f'secret_{i}' for i in range(10000)}
        data['normal_field'] = 'value'
        
        try:
            cleaned = cleaner.clean_credentials(data)
            # All passwords should be masked
            for i in range(min(100, 10000)):  # Check first 100
                assert cleaned[f'password_{i}'] == '***REDACTED***'
            assert cleaned['normal_field'] == 'value'
        except MemoryError:
            pytest.fail("Memory exhaustion: Many credential fields caused memory error")


# ============================================================================
# 5. CONFIGURATION INJECTION ATTACKS
# ============================================================================

class TestCredentialCleanupConfigurationInjection:
    """Test configuration injection vulnerabilities."""
    
    def test_custom_fields_type_validation(self):
        """Test that custom_fields parameter validates types correctly."""
        # Should handle non-list custom_fields gracefully
        malicious_configs = [
            None,
            'not_a_list',
            123,
            {'not': 'a_list'},
            ['valid', 123, None, {}],  # Mixed types in list
        ]
        
        for malicious_config in malicious_configs:
            try:
                if malicious_config is None:
                    # None should be handled (defaults to empty list)
                    cleaner = CredentialCleaner(custom_fields=None)
                    assert cleaner.credential_fields is not None
                elif isinstance(malicious_config, str):
                    # String should raise TypeError or be handled
                    with pytest.raises((TypeError, AttributeError)):
                        CredentialCleaner(custom_fields=malicious_config)
                elif isinstance(malicious_config, (int, dict)):
                    # Non-list types should raise TypeError
                    with pytest.raises((TypeError, AttributeError)):
                        CredentialCleaner(custom_fields=malicious_config)
                elif isinstance(malicious_config, list):
                    # List with non-string items should be handled or raise error
                    try:
                        cleaner = CredentialCleaner(custom_fields=malicious_config)
                        # If it succeeds, verify it handles non-strings gracefully
                        assert cleaner.credential_fields is not None
                    except (TypeError, AttributeError):
                        pass  # Expected for non-string items
            except Exception as e:
                # Should not crash with unhandled exception
                assert isinstance(e, (TypeError, AttributeError, ValueError))
    
    def test_custom_fields_injection_patterns(self):
        """Test that custom fields can't be used for injection attacks."""
        cleaner = CredentialCleaner(custom_fields=['normal_field'])
        
        # Custom field should be treated as credential
        data = {'normal_field': 'value', 'other_field': 'other'}
        cleaned = cleaner.clean_credentials(data)
        
        # normal_field should be masked (treated as credential)
        assert cleaned['normal_field'] == '***REDACTED***'
        assert cleaned['other_field'] == 'other'
    
    def test_mode_injection(self):
        """Test that mode parameter is validated correctly."""
        # Invalid modes should raise ValueError
        with pytest.raises(ValueError, match="Mode must be 'mask' or 'remove'"):
            CredentialCleaner(mode='inject')
        
        with pytest.raises(ValueError, match="Mode must be 'mask' or 'remove'"):
            CredentialCleaner(mode='')
        
        with pytest.raises(ValueError, match="Mode must be 'mask' or 'remove'"):
            CredentialCleaner(mode=None)
        
        # Valid modes should work
        cleaner1 = CredentialCleaner(mode='mask')
        assert cleaner1.mode == 'mask'
        
        cleaner2 = CredentialCleaner(mode='remove')
        assert cleaner2.mode == 'remove'
        
        # Case insensitive
        cleaner3 = CredentialCleaner(mode='MASK')
        assert cleaner3.mode == 'mask'


# ============================================================================
# 6. PATTERN BYPASS ATTEMPTS
# ============================================================================

class TestCredentialCleanupPatternBypass:
    """Test pattern bypass attempts."""
    
    def test_unicode_credential_field_names(self):
        """Test that Unicode field names are handled correctly."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Unicode variations of 'password'
        unicode_fields = [
            'pässword',  # Unicode character
            'passwörd',  # Unicode character
            'password\u200b',  # Zero-width space
            'password\u200c',  # Zero-width non-joiner
            'password\u200d',  # Zero-width joiner
            'password\ufeff',  # BOM
        ]
        
        for field_name in unicode_fields:
            data = {field_name: 'secret'}
            cleaned = cleaner.clean_credentials(data)
            
            # Should either mask it (if pattern matches) or leave it (if pattern doesn't match)
            # The key is that it doesn't crash
            assert field_name in cleaned or '***REDACTED***' in str(cleaned.values())
    
    def test_control_character_field_names(self):
        """Test that control characters in field names are handled."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Control characters in field names
        control_char_fields = [
            'pass\x00word',  # Null byte
            'pass\nword',   # Newline
            'pass\tword',   # Tab
            'pass\rword',   # Carriage return
        ]
        
        for field_name in control_char_fields:
            data = {field_name: 'secret'}
            try:
                cleaned = cleaner.clean_credentials(data)
                # Should handle without crashing
                assert isinstance(cleaned, dict)
            except Exception as e:
                # Should not crash with unhandled exception
                assert False, f"Control character in field name caused unhandled exception: {e}"
    
    def test_obfuscated_credential_field_names(self):
        """Test obfuscated credential field names."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Obfuscated field names that might bypass patterns
        obfuscated_fields = [
            'p@ssw0rd',  # Character substitution
            'p_a_s_s_w_o_r_d',  # Separated
            'PASS_WORD',  # Different case and separator
            'pass_word',  # Underscore
            'pass-word',  # Hyphen
            'pass.word',  # Dot
        ]
        
        for field_name in obfuscated_fields:
            data = {field_name: 'secret'}
            cleaned = cleaner.clean_credentials(data)
            
            # Pattern matching should catch most of these
            # If pattern matches, should be masked
            # If not, should be preserved
            assert field_name in cleaned or '***REDACTED***' in str(cleaned.values())


# ============================================================================
# 7. TYPE CONFUSION ATTACKS
# ============================================================================

class TestCredentialCleanupTypeConfusion:
    """Test type confusion vulnerabilities."""
    
    def test_non_string_credential_values(self):
        """Test that non-string credential values are handled correctly."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Non-string values in credential fields
        data = {
            'password': 12345,  # Integer
            'api_key': None,    # None
            'token': True,      # Boolean
            'secret': ['list', 'of', 'values'],  # List
            'auth': {'nested': 'dict'},  # Dict
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        # All credential fields should be masked regardless of value type
        assert cleaned['password'] == '***REDACTED***'
        assert cleaned['api_key'] == '***REDACTED***'
        assert cleaned['token'] == '***REDACTED***'
        # For containers, they should be processed recursively
        if isinstance(cleaned.get('secret'), list):
            # List should be preserved but contents might be cleaned
            assert isinstance(cleaned['secret'], list)
        if isinstance(cleaned.get('auth'), dict):
            # Dict should be preserved
            assert isinstance(cleaned['auth'], dict)
    
    def test_non_dict_list_payload(self):
        """Test that non-dict/list payloads are handled correctly."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Primitive types should be returned as-is
        assert cleaner.clean_credentials('string') == 'string'
        assert cleaner.clean_credentials(123) == 123
        assert cleaner.clean_credentials(True) is True
        assert cleaner.clean_credentials(None) is None
    
    def test_mixed_type_structures(self):
        """Test structures with mixed types."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Mixed type structure
        data = {
            'password': 'secret',
            'numbers': [1, 2, 3],
            'mixed': ['string', 123, {'nested': 'value', 'token': 'secret'}],
            'null_field': None,
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        # Password should be masked
        assert cleaned['password'] == '***REDACTED***'
        # Other fields should be preserved
        assert cleaned['numbers'] == [1, 2, 3]
        # Nested token should be masked
        if isinstance(cleaned.get('mixed'), list) and len(cleaned['mixed']) > 2:
            nested = cleaned['mixed'][2]
            if isinstance(nested, dict) and 'token' in nested:
                assert nested['token'] == '***REDACTED***'


# ============================================================================
# 8. INFORMATION DISCLOSURE
# ============================================================================

class TestCredentialCleanupInformationDisclosure:
    """Test information disclosure vulnerabilities."""
    
    def test_error_message_sanitization(self):
        """Test that error messages don't leak sensitive information."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Try to trigger errors that might leak information
        # Most operations should not raise exceptions, but if they do,
        # they shouldn't leak credential data
        
        # Test with invalid data structures
        try:
            # This might raise an exception
            result = cleaner.clean_credentials(object())  # Invalid type
            # If it doesn't raise, should return as-is
            assert result is not None
        except Exception as e:
            # Error message should not contain credential data
            error_msg = str(e).lower()
            assert 'secret' not in error_msg
            assert 'password' not in error_msg
            assert 'token' not in error_msg
            assert 'key' not in error_msg
    
    def test_exception_handling_in_cleanup(self):
        """Test that exceptions during cleanup don't leak information."""
        # Create a data structure that might cause issues
        class ProblematicObject:
            def __getitem__(self, key):
                raise Exception("Internal error with secret data")
        
        cleaner = CredentialCleaner(mode='mask')
        
        # Should handle gracefully without leaking
        try:
            result = cleaner.clean_credentials(ProblematicObject())
        except Exception as e:
            # If exception is raised, it shouldn't leak credential info
            error_msg = str(e).lower()
            assert 'secret' not in error_msg


# ============================================================================
# 9. INCOMPLETE REDACTION SCENARIOS
# ============================================================================

class TestCredentialCleanupIncompleteRedaction:
    """Test incomplete redaction scenarios."""
    
    def test_credential_in_nested_container(self):
        """Test that credentials in nested containers are properly handled."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Credential field with container value should be processed recursively
        data = {
            'password': {
                'nested_password': 'secret',
                'normal_field': 'value'
            }
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        # The password field itself should be processed recursively
        # The nested_password inside should also be masked
        if isinstance(cleaned.get('password'), dict):
            assert cleaned['password'].get('nested_password') == '***REDACTED***'
            assert cleaned['password'].get('normal_field') == 'value'
    
    def test_credential_partial_match(self):
        """Test that partial credential matches are handled."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Field names that partially match patterns
        data = {
            'user_password_field': 'secret1',
            'api_secret_key': 'secret2',
            'auth_token_value': 'secret3',
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        # All should be masked due to pattern matching
        assert cleaned['user_password_field'] == '***REDACTED***'
        assert cleaned['api_secret_key'] == '***REDACTED***'
        assert cleaned['auth_token_value'] == '***REDACTED***'
    
    def test_remove_mode_completeness(self):
        """Test that remove mode completely removes credentials."""
        cleaner = CredentialCleaner(mode='remove')
        
        data = {
            'username': 'user',
            'password': 'secret',
            'api_key': 'key',
            'normal_field': 'value',
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        # Credentials should be completely removed
        assert 'password' not in cleaned
        assert 'api_key' not in cleaned
        # Non-credentials should remain
        assert cleaned['username'] == 'user'
        assert cleaned['normal_field'] == 'value'


# ============================================================================
# 10. EDGE CASES AND SPECIAL CHARACTERS
# ============================================================================

class TestCredentialCleanupEdgeCases:
    """Test edge cases and special character handling."""
    
    def test_empty_string_credentials(self):
        """Test that empty string credentials are handled."""
        cleaner = CredentialCleaner(mode='mask')
        
        data = {
            'password': '',
            'api_key': '',
            'token': None,
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        # Empty strings should still be masked
        assert cleaned['password'] == '***REDACTED***'
        assert cleaned['api_key'] == '***REDACTED***'
        # None should also be masked
        assert cleaned['token'] == '***REDACTED***'
    
    def test_very_long_credential_values(self):
        """Test that very long credential values are handled."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Very long credential value (1MB)
        long_secret = 'x' * (1024 * 1024)
        data = {
            'password': long_secret,
            'api_key': 'normal_key',
        }
        
        cleaned = cleaner.clean_credentials(data)
        
        # Should be masked regardless of length
        assert cleaned['password'] == '***REDACTED***'
        assert cleaned['api_key'] == '***REDACTED***'
    
    def test_special_characters_in_credential_values(self):
        """Test special characters in credential values."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Special characters that might cause issues
        special_values = [
            '\x00\x01\x02',  # Control characters
            'secret\nwith\nnewlines',
            'secret\twith\ttabs',
            'secret"with"quotes',
            "secret'with'quotes",
            'secret<script>alert(1)</script>',  # XSS attempt
            'secret; DROP TABLE users;--',  # SQL injection attempt
        ]
        
        for special_value in special_values:
            data = {'password': special_value}
            cleaned = cleaner.clean_credentials(data)
            
            # Should be masked regardless of content
            assert cleaned['password'] == '***REDACTED***'
    
    def test_unicode_credential_values(self):
        """Test Unicode characters in credential values."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Unicode values
        unicode_values = [
            'secret\u4e2d\u6587',  # Chinese characters
            'secret\u3042\u3044\u3046',  # Japanese characters
            'secret\U0001F600',  # Emoji
        ]
        
        for unicode_value in unicode_values:
            data = {'password': unicode_value}
            cleaned = cleaner.clean_credentials(data)
            
            # Should be masked
            assert cleaned['password'] == '***REDACTED***'
    
    def test_empty_dict_and_list(self):
        """Test empty structures."""
        cleaner = CredentialCleaner(mode='mask')
        
        assert cleaner.clean_credentials({}) == {}
        assert cleaner.clean_credentials([]) == []
        assert cleaner.clean_credentials(None) is None
    
    def test_headers_type_validation(self):
        """Test that clean_headers validates input types."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Non-dict inputs should be handled gracefully
        assert cleaner.clean_headers(None) == {}
        assert cleaner.clean_headers('not_a_dict') == {}
        assert cleaner.clean_headers(123) == {}
        assert cleaner.clean_headers([]) == {}
    
    def test_query_params_type_validation(self):
        """Test that clean_query_params validates input types."""
        cleaner = CredentialCleaner(mode='mask')
        
        # Non-dict inputs should be handled gracefully
        assert cleaner.clean_query_params(None) == {}
        assert cleaner.clean_query_params('not_a_dict') == {}
        assert cleaner.clean_query_params(123) == {}
        assert cleaner.clean_query_params([]) == {}

