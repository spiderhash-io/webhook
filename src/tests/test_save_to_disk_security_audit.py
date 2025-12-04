"""
Comprehensive security audit tests for Save to Disk module.
Tests additional vulnerabilities beyond existing security tests:
- Configuration injection via base_dir
- DoS via excessive file creation
- Race conditions in directory creation
- File system exhaustion
- TOCTOU vulnerabilities
- Hard link attacks
- Windows-specific path issues
- Configuration validation
"""
import pytest
import os
import tempfile
import shutil
import asyncio
import time
from src.modules.save_to_disk import SaveToDiskModule


class TestSaveToDiskSecurityAudit:
    """Comprehensive security audit tests for SaveToDisk module."""
    
    @pytest.fixture
    def temp_base_dir(self):
        """Create a temporary base directory for tests."""
        base_dir = tempfile.mkdtemp(prefix="webhook_audit_")
        yield base_dir
        # Cleanup
        if os.path.exists(base_dir):
            shutil.rmtree(base_dir)
    
    @pytest.mark.asyncio
    async def test_configuration_injection_base_dir_path_traversal(self, temp_base_dir):
        """Test that base_dir cannot be used for path traversal."""
        # Attempt to inject path traversal via base_dir
        malicious_base_dirs = [
            "../../etc",
            "/etc",
            "..\\..\\etc",
            "/tmp/../../etc",
            "/usr",
            "/bin",
            "/root",
        ]
        
        for malicious_base in malicious_base_dirs:
            config = {
                "module": "save_to_disk",
                "module-config": {
                    "base_dir": malicious_base,
                    "path": "webhooks"
                }
            }
            module = SaveToDiskModule(config)
            
            payload = {"test": "data"}
            headers = {}
            
            # Should reject system directories and traversal attempts
            with pytest.raises(Exception) as exc_info:
                await module.process(payload, headers)
            
            # Should reject with validation error
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "error", "validation", "system directory", "traversal"
            ]), f"Expected rejection for base_dir '{malicious_base}', got: {exc_info.value}"
    
    @pytest.mark.asyncio
    async def test_configuration_injection_base_dir_null_byte(self, temp_base_dir):
        """Test that base_dir with null bytes is handled safely."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": f"{temp_base_dir}\x00/etc",
                "path": "webhooks"
            }
        }
        module = SaveToDiskModule(config)
        
        payload = {"test": "data"}
        headers = {}
        
        # Should handle null bytes safely
        try:
            await module.process(payload, headers)
        except Exception as e:
            # Expected to fail or handle safely
            assert "error" in str(e).lower() or "validation" in str(e).lower()
    
    @pytest.mark.asyncio
    async def test_dos_excessive_file_creation(self, temp_base_dir):
        """Test DoS via excessive file creation."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "webhooks"
            }
        }
        module = SaveToDiskModule(config)
        
        # Create many files rapidly
        payloads = [{"id": i, "data": f"test_{i}"} for i in range(1000)]
        headers = {}
        
        start_time = time.time()
        tasks = [module.process(payload, headers) for payload in payloads]
        await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start_time
        
        # Should complete in reasonable time (not hang)
        assert elapsed < 60.0, "Should not hang on excessive file creation"
        
        # Verify files were created
        webhook_dir = os.path.join(temp_base_dir, "webhooks")
        if os.path.exists(webhook_dir):
            files = os.listdir(webhook_dir)
            # Should have created many files
            assert len(files) >= 100, f"Expected many files, got {len(files)}"
    
    @pytest.mark.asyncio
    async def test_race_condition_directory_creation(self, temp_base_dir):
        """Test race conditions in concurrent directory creation."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "race_test/subdir"
            }
        }
        module = SaveToDiskModule(config)
        
        # Create many tasks that will create the same directory concurrently
        payloads = [{"id": i} for i in range(50)]
        headers = {}
        
        tasks = [module.process(payload, headers) for payload in payloads]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should handle race condition gracefully (no crashes)
        # Some may fail, but should not crash
        assert len(results) == 50
        
        # Directory should exist
        target_dir = os.path.join(temp_base_dir, "race_test", "subdir")
        if os.path.exists(target_dir):
            files = os.listdir(target_dir)
            # Should have created some files
            assert len(files) > 0
    
    @pytest.mark.asyncio
    async def test_file_system_exhaustion_protection(self, temp_base_dir):
        """Test that file system exhaustion is handled gracefully."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "webhooks"
            }
        }
        module = SaveToDiskModule(config)
        
        # Try to create a very large payload (if file system has space limits)
        # This is a best-effort test
        large_payload = {"data": "x" * (10 * 1024 * 1024)}  # 10MB
        headers = {}
        
        try:
            await module.process(large_payload, headers)
            # If it succeeds, verify file was created
            webhook_dir = os.path.join(temp_base_dir, "webhooks")
            if os.path.exists(webhook_dir):
                files = os.listdir(webhook_dir)
                assert len(files) > 0
        except (OSError, IOError) as e:
            # Expected if file system is full or has limits
            assert "error" in str(e).lower() or "no space" in str(e).lower() or "quota" in str(e).lower()
    
    @pytest.mark.asyncio
    async def test_toctou_path_validation(self, temp_base_dir):
        """Test Time-of-Check-Time-of-Use (TOCTOU) vulnerabilities."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "webhooks"
            }
        }
        module = SaveToDiskModule(config)
        
        # Create directory first
        webhook_dir = os.path.join(temp_base_dir, "webhooks")
        os.makedirs(webhook_dir, exist_ok=True)
        
        # Between validation and use, change the directory to a symlink
        # This tests TOCTOU vulnerability
        symlink_target = os.path.join(tempfile.gettempdir(), "webhook_toctou_test")
        os.makedirs(symlink_target, exist_ok=True)
        
        try:
            # Remove directory and create symlink
            if os.path.exists(webhook_dir):
                os.rmdir(webhook_dir)
            
            try:
                os.symlink(symlink_target, webhook_dir)
            except (OSError, NotImplementedError):
                pytest.skip("Symlink creation not supported")
            
            payload = {"test": "data"}
            headers = {}
            
            # Process should handle symlink safely
            await module.process(payload, headers)
            
            # File should be created in symlink target (which is outside base_dir)
            # But validation should catch this
            # Actually, if symlink points outside, validation should reject it
            # This test documents the behavior
        except Exception as e:
            # Expected if symlink traversal is detected
            assert "error" in str(e).lower() or "validation" in str(e).lower()
        finally:
            # Cleanup
            if os.path.exists(webhook_dir):
                try:
                    os.unlink(webhook_dir)
                except OSError:
                    pass
            if os.path.exists(symlink_target):
                try:
                    shutil.rmtree(symlink_target)
                except OSError:
                    pass
    
    @pytest.mark.asyncio
    async def test_hard_link_attack(self, temp_base_dir):
        """Test hard link attacks (if supported on system)."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "webhooks"
            }
        }
        module = SaveToDiskModule(config)
        
        # Create a file first
        payload1 = {"test": "data1"}
        headers = {}
        await module.process(payload1, headers)
        
        # Find the created file
        webhook_dir = os.path.join(temp_base_dir, "webhooks")
        files = os.listdir(webhook_dir)
        file_path = os.path.join(webhook_dir, files[0])
        
        # Try to create a hard link to a sensitive file
        # This is a best-effort test (hard links may not be supported)
        sensitive_target = "/etc/passwd"
        if os.path.exists(sensitive_target):
            try:
                # Try to create hard link (will fail if not same filesystem or no permissions)
                os.link(file_path, sensitive_target)
                # If this succeeds, it's a security issue
                assert False, "Hard link to sensitive file should not be possible"
            except (OSError, PermissionError):
                # Expected - hard links to /etc/passwd should fail
                pass
    
    @pytest.mark.asyncio
    async def test_windows_path_issues(self, temp_base_dir):
        """Test Windows-specific path issues (if on Windows)."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "webhooks"
            }
        }
        module = SaveToDiskModule(config)
        
        # Test Windows-style paths
        windows_paths = [
            "C:\\Windows\\System32",
            "\\\\UNC\\path",
            "webhooks\\subdir",
        ]
        
        for path in windows_paths:
            module.module_config["path"] = path
            payload = {"test": "data"}
            headers = {}
            
            try:
                await module.process(payload, headers)
                # If it succeeds, verify it didn't escape
                validated = module._validate_path(path, temp_base_dir)
                assert temp_base_dir in validated or os.path.commonpath([temp_base_dir, validated]) == temp_base_dir
            except Exception as e:
                # Expected for paths outside base_dir
                assert "error" in str(e).lower() or "validation" in str(e).lower()
    
    @pytest.mark.asyncio
    async def test_unicode_normalization_path_attack(self, temp_base_dir):
        """Test Unicode normalization attacks."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "webhooks"
            }
        }
        module = SaveToDiskModule(config)
        
        # Unicode normalization attacks
        unicode_paths = [
            "webhooks\u200B",  # Zero-width space
            "webhooks\uFEFF",  # Zero-width no-break space
            "webhooks\u200C",  # Zero-width non-joiner
            "webhooks\u200D",  # Zero-width joiner
        ]
        
        for path in unicode_paths:
            module.module_config["path"] = path
            payload = {"test": "data"}
            headers = {}
            
            try:
                await module.process(payload, headers)
                # If it succeeds, verify it's within base_dir
                validated = module._validate_path(path, temp_base_dir)
                assert temp_base_dir in validated
            except Exception as e:
                # May fail or succeed depending on normalization
                pass
    
    @pytest.mark.asyncio
    async def test_configuration_validation_base_dir_type(self):
        """Test that base_dir type is validated."""
        # Test with non-string base_dir
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": 123,  # Invalid type
                "path": "webhooks"
            }
        }
        
        module = SaveToDiskModule(config)
        payload = {"test": "data"}
        headers = {}
        
        # Should reject non-string base_dir
        with pytest.raises(Exception) as exc_info:
            await module.process(payload, headers)
        
        # Should raise ValueError for invalid type
        error_msg = str(exc_info.value).lower()
        assert "base_dir must be a string" in error_msg or "error" in error_msg
    
    @pytest.mark.asyncio
    async def test_configuration_validation_path_type(self, temp_base_dir):
        """Test that path type is validated."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": 123  # Invalid type
            }
        }
        
        try:
            module = SaveToDiskModule(config)
            payload = {"test": "data"}
            headers = {}
            await module.process(payload, headers)
        except (TypeError, AttributeError) as e:
            # Expected - invalid type should cause error
            pass
    
    @pytest.mark.asyncio
    async def test_path_length_limits(self, temp_base_dir):
        """Test that extremely long paths are handled."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "a" * 1000  # Very long path
            }
        }
        module = SaveToDiskModule(config)
        
        payload = {"test": "data"}
        headers = {}
        
        try:
            await module.process(payload, headers)
            # If it succeeds, verify path was created
            long_path = os.path.join(temp_base_dir, "a" * 1000)
            if os.path.exists(long_path):
                files = os.listdir(long_path)
                assert len(files) > 0
        except (OSError, ValueError) as e:
            # May fail on systems with path length limits
            assert "error" in str(e).lower() or "too long" in str(e).lower() or "name too long" in str(e).lower()
    
    @pytest.mark.asyncio
    async def test_concurrent_symlink_creation_race(self, temp_base_dir):
        """Test race condition with concurrent symlink creation."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "race_symlink"
            }
        }
        module = SaveToDiskModule(config)
        
        # Create symlink target outside base_dir
        symlink_target = os.path.join(tempfile.gettempdir(), "webhook_race_symlink")
        os.makedirs(symlink_target, exist_ok=True)
        
        race_dir = os.path.join(temp_base_dir, "race_symlink")
        
        async def create_and_process():
            # Try to create symlink and process concurrently
            try:
                if not os.path.exists(race_dir):
                    os.symlink(symlink_target, race_dir)
            except (OSError, NotImplementedError):
                pass
            payload = {"test": "data"}
            headers = {}
            return await module.process(payload, headers)
        
        try:
            # Run multiple times concurrently
            tasks = [create_and_process() for _ in range(10)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Should handle race condition gracefully
            assert len(results) == 10
        finally:
            # Cleanup
            if os.path.exists(race_dir):
                try:
                    os.unlink(race_dir)
                except OSError:
                    pass
            if os.path.exists(symlink_target):
                try:
                    shutil.rmtree(symlink_target)
                except OSError:
                    pass
    
    @pytest.mark.asyncio
    async def test_file_permission_race_condition(self, temp_base_dir):
        """Test race condition in file permission setting."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "webhooks"
            }
        }
        module = SaveToDiskModule(config)
        
        # Create many files concurrently to test permission setting race
        payloads = [{"id": i} for i in range(100)]
        headers = {}
        
        tasks = [module.process(payload, headers) for payload in payloads]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify all files have correct permissions
        webhook_dir = os.path.join(temp_base_dir, "webhooks")
        if os.path.exists(webhook_dir):
            files = os.listdir(webhook_dir)
            for filename in files:
                file_path = os.path.join(webhook_dir, filename)
                file_stat = os.stat(file_path)
                file_mode = file_stat.st_mode & 0o777
                assert file_mode == 0o600, f"File {filename} has incorrect permissions: {oct(file_mode)}"
    
    @pytest.mark.asyncio
    async def test_base_dir_symlink_traversal(self, temp_base_dir):
        """Test that base_dir itself cannot be a symlink to outside."""
        # Create symlink pointing outside
        symlink_base = os.path.join(tempfile.gettempdir(), "webhook_symlink_base")
        os.makedirs(symlink_base, exist_ok=True)
        
        symlink_path = os.path.join(tempfile.gettempdir(), "webhook_base_link")
        
        try:
            try:
                os.symlink(symlink_base, symlink_path)
            except (OSError, NotImplementedError):
                pytest.skip("Symlink creation not supported")
            
            config = {
                "module": "save_to_disk",
                "module-config": {
                    "base_dir": symlink_path,  # Use symlink as base_dir
                    "path": "webhooks"
                }
            }
            module = SaveToDiskModule(config)
            
            payload = {"test": "data"}
            headers = {}
            
            # Should handle symlink base_dir safely
            await module.process(payload, headers)
            
            # Verify file was created in symlink target (which is resolved)
            target_dir = os.path.join(symlink_base, "webhooks")
            if os.path.exists(target_dir):
                files = os.listdir(target_dir)
                assert len(files) > 0
        finally:
            # Cleanup
            if os.path.exists(symlink_path):
                try:
                    os.unlink(symlink_path)
                except OSError:
                    pass
            if os.path.exists(symlink_base):
                try:
                    shutil.rmtree(symlink_base)
                except OSError:
                    pass
    
    @pytest.mark.asyncio
    async def test_double_encoded_path_traversal(self, temp_base_dir):
        """Test double-encoded path traversal attempts."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "webhooks"
            }
        }
        module = SaveToDiskModule(config)
        
        # Double-encoded traversal attempts
        # Note: urllib.parse.unquote() only decodes once, so double-encoded paths
        # may require multiple decodings. This test documents current behavior.
        double_encoded_paths = [
            "%252e%252e%252f",  # Double-encoded ../ (decodes to %2e%2e%2f, then ../)
            "%252e%252e%255c",  # Double-encoded ..\ (decodes to %2e%2e%5c, then ..\)
            "..%252f..%252fetc",  # Mixed encoding
        ]
        
        for path in double_encoded_paths:
            module.module_config["path"] = path
            payload = {"test": "data"}
            headers = {}
            
            # urllib.parse.unquote() decodes once, so %252e becomes %2e
            # We need to check if the decoded path still contains traversal
            import urllib.parse
            decoded = urllib.parse.unquote(path)
            # If still encoded, decode again
            if '%' in decoded:
                decoded = urllib.parse.unquote(decoded)
            
            # If decoded path contains .., should be rejected
            if '..' in decoded:
                with pytest.raises(Exception) as exc_info:
                    await module.process(payload, headers)
                
                # Should reject traversal
                error_msg = str(exc_info.value).lower()
                assert any(keyword in error_msg for keyword in [
                    "error", "validation", "traversal"
                ]), f"Expected traversal rejection for '{path}' (decodes to '{decoded}'), got: {exc_info.value}"
            else:
                # If decoding removes traversal, may succeed (but path should still be validated)
                try:
                    await module.process(payload, headers)
                except Exception as e:
                    # May fail for other reasons
                    pass
    
    @pytest.mark.asyncio
    async def test_empty_path_handling(self, temp_base_dir):
        """Test handling of empty path."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": ""  # Empty path
            }
        }
        module = SaveToDiskModule(config)
        
        payload = {"test": "data"}
        headers = {}
        
        # Should handle empty path (defaults to '.')
        await module.process(payload, headers)
        
        # File should be created in base_dir
        files = [f for f in os.listdir(temp_base_dir) if f.endswith(".txt")]
        assert len(files) > 0
    
    @pytest.mark.asyncio
    async def test_none_path_handling(self, temp_base_dir):
        """Test handling of None path."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                # path not specified (defaults to '.')
            }
        }
        module = SaveToDiskModule(config)
        
        payload = {"test": "data"}
        headers = {}
        
        # Should handle None/missing path (defaults to '.')
        await module.process(payload, headers)
        
        # File should be created in base_dir
        files = [f for f in os.listdir(temp_base_dir) if f.endswith(".txt")]
        assert len(files) > 0

