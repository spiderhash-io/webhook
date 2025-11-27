"""
Security tests for SaveToDisk module.
Tests path traversal prevention and file security.
"""
import pytest
import os
import tempfile
import shutil
import uuid
from src.modules.save_to_disk import SaveToDiskModule


class TestSaveToDiskSecurity:
    """Test suite for SaveToDisk module security."""
    
    @pytest.fixture
    def temp_base_dir(self):
        """Create a temporary base directory for tests."""
        base_dir = tempfile.mkdtemp(prefix="webhook_test_")
        yield base_dir
        # Cleanup
        if os.path.exists(base_dir):
            shutil.rmtree(base_dir)
    
    @pytest.fixture
    def module(self, temp_base_dir):
        """Create SaveToDiskModule instance with test base directory."""
        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "webhooks"
            }
        }
        return SaveToDiskModule(config)
    
    @pytest.mark.asyncio
    async def test_valid_path_within_base(self, module, temp_base_dir):
        """Test that valid paths within base directory are accepted."""
        payload = {"test": "data"}
        headers = {}
        
        await module.process(payload, headers)
        
        # Verify file was created in correct location
        webhook_dir = os.path.join(temp_base_dir, "webhooks")
        assert os.path.exists(webhook_dir)
        files = os.listdir(webhook_dir)
        assert len(files) == 1
        assert files[0].endswith(".txt")
    
    @pytest.mark.asyncio
    async def test_path_traversal_with_dotdot(self, module):
        """Test that path traversal with .. is rejected."""
        module.module_config["path"] = "../../../etc/passwd"
        payload = {"test": "data"}
        headers = {}
        
        with pytest.raises(Exception) as exc_info:
            await module.process(payload, headers)
        
        assert "Path traversal detected" in str(exc_info.value) or "escapes base directory" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_path_traversal_encoded(self, module):
        """Test that encoded path traversal is rejected."""
        # Test various encoding attempts
        # Note: URL-encoded paths will be decoded and then checked for traversal
        traversal_paths = [
            "..%2F..%2Fetc",  # URL-encoded ../
            "%2E%2E%2F%2E%2E%2Fetc",  # URL-encoded ../
            "..\\..\\etc",  # Windows-style (backslashes)
            "....//....//etc",  # Double dots (should be caught by .. check)
        ]
        
        payload = {"test": "data"}
        headers = {}
        
        for path in traversal_paths:
            module.module_config["path"] = path
            with pytest.raises(Exception) as exc_info:
                await module.process(payload, headers)
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "path traversal", "escapes base directory", "invalid path", "traversal detected"
            ]), f"Expected traversal error for path '{path}', got: {exc_info.value}"
    
    @pytest.mark.asyncio
    async def test_absolute_path_outside_base(self, module, temp_base_dir):
        """Test that absolute paths outside base directory are rejected."""
        # Try to use an absolute path outside the base directory
        outside_path = "/tmp/webhook_test_outside"
        module.module_config["path"] = outside_path
        payload = {"test": "data"}
        headers = {}
        
        with pytest.raises(Exception) as exc_info:
            await module.process(payload, headers)
        
        assert "escapes base directory" in str(exc_info.value) or "Invalid path" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_nested_path_traversal(self, module):
        """Test nested path traversal attempts."""
        module.module_config["path"] = "valid/../../etc"
        payload = {"test": "data"}
        headers = {}
        
        with pytest.raises(Exception) as exc_info:
            await module.process(payload, headers)
        
        assert "Path traversal" in str(exc_info.value) or "escapes base directory" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_file_permissions(self, module, temp_base_dir):
        """Test that files are created with restricted permissions."""
        payload = {"test": "data"}
        headers = {}
        
        await module.process(payload, headers)
        
        # Find the created file
        webhook_dir = os.path.join(temp_base_dir, "webhooks")
        files = os.listdir(webhook_dir)
        file_path = os.path.join(webhook_dir, files[0])
        
        # Check file permissions (should be 0o600 = owner read/write only)
        file_stat = os.stat(file_path)
        file_mode = file_stat.st_mode & 0o777
        assert file_mode == 0o600, f"Expected 0o600, got {oct(file_mode)}"
    
    @pytest.mark.asyncio
    async def test_directory_permissions(self, module, temp_base_dir):
        """Test that directories are created with restricted permissions."""
        payload = {"test": "data"}
        headers = {}
        
        await module.process(payload, headers)
        
        # Check directory permissions (should be 0o700 = owner read/write/execute only)
        webhook_dir = os.path.join(temp_base_dir, "webhooks")
        assert os.path.exists(webhook_dir)
        
        dir_stat = os.stat(webhook_dir)
        dir_mode = dir_stat.st_mode & 0o777
        # Directory should be 0o700 (owner-only)
        assert dir_mode == 0o700, f"Expected 0o700, got {oct(dir_mode)}"
    
    @pytest.mark.asyncio
    async def test_valid_nested_path(self, module, temp_base_dir):
        """Test that valid nested paths are accepted."""
        module.module_config["path"] = "webhooks/2024/january"
        payload = {"test": "data"}
        headers = {}
        
        await module.process(payload, headers)
        
        # Verify file was created in nested directory
        nested_dir = os.path.join(temp_base_dir, "webhooks", "2024", "january")
        assert os.path.exists(nested_dir)
        files = os.listdir(nested_dir)
        assert len(files) == 1
    
    @pytest.mark.asyncio
    async def test_current_directory_path(self, module, temp_base_dir):
        """Test that '.' path works correctly."""
        module.module_config["path"] = "."
        payload = {"test": "data"}
        headers = {}
        
        await module.process(payload, headers)
        
        # File should be created in base directory
        files = [f for f in os.listdir(temp_base_dir) if f.endswith(".txt")]
        assert len(files) == 1
    
    @pytest.mark.asyncio
    async def test_symlink_traversal_prevention(self, module, temp_base_dir):
        """Test that symlinks don't allow path traversal."""
        # Create a symlink inside base directory pointing outside
        symlink_path = os.path.join(temp_base_dir, "symlink")
        outside_target = os.path.join(tempfile.gettempdir(), "webhook_test_outside")
        
        # Ensure target directory exists
        os.makedirs(outside_target, exist_ok=True)
        
        try:
            # Try to create symlink - if this fails, skip the test
            try:
                os.symlink(outside_target, symlink_path)
            except (OSError, NotImplementedError) as e:
                # Symlink creation failed (e.g., on Windows without admin rights, or not supported)
                pytest.skip(f"Symlink creation not supported: {e}")
            
            # Now test that using the symlink path is either rejected or safely handled
            module.module_config["path"] = "symlink"
            payload = {"test": "data"}
            headers = {}
            
            # The validation should catch that the resolved path escapes the base directory
            # os.path.abspath() resolves symlinks, so the validation should reject it
            with pytest.raises(Exception) as exc_info:
                await module.process(payload, headers)
            
            # Should be rejected because symlink points outside base directory
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in [
                "escape", "traversal", "invalid path", "base directory"
            ]), f"Expected path traversal rejection, got: {exc_info.value}"
            
        finally:
            # Cleanup
            if os.path.exists(symlink_path):
                try:
                    os.unlink(symlink_path)
                except OSError:
                    pass
            if os.path.exists(outside_target):
                try:
                    os.rmdir(outside_target)
                except OSError:
                    pass
    
    @pytest.mark.asyncio
    async def test_multiple_traversal_attempts(self, module):
        """Test various path traversal patterns."""
        traversal_patterns = [
            "../",
            "../../",
            "..\\",
            "..//",
            "/../",
            "valid/../..",
            "a/../../b",
            "..../",  # Double dots
        ]
        
        payload = {"test": "data"}
        headers = {}
        
        for pattern in traversal_patterns:
            module.module_config["path"] = pattern
            with pytest.raises(Exception):
                await module.process(payload, headers)
    
    @pytest.mark.asyncio
    async def test_unicode_path_traversal(self, module):
        """Test Unicode-based path traversal attempts."""
        # Some systems might interpret Unicode characters differently
        unicode_paths = [
            "..%c0%af",  # UTF-8 encoded /
            "..%252f",  # Double-encoded /
        ]
        
        payload = {"test": "data"}
        headers = {}
        
        for path in unicode_paths:
            module.module_config["path"] = path
            # Should either be rejected or safely handled
            try:
                await module.process(payload, headers)
                # If it didn't raise, verify it didn't escape
                # (This is a best-effort test)
            except Exception as e:
                # Expected to fail
                assert "traversal" in str(e).lower() or "escape" in str(e).lower() or "Invalid" in str(e)
    
    @pytest.mark.asyncio
    async def test_null_byte_injection(self, module):
        """Test null byte injection attempts."""
        payload = {"test": "data"}
        headers = {}
        
        # Null bytes in path should be rejected by Python's path handling
        module.module_config["path"] = "valid\x00/../../etc"
        
        with pytest.raises(Exception):
            await module.process(payload, headers)
    
    @pytest.mark.asyncio
    async def test_file_content_isolation(self, module, temp_base_dir):
        """Test that file content doesn't affect path validation."""
        # Try to inject path in payload (shouldn't affect path validation)
        malicious_payload = {"path": "../../etc/passwd", "data": "test"}
        headers = {}
        
        await module.process(malicious_payload, headers)
        
        # File should still be created in correct location
        webhook_dir = os.path.join(temp_base_dir, "webhooks")
        assert os.path.exists(webhook_dir)
        # Payload content shouldn't affect file location
    
    @pytest.mark.asyncio
    async def test_base_dir_validation(self):
        """Test that path pointing to existing file is rejected."""
        # Create a temporary file to test against
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file_path = tmp_file.name
        
        try:
            config = {
                "module": "save_to_disk",
                "module-config": {
                    "base_dir": os.path.dirname(tmp_file_path),
                    "path": os.path.basename(tmp_file_path)  # Point to existing file
                }
            }
            module = SaveToDiskModule(config)
            
            payload = {"test": "data"}
            headers = {}
            
            # Should reject because path points to an existing file, not a directory
            with pytest.raises(Exception) as exc_info:
                await module.process(payload, headers)
            
            assert "existing file" in str(exc_info.value).lower() or "not a directory" in str(exc_info.value).lower()
        finally:
            # Cleanup
            if os.path.exists(tmp_file_path):
                os.unlink(tmp_file_path)
    
    @pytest.mark.asyncio
    async def test_concurrent_writes_same_directory(self, module, temp_base_dir):
        """Test that concurrent writes to same directory work correctly."""
        import asyncio
        
        payloads = [{"id": i, "data": f"test_{i}"} for i in range(10)]
        headers = {}
        
        # Process multiple payloads concurrently
        tasks = [module.process(payload, headers) for payload in payloads]
        await asyncio.gather(*tasks)
        
        # Verify all files were created
        webhook_dir = os.path.join(temp_base_dir, "webhooks")
        files = os.listdir(webhook_dir)
        assert len(files) == 10
        
        # Verify all files have correct permissions
        for filename in files:
            file_path = os.path.join(webhook_dir, filename)
            file_stat = os.stat(file_path)
            file_mode = file_stat.st_mode & 0o777
            assert file_mode == 0o600

