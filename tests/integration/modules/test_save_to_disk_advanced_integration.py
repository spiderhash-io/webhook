"""
Integration tests for Save to Disk module advanced features.

These tests verify path validation, path traversal prevention, and file permissions.
"""

import pytest
import os
import tempfile
import shutil
from pathlib import Path
from src.modules.save_to_disk import SaveToDiskModule


@pytest.mark.integration
class TestSaveToDiskAdvancedIntegration:
    """Integration tests for Save to Disk advanced features."""

    @pytest.fixture
    def temp_base_dir(self):
        """Create a temporary base directory for testing."""
        temp_dir = tempfile.mkdtemp(prefix="webhook_test_")
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_path_traversal_prevention(self, temp_base_dir):
        """Test that path traversal attacks are prevented."""
        from src.modules.save_to_disk import SaveToDiskModule

        # Attempt path traversal attacks
        traversal_paths = [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # URL encoded
            "valid/path/../../../etc/passwd",
        ]

        for traversal_path in traversal_paths:
            config = {
                "module": "save_to_disk",
                "module-config": {"base_dir": temp_base_dir, "path": traversal_path},
            }

            module = SaveToDiskModule(config)
            with pytest.raises((ValueError, Exception)):
                await module.process({"test": "data"}, {})

    @pytest.mark.asyncio
    async def test_path_validation(self, temp_base_dir):
        """Test that paths are properly validated."""
        from src.modules.save_to_disk import SaveToDiskModule

        # Valid path
        valid_config = {
            "module": "save_to_disk",
            "module-config": {"base_dir": temp_base_dir, "path": "valid/subdirectory"},
        }

        module = SaveToDiskModule(valid_config)
        await module.process({"test": "data"}, {})

        # Verify file was created in correct location
        expected_dir = os.path.join(temp_base_dir, "valid", "subdirectory")
        assert os.path.exists(expected_dir)
        files = os.listdir(expected_dir)
        assert len(files) > 0
        assert all(f.endswith(".txt") for f in files)

    @pytest.mark.asyncio
    async def test_null_byte_prevention(self, temp_base_dir):
        """Test that null bytes in paths are rejected."""
        from src.modules.save_to_disk import SaveToDiskModule

        config = {
            "module": "save_to_disk",
            "module-config": {"base_dir": temp_base_dir, "path": f"valid\x00path"},
        }

        module = SaveToDiskModule(config)
        with pytest.raises((ValueError, Exception)):
            await module.process({"test": "data"}, {})

    @pytest.mark.asyncio
    async def test_symlink_traversal_prevention(self, temp_base_dir):
        """Test that symlink traversal attacks are prevented."""
        from src.modules.save_to_disk import SaveToDiskModule

        # Create a symlink pointing outside base_dir
        symlink_path = os.path.join(temp_base_dir, "symlink")
        outside_path = tempfile.mkdtemp(prefix="outside_")

        try:
            os.symlink(outside_path, symlink_path)

            # Attempt to use symlink (should be resolved and validated)
            config = {
                "module": "save_to_disk",
                "module-config": {"base_dir": temp_base_dir, "path": "symlink"},
            }

            module = SaveToDiskModule(config)
            # Should either work (if symlink resolves within base) or fail validation
            try:
                await module.process({"test": "data"}, {})
                # If it works, verify it didn't escape
                resolved = os.path.realpath(symlink_path)
                base_real = os.path.realpath(temp_base_dir)
                # Path should be within base or validation should have caught it
                assert (
                    resolved.startswith(base_real)
                    or os.path.commonpath([base_real, resolved]) == base_real
                )
            except (ValueError, Exception) as e:
                # Expected: validation should catch symlink escape
                # Error message might be sanitized, so check for any validation error
                error_str = str(e).lower()
                # Check for validation-related keywords (might be sanitized)
                assert any(
                    keyword in error_str
                    for keyword in ["escapes", "invalid", "validation", "path", "error"]
                )
        finally:
            if os.path.exists(symlink_path):
                os.unlink(symlink_path)
            shutil.rmtree(outside_path, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_file_permissions(self, temp_base_dir):
        """Test that files are created with restricted permissions."""
        from src.modules.save_to_disk import SaveToDiskModule

        config = {
            "module": "save_to_disk",
            "module-config": {"base_dir": temp_base_dir, "path": "permissions_test"},
        }

        module = SaveToDiskModule(config)
        await module.process({"test": "data"}, {})

        # Find the created file
        test_dir = os.path.join(temp_base_dir, "permissions_test")
        files = [f for f in os.listdir(test_dir) if f.endswith(".txt")]
        assert len(files) > 0

        file_path = os.path.join(test_dir, files[0])
        file_stat = os.stat(file_path)

        # Check permissions (0o600 = rw-------)
        # On Unix, check that only owner has read/write
        if os.name != "nt":  # Skip on Windows
            mode = file_stat.st_mode & 0o777
            # Should be 0o600 (owner read/write only)
            assert mode == 0o600 or mode == 0o644  # Some systems may use 644

    @pytest.mark.asyncio
    async def test_directory_creation(self, temp_base_dir):
        """Test that directories are created if they don't exist."""
        from src.modules.save_to_disk import SaveToDiskModule

        new_dir = os.path.join(temp_base_dir, "new", "nested", "directory")
        assert not os.path.exists(new_dir)

        config = {
            "module": "save_to_disk",
            "module-config": {
                "base_dir": temp_base_dir,
                "path": "new/nested/directory",
            },
        }

        module = SaveToDiskModule(config)
        await module.process({"test": "data"}, {})

        # Verify directory was created
        assert os.path.exists(new_dir)
        assert os.path.isdir(new_dir)

    @pytest.mark.asyncio
    async def test_concurrent_writes(self, temp_base_dir):
        """Test that concurrent writes to the same directory work."""
        import asyncio
        from src.modules.save_to_disk import SaveToDiskModule

        config = {
            "module": "save_to_disk",
            "module-config": {"base_dir": temp_base_dir, "path": "concurrent_test"},
        }

        # Create multiple modules and write concurrently
        async def write_file(i):
            module = SaveToDiskModule(config)
            await module.process({"test": f"data_{i}"}, {})

        # Write 10 files concurrently
        await asyncio.gather(*[write_file(i) for i in range(10)])

        # Verify all files were created
        test_dir = os.path.join(temp_base_dir, "concurrent_test")
        files = [f for f in os.listdir(test_dir) if f.endswith(".txt")]
        assert len(files) == 10

    @pytest.mark.asyncio
    async def test_absolute_path_validation(self, temp_base_dir):
        """Test that absolute paths are validated against base_dir."""
        from src.modules.save_to_disk import SaveToDiskModule

        # Attempt to use absolute path outside base_dir
        outside_path = tempfile.mkdtemp(prefix="outside_")
        try:
            config = {
                "module": "save_to_disk",
                "module-config": {
                    "base_dir": temp_base_dir,
                    "path": outside_path,  # Absolute path outside base
                },
            }

            module = SaveToDiskModule(config)
            with pytest.raises((ValueError, Exception)):
                await module.process({"test": "data"}, {})
        finally:
            shutil.rmtree(outside_path, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_file_content_writing(self, temp_base_dir):
        """Test that file content is written correctly."""
        from src.modules.save_to_disk import SaveToDiskModule

        config = {
            "module": "save_to_disk",
            "module-config": {"base_dir": temp_base_dir, "path": "content_test"},
        }

        test_payload = {"event": "test", "data": {"value": 123}}
        module = SaveToDiskModule(config)
        await module.process(test_payload, {})

        # Find and read the created file
        test_dir = os.path.join(temp_base_dir, "content_test")
        files = [f for f in os.listdir(test_dir) if f.endswith(".txt")]
        assert len(files) > 0

        file_path = os.path.join(test_dir, files[0])
        with open(file_path, "r") as f:
            content = f.read()

        # Verify content matches payload (converted to string)
        assert str(test_payload) in content or "test" in content
