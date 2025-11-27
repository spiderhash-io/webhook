import uuid
import os
from typing import Any, Dict
from src.modules.base import BaseModule


class SaveToDiskModule(BaseModule):
    """Module for saving webhook payloads to disk."""
    
    def _validate_path(self, path: str, base_dir: str = None) -> str:
        """
        Validate and sanitize file path to prevent path traversal attacks.
        
        Args:
            path: The configured path from module-config
            base_dir: Base directory to restrict paths to (default: current working directory)
            
        Returns:
            Validated absolute path within base directory
            
        Raises:
            ValueError: If path contains traversal sequences or escapes base directory
        """
        if base_dir is None:
            base_dir = os.getcwd()
        
        # Normalize base directory to absolute path
        base_dir = os.path.abspath(base_dir)
        
        # URL decode the path to catch encoded traversal attempts
        import urllib.parse
        try:
            # Decode URL-encoded characters (e.g., %2F -> /, %2E -> .)
            decoded_path = urllib.parse.unquote(path)
        except Exception:
            # If decoding fails, use original path
            decoded_path = path
        
        # Reject paths containing traversal sequences (check both original and decoded)
        if '..' in path or '..' in decoded_path:
            raise ValueError(f"Path traversal detected: path cannot contain '..'")
        
        # Reject paths with null bytes
        if '\x00' in path or '\x00' in decoded_path:
            raise ValueError(f"Path contains null byte: invalid path")
        
        # Use decoded path for further processing
        path = decoded_path
        
        # Reject absolute paths that don't start with base_dir
        if os.path.isabs(path):
            abs_path = os.path.abspath(path)
        else:
            # Resolve relative path from base directory
            abs_path = os.path.abspath(os.path.join(base_dir, path))
        
        # Resolve symlinks to prevent symlink traversal attacks
        # Use realpath to resolve all symlinks in the path
        try:
            real_path = os.path.realpath(abs_path)
        except OSError:
            # If realpath fails (e.g., broken symlink), use abs_path
            real_path = abs_path
        
        # Ensure the resolved path is within base directory
        try:
            # Use commonpath to check if path is within base_dir
            # Also resolve base_dir to handle symlinks in base directory
            base_dir_real = os.path.realpath(base_dir)
            common_path = os.path.commonpath([base_dir_real, real_path])
            if common_path != base_dir_real:
                raise ValueError(f"Path escapes base directory: {path}")
        except ValueError:
            # commonpath raises ValueError if paths are on different drives (Windows)
            # In this case, check if real_path starts with base_dir_real
            if not real_path.startswith(base_dir_real):
                raise ValueError(f"Path escapes base directory: {path}")
        
        # Check if the path points to an existing file (should be a directory)
        # Use real_path to check the actual target (not the symlink)
        if os.path.exists(real_path) and not os.path.isdir(real_path):
            raise ValueError(f"Path points to an existing file, not a directory: {path}")
        
        # Return the real (resolved) path
        return real_path
    
    async def process(self, payload: Any, headers: Dict[str, str]) -> None:
        """Save payload to disk as a text file."""
        my_uuid = uuid.uuid4()
        
        # Get base directory from config or use current directory
        base_dir = self.module_config.get('base_dir', os.getcwd())
        path = self.module_config.get('path', '.')
        
        # Validate and sanitize path
        try:
            validated_path = self._validate_path(path, base_dir)
        except ValueError as e:
            # Log detailed error server-side (includes path details)
            print(f"ERROR: Invalid path configuration for webhook: {str(e)}")
            # Raise generic error to client (don't expose path details)
            from src.utils import sanitize_error_message
            raise Exception(sanitize_error_message(e, "path validation"))
        
        # Create directory if it doesn't exist
        if not os.path.exists(validated_path):
            os.makedirs(validated_path, mode=0o700)  # Owner-only permissions
        
        # Construct file path (UUID prevents collisions and injection)
        file_path = os.path.join(validated_path, f"{my_uuid}.txt")
        
        # Write file with restricted permissions
        try:
            with open(file_path, mode="w") as f:
                f.write(str(payload))
                f.flush()
            # Set file permissions to owner-only (0o600 = rw-------)
            os.chmod(file_path, 0o600)
        except (OSError, IOError) as e:
            # Log detailed error server-side (includes file path details)
            print(f"ERROR: Failed to write file: {str(e)}")
            # Raise generic error to client (don't expose file path)
            from src.utils import sanitize_error_message
            raise Exception(sanitize_error_message(e, "file write operation"))
