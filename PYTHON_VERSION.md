# Python Version Requirements

This project uses **Python 3.11** for all Docker builds and CI/CD pipelines.

## Docker Images
- `Dockerfile.smaller` - Python 3.11 (primary production image)
- `Dockerfile.small` - Python 3.11
- `Dockerfile` - Python 3.11

## CI/CD
- GitLab CI uses Python 3.11 for unit tests

## Local Development
For local development, you can use Python 3.11 or newer (3.12+ is also fine).

### Creating/Recreating Virtual Environment with Python 3.11

If you want to match the Docker environment exactly:

```bash
# Remove old venv if it exists
rm -rf venv

# Create new venv with Python 3.11 (if available)
python3.11 -m venv venv

# Or use python3 if 3.11+ is the default
python3 -m venv venv

# Activate and install dependencies
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements-dev.txt
```

### Checking Python Version

```bash
# Check system Python
python3 --version

# Check venv Python
venv/bin/python --version

# Should show Python 3.11.x or newer
```

## Why Python 3.11?

- Python 3.9 reached end-of-life (EOL) in October 2025
- Python 3.11 provides:
  - Better performance (10-60% faster than 3.9)
  - Security updates and bug fixes
  - Better error messages
  - Improved typing support
  - No more EOL warnings from dependencies
