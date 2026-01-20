# Contributing to Core Webhook Module

Thank you for your interest in contributing to Core Webhook Module! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Pull Request Process](#pull-request-process)
- [Community](#community)

## Code of Conduct

This project adheres to the Contributor Covenant [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior by opening a GitHub issue with the `conduct` label.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/webhook.git
   cd webhook
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/spiderhash-io/webhook.git
   ```

## Development Setup

### Prerequisites

- Python 3.9 or higher
- Docker and Docker Compose (for integration tests)
- Git

### Local Development Environment

1. **Create a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install development dependencies**:
   ```bash
   make install-dev
   # Or manually:
   pip install -r requirements-dev.txt
   ```

3. **Copy example configurations**:
   ```bash
   cp config/examples/webhooks.example.json config/development/webhooks.json
   cp config/examples/connections.example.json config/development/connections.json
   ```

4. **Run the development server**:
   ```bash
   make run
   # Or manually:
   uvicorn src.main:app --reload
   ```

5. **Access the API documentation**:
   - Swagger UI: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

### Running Tests

```bash
# Run unit tests (fast, no external dependencies)
make test

# Run integration tests (requires Docker services)
make integration-up        # Start services
make test-integration      # Run integration tests
make integration-down      # Stop services

# Run all tests
make test-all

# Run tests with coverage
make test-cov
```

## How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Open a new issue** using the Bug Report template
3. **Include**:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (Python version, OS, etc.)
   - Error messages and logs
   - Minimal reproducible example

### Suggesting Features

1. **Check existing issues** and discussions
2. **Open a new issue** using the Feature Request template
3. **Include**:
   - Clear description of the problem
   - Proposed solution
   - Alternative solutions considered
   - Use cases and benefits

### Improving Documentation

Documentation improvements are always welcome! This includes:

- Fixing typos and grammar
- Adding examples and tutorials
- Clarifying confusing sections
- Adding missing documentation

You can edit documentation directly on GitHub or submit a PR.

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://pep8.org/) with some modifications:

- **Line length**: 100 characters (not 79)
- **Formatter**: Black (default settings)
- **Linter**: Flake8
- **Type hints**: Use type hints for all function signatures
- **Type checker**: Mypy

### Code Quality Tools

Run these before submitting a PR:

```bash
# Format code with Black
make format
# Or: black src/ tests/

# Lint with Flake8
make lint
# Or: flake8 src/ tests/

# Type check with Mypy
make type-check
# Or: mypy src/

# Security scan with Bandit
make security-scan
# Or: bandit -r src/
```

### Project Structure

```
src/
├── main.py              # FastAPI application entry point
├── webhook.py           # Core webhook processing logic
├── config.py            # Configuration loading
├── config_manager.py    # Live config reload
├── validators.py        # Authentication validators
├── modules/             # Output modules
│   ├── base.py         # Base module class
│   ├── registry.py     # Module registry
│   └── *.py            # Individual modules
└── utils.py             # Utility functions

tests/
├── unit/                # Unit tests (no external dependencies)
└── integration/         # Integration tests (require services)

docs/                    # Documentation
config/                  # Configuration files
docker/                  # Docker files and compose configs
```

## Testing Guidelines

### Writing Tests

- **Unit tests**: Fast, isolated, no external dependencies
- **Integration tests**: Test with real services (Docker)
- **Test file naming**: `test_*.py` (pytest convention)
- **Test function naming**: `test_<functionality>_<scenario>()`

### Test Markers

Use pytest markers to categorize tests:

```python
@pytest.mark.unit           # Unit test
@pytest.mark.integration    # Integration test
@pytest.mark.slow           # Slow-running test
@pytest.mark.longrunning    # Very long test (>30s)
```

### Test Coverage

- Aim for **90%+ code coverage** for new code
- All new features must include tests
- Bug fixes should include regression tests

### Example Test

```python
import pytest
from src.modules.log import LogModule

@pytest.mark.unit
@pytest.mark.asyncio
async def test_log_module_json_payload():
    """Test LogModule with JSON payload."""
    module = LogModule({})
    payload = {"event": "test", "data": "value"}
    
    # Should not raise exception
    await module.process(payload, webhook_id="test_webhook")
```

## Commit Message Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/) specification:

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, no logic change)
- **refactor**: Code refactoring (no feature or bug fix)
- **perf**: Performance improvements
- **test**: Adding or updating tests
- **chore**: Maintenance tasks (dependencies, build, etc.)
- **ci**: CI/CD changes

### Examples

```
feat(modules): add AWS SQS module

Add support for publishing webhook payloads to AWS SQS queues.
Includes configuration validation and error handling.

Closes #123
```

```
fix(validators): constant-time HMAC comparison

Replace string comparison with constant-time comparison
to prevent timing attacks.

Fixes #456
```

```
docs(readme): add quick start section

Add a 5-minute quick start guide to help new users
get started quickly.
```

## Pull Request Process

### Before Submitting

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following coding standards

3. **Add tests** for new functionality

4. **Run tests** and ensure they pass:
   ```bash
   make test
   make test-integration  # If applicable
   ```

5. **Run code quality tools**:
   ```bash
   make format
   make lint
   make type-check
   ```

6. **Update documentation** if needed

7. **Commit your changes** with conventional commit messages

8. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

### Submitting the Pull Request

1. **Go to the GitHub repository** and create a Pull Request

2. **Fill out the PR template** completely:
   - Clear description of changes
   - Link related issues
   - Describe testing performed
   - Check all applicable boxes

3. **Ensure CI passes**:
   - All tests pass
   - Code coverage maintained
   - Linting and type checking pass
   - Security scans pass

4. **Address review feedback** promptly

5. **Keep your PR up to date** with the main branch:
   ```bash
   git fetch upstream
   git rebase upstream/main
   git push --force-with-lease origin feature/your-feature-name
   ```

### PR Review Process

- Maintainers will review your PR within **7 days**
- Address feedback and make requested changes
- Once approved, maintainers will merge your PR
- Your contribution will be credited in release notes

## Adding a New Output Module

If you're adding a new output module:

1. **Create module file**: `src/modules/your_module.py`

2. **Extend BaseModule**:
   ```python
   from src.modules.base import BaseModule
   
   class YourModule(BaseModule):
       async def process(self, data, webhook_id: str):
           # Your implementation
           pass
   ```

3. **Register in registry**: `src/modules/registry.py`

4. **Add connection type** (if needed): `src/config.py`

5. **Add tests**: `tests/unit/test_your_module.py`

6. **Update documentation**: 
   - `docs/ARCHITECTURE.md`
   - `README.md`

7. **Add example config**: `config/examples/connections.example.json`

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed module development guide.

## Community

### Communication Channels

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: Questions, ideas, general discussion
- **Pull Requests**: Code contributions

### Getting Help

- Check the [documentation](docs/)
- Search [existing issues](https://github.com/spiderhash-io/webhook/issues)
- Ask in [GitHub Discussions](https://github.com/spiderhash-io/webhook/discussions)

### Recognition

Contributors are recognized in:

- Release notes
- CHANGELOG.md
- GitHub contributors page

Thank you for contributing to Core Webhook Module!

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
