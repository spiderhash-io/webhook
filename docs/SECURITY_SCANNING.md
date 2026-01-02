# Security Scanning

This project uses **offline security scanning tools** that work without internet connection:

- **Bandit**: Static security analysis for Python source code
- **Safety**: Checks Python dependencies against a vulnerability database

## Quick Start

Run all security scans:
```bash
make security-scan
```

Or run individually:
```bash
make security-bandit    # Scan source code
make security-safety    # Check dependencies
```

## Installation

The security scanning tools are included in `requirements-dev.txt`:

```bash
pip install -r requirements-dev.txt
```

Or use the Makefile:
```bash
make install-dev
```

## Bandit - Source Code Security Scanner

**Bandit** performs static security analysis on your Python source code to find common security issues.

### Usage

```bash
# Run Bandit scan
make security-bandit

# Or manually:
python -m bandit -r src/ -f screen
python -m bandit -r src/ -f json -o bandit-report.json
```

### Configuration

Bandit configuration is in `.bandit` file in the project root. It:
- Excludes test files and common false positives
- Configures which security tests to run
- Customizes output format

### What Bandit Checks

Bandit scans for common security issues such as:
- Hardcoded passwords and secrets
- SQL injection vulnerabilities
- Use of insecure functions (eval, exec, etc.)
- SSL/TLS misconfigurations
- Insecure random number generation
- And many more...

## Safety - Dependency Vulnerability Checker

**Safety** checks your Python dependencies against a database of known security vulnerabilities.

### Usage

```bash
# Run Safety check
make security-safety

# Or manually:
python -m safety check
python -m safety check --json --output safety-report.json
```

### First Run

**Note**: Safety requires internet for the first run to download the vulnerability database. After that, it can work offline using the cached database.

```bash
# First run (downloads database)
python -m safety check

# Subsequent runs work offline
python -m safety check
```

### What Safety Checks

Safety checks `requirements.txt` against known vulnerabilities in:
- PyPI packages
- Common security advisories
- CVE databases

## Reports

Both tools generate JSON reports:
- `bandit-report.json` - Bandit scan results
- `safety-report.json` - Safety dependency check results

These reports are excluded from git (via `.gitignore`) but can be used for CI/CD integration.

## CI/CD Integration

### GitLab CI Example

Add to `.gitlab-ci.yml`:

```yaml
security-scan:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install -r requirements-dev.txt
  script:
    - make security-scan
  artifacts:
    reports:
      junit: bandit-report.json
    paths:
      - bandit-report.json
      - safety-report.json
    expire_in: 1 week
```

## Manual Commands

### Bandit

```bash
# Screen output
python -m bandit -r src/ -f screen

# JSON output
python -m bandit -r src/ -f json -o bandit-report.json

# HTML output
python -m bandit -r src/ -f html -o bandit-report.html

# Specific severity levels
python -m bandit -r src/ -ll  # Low and medium severity
python -m bandit -r src/ -lll # All severity levels
```

### Safety

```bash
# Standard check
python -m safety check

# JSON output
python -m safety check --json --output safety-report.json

# Check specific file
python -m safety check --file requirements.txt

# Full report
python -m safety check --full-report
```

## Configuration Files

- `.bandit` - Bandit configuration (test selection, exclusions, etc.)
- `requirements.txt` - Dependencies checked by Safety

## Additional Resources

- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Safety Documentation](https://pyup.io/safety/)
- [Bandit on PyPI](https://pypi.org/project/bandit/)
- [Safety on PyPI](https://pypi.org/project/safety/)
