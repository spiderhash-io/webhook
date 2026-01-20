# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Core Webhook Module seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### How to Report a Security Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by:

1. **Opening a GitHub Issue** with the label `security` and prefix the title with `[SECURITY]`
2. Provide as much information as possible about the vulnerability:
   - Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
   - Full paths of source file(s) related to the manifestation of the issue
   - The location of the affected source code (tag/branch/commit or direct URL)
   - Any special configuration required to reproduce the issue
   - Step-by-step instructions to reproduce the issue
   - Proof-of-concept or exploit code (if possible)
   - Impact of the issue, including how an attacker might exploit it

### What to Expect

- We will acknowledge receipt of your vulnerability report within 3 business days
- We will provide a more detailed response within 7 days indicating the next steps
- We will keep you informed about the progress toward fixing the vulnerability
- We will credit you in the release notes when the vulnerability is fixed (unless you prefer to remain anonymous)

## Security Update Process

1. The security issue is received and assigned to a primary handler
2. The problem is confirmed and a list of affected versions is determined
3. Code is audited to find any similar problems
4. Fixes are prepared for all supported versions
5. A new release is made available with security patches
6. The vulnerability is publicly disclosed in the release notes

## Security Best Practices

When deploying Core Webhook Module in production, we recommend:

### 1. Authentication
- Always use authentication (Bearer tokens, JWT, HMAC, etc.)
- Rotate credentials regularly
- Use strong, randomly generated secrets
- Store secrets in environment variables or secret management systems

### 2. Network Security
- Use HTTPS/TLS for all webhook endpoints
- Implement IP whitelisting when possible
- Deploy behind a reverse proxy (nginx, Traefik) with rate limiting
- Use a Web Application Firewall (WAF) for additional protection

### 3. Input Validation
- Enable JSON schema validation for webhook payloads
- Set appropriate payload size limits
- Configure depth and string length validation
- Use credential cleanup to prevent credential exposure

### 4. Rate Limiting
- Configure per-webhook rate limits
- Monitor for unusual traffic patterns
- Implement exponential backoff for failed requests

### 5. Monitoring & Logging
- Enable structured logging with correlation IDs
- Monitor for failed authentication attempts
- Set up alerts for security events
- Regularly review logs for suspicious activity
- Use ClickHouse analytics for centralized monitoring

### 6. Updates
- Keep Core Webhook Module updated to the latest version
- Subscribe to security advisories
- Regularly update dependencies
- Run security scans (Bandit, Safety) in CI/CD

### 7. Container Security
- Use official Docker images from Docker Hub (`spiderhash/webhook`)
- Scan images for vulnerabilities (Trivy, Snyk)
- Run containers with minimal privileges
- Use read-only file systems where possible

### 8. Configuration Management
- Never commit secrets to version control
- Use environment variable substitution for sensitive values
- Restrict access to configuration files
- Enable config file validation

## Known Security Features

Core Webhook Module includes the following security features:

- **11 Authentication Methods**: Bearer, Basic, JWT, HMAC, IP whitelist, OAuth 1.0/2.0, Digest, Header-based, Query param, reCAPTCHA
- **Input Validation**: JSON schema validation, size/depth/length limits
- **Rate Limiting**: Sliding window rate limiting per webhook
- **Credential Cleanup**: Automatic credential redaction in logs and storage
- **Constant-Time Comparison**: Timing attack resistant HMAC/token validation
- **CORS Support**: Configurable CORS middleware
- **SSL/TLS Support**: Full HTTPS support with reverse proxy integration

## Security Scanning

This project includes automated security scanning:

- **Bandit**: Python code security analysis
- **Safety**: Dependency vulnerability scanning
- **CodeQL**: Semantic code analysis
- **Docker Image Scanning**: Container vulnerability detection

Security scan results are available in the GitHub Actions CI pipeline.

## Disclosure Policy

When we learn of a critical security vulnerability, we will:

1. Privately notify users who may be affected
2. Release a security patch as quickly as possible
3. Publicly disclose the vulnerability after patches are available
4. Credit the reporter (unless they prefer anonymity)

## Comments on This Policy

If you have suggestions on how this process could be improved, please submit a pull request or open an issue.

## Attribution

This security policy is based on the [OWASP Vulnerability Disclosure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html).
