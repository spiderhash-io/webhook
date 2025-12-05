# Security Audit Report: RecaptchaValidator

## Executive Summary

**Feature Audited:** RecaptchaValidator (`src/validators.py`) - Google reCAPTCHA token validation

**Date:** 2024-2025

**Final Risk Assessment:** **LOW**

The RecaptchaValidator is responsible for validating Google reCAPTCHA tokens provided in webhook requests. This audit identified and fixed several security vulnerabilities related to error information disclosure. The validator correctly handles IP spoofing (which is expected behavior for reCAPTCHA validation), SSRF prevention (via hardcoded URL), and token extraction security.

---

## 1. Feature Selection & Code Analysis

### Feature Overview
The `RecaptchaValidator` class is responsible for:
- Extracting reCAPTCHA tokens from HTTP headers or request body
- Validating tokens with Google's reCAPTCHA API
- Enforcing score thresholds for reCAPTCHA v3
- Handling both reCAPTCHA v2 and v3 validation

### Key Components
- **Location:** `src/validators.py` (lines 1692-1803)
- **Key Methods:**
  - `__init__(config)`: Initializes validator with configuration
  - `_extract_token(headers, body)`: Extracts token from headers or body
  - `validate(headers, body)`: Main validation method that verifies token with Google
- **Dependencies:**
  - `httpx` library: For making async HTTP requests to Google's API
  - `json` module: For parsing JSON payloads
  - Google reCAPTCHA API: External service for token verification

### Architecture
```
RecaptchaValidator
├── _extract_token() → Extracts token from header or body
├── validate() → Verifies token with Google API
│   ├── Extracts client IP (for v3)
│   ├── Makes HTTP POST to Google
│   └── Validates score threshold (v3 only)
└── Returns validation result
```

---

## 2. Threat Research (External HTTP-based Attacks Only)

### Vulnerabilities Researched (OWASP Top 10 2024-2025)

Based on HTTP-based attack vectors, the following vulnerabilities were identified:

1. **Server-Side Request Forgery (SSRF) (A10:2021)**
   - **URL Manipulation:** If the verification URL could be changed, it could lead to SSRF attacks
   - **Risk:** Attackers could potentially make the validator send requests to internal services
   - **Mitigation:** The `verify_url` is hardcoded to Google's API, preventing SSRF

2. **Information Disclosure (A05:2021)**
   - **Error Message Leakage:** Error messages could expose sensitive information like secret keys, internal paths, or system details
   - **Stack Trace Disclosure:** Generic exceptions could leak stack traces or file paths
   - **Risk:** Attackers could learn about internal system structure or sensitive configuration

3. **IP Spoofing (A07:2021)**
   - **X-Forwarded-For Manipulation:** The validator trusts `X-Forwarded-For` and `X-Real-IP` headers without validation
   - **Risk:** Attackers could spoof their IP address, potentially affecting reCAPTCHA scoring
   - **Note:** This is expected behavior for reCAPTCHA - IP validation should be done at the proxy/load balancer level

4. **Token Manipulation (A03:2021)**
   - **Token Injection:** Malicious tokens could be injected via headers or body
   - **JSON Injection:** Token extraction from body could be vulnerable to JSON injection
   - **Risk:** Attackers could attempt to bypass validation or cause errors

5. **Denial of Service (DoS) (A04:2021)**
   - **Timeout Handling:** Fixed timeout of 10 seconds could be exploited for DoS
   - **Large Tokens:** Very long tokens could cause memory exhaustion
   - **Malformed JSON:** Malformed JSON in body could cause parsing errors
   - **Risk:** Attackers could exhaust server resources or cause crashes

6. **Configuration Security (A05:2021)**
   - **Type Validation:** Configuration values (min_score, version) are not validated
   - **Secret Key Exposure:** Secret key could be exposed in error messages or logs
   - **Risk:** Misconfiguration could lead to security bypasses or information disclosure

---

## 3. Existing Test Coverage Check

The following existing test files were reviewed:
- `src/tests/test_recaptcha.py`: Basic functional tests for token validation, score checking, IP handling, and error scenarios

**Coverage Gaps Found:**
While existing tests covered basic functionality, the following security scenarios were missing:
- **Error Message Sanitization:** No explicit tests ensuring error messages don't leak sensitive information
- **IP Spoofing:** No tests for IP spoofing via `X-Forwarded-For` or `X-Real-IP` headers
- **SSRF Prevention:** No tests verifying that the verification URL cannot be changed
- **Token Injection:** No tests for malicious token injection attempts
- **DoS Attacks:** No tests for timeout handling, large tokens, or malformed JSON
- **Configuration Security:** Limited tests for configuration validation and type checking
- **Secret Key Security:** No tests ensuring secret key is not exposed in error messages

---

## 4. New Comprehensive Security Tests

**File:** `src/tests/test_recaptcha_security_audit.py`
**Count:** 26 new security tests were added to cover the identified gaps.

**Key new tests include:**

### IP Spoofing & Header Manipulation (3 tests)
- `test_ip_spoofing_via_x_forwarded_for`: Tests IP spoofing via `X-Forwarded-For` header
- `test_ip_spoofing_via_x_real_ip`: Tests IP spoofing via `X-Real-IP` header
- `test_x_forwarded_for_multiple_ips`: Tests handling of multiple IPs in `X-Forwarded-For`

### SSRF & URL Validation (2 tests)
- `test_verify_url_hardcoded`: Verifies that verification URL is hardcoded to Google
- `test_no_internal_network_access`: Verifies that URL cannot point to internal networks

### Error Information Disclosure (3 tests)
- `test_error_message_sanitization`: Verifies error messages don't expose secret keys
- `test_httpx_error_sanitization`: Verifies `httpx.HTTPError` messages are sanitized
- `test_generic_exception_sanitization`: Verifies generic exceptions are sanitized

### Token Extraction Security (3 tests)
- `test_token_injection_via_header`: Tests handling of malicious tokens in headers
- `test_token_extraction_from_body_json_injection`: Tests token extraction with JSON injection attempts
- `test_token_extraction_case_sensitivity`: Tests token extraction with case variations

### Configuration Security (3 tests)
- `test_config_type_validation`: Tests handling of invalid configuration types
- `test_min_score_validation`: Tests validation of `min_score` configuration
- `test_negative_min_score`: Tests handling of negative `min_score` values

### DoS Attacks (3 tests)
- `test_timeout_handling`: Tests timeout enforcement
- `test_very_long_token_dos`: Tests handling of very long tokens (1MB)
- `test_malformed_json_body_dos`: Tests handling of malformed JSON in body

### Secret Key Security (2 tests)
- `test_secret_key_not_in_error_messages`: Verifies secret key is not exposed in error messages
- `test_empty_secret_key_handling`: Tests handling of empty secret key

### Version & Score Validation (3 tests)
- `test_v2_no_score_check`: Tests that v2 doesn't check score
- `test_v3_score_threshold_enforcement`: Tests v3 score threshold enforcement
- `test_missing_score_in_response`: Tests handling of missing score in v3 response

### Library Dependency Security (1 test)
- `test_missing_httpx_library`: Tests behavior when `httpx` library is not installed

### Edge Cases (3 tests)
- `test_empty_token_handling`: Tests handling of empty tokens
- `test_whitespace_only_token`: Tests handling of whitespace-only tokens
- `test_invalid_json_response_handling`: Tests handling of invalid JSON responses from Google

---

## 5. Fixes Applied

The following minimal, secure code fixes were implemented in `src/validators.py`:

### 1. Error Message Sanitization
- **Vulnerability:** Error messages from `httpx.HTTPError` and generic exceptions could expose sensitive information like internal paths, secret keys, or system details.
- **Fix:** Wrapped `httpx.HTTPError` and generic `Exception` handlers with `sanitize_error_message()` to provide generic, safe error messages to the client while logging detailed errors internally.
- **Diff Summary:**
```diff
--- a/src/validators.py
+++ b/src/validators.py
@@ -1797,8 +1797,10 @@ class RecaptchaValidator(BaseValidator):
         except ImportError:
             return False, "httpx library not installed"
         except httpx.HTTPError as e:
-            return False, f"Failed to verify reCAPTCHA token: {str(e)}"
+            # SECURITY: Sanitize HTTP error messages to prevent information disclosure
+            from src.utils import sanitize_error_message
+            return False, sanitize_error_message(e, "reCAPTCHA verification")
         except json.JSONDecodeError:
             return False, "Invalid response from reCAPTCHA service"
         except Exception as e:
-            return False, f"reCAPTCHA validation error: {str(e)}"
+            # SECURITY: Sanitize generic exception messages to prevent information disclosure
+            from src.utils import sanitize_error_message
+            return False, sanitize_error_message(e, "reCAPTCHA validation")
```

---

## 6. Final Risk Assessment

**Final Risk:** **LOW**

The `RecaptchaValidator` is now robust against various security threats:

1. **SSRF Prevention:** The verification URL is hardcoded to Google's API (`https://www.google.com/recaptcha/api/siteverify`), preventing SSRF attacks.

2. **Error Information Disclosure:** All error messages are sanitized using `sanitize_error_message()`, preventing leakage of sensitive information like secret keys, internal paths, or system details.

3. **IP Spoofing:** The validator trusts `X-Forwarded-For` and `X-Real-IP` headers, which is expected behavior for reCAPTCHA validation. IP validation should be done at the proxy/load balancer level using trusted proxy configuration.

4. **Token Security:** Token extraction handles malicious inputs safely, and tokens are validated with Google's API before being trusted.

5. **DoS Mitigation:** The validator uses a fixed timeout (10 seconds) and handles large tokens and malformed JSON gracefully without crashing.

6. **Configuration Security:** While configuration values (min_score, version) are not strictly validated, they are handled safely during validation, and invalid values result in appropriate error messages.

**Assumptions:**
- The `httpx` library is kept up-to-date to benefit from security fixes
- IP validation is done at the proxy/load balancer level using trusted proxy configuration
- Secret keys are stored securely and not logged or exposed in error messages
- Production deployments use appropriate resource limits (CPU, memory, timeout) to mitigate DoS attacks
- The Google reCAPTCHA API is available and responsive

**Recommendations:**
- Consider adding explicit validation for `min_score` (should be between 0.0 and 1.0)
- Consider adding validation for `version` (should be "v2" or "v3")
- Consider adding IP validation if the validator is used behind a trusted proxy (validate `X-Forwarded-For` against trusted proxy list)
- Monitor `httpx` library updates for security patches
- Consider adding rate limiting for reCAPTCHA validation requests to prevent DoS

---

## 7. Test Results

All 26 new security tests pass, along with the 12 existing functional tests:
- **Total Tests:** 38 tests
- **Passing:** 38 tests
- **Failing:** 0 tests
- **Coverage:** Comprehensive coverage of SSRF, error disclosure, IP spoofing, token manipulation, DoS, and configuration security scenarios

---

## 8. References

- OWASP Top 10 2021: https://owasp.org/Top10/
- Google reCAPTCHA Documentation: https://developers.google.com/recaptcha
- reCAPTCHA API Reference: https://developers.google.com/recaptcha/docs/verify

