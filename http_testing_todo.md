# HTTP Request Testing Todo List - Comparison with ngrok

Based on analysis of ngrok's HTTP handling code and comparison with existing core-webhook-module tests.

## ngrok HTTP Handling Patterns Observed:
1. Host header parsing and validation (vhost multiplexing)
2. Authorization header extraction and validation
3. Bad request handling (400 responses)
4. Connection deadline/timeout handling
5. TLS/SSL connection handling
6. Request parsing error handling
7. Connection recovery from failures

## Missing Test Coverage (HTTP Request Tests Only):

### 1. HTTP Request Parsing Edge Cases
- Test malformed HTTP request line (invalid method, version, path)
- Test extremely long HTTP headers (header size limits)
- Test duplicate headers handling
- Test header name case sensitivity
- Test missing required headers (Host, Content-Length)
- Test invalid HTTP version (HTTP/0.9, HTTP/3.0)

### 2. HTTP Method Validation
- Test invalid HTTP methods (non-standard methods)
- Test method case sensitivity
- Test empty method in request line
- Test method with special characters

### 3. URL/Path Handling
- Test URL encoding edge cases (%00 null bytes, %2e path traversal)
- Test extremely long URLs (URL length limits)
- Test malformed URLs (invalid characters, missing scheme)
- Test double encoding attacks
- Test protocol-relative URLs (//evil.com)

### 4. Host Header Security
- Test Host header injection attacks
- Test Host header with port manipulation
- Test missing Host header handling
- Test multiple Host headers
- Test Host header with IP addresses vs domain names

### 5. Connection Handling
- Test connection close handling mid-request
- Test keep-alive connection exhaustion
- Test connection pool limits
- Test slowloris-style attacks (slow headers)
- Test request timeout vs connection timeout distinction

### 6. Request Body Handling
- Test Content-Length mismatch (declared vs actual)
- Test chunked transfer encoding edge cases
- Test extremely large request bodies
- Test malformed JSON/XML in body
- Test body without Content-Length header

### 7. HTTP Response Handling
- Test handling of non-standard HTTP status codes
- Test response header injection
- Test response splitting attacks
- Test response size limits

### 8. Protocol-Level Attacks
- Test HTTP request smuggling (CL.TE, TE.CL variants)
- Test HTTP/2 downgrade attacks
- Test protocol confusion attacks

Note: Focus only on HTTP request-level tests that can be triggered via external HTTP requests.

