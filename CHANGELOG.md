# Changelog

All notable changes to this project will be documented in this file.

## [2025-02-07]

### Added
- **teaching-materials/**: New directory for educational content
  - Moved `GitHubreadme.md` into this directory
  - Contains GitHub tutorial and number guessing game example
- **check_db.py**: New utility to inspect SQLite database contents
  ```python
  # Run to view all users and their password hashes:
  python check_db.py
  ```
  - Demonstrates contrast between secure (SQLite) and insecure (JSON) storage
  - Shows proper password hashing in action
  - Useful for security education and vulnerability demonstration
- **Session Vulnerability Demo**:
  - New `/report` endpoint with intentionally weak session management
  - Exposed session data to JavaScript
  - Disabled secure cookie attributes
  ```python
  app.config['SESSION_COOKIE_SECURE'] = False
  app.config['SESSION_COOKIE_HTTPONLY'] = False
  app.config['SESSION_COOKIE_SAMESITE'] = None
  ```
  - Extended session lifetime to 365 days
  - No session validation or CSRF protection
- **Enhanced SQL Injection Demo**:
  - Added password field injection vulnerability
  - Combined username and password in SQL query
  - Improved error handling and logging
  - Updated UI with dual injection methods
  ```python
  query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
  ```
- **OWASP Alignment Update**:
  - Added IDOR vulnerability demo (`/user/<id>`)
  - Added CSRF vulnerability in transfer endpoint
  - Added stored XSS vulnerability in comments
  - Added security headers demonstration
  - Added comprehensive logging

### Changed
- **templates/search.html**: Added `| safe` filter to query output to demonstrate XSS vulnerability
  ```html
  <!-- Before -->
  <p>Your search term was: {{ query }}</p>
  
  <!-- After -->
  <p>Your search term was: {{ query | safe }}</p>
  ```
  - This change allows proper demonstration of XSS vulnerability as documented in HACKER.md
  - XSS test case now works: `<script>alert('XSS Vulnerability!');</script>`
- **app.py**: Modified registration to demonstrate weak password storage
  ```python
  # Added plaintext password storage to users.json
  users[username] = password  # Store password in plaintext
  ```
  - Passwords now stored in both SQLite (hashed) and users.json (plaintext)
  - Allows demonstration of password storage vulnerability
  - Matches expected behavior in HACKER.md
- **Enhanced XSS Demo**:
  - Added stored XSS in comments section
  - Improved reflected XSS examples
- **Security Headers**:
  - Intentionally misconfigured for demonstration
  - Added weak X-Frame-Options
  - Missing CSP headers
- **Documentation**:
  - Updated all vulnerabilities to align with OWASP Top 10 2021
  - Added detailed explanations for each vulnerability
  - Improved testing instructions

### Security
- Intentionally disabled Jinja2's automatic HTML escaping in search template
- This change aligns with the security lab's educational purpose
- Students can now properly test and understand XSS vulnerabilities

### Documentation
- Created this CHANGELOG.md to track project modifications
- All changes are intentional and part of the security learning environment
- Reference HACKER.md for complete vulnerability documentation

## [Unreleased]

### Added
- Complete OWASP Top 10:2021 coverage with new vulnerabilities:
  - A04: Insecure Design - Added predictable resource locations demo
  - A06: Vulnerable Components - Added outdated dependency demo
  - A09: Security Logging Failures - Added insecure logging demo
  - A10: SSRF - Added vulnerable URL fetching demo
- New demo endpoints:
  - `/admin/login` for demonstrating logging vulnerabilities
  - `/check_dependency` for vulnerable components demo
  - `/download/<filename>` for insecure design demo
  - `/fetch-url` for SSRF demo
- Added sample files in uploads directory for insecure design demo
- Updated home page with comprehensive OWASP alignment footer
- Added detailed testing instructions in HACKER.md

### Changed
- Updated logging configuration to demonstrate security failures
- Modified requirements.txt to include intentionally vulnerable dependency
- Improved documentation with demo credentials and test scenarios
- Enhanced UI with responsive grid layout for OWASP categories

### Security
- Intentionally added vulnerable logging practices for educational purposes
- Added known vulnerable dependency (requests 2.0.1) for demonstration
- Implemented predictable resource locations for teaching purposes
- Added SSRF vulnerability for security training
