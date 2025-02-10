# OWASP Top 10 2021 Alignment

This document details how our intentional vulnerabilities align with the OWASP Top 10 2021 categories. Each vulnerability is implemented for educational purposes to demonstrate common security issues.

## A01:2021 - Broken Access Control
### Our Implementation
1. **IDOR Vulnerability** (`/user/<id>`)
   ```python
   @app.route('/user/<id>')
   def get_user(id):
       # No authorization check
       return jsonify(USERS[id])
   ```
   - Direct object reference without authentication
   - No role-based access control
   - Predictable resource locations

2. **Missing Authentication** (`/report`)
   - Sensitive endpoints without access control
   - No session validation
   - Missing authorization checks

## A02:2021 - Cryptographic Failures
### Our Implementation
1. **Weak Password Storage**
   ```python
   # Plaintext storage in JSON
   users = {'username': 'password'}
   ```
   - Passwords stored in plaintext
   - No salting mechanism
   - Weak hashing algorithms

## A03:2021 - Injection
### Our Implementation
1. **SQL Injection** (Login)
   ```python
   query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
   ```
   - Direct string concatenation
   - No input sanitization
   - Multiple injection points (username/password)

2. **Cross-Site Scripting (XSS)**
   - Reflected XSS in search
   - Stored XSS in comments
   ```html
   {{ comment.text | safe }}  <!-- No escaping -->
   ```

## A04:2021 - Insecure Design
### Our Implementation
1. **Predictable Resource Locations**
   - Sequential user IDs
   - Guessable endpoints
   - Missing access controls

2. **Weak Session Management**
   ```python
   app.permanent_session_lifetime = timedelta(days=365)
   ```

## A05:2021 - Security Misconfiguration
### Our Implementation
1. **Missing Security Headers**
   ```python
   # Weak or missing headers
   response.headers['X-Frame-Options'] = 'ALLOW-FROM *'
   # Missing CSP header
   ```
   - Missing Content Security Policy
   - Weak X-Frame-Options
   - Missing HSTS

2. **Debug Information Exposure**
   - Detailed error messages
   - SQL query logging
   - Stack traces in responses

## A06:2021 - Vulnerable Components
### Our Implementation
1. **Outdated Dependencies**
   - Intentionally using older versions
   - Known vulnerabilities
   - Missing security patches

## A07:2021 - Authentication Failures
### Our Implementation
1. **Weak Session Management**
   ```python
   app.config['SESSION_COOKIE_SECURE'] = False
   ```
   - Long session duration
   - Insecure session cookies
   - Missing session validation

2. **Weak Password Policy**
   - No password complexity requirements
   - No brute force protection
   - No multi-factor authentication

## A08:2021 - Software and Data Integrity Failures
### Our Implementation
1. **CSRF Vulnerability**
   ```python
   @app.route('/transfer', methods=['POST'])
   def transfer():
       # No CSRF token validation
       amount = request.form.get('amount')
   ```
   - Missing CSRF tokens
   - No origin validation
   - Insecure state changes

## A09:2021 - Security Logging Failures
### Our Implementation
1. **Insufficient Logging**
   ```python
   # Basic logging without security context
   logging.info(f"Access attempt from IP: {request.remote_addr}")
   ```
   - Missing critical event logging
   - No audit trail
   - Insufficient detail in logs

## A10:2021 - Server-Side Request Forgery
### Our Implementation
1. **Unrestricted File Access**
   - No URL validation
   - Missing input sanitization
   - Direct file system access

## Security Recommendations

### 1. Access Control
```python
from functools import wraps

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated
```

### 2. Secure Password Storage
```python
from werkzeug.security import generate_password_hash
password_hash = generate_password_hash(password, method='pbkdf2:sha256')
```

### 3. SQL Injection Prevention
```python
cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
              (username, password))
```

### 4. XSS Prevention
```python
from markupsafe import escape
escaped_text = escape(user_input)
```

### 5. Security Headers
```python
response.headers['Content-Security-Policy'] = "default-src 'self'"
response.headers['X-Frame-Options'] = 'SAMEORIGIN'
response.headers['Strict-Transport-Security'] = 'max-age=31536000'
```

### 6. CSRF Protection
```python
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
```

## Testing Tools
1. OWASP ZAP
2. Burp Suite
3. SQLMap
4. XSSer
5. Nikto

## References
- [OWASP Top 10:2021](https://owasp.org/Top10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
