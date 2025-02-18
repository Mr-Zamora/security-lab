# PWA Security Lab - Comprehensive Vulnerability Documentation

This document outlines the security vulnerabilities identified in the client's Progressive Web App (PWA). It provides detailed replication steps, explanations of why each vulnerability exists, and recommendations for fixes. The testing methodologies used include blackbox, whitebox, and greybox testing, along with Google Lighthouse audits.

## Overview
This security lab contains multiple intentional vulnerabilities designed for educational purposes. Each vulnerability demonstrates common security issues found in web applications, aligned with OWASP Top 10 guidelines.

## Vulnerabilities and Testing Instructions

### 1. SQL Injection
#### Description
The login form is intentionally vulnerable to SQL injection attacks through both username and password fields.

#### Test Methods
##### Basic Methods:
1. Username Injection:
   - Username: `admin' OR '1'='1`
   - Password: (anything)

2. Password Injection:
   - Username: (anything)
   - Password: `' OR '1'='1--`

##### Advanced Payloads:
1. Using LIKE operator:
   ```sql
   admin' OR username LIKE '%admin%'
   ```

2. Using boolean logic:
   ```sql
   x' OR 'a'='a
   ```

3. Using comments:
   ```sql
   admin'--
   ```

4. Using OR with numbers:
   ```sql
   admin' OR 5>3--
   ```

5. Using UNION:
   ```sql
   admin' UNION SELECT 'admin', '123
   ```

#### Why These Work
- `OR '1'='1` - Always evaluates to TRUE
- `--` - Comments out remaining SQL
- `UNION` - Combines queries
- `LIKE` - Pattern matching
- Server logs all queries for observation

#### Test Steps
1. Go to `/login` page
2. Try different payloads in either field
3. Check server logs for query execution
4. Observe authentication bypass

**Note:** The server logs all SQL queries, allowing you to see how each injection affects the final query. Check the terminal output while testing.

### 2. Weak Password Storage
#### Description
Demonstrates insecure password storage practices.

#### Test Steps:
1. Go to `/register` page
2. Create an account
3. Check `users.json` for plaintext password
4. Run `check_db.py` to see hashed version

### 3. Cross-Site Scripting (XSS)
#### Description
Multiple XSS vulnerabilities in both reflected and stored contexts.

#### Test Methods:
##### Reflected XSS (Search):
1. Go to `/search` page
2. Enter: `<script>alert('XSS!');</script>`

##### Stored XSS (Comments):
1. Go to `/stored-xss` page
2. Post: `<script>alert('Stored XSS!');</script>`
3. Reload page to see persistent XSS

### 4. Insecure API Endpoint
#### Description
API endpoint vulnerable to unauthorized access and XSS through JSON data.

#### Test Methods:
1. Direct API Access:
   - Access `/api/data` directly
   - Send POST request with JSON payload
   - Check `data.json` for stored data

2. XSS Through JSON:
```json
{
  "data": "<script>alert('API Vulnerability!');</script>"
}
```

#### Alternative Payloads:
1. Image-based XSS:
```json
{
  "data": "<img src=x onerror='alert(\"XSS\")'>"
}
```

2. SVG-based XSS:
```json
{
  "data": "<svg onload='alert(\"XSS\")'>"
}
```

### **5. Unprotected Sessions**

#### **Description**
The application uses insecure session management that can be exploited through session hijacking and persistence attacks. Sessions are configured with weak security settings and expose sensitive data.

#### **Vulnerabilities Found**
1. Sessions accessible via JavaScript (no HttpOnly flag)
2. Sessions work over HTTP (no Secure flag)
3. No SameSite cookie protection
4. Extremely long session duration (365 days)
5. No session rotation on login
6. No proper session invalidation

#### **Steps to Replicate**

##### Method 1: Session Inspection and Hijacking
1. First, log in to the application:
   - Go to `http://127.0.0.1:5000/login`
   - Use SQL injection to login:
     - Username: `admin' OR '1'='1`
     - Password: (any value)

2. Navigate to the Report Page: `http://127.0.0.1:5000/report`

3. Open Browser DevTools (F12) and in Console, execute either:
   ```javascript
   // View all cookies
   console.log(document.cookie)

   // Or for better readability, use:
   document.cookie.split(';').forEach(cookie => console.log(cookie.trim()))
   ```

4. Note that session cookie is accessible via JavaScript, which makes it vulnerable to XSS attacks

**Important**: You must run these commands while on a page from the Flask application (like `/report` or `/login`). The commands won't work if you try them on a different domain or local file.

##### Method 2: Session Persistence Test
1. Log in using the steps from Method 1
2. Note your session cookie value using the console commands above
3. Close your browser completely
4. Open a new browser window
5. Go to `http://127.0.0.1:5000/report`
6. You should still be logged in
7. Check that the session cookie value remains the same

##### Method 3: Cross-Site Testing
1. While logged in, open the browser console (F12)
2. Execute this cross-origin request:
   ```javascript
   fetch('http://127.0.0.1:5000/api/data', {
       credentials: 'include'  // This will send cookies
   }).then(r => r.json()).then(console.log)
   ```
3. Note that the request succeeds due to missing SameSite protection

#### **Vulnerable Configuration**
From app.py:
```python
# Session Configuration (Intentionally Vulnerable)
app.permanent_session_lifetime = timedelta(days=365)  # Extremely long session
app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP (not HTTPS only)
app.config['SESSION_COOKIE_HTTPONLY'] = False  # Allow JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = None  # Allow cross-site requests
```

#### **Impact**
1. **Session Hijacking**: Attackers can steal session cookies through XSS or malicious JavaScript
2. **Persistence Abuse**: Sessions remain valid for extremely long periods
3. **Cross-Site Attacks**: Missing SameSite protection enables CSRF attacks
4. **Man-in-the-Middle**: Non-secure cookies can be intercepted over HTTP

#### **Recommendation**
1. Implement secure session configuration:
   ```python
   # Secure Configuration
   app.config.update(
       SESSION_COOKIE_SECURE=True,        # HTTPS only
       SESSION_COOKIE_HTTPONLY=True,      # No JavaScript access
       SESSION_COOKIE_SAMESITE='Strict',  # Prevent CSRF
       PERMANENT_SESSION_LIFETIME=timedelta(hours=1)  # Short lifetime
   )
   ```

2. Implement session security measures:
   ```python
   @app.before_request
   def secure_session():
       # Rotate session ID on login
       if 'user_id' in session and 'session_created' not in session:
           session.regenerate()
           session['session_created'] = datetime.now()
       
       # Expire old sessions
       if 'session_created' in session:
           created = session['session_created']
           if datetime.now() - created > timedelta(hours=1):
               session.clear()
   ```

3. Add security headers:
   ```python
   @app.after_request
   def add_security_headers(response):
       response.headers['Strict-Transport-Security'] = 'max-age=31536000'
       response.headers['Content-Security-Policy'] = "default-src 'self'"
       return response
   ```

4. Implement proper session cleanup:
   - Clear sessions on logout
   - Implement server-side session tracking
   - Add rate limiting for session creation
### 6. IDOR (Insecure Direct Object Reference)
#### Description
Demonstrates unauthorized access to user data.

#### Test Steps:
1. Try accessing:
   - `/user/1`
   - `/user/2`
2. No authentication required
3. Can view any user's data

### 7. CSRF (Cross-Site Request Forgery)
#### Description
Demonstrates unauthorized actions through cross-site requests.

#### Test Payload:
```html
<form id="csrf" action="http://localhost:5000/transfer" method="POST">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="to_user" value="attacker">
</form>
<script>document.getElementById('csrf').submit();</script>
```

#### Test Steps:
1. Log in to the application
2. Create a new HTML file with this content:
   ```html
   <form id="csrf" action="http://localhost:5000/transfer" method="POST">
       <input type="hidden" name="amount" value="1000">
       <input type="hidden" name="to_user" value="attacker">
   </form>
   <script>document.getElementById('csrf').submit();</script>
   ```
3. Open the HTML file in a browser
4. Observe the unauthorized transfer

### 8. Missing Security Headers
#### Description
Demonstrates security implications of missing HTTP headers.

#### Test Steps:
1. Use browser dev tools (F12)
2. Go to Network tab
3. Inspect response headers
4. Notice specifically:
   - Missing CSP headers
   - Weak X-Frame-Options
   - Missing security headers

### 9. Insecure Design (A04)
#### Description
Demonstrates predictable resource locations and weak architecture design patterns.

#### Test Steps:
1. Files are stored in predictable locations:
   ```
   /uploads/file1.txt
   /uploads/file2.txt
   ```
2. No access control on downloads
3. Sequential and predictable IDs
4. Weak architectural security controls

### 10. Vulnerable Components (A06)
#### Description
Application uses outdated dependencies with known vulnerabilities.

#### Test Steps:
1. Visit `/check_dependency` for vulnerability check
2. Notable issues:
   - Using requests v2.0.1 (known vulnerable)
   - No dependency scanning
   - Outdated components with CVEs
3. Check the terminal output for detailed vulnerability information

### 11. Security Logging Failures (A09)
#### Description
Demonstrates poor logging practices and missing audit trails.

#### Test Credentials:
- Username: `admin`
- Password: `admin123`

#### Test Steps:
1. Log in using demo credentials
2. Check server logs - sensitive data exposed
3. Notice missing audit trails
4. Test using the insecure login form:
   ```html
   <form action="/admin/login" method="POST">
       <input type="text" name="username" placeholder="Username" required>
       <input type="password" name="password" placeholder="Password" required>
       <button type="submit">Test Insecure Login</button>
   </form>
   ```

**Note**: This is a separate demo endpoint using hardcoded credentials. The main authentication system uses the database and is demonstrated in other vulnerabilities.

### 12. SSRF Vulnerability (A10)
#### Description
Server-Side Request Forgery vulnerability allowing unauthorized access to internal resources.

#### Test Steps:
1. Access `/fetch-url` endpoint
2. Use the provided form:
   ```html
   <form action="/fetch-url" method="POST">
       <input type="text" name="url" placeholder="Enter URL to fetch" required>
       <button type="submit">Fetch URL</button>
   </form>
   ```
3. Try accessing internal resources:
   ```
   file:///etc/passwd
   http://localhost:8080
   ```
4. Server will fetch URLs without proper validation

## Security Testing Methodology
- **Blackbox Testing**: Testing without knowledge of internal systems
- **Whitebox Testing**: Testing with full access to source code
- **Greybox Testing**: Combination of both approaches
- **Google Lighthouse**: For PWA security audits

## Important Notes
1. This is an educational environment only
2. All vulnerabilities are intentional
3. Do not use these techniques on production systems
4. Server logs all activities for learning purposes

## Recommendations for Secure Implementation
1. Input validation and sanitization
2. Proper authentication and authorization
3. Secure session management
4. Implementation of security headers
5. Regular security audits
6. Proper error handling and logging
7. Use of prepared statements for SQL
8. Implementation of CSP headers

## OWASP Top 10:2021 Alignment
### A01: Broken Access Control
- IDOR in user endpoint
- Missing access controls

### A02: Cryptographic Failures
- Plaintext passwords
- Weak storage methods

### A03: Injection
- SQL Injection
- XSS (Reflected & Stored)

### A04: Insecure Design
- Predictable IDs
- Weak sessions

### A05: Security Misconfiguration
- Missing headers
- Information exposure

### A06: Vulnerable Components
- Outdated dependencies
- Known vulnerabilities

### A07: Authentication Failures
- Weak session management
- No MFA

### A08: Software Integrity Failures
- CSRF vulnerability
- No integrity checks

### A09: Logging Failures
- Basic logging only
- No audit trail

### A10: SSRF
- Unrestricted file access
- No URL validation

## Important Note
This is an educational demo. All vulnerabilities are intentional. Do not use in production.
