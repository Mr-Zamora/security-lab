# Hacker's Report: Breaking into the Client's PWA

This document outlines the security vulnerabilities identified in the client's Progressive Web App (PWA). It provides detailed replication steps, explanations of why each vulnerability exists, and recommendations for fixes. The testing methodologies used include **blackbox**, **whitebox**, and **greybox testing**, along with **Google Lighthouse** audits.

---

## **Objectives**
- Identify security weaknesses in the PWA.
- Simulate real-world attacks to demonstrate vulnerabilities.
- Provide actionable recommendations to secure the system.

---

## **Vulnerabilities and Replication Steps**

### **1. SQL Injection Demo**

#### **Description**
The login form allows SQL injection through both username and password fields, demonstrating multiple attack vectors.

#### **Steps to Replicate**

##### Method 1: Username Injection
1. Navigate to the Login Page: `http://127.0.0.1:5000/login`
2. Enter in the **Username** field:
   ```sql
   admin' OR '1'='1
   ```
3. Enter any password
4. Click Login

##### Method 2: Password Injection
1. Navigate to the Login Page: `http://127.0.0.1:5000/login`
2. Enter any username
3. Enter in the **Password** field:
   ```sql
   ' OR '1'='1--
   ```
4. Click Login

##### Alternative SQL Injection Payloads

1. Using LIKE operator:
```sql
admin' OR username LIKE '%admin%
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

#### **Why These Work**
- `OR '1'='1` - Always evaluates to TRUE
- `--` - Comments out remaining SQL
- `UNION` - Combines queries
- The server logs all SQL queries, allowing observation of injection effects

#### **How to Test Systematically**
1. Go to Login Page
2. Try different payloads in either field
3. Check server logs for query execution
4. Observe authentication bypass

### **4. Insecure API Endpoint**

#### **Description**
The API endpoint is vulnerable to multiple attack vectors including XSS through JSON data and lacks proper authentication.

#### **Steps to Replicate**

##### Method 1: Direct API Access
1. Access the API endpoint directly: `http://127.0.0.1:5000/api/data`
2. Send POST request with malicious payload:
   ```json
   {
     "data": "<script>alert('API Vulnerability!');</script>"
   }
   ```

##### Method 2: XSS Through JSON
1. Create a test HTML file (test_api.html):
```html
<!DOCTYPE html>
<html>
<head>
    <title>Test API Vulnerability</title>
</head>
<body>
    <h2>Test API Vulnerability</h2>
    <form id="apiForm" onsubmit="submitForm(event)">
        <textarea id="jsonData" style="width: 300px; height: 100px">{"data": "<script>alert('API Vulnerability!');</script>"}</textarea>
        <br><br>
        <button type="submit">Send</button>
    </form>

    <script>
        function submitForm(event) {
            event.preventDefault();
            const data = document.getElementById('jsonData').value;
            fetch('http://127.0.0.1:5000/api/data', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: data
            })
            .then(response => response.json())
            .then(result => alert('Success: ' + JSON.stringify(result)))
            .catch(error => alert('Error: ' + error));
        }
    </script>
</body>
</html>
```

##### Alternative XSS Payloads
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

#### **Why It's Vulnerable**
1. No input sanitization on JSON data
2. Stored XSS through API endpoint
3. No authentication required for API access
4. No Content-Security-Policy headers
5. Direct rendering of user input

#### **Expected Results**
- Successful POST requests store unsanitized data
- XSS payloads execute when data is rendered
- No authentication barriers prevent API access

#### **Recommendation**
1. Implement proper input sanitization for JSON data
2. Add authentication to API endpoints
3. Implement Content-Security-Policy headers
4. Validate and escape all user input before storage or rendering
5. Add rate limiting to prevent abuse

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

### **6. Weak Password Storage**

#### **Description**
Passwords are stored in plaintext, exposing them to anyone with access to the server.

#### **Steps to Replicate**
1. Navigate to the Registration Page: `http://127.0.0.1:5000/register`
2. Create a new user:
   - Username: `testuser`
   - Password: `mypassword`
3. Compare storage methods:
   
   a. View plaintext passwords in `users.json`:
   ```json
   {
       "testuser": "mypassword"
   }
   ```
   
   b. View hashed passwords in SQLite using check_db.py:
   ```bash
   python check_db.py
   ```
   Output shows secure vs insecure storage:
   ```
   Users in database:
   ID: 1, Username: testuser, Password: scrypt:32768:8:1$...[hashed]...
   ```

#### **Why This Happens**
- Passwords are saved directly without hashing in users.json
- SQLite database uses proper password hashing
- This dual storage demonstrates the contrast between secure and insecure practices

#### **Security Impact**
- users.json: Passwords are immediately readable by anyone with file access
- users.db: Passwords are properly hashed and protected

#### **Google Lighthouse Insights**
- Flagged unencrypted HTTP connections, highlighting potential risks of transmitting plaintext passwords.

#### **Recommendation**
- Hash passwords before storing them:
   ```python
   from werkzeug.security import generate_password_hash
   hashed_password = generate_password_hash(password)
   ```

### **7. Stored XSS**

#### **Description**
The application stores user input without sanitization, allowing malicious scripts to be executed.

#### **Steps to Replicate**
1. Navigate to the Comment Section: `http://127.0.0.1:5000/comments`
2. Enter the following in the comment field:
   ```html
   <script>alert('XSS Vulnerability!');</script>
   ```
3. Submit the form.

#### **Expected Result**
A browser popup displays the alert message "XSS Vulnerability!".

#### **Why This Happens**
- User input is stored without sanitization.

#### **Google Lighthouse Insights**
- Missing Content-Security-Policy headers flagged.
- Warned about the absence of X-XSS-Protection.

#### **Recommendation**
- Escape user input before storing it:
   ```python
   from markupsafe import escape
   return f"Comment: {escape(comment)}"
   ```

### **8. Security Misconfiguration**

#### **Description**
The application lacks critical security headers, making it vulnerable to various attacks.

#### **Steps to Check**
1. Use browser developer tools
2. Examine response headers
3. Note missing or misconfigured headers:
   - No Content-Security-Policy
   - Weak X-Frame-Options
   - Missing HSTS

#### **Impact**
- Clickjacking vulnerability
- XSS exploitation easier
- Man-in-the-middle attacks possible

#### **Recommendation**
```python
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response
```

### **9. Insecure Design (A04)**

#### **Description**
The application's design allows for predictable resource locations and weak session management.

#### **Steps to Replicate**
1. Access the endpoint directly: `http://localhost:5000/user/1`
2. Try different IDs: `/user/2`, `/user/3`, etc.
3. Note that no authentication is required

#### **Expected Result**
- Direct access to user data
- JSON response with user details
- No authorization checks performed

#### **Why This Happens**
- No authentication check before accessing data
- Direct exposure of database IDs
- Missing access control checks

#### **Recommendation**
- Implement proper authentication
- Use indirect references
- Add authorization checks
- Implement role-based access control

### **10. Vulnerable Components (A06)**

#### **Description**
The application uses outdated dependencies with known vulnerabilities.

#### **Steps to Check**
1. Use dependency scanning tools
2. Examine the application's dependencies
3. Note outdated or vulnerable components:
   - Outdated Flask version
   - Vulnerable Werkzeug version

#### **Impact**
- Potential for exploitation of known vulnerabilities
- Increased risk of security breaches

#### **Recommendation**
- Update dependencies to the latest versions:
   ```bash
   pip install --upgrade flask
   pip install --upgrade werkzeug
   ```

### **11. Security Logging Failures (A09)**

#### **Description**
The application fails to properly log security events, making it difficult to detect and respond to security incidents.

#### **Demo Credentials**
```
Username: admin
Password: admin123
```
This is a separate demo endpoint using hardcoded credentials specifically to demonstrate logging vulnerabilities. The main user authentication system uses the database and is demonstrated in other vulnerabilities.

#### **Test Scenario 1: Sensitive Data Exposure in Logs**

1. Open a terminal and start monitoring the application logs:
   ```bash
   type app.log
   ```

2. Go to the admin login form on the home page (under "11. Security Logging Failures")
3. Submit these credentials:
   - Username: `admin`
   - Password: `admin123`
4. Check the logs again:
   ```bash
   type app.log
   ```
   You should see sensitive information exposed:
   ```
   [ADMIN LOGIN] Attempt with credentials - Username: admin, Password: admin123
   ```

**Security Impact**: Passwords and sensitive data are logged in plaintext, risking exposure through log files.

#### **Test Scenario 2: Missing Critical Event Logging**

1. Try these login attempts:
   - Correct credentials (admin/admin123)
   - Wrong password (admin/wrongpass)
   - Wrong username (notadmin/admin123)
   - SQL injection attempt (admin' OR '1'='1)

2. Check the logs. Notice that many critical security events are not logged:
   - No IP addresses logged
   - No timestamps on events
   - No session IDs tracked
   - No user agent information
   - No success/failure status
   - No rate limiting information

**Security Impact**: Inability to detect and investigate security incidents.

#### **Test Scenario 3: Insufficient Logging Detail**

1. Try to perform a password reset for any user
2. Check the logs and notice:
   - No record of who initiated the reset
   - No timestamp of the action
   - No success/failure status

**Security Impact**: Forensic investigation becomes impossible due to missing crucial details.

#### **Test Scenario 4: No Log Protection**

1. Locate the log file in the application directory
2. Notice that:
   - Logs are stored without encryption
   - No log rotation implemented
   - No access controls on log files
   - No backup strategy

**Security Impact**: Log tampering and deletion go undetected.

#### **Test Scenario 5: Missing Audit Trail**

1. As an admin user:
   - Create a new user account
   - Modify user permissions
   - Delete a user

2. Try to reconstruct the sequence of events from logs
3. Notice that it's impossible to:
   - Track who made what changes
   - Determine the timing of changes
   - See the previous vs new values

**Security Impact**: No accountability for administrative actions.

#### **Proper Implementation Would Include**

1. **Structured Logging**:
   ```python
   logging.info({
       "event": "login_attempt",
       "username": username,
       "ip": request.remote_addr,
       "user_agent": request.user_agent.string,
       "timestamp": datetime.utcnow().isoformat(),
       "success": success
   })
   ```

2. **Critical Events to Log**:
   - Authentication events (success/failure)
   - Authorization failures
   - Input validation failures
   - Application errors
   - Security configuration changes
   - Data access and modification

3. **Log Protection**:
   - Implement log rotation
   - Use append-only logs
   - Store logs securely
   - Regular log backups
   - Log integrity monitoring

4. **Never Log**:
   - Passwords (plain text or hashed)
   - Session tokens
   - API keys
   - Sensitive personal data
   - Banking/financial data

#### **Mitigation Steps**

1. Implement structured logging with proper formatting:
   ```python
   logging.basicConfig(
       level=logging.INFO,
       format='%(asctime)s - %(levelname)s - %(client_ip)s - %(message)s',
       datefmt='%Y-%m-%d %H:%M:%S'
   )
   ```

2. Use logging levels appropriately:
   ```python
   logging.info("User logged in successfully")  # Normal operations
   logging.warning("Failed login attempt")      # Potential security events
   logging.error("Authorization failure")       # Security incidents
   ```

3. Include contextual information:
   ```python
   extra = {
       'client_ip': request.remote_addr,
       'user_id': current_user.id,
       'action': 'password_change'
   }
   logger.info("Password changed", extra=extra)
   ```

4. Implement secure log handling:
   ```python
   from logging.handlers import RotatingFileHandler
   
   handler = RotatingFileHandler(
       'app.log',
       maxBytes=10000000,  # 10MB
       backupCount=5
   )
   ```

#### **Testing Tools**

- Log analysis tools (e.g., ELK Stack)
- Log monitoring systems
- SIEM solutions
- File integrity monitoring tools

### **12. SSRF Vulnerability (A10)**

#### **Description**
The application allows for Server-Side Request Forgery (SSRF) attacks, enabling an attacker to make unauthorized requests.

#### **Steps to Replicate**
1. Navigate to the SSRF Endpoint: `http://127.0.0.1:5000/ssrf`
2. Enter a URL in the input field:
   ```html
   http://localhost:5000/admin
   ```
3. Submit the form.

#### **Expected Result**
The application makes a request to the specified URL, potentially allowing access to sensitive data or systems.

#### **Why This Happens**
- The application does not validate or sanitize the input URL.

#### **Recommendation**
- Validate and sanitize the input URL:
   ```python
   from urllib.parse import urlparse
   
   def is_valid_url(url):
       try:
           result = urlparse(url)
           return all([result.scheme, result.netloc])
       except ValueError:
           return False
   ```

---

## **Summary of Tools and Testing Methodologies**

### **1. Testing Methodologies**
- **Blackbox Testing**:
  Simulated attacks without access to source code, using form inputs and browser interactions.
- **Whitebox Testing**:
  Reviewed the source code to identify vulnerabilities like raw SQL queries and unsanitized inputs.
- **Greybox Testing**:
  Combined knowledge of the codebase with manual tests to refine attacks.

### **2. Tools Used**
- **Google Lighthouse**:
  Identified missing security headers, outdated libraries, and unencrypted HTTP connections.
- **Browser Developer Tools**:
  Inspected requests, cookies, and DOM behavior to uncover vulnerabilities.

---

## **Recommendations**

### **Critical Fixes:**
- Use parameterised queries to prevent SQL Injection.
- Hash passwords before storing them.
- Sanitize user input to prevent XSS.

### **Intermediate Fixes:**
- Add Content-Security-Policy and other headers to restrict script execution.
- Enforce HTTPS using Flask-Talisman.

### **Ongoing Practices:**
- Regularly audit dependencies for vulnerabilities.
- Perform routine penetration testing to ensure continued security.
