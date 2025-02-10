# Flask PWA Security Lab

This project is a Flask-based Progressive Web App (PWA) intentionally designed with security vulnerabilities. The goal is to provide students with a practical learning environment to identify, test, and fix common web security issues.

## **Features**
1. **Login Page**:
   - Vulnerable to SQL Injection.
   - Demonstrates weak password storage (if using `users.json`).
2. **Registration Page**:
   - Demonstrates insecure password storage.
   - Can be upgraded to use hashed passwords.
3. **Search Bar**:
   - Vulnerable to XSS (Cross-Site Scripting).
4. **API Endpoint**:
   - Demonstrates insecure JSON handling and lacks CSRF protection.
5. **Session Management**:
   - Sessions are unprotected and set to expire after 5 minutes but can be modified to demonstrate session hijacking.

## **Hacker's Report**
For a detailed analysis of the vulnerabilities, including replication steps and recommendations, refer to the [HACKER.md](HACKER.md) file.

---

## **Setup**
### **1. Clone the Repository**
```bash
git clone <repository_url>
cd flask-pwa-security
