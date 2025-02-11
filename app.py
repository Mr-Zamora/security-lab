from flask import Flask, render_template, request, jsonify, session, redirect, send_from_directory
import sqlite3
import json
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from werkzeug.security import check_password_hash
import logging
from functools import wraps
import urllib.request
import requests
from packaging import version
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.secret_key = "supersecretkey"  # For session management

# JSON Files for API Data
USERS_JSON = "users.json"
DATA_JSON = "data.json"

# SQLite for User Authentication
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY,
                 username TEXT,
                 password TEXT)''')
    # Default admin user with a hashed password
    c.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', ?)",
              (generate_password_hash('admin123'),))
    conn.commit()
    conn.close()

init_db()

# Helper Functions for JSON File Operations
def load_json(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_json(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Intentionally Vulnerable SQL Query for SQL Injection Testing
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"Executing query: {query}")  # Debugging: Show the query
        
        try:
            c.execute(query)
            user = c.fetchone()
            conn.close()

            # Check for various SQL injection patterns
            sql_patterns = [
                "' OR '1'='1",    # Basic OR injection
                "' OR 1=1--",     # Comment injection
                "' OR 'a'='a",    # Boolean logic
                "' OR 5>3--",     # Numeric comparison
                "' OR username LIKE '%",  # LIKE operator
                "' UNION SELECT"   # UNION injection
            ]

            # If query returns a user OR contains injection pattern
            if user or any(pattern.lower() in (username + password).lower() for pattern in sql_patterns):
                session['logged_in'] = True
                session['username'] = username
                return "Login successful! (SQL Injection)"
            
            return "Invalid credentials!", 401
        except sqlite3.Error as e:
            print(f"SQL Error: {e}")  # Log the error
            conn.close()
            return "Database error", 500
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Save to SQLite with hashed password
        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()

        # Save to users.json in plaintext (vulnerable storage)
        try:
            with open(USERS_JSON, 'r') as f:
                users = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            users = {}
        
        users[username] = password  # Store password in plaintext
        
        with open(USERS_JSON, 'w') as f:
            json.dump(users, f, indent=4)
        
        return "Registration successful!"
    return render_template('register.html')

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')  # Get search query from URL parameters
    return render_template('search.html', query=query)  # Pass query to template

@app.route('/api/data', methods=['GET', 'POST'])
def api_data():
    if request.method == 'GET':
        # Load data from JSON
        data = load_json(DATA_JSON)
        return jsonify(data)

    if request.method == 'POST':
        # No CSRF Protection and Insecure JSON Handling
        if not request.json or 'data' not in request.json:
            return jsonify({"error": "Invalid JSON data"}), 400
        new_data = request.json['data']
        data = load_json(DATA_JSON)
        data.append(new_data)
        save_json(DATA_JSON, data)
        return jsonify({"message": "Data added successfully!"})

@app.route('/report')
def report():
    # Vulnerable: No session validation
    # Vulnerable: No CSRF protection
    # Should check if user is logged in, but doesn't
    return render_template('report.html')

# Setup logging - intentionally insecure
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',  # Insecure - no timestamps, levels, or source info
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

# Simulated user data for IDOR demo
USERS = {
    '1': {'name': 'admin', 'balance': 1000},
    '2': {'name': 'user', 'balance': 500}
}

# Intentionally vulnerable decorators
def log_access(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logging.info(f"Access attempt from IP: {request.remote_addr}")
        return f(*args, **kwargs)
    return decorated_function

@app.route('/user/<id>')
def get_user(id):
    # Intentionally vulnerable: IDOR - no authorization check
    if id in USERS:
        return jsonify(USERS[id])
    return "User not found", 404

# User balances for CSRF demo
USER_BALANCES = {
    'admin': 1000,
    'user': 500
}

@app.route('/balance')
def get_balance():
    if 'username' not in session:
        return jsonify({"error": "Not logged in"}), 401
    username = session['username']
    balance = USER_BALANCES.get(username, 0)
    return jsonify({"username": username, "balance": balance})

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'username' not in session:
        return jsonify({"error": "Not logged in"}), 401

    if request.method == 'GET':
        return render_template('transfer.html')

    # Intentionally vulnerable to CSRF
    from_user = session['username']
    to_user = request.form.get('to_user')
    try:
        amount = int(request.form.get('amount', 0))
    except ValueError:
        return jsonify({"error": "Invalid amount"}), 400

    if from_user not in USER_BALANCES or to_user not in USER_BALANCES:
        return jsonify({"error": "Invalid user"}), 400

    if USER_BALANCES[from_user] < amount:
        return jsonify({"error": "Insufficient funds"}), 400

    # Perform transfer
    USER_BALANCES[from_user] -= amount
    USER_BALANCES[to_user] += amount

    return jsonify({
        "message": f"Transferred ${amount} to {to_user}",
        "new_balance": USER_BALANCES[from_user]
    })

@app.route('/stored-xss')
def stored_xss():
    # Intentionally vulnerable: Stored XSS
    comments = load_json("comments.json")
    return render_template('comments.html', comments=comments)

@app.route('/add-comment', methods=['POST'])
def add_comment():
    # Intentionally vulnerable: Stored XSS
    comment = request.form.get('comment')
    comments = load_json("comments.json")
    comments.append({"text": comment})  # No sanitization
    save_json("comments.json", comments)
    return redirect('/stored-xss')

# Intentionally weak security headers
@app.after_request
def add_security_headers(response):
    # Intentionally missing or weak security headers
    response.headers['X-Frame-Options'] = 'ALLOW-FROM *'  # Vulnerable to clickjacking
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Missing CSP header intentionally
    return response

# Session Configuration (Intentionally Vulnerable)
app.permanent_session_lifetime = timedelta(days=365)  # Extremely long session
app.config['SESSION_COOKIE_SECURE'] = False  # Allow HTTP (not HTTPS only)
app.config['SESSION_COOKIE_HTTPONLY'] = False  # Allow JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = None  # Allow cross-site requests

@app.before_request
def set_session_expiration():
    session.permanent = True

# A04: Insecure Design - Predictable Resource Location
@app.route('/download/<filename>')
def download_file(filename):
    # Insecure: Predictable resource locations and no access control
    return send_from_directory('uploads', filename)

# A06: Vulnerable Components
VULNERABLE_DEPENDENCY_VERSION = "2.0.1"  # Known vulnerable version

@app.route('/check_dependency')
def check_dependency():
    # Intentionally using a known vulnerable version
    current_version = VULNERABLE_DEPENDENCY_VERSION
    try:
        response = requests.get("https://pypi.org/pypi/requests/json")
        latest_version = response.json()["info"]["version"]
        is_vulnerable = version.parse(current_version) < version.parse(latest_version)
        return jsonify({
            "current_version": current_version,
            "latest_version": latest_version,
            "is_vulnerable": is_vulnerable
        })
    except Exception as e:
        return str(e)

# A09: Security Logging Failures
@app.route('/admin/login', methods=['POST'])
def admin_login():
    """
    This is a separate endpoint purely to demonstrate logging vulnerabilities.
    It uses hardcoded credentials (admin/admin123) and intentionally poor logging practices.
    The main user authentication is handled by the /login endpoint.
    """
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Insecure logging - exposing sensitive data
    logging.info(f"[ADMIN LOGIN] Attempt with credentials - Username: {username}, Password: {password}")
    
    # Using hardcoded credentials for demo purposes
    DEMO_ADMIN = {"username": "admin", "password": "admin123"}
    
    if username == DEMO_ADMIN["username"] and password == DEMO_ADMIN["password"]:
        # Missing success logging
        return "Login successful (Demo Only - See HACKER.md for details)"
    else:
        # Missing failure logging
        return "Login failed (Demo Only - See HACKER.md for details)"

# A10: SSRF Vulnerability
@app.route('/fetch-url', methods=['POST'])
def fetch_url():
    url = request.form.get('url')
    try:
        # Vulnerable to SSRF - no URL validation
        response = urllib.request.urlopen(url)
        return response.read().decode('utf-8')
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    init_db()  # Initialize the database
    app.run(debug=True)
