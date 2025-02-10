import sqlite3

# Recreate the users database
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Drop and recreate the users table
c.execute("DROP TABLE IF EXISTS users")
c.execute('''
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT
)
''')

# Insert a user with a plaintext password
c.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
conn.commit()

conn.close()
