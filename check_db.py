import sqlite3

def check_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Check if users table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if not c.fetchone():
        print("No users table found!")
        return
    
    # Get all users
    print("Users in database:")
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    for user in users:
        print(f"ID: {user[0]}, Username: {user[1]}, Password: {user[2]}")
    
    conn.close()

if __name__ == "__main__":
    check_users()
