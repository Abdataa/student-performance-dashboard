# db_setup.py
import sqlite3

# Connect to SQLite database (will create if not exists)
conn = sqlite3.connect('database.db')
c = conn.cursor()

# Create users table
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    is_active BOOLEAN DEFAULT 1
)
''')

conn.commit()
conn.close()
print("Users table created successfully.")
