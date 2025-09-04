import sqlite3

DB_PATH = 'users.db'

def init_db(db_path='users.db'):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        lockout_until REAL DEFAULT 0,
        lockout_count INTEGER DEFAULT 0
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Create default admin if it doesn't exist
    c.execute("SELECT * FROM admins WHERE username = 'admin'")
    if not c.fetchone():
        import bcrypt
        default_password = bcrypt.hashpw("Password123".encode(), bcrypt.gensalt()).decode()
        c.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)", ("admin", default_password))
        print("✅ Default admin created (username: admin, password: Password123)")

    conn.commit()
    conn.close()
