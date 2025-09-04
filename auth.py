import sqlite3, bcrypt, re, time
from db import DB_PATH

MAX_ATTEMPTS = 3
BASE_LOCKOUT_TIME = 5       # seconds
MAX_LOCKOUT_TIME = 86400    # 24 hours (in seconds)
RESET_LOCKOUT_PERIOD = 86400  # 24 hours (in seconds)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def validate_password(password: str) -> bool:
    if len(password) < 8: return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[0-9]", password): return False
    if not re.search(r"[!@#$%^&*()_\-]", password): return False
    return True

def log_event(username: str, action: str, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        "INSERT INTO audit_logs (username, action, timestamp) VALUES (?, ?, ?)",
        (username, action, time.time())
    )
    conn.commit()
    conn.close()

def show_logs(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT username, action, datetime(timestamp, 'unixepoch') FROM audit_logs ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()

    print("\n=== Audit Logs ===")
    for username, action, timestamp in rows:
        print(f"[{timestamp}] {username} - {action}")
    print("==================\n")


def register_user(username: str, password: str, db_path=DB_PATH):
    if not validate_password(password):
        print("\nPassword too weak!")
        print("Password must be at least 8 characters long and include:")
        print(" - At least one uppercase letter (A-Z)")
        print(" - At least one lowercase letter (a-z)")
        print(" - At least one number (0-9)")
        print(" - At least one special character (!@#$%^&*()-_)")
        log_event(username, "registration_failed", db_path)
        return
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()

        c.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,))
        if c.fetchone():
            print("⚠️ Username already exists (case-insensitive).")
            print("Please choose a different username.")
            print("Please add numbers or special characters to make it unique.")
            log_event(username, "registration_failed_duplicate", db_path)
            conn.close()
            return

        c.execute(
            "INSERT INTO users (username, password_hash, failed_attempts, lockout_until, lockout_count) VALUES (?, ?, 0, 0, 0)",
            (username, hash_password(password)),
        )
        conn.commit()
        conn.close()
        print("User registered successfully!")
        log_event(username, "registration_success", db_path)

    except sqlite3.IntegrityError:
        try:
            conn.close()
        except:
            pass
        print("⚠️ Registration failed due to database error.")
        log_event(username, "registration_failed_db_error", db_path)
    finally:
        conn.close()

def login_admin(username: str, password: str, db_path=DB_PATH) -> bool:
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM admins WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        log_event(username, "admin_login_failed_no_user", db_path)
        return False

    hashed = row[0]
    if check_password(password, hashed):
        log_event(username, "admin_login_success", db_path)
        return True
    else:
        log_event(username, "admin_login_failed", db_path)
        return False

def list_users(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT username FROM users ORDER BY username ASC")
    rows = c.fetchall()
    conn.close()

    if not rows:
        print("⚠️ No registered users found.")
        return

    print("\n=== Registered Users ===")
    for (username,) in rows:
        print(f"- {username}")
    print("========================\n")    

def remove_user(target_username: str, db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (target_username,))
    row = c.fetchone()

    if not row:
        log_event("admin", f"remove_user_failed_{target_username}", db_path)
        conn.close()
        print(f"⚠️ No user found with username '{target_username}'.")
        return

    c.execute("DELETE FROM users WHERE LOWER(username) = LOWER(?)", (target_username,))
    conn.commit()
    conn.close()

    log_event("admin", f"remove_user_success_{target_username}", db_path)
    print(f"✅ User '{target_username}' has been removed.")



def login_user(username: str, password: str, db_path=DB_PATH) -> bool:
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT password_hash, failed_attempts, lockout_until, lockout_count FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if not row:
        print("Invalid username or password.")
        log_event(username, "login_failed_no_user", db_path)
        conn.close()
        return False

    hashed, failed_attempts, lockout_until, lockout_count = row
    now = time.time()

    if lockout_until and now - lockout_until > RESET_LOCKOUT_PERIOD:
        lockout_count = 0
        c.execute("UPDATE users SET lockout_count = 0 WHERE username = ?", (username,))
        conn.commit()

    if lockout_until and now < lockout_until:
        remaining = int(lockout_until - now)
        print(f"Account locked. Try again in {remaining} seconds.")
        conn.close()
        return False

    if check_password(password, hashed):
        print("Login successful!")
        log_event(username, "login_success", db_path)
        c.execute("UPDATE users SET failed_attempts = 0, lockout_until = 0, lockout_count = 0 WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return True
    else:
        print("Invalid username or password.")
        failed_attempts += 1

        log_event(username, "login_failed", db_path)

        if failed_attempts >= MAX_ATTEMPTS:
            lockout_count += 1
            lock_duration = min(BASE_LOCKOUT_TIME * (2 ** (lockout_count - 1)), MAX_LOCKOUT_TIME)
            lock_time = now + lock_duration

            log_event(username, f"account_locked_{int(lock_duration)}s", db_path)

            c.execute("UPDATE users SET failed_attempts = 0, lockout_until = ?, lockout_count = ? WHERE username = ?",
                      (lock_time, lockout_count, username))
            print(f"Account locked for {int(lock_duration)} seconds.")
        else:
            c.execute("UPDATE users SET failed_attempts = ? WHERE username = ?", (failed_attempts, username))

        conn.commit()
        conn.close()
        return False
