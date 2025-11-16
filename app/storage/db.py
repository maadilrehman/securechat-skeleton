# app/storage/db.py
import argparse
import os
import mysql.connector
from mysql.connector import errorcode, errors
import binascii

# Read environment variables (use .env in your repo)
MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3307"))
MYSQL_DB = os.getenv("MYSQL_DB", "securechat")
MYSQL_USER = os.getenv("MYSQL_USER", "scuser")
MYSQL_PASS = os.getenv("MYSQL_PASS", "scpass")

def get_conn():
    # Return a fresh connection; callers MUST close
    return mysql.connector.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASS,
        database=MYSQL_DB,
        autocommit=True,
        use_pure=True
    )

def init_db():
    """Create database and users table if necessary. Safe to call multiple times."""
    conn = None
    try:
        # Connect as root-like account if available (we rely on container env having created DB),
        # but fallback to current credentials.
        conn = mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASS,
            autocommit=True,
            use_pure=True
        )
        cur = conn.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DB}`;")
        cur.close()
        conn.close()

        # Connect to the DB and create table
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email VARCHAR(255) PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL
        );
        """)
        cur.close()
        print("[+] Database initialized and users table created.")
    except mysql.connector.Error as err:
        print("[-] MySQL error during init_db:", err)
        # re-raise so caller can handle, but keep message printed
        raise
    finally:
        if conn:
            conn.close()

def insert_user(email: str, username: str, salt: bytes, pwd_hash_hex: str) -> bool:
    """
    Insert a new user. Returns True on success, False if unique constraint prevents insert.
    salt must be bytes of length 16.
    """
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        # Ensure salt is bytes
        if isinstance(salt, memoryview):
            salt_param = bytes(salt)
        else:
            salt_param = salt
        cur.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
            (email, username, salt_param, pwd_hash_hex)
        )
        cur.close()
        # autocommit=True used in get_conn, so commit not necessary
        return True
    except mysql.connector.IntegrityError as e:
        # duplicate email or username
        # print minimal debug info
        print("[-] insert_user IntegrityError:", e)
        return False
    except Exception as e:
        print("[-] insert_user exception:", e)
        raise
    finally:
        if conn:
            conn.close()

def get_user_by_email(email: str):
    """
    Returns a dict {email, username, salt (bytes), pwd_hash} or None.
    salt is returned as bytes (not memoryview).
    """
    conn = None
    try:
        conn = get_conn()
        # use dictionary cursor for clarity
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT email, username, salt, pwd_hash FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        cur.close()
        if row:
            salt_val = row["salt"]
            # MySQL connector may return memoryview; convert to bytes
            if isinstance(salt_val, memoryview):
                salt_val = bytes(salt_val)
            elif isinstance(salt_val, bytearray):
                salt_val = bytes(salt_val)
            # ensure pwd_hash is str
            pwd_hash = row["pwd_hash"]
            if not isinstance(pwd_hash, str):
                pwd_hash = str(pwd_hash)
            return {
                "email": row["email"],
                "username": row["username"],
                "salt": salt_val,
                "pwd_hash": pwd_hash
            }
        return None
    except Exception as e:
        print("[-] get_user_by_email exception:", e)
        # re-raise so caller (server) can print stacktrace/log and handle it
        raise
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true", help="Initialize DB and create tables")
    args = parser.parse_args()
    if args.init:
        init_db()
