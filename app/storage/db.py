# app/storage/db.py
import os, hmac
from hashlib import sha256
import pymysql
from dotenv import load_dotenv

load_dotenv()  # no-op if missing

def _conn():
    return pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", ""),
        database=os.getenv("DB_NAME", "securechat"),
        autocommit=True,
    )

def ensure_schema():
    with _conn() as c:
        with c.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
              email VARCHAR(255) NOT NULL,
              username VARCHAR(64) NOT NULL UNIQUE,
              salt VARBINARY(16) NOT NULL,
              pwd_hash CHAR(64) NOT NULL,
              PRIMARY KEY (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)

def create_user(email: str, username: str, pwd_plain: str) -> bool:
    ensure_schema()
    salt = os.urandom(16)
    h = sha256(salt + pwd_plain.encode()).hexdigest()
    with _conn() as c:
        with c.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE username=%s OR email=%s", (username, email))
            if cur.fetchone():
                return False
            cur.execute("INSERT INTO users(email,username,salt,pwd_hash) VALUES(%s,%s,%s,%s)",
                        (email, username, salt, h))
    return True

def auth_user(email: str, pwd_plain: str) -> str | None:
    ensure_schema()
    with _conn() as c:
        with c.cursor() as cur:
            cur.execute("SELECT username, salt, pwd_hash FROM users WHERE email=%s", (email,))
            row = cur.fetchone()
            if not row:
                return None
            username, salt, pwd_hash = row
            calc = sha256(salt + pwd_plain.encode()).hexdigest()
            if hmac.compare_digest(calc, pwd_hash):
                return username
            return None
