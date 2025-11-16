# server/login.py
import pymysql
import os
from dotenv import load_dotenv

# Fix imports when running script directly
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[1]))

# Now this works no matter where you run from
from server.auth_utils import gen_salt, hash_pwd , constant_time_compare


load_dotenv(Path(__file__).resolve().parents[1] / ".env.example")

def get_conn():
    return pymysql.connect(
        host=os.getenv("MYSQL_HOST","localhost"),
        port=int(os.getenv("MYSQL_PORT","3306")),
        user=os.getenv("MYSQL_USER","root"),
        password=os.getenv("MYSQL_PASSWORD",""),
        db=os.getenv("MYSQL_DB","securechat_db"),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

def verify_login(username, password) -> bool:
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT salt, pwd_hash FROM users WHERE username=%s", (username,))
            row = cur.fetchone()
            if not row:
                return False
            salt = row['salt']  # bytes
            stored_hash = row['pwd_hash']  # hex string
            computed_hash = hash_pwd(salt, password)
            return constant_time_compare(stored_hash, computed_hash)
    finally:
        conn.close()

if __name__ == "__main__":
    import getpass
    username = input("username: ").strip()
    pwd = getpass.getpass("password: ")
    ok = verify_login(username, pwd)
    print("Login", "successful" if ok else "failed")
