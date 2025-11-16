# server/register.py
import pymysql
import os
from dotenv import load_dotenv

# Fix imports when running script directly
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parents[1]))

# Now this works no matter where you run from
from server.auth_utils import gen_salt, hash_pwd
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

def register(email, username, password):
    salt = gen_salt(16)
    pwd_hash = hash_pwd(salt, password)  # hex string
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            sql = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
            cur.execute(sql, (email, username, salt, pwd_hash))
        print("User registered:", username)
    except pymysql.err.IntegrityError as e:
        print("Registration failed (duplicate?):", e)
    finally:
        conn.close()

if __name__ == "__main__":
    # local test, don't use in production
    import getpass
    email = input("email: ").strip()
    username = input("username: ").strip()
    pwd = getpass.getpass("password: ")
    register(email, username, pwd)
