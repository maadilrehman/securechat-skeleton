import mysql.connector
import os, base64, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# DB connection
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="YOUR_PASSWORD",  # replace with your MySQL password
    database="securechat"
)
cursor = conn.cursor()

def register_user(email, username, password):
    salt = os.urandom(16)
    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
    cursor.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                   (email, username, salt, pwd_hash))
    conn.commit()
    print("User registered successfully.")

def login_user(email, password):
    cursor.execute("SELECT salt, pwd_hash FROM users WHERE email=%s", (email,))
    result = cursor.fetchone()
    if result:
        salt, stored_hash = result
        pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
        if pwd_hash == stored_hash:
            print("Login successful")
            return True
    print("Login failed")
    return False
