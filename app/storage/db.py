import mysql.connector
import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes

# Load database credentials from the .env file
load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

def get_db_connection():
    """Establishes a connection to the MySQL database."""
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        # In a real app, you'd have better error handling
        # For this assignment, exiting might be okay if the DB is required.
        return None

def register_user(email: str, username: str, password: str) -> bool:
    """
    Registers a new user with a salt and hashed password.
    Implements Section 2.2, steps 5-6.
    """
    conn = get_db_connection()
    if not conn:
        return False

    try:
        # 1. Generate a 16-byte random salt [cite: 180]
        salt = os.urandom(16)

        # 2. Compute the salted password hash [cite: 181-182]
        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        digest.update(password.encode('utf-8'))
        pwd_hash = digest.finalize().hex()

        # 3. Store the user in the database [cite: 183-184]
        cursor = conn.cursor()
        query = """
            INSERT INTO users (email, username, salt, pwd_hash)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (email, username, salt, pwd_hash))
        conn.commit()

        print(f"DB: Successfully registered user '{username}'")
        return True

    except mysql.connector.Error as err:
        # This will catch errors, e.g., if the username is not unique
        print(f"DB: Error registering user: {err}")
        return False
    finally:
        conn.close()

def verify_user(email: str, password: str) -> bool:
    """
    Verifies a user's login credentials.
    Implements Section 2.2, step 7.
    """
    conn = get_db_connection()
    if not conn:
        return False

    try:
        # 1. Fetch the user's salt and stored hash 
        cursor = conn.cursor()
        query = "SELECT salt, pwd_hash FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        result = cursor.fetchone()

        if not result:
            print(f"DB: Login failed. User '{email}' not found.")
            return False

        salt, stored_hash = result

        # 2. Re-compute the hash with the provided password
        digest = hashes.Hash(hashes.SHA256())
        digest.update(salt)
        digest.update(password.encode('utf-8'))
        computed_hash = digest.finalize().hex()

        # 3. Compare the hashes [cite: 189]
        if computed_hash == stored_hash:
            print(f"DB: User '{email}' successfully verified.")
            return True
        else:
            print(f"DB: Login failed. Invalid password for '{email}'.")
            return False

    except mysql.connector.Error as err:
        print(f"DB: Error verifying user: {err}")
        return False
    finally:
        conn.close()