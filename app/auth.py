import mysql.connector
import os
import hashlib

# Database connection
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root123",
    database="securechat"
)
cursor = conn.cursor()

def register_user(email, username, password):
    """Register a new user with salted password hash"""
    try:
        salt = os.urandom(16)
        pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        print(f"✅ User '{username}' registered successfully.")
        return True
    except mysql.connector.IntegrityError:
        print("❌ Error: Email or username already exists.")
        return False
    except Exception as e:
        print(f"❌ Error during registration: {e}")
        return False

def login_user(email, password):
    """Authenticate user by checking salted hash"""
    try:
        cursor.execute("SELECT salt, pwd_hash FROM users WHERE email=%s", (email,))
        result = cursor.fetchone()
        
        if result:
            salt, stored_hash = result
            pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
            
            if pwd_hash == stored_hash:
                print(f"✅ Login successful for {email}")
                return True
        
        print("❌ Login failed: Invalid email or password")
        return False
    except Exception as e:
        print(f"❌ Error during login: {e}")
        return False

def close_connection():
    """Close database connection"""
    cursor.close()
    conn.close()

# Test the functions
if __name__ == "__main__":
    print("=== Testing Registration ===")
    register_user("test@example.com", "testuser", "password123")
    
    print("\n=== Testing Login ===")
    login_user("test@example.com", "password123")
    
    print("\n=== Testing Wrong Password ===")
    login_user("test@example.com", "wrongpassword")
    
    close_connection()
    print("\n✅ All tests completed!")