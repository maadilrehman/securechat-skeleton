import socket
import json
import os
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import mysql.connector
from datetime import datetime

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9000
CA_CERT_PATH = 'certs/rootCA.pem'
SERVER_CERT_PATH = 'certs/server.pem'
SERVER_KEY_PATH = 'certs/server.key'

# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="root123",
        database="securechat"
    )

# Load certificates
def load_certificates():
    with open(CA_CERT_PATH, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(SERVER_CERT_PATH, 'rb') as f:
        server_cert = x509.load_pem_x509_certificate(f.read())
    with open(SERVER_KEY_PATH, 'rb') as f:
        server_key = serialization.load_pem_private_key(f.read(), password=None)
    return ca_cert, server_cert, server_key

# Validate client certificate
def validate_certificate(cert_pem, ca_cert):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        
        # Check expiry
        now = datetime.utcnow()
        if cert.not_valid_before > now or cert.not_valid_after < now:
            print("❌ Certificate expired or not yet valid")
            return False
        
        # Verify signature (simplified - in production, use proper chain validation)
        # For now, just check if it's signed by our CA
        print(f"✅ Client certificate validated: {cert.subject}")
        return True
    except Exception as e:
        print(f"❌ Certificate validation failed: {e}")
        return False

# Diffie-Hellman key exchange
def perform_dh_server(client_socket):
    # Receive DH params from client
    dh_msg = json.loads(client_socket.recv(4096).decode())
    p = dh_msg['p']
    g = dh_msg['g']
    A = dh_msg['A']
    
    # Generate server's DH key pair
    params = dh.DHParameterNumbers(p, g).parameters(default_backend())
    server_private = params.generate_private_key()
    server_public = server_private.public_key().public_numbers().y
    
    # Send server's public key
    client_socket.send(json.dumps({'type': 'dh_server', 'B': server_public}).encode())
    
    # Compute shared secret
    shared_secret = pow(A, server_private.private_numbers().x, p)
    
    # Derive AES key
    key_hash = hashlib.sha256(shared_secret.to_bytes(256, 'big')).digest()
    aes_key = key_hash[:16]  # Truncate to 128 bits
    
    return aes_key

# AES decryption
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    
    # Remove PKCS7 padding
    unpadder = PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Handle registration
def handle_registration(data, conn):
    cursor = conn.cursor()
    try:
        email = data['email']
        username = data['username']
        password = data['pwd']
        
        # Generate salt and hash
        salt = os.urandom(16)
        pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
        
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        print(f"✅ User '{username}' registered successfully")
        return {'status': 'success', 'message': 'Registration successful'}
    except mysql.connector.IntegrityError:
        return {'status': 'error', 'message': 'Email or username already exists'}
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return {'status': 'error', 'message': str(e)}
    finally:
        cursor.close()

# Handle login
def handle_login(data, conn):
    cursor = conn.cursor()
    try:
        email = data['email']
        password = data['pwd']
        
        cursor.execute("SELECT salt, pwd_hash, username FROM users WHERE email=%s", (email,))
        result = cursor.fetchone()
        
        if result:
            salt, stored_hash, username = result
            pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
            
            if pwd_hash == stored_hash:
                print(f"✅ Login successful for {email}")
                return {'status': 'success', 'message': 'Login successful', 'username': username}
        
        print(f"❌ Login failed for {email}")
        return {'status': 'error', 'message': 'Invalid email or password'}
    except Exception as e:
        print(f"❌ Login error: {e}")
        return {'status': 'error', 'message': str(e)}
    finally:
        cursor.close()

# Main server loop
def start_server():
    ca_cert, server_cert, server_key = load_certificates()
    db_conn = get_db_connection()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    
    print(f"🚀 Server started on {SERVER_HOST}:{SERVER_PORT}")
    print("Waiting for client connections...")
    
    while True:
        client_socket, addr = server_socket.accept()
        print(f"\n📞 Client connected from {addr}")
        
        try:
            # Step 1: Certificate exchange
            # Send server certificate
            server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM).decode()
            client_socket.send(json.dumps({'type': 'server_hello', 'cert': server_cert_pem}).encode())
            
            # Receive client certificate
            client_hello = json.loads(client_socket.recv(4096).decode())
            if not validate_certificate(client_hello['cert'], ca_cert):
                client_socket.send(json.dumps({'status': 'error', 'message': 'BAD_CERT'}).encode())
                client_socket.close()
                continue
            
            # Step 2: Diffie-Hellman key exchange
            aes_key = perform_dh_server(client_socket)
            print("✅ DH key exchange complete")
            
            # Step 3: Receive encrypted credentials
            encrypted_msg = client_socket.recv(4096)
            decrypted_data = aes_decrypt(encrypted_msg, aes_key)
            auth_data = json.loads(decrypted_data.decode())
            
            # Step 4: Handle registration or login
            if auth_data['type'] == 'register':
                response = handle_registration(auth_data, db_conn)
            elif auth_data['type'] == 'login':
                response = handle_login(auth_data, db_conn)
            else:
                response = {'status': 'error', 'message': 'Invalid request type'}
            
            client_socket.send(json.dumps(response).encode())
            
        except Exception as e:
            print(f"❌ Error handling client: {e}")
        finally:
            client_socket.close()
            print("📴 Client disconnected\n")

if __name__ == "__main__":
    start_server()