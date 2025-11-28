import socket
import json
import os
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from datetime import datetime

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9000
CA_CERT_PATH = 'certs/rootCA.pem'
CLIENT_CERT_PATH = 'certs/client.pem'
CLIENT_KEY_PATH = 'certs/client.key'

# Load certificates
def load_certificates():
    with open(CA_CERT_PATH, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(CLIENT_CERT_PATH, 'rb') as f:
        client_cert = x509.load_pem_x509_certificate(f.read())
    with open(CLIENT_KEY_PATH, 'rb') as f:
        client_key = serialization.load_pem_private_key(f.read(), password=None)
    return ca_cert, client_cert, client_key

# Validate server certificate
def validate_certificate(cert_pem, ca_cert):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        
        # Check expiry
        now = datetime.utcnow()
        if cert.not_valid_before > now or cert.not_valid_after < now:
            print("❌ Server certificate expired or not yet valid")
            return False
        
        print(f"✅ Server certificate validated: {cert.subject}")
        return True
    except Exception as e:
        print(f"❌ Certificate validation failed: {e}")
        return False

# Diffie-Hellman key exchange
def perform_dh_client(client_socket):
    # Generate DH parameters (using standard 2048-bit prime)
    params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    p = params.parameter_numbers().p
    g = params.parameter_numbers().g
    
    # Generate client's DH key pair
    client_private = params.generate_private_key()
    client_public = client_private.public_key().public_numbers().y
    
    # Send DH params and client's public key
    dh_msg = {'type': 'dh_client', 'p': p, 'g': g, 'A': client_public}
    client_socket.send(json.dumps(dh_msg).encode())
    
    # Receive server's public key
    server_response = json.loads(client_socket.recv(4096).decode())
    B = server_response['B']
    
    # Compute shared secret
    shared_secret = pow(B, client_private.private_numbers().x, p)
    
    # Derive AES key
    key_hash = hashlib.sha256(shared_secret.to_bytes(256, 'big')).digest()
    aes_key = key_hash[:16]  # Truncate to 128 bits
    
    return aes_key

# AES encryption
def aes_encrypt(plaintext, key):
    # Generate random IV
    iv = os.urandom(16)
    
    # Apply PKCS7 padding
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + ciphertext  # Prepend IV to ciphertext

# Connect to server
def connect_to_server():
    ca_cert, client_cert, client_key = load_certificates()
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print(f"✅ Connected to server at {SERVER_HOST}:{SERVER_PORT}")
    
    # Step 1: Receive server certificate
    server_hello = json.loads(client_socket.recv(4096).decode())
    if not validate_certificate(server_hello['cert'], ca_cert):
        print("❌ Server certificate validation failed. Aborting.")
        client_socket.close()
        return None
    
    # Step 2: Send client certificate
    client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode()
    client_socket.send(json.dumps({'type': 'client_hello', 'cert': client_cert_pem}).encode())
    
    # Step 3: Perform Diffie-Hellman key exchange
    aes_key = perform_dh_client(client_socket)
    print("✅ DH key exchange complete. Secure channel established.")
    
    return client_socket, aes_key

# Register user
def register_user():
    client_socket, aes_key = connect_to_server()
    if not client_socket:
        return
    
    print("\n=== REGISTRATION ===")
    email = input("Email: ")
    username = input("Username: ")
    password = input("Password: ")
    
    # Prepare registration data
    reg_data = {
        'type': 'register',
        'email': email,
        'username': username,
        'pwd': password
    }
    
    # Encrypt and send
    encrypted_data = aes_encrypt(json.dumps(reg_data), aes_key)
    client_socket.send(encrypted_data)
    
    # Receive response
    response = json.loads(client_socket.recv(4096).decode())
    print(f"\n{response['message']}")
    
    client_socket.close()

# Login user
def login_user():
    client_socket, aes_key = connect_to_server()
    if not client_socket:
        return
    
    print("\n=== LOGIN ===")
    email = input("Email: ")
    password = input("Password: ")
    
    # Prepare login data
    login_data = {
        'type': 'login',
        'email': email,
        'pwd': password
    }
    
    # Encrypt and send
    encrypted_data = aes_encrypt(json.dumps(login_data), aes_key)
    client_socket.send(encrypted_data)
    
    # Receive response
    response = json.loads(client_socket.recv(4096).decode())
    print(f"\n{response['message']}")
    
    if response['status'] == 'success':
        print(f"Welcome, {response['username']}!")
    
    client_socket.close()

# Main menu
def main():
    print("=" * 50)
    print("SECURE CHAT - CLIENT")
    print("=" * 50)
    print("1. Register")
    print("2. Login")
    print("3. Exit")
    
    choice = input("\nChoose an option: ")
    
    if choice == '1':
        register_user()
    elif choice == '2':
        login_user()
    elif choice == '3':
        print("Goodbye!")
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()