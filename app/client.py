import socket
import json
import os
import hashlib
import time
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh, padding as asym_padding
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

# Validate certificate
def validate_certificate(cert_pem, ca_cert):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        now = datetime.now()
        if cert.not_valid_before_utc.replace(tzinfo=None) > now or cert.not_valid_after_utc.replace(tzinfo=None) < now:
            print("❌ Server certificate expired")
            return False
        print(f"✅ Server certificate validated: {cert.subject}")
        return True
    except Exception as e:
        print(f"❌ Certificate validation failed: {e}")
        return False

# DH key exchange
def perform_dh_client(client_socket):
    params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    p = params.parameter_numbers().p
    g = params.parameter_numbers().g
    
    client_private = params.generate_private_key()
    client_public = client_private.public_key().public_numbers().y
    
    dh_msg = {'type': 'dh_client', 'p': p, 'g': g, 'A': client_public}
    client_socket.send(json.dumps(dh_msg).encode())
    
    server_response = json.loads(client_socket.recv(4096).decode())
    B = server_response['B']
    
    shared_secret = pow(B, client_private.private_numbers().x, p)
    key_hash = hashlib.sha256(shared_secret.to_bytes(256, 'big')).digest()
    aes_key = key_hash[:16]
    
    return aes_key

# AES encrypt
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

# AES decrypt
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Connect
def connect_to_server():
    ca_cert, client_cert, client_key = load_certificates()
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print(f"✅ Connected to server at {SERVER_HOST}:{SERVER_PORT}")
    
    server_hello = json.loads(client_socket.recv(4096).decode())
    if not validate_certificate(server_hello['cert'], ca_cert):
        print("❌ Server certificate validation failed. Aborting.")
        client_socket.close()
        return None, None, None
    
    client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode()
    client_socket.send(json.dumps({'type': 'client_hello', 'cert': client_cert_pem}).encode())
    
    auth_key = perform_dh_client(client_socket)
    print("✅ Auth DH key exchange complete")
    
    return client_socket, auth_key, (ca_cert, client_cert, client_key)

# Register
def register_user():
    client_socket, auth_key, certs = connect_to_server()
    if not client_socket:
        return
    
    print("\n=== REGISTRATION ===")
    email = input("Email: ")
    username = input("Username: ")
    password = input("Password: ")
    
    reg_data = {
        'type': 'register',
        'email': email,
        'username': username,
        'pwd': password
    }
    
    encrypted_data = aes_encrypt(json.dumps(reg_data), auth_key)
    client_socket.send(encrypted_data)
    
    response = json.loads(client_socket.recv(4096).decode())
    print(f"\n{response['message']}")
    
    client_socket.close()

# Login and chat
def login_and_chat():
    client_socket, auth_key, certs = connect_to_server()
    if not client_socket:
        return
    
    ca_cert, client_cert, client_key = certs
    
    print("\n=== LOGIN ===")
    email = input("Email: ")
    password = input("Password: ")
    
    login_data = {
        'type': 'login',
        'email': email,
        'pwd': password
    }
    
    encrypted_data = aes_encrypt(json.dumps(login_data), auth_key)
    client_socket.send(encrypted_data)
    
    response = json.loads(client_socket.recv(4096).decode())
    print(f"\n{response['message']}")
    
    if response['status'] != 'success':
        client_socket.close()
        return
    
    username = response['username']
    print(f"Welcome, {username}!")
    
    # Post-login DH for chat session
    session_key = perform_dh_client(client_socket)
    print("✅ Chat session key established\n")
    
    # Chat loop
    seqno = 0
    transcript = []
    
    print("=" * 50)
    print("CHAT SESSION (type 'exit' to end)")
    print("=" * 50)
    
    while True:
        message = input("You: ")
        
        if message.lower() == 'exit':
            client_socket.send(json.dumps({'type': 'end_chat'}).encode())
            break
        
        # Encrypt message
        ct = aes_encrypt(message, session_key)
        ct_b64 = base64.b64encode(ct).decode()
        
        # Sign message
        ts = int(time.time() * 1000)
        signed_data = f"{seqno}|{ts}|{ct_b64}".encode()
        digest = hashlib.sha256(signed_data).digest()
        signature = client_key.sign(
            digest,
            asym_padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        msg = {
            'type': 'msg',
            'seqno': seqno,
            'ts': ts,
            'ct': ct_b64,
            'sig': base64.b64encode(signature).decode()
        }
        
        client_socket.send(json.dumps(msg).encode())
        transcript.append(f"{seqno}|{ts}|{ct_b64}|{msg['sig']}")
        seqno += 1
        
        # Receive server response
        server_msg = json.loads(client_socket.recv(4096).decode())
        if server_msg.get('status') == 'error':
            print(f"❌ Error: {server_msg['message']}")
        else:
            # Decrypt server message
            server_ct = base64.b64decode(server_msg['ct'])
            server_plaintext = aes_decrypt(server_ct, session_key).decode()
            print(f"Server: {server_plaintext}\n")
            seqno += 1
    
    # Save transcript
    os.makedirs('transcripts', exist_ok=True)
    with open(f'transcripts/client_{username}_{int(time.time())}.txt', 'w') as f:
        f.write('\n'.join(transcript))
    print(f"\n✅ Transcript saved ({len(transcript)} messages)")
    
    client_socket.close()

# Main
def main():
    print("=" * 50)
    print("SECURE CHAT - CLIENT")
    print("=" * 50)
    print("1. Register")
    print("2. Login & Chat")
    print("3. Exit")
    
    choice = input("\nChoose an option: ")
    
    if choice == '1':
        register_user()
    elif choice == '2':
        login_and_chat()
    elif choice == '3':
        print("Goodbye!")
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()