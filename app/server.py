import socket
import json
import os
import hashlib
import time
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh, padding as asym_padding
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

# Validate certificate
def validate_certificate(cert_pem, ca_cert):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        now = datetime.now()
        if cert.not_valid_before_utc.replace(tzinfo=None) > now or cert.not_valid_after_utc.replace(tzinfo=None) < now:
            print("❌ Certificate expired or not yet valid")
            return False, None
        print(f"✅ Client certificate validated: {cert.subject}")
        return True, cert
    except Exception as e:
        print(f"❌ Certificate validation failed: {e}")
        return False, None

# Diffie-Hellman key exchange
def perform_dh_server(client_socket):
    dh_msg = json.loads(client_socket.recv(4096).decode())
    p = dh_msg['p']
    g = dh_msg['g']
    A = dh_msg['A']
    
    params = dh.DHParameterNumbers(p, g).parameters(default_backend())
    server_private = params.generate_private_key()
    server_public = server_private.public_key().public_numbers().y
    
    client_socket.send(json.dumps({'type': 'dh_server', 'B': server_public}).encode())
    
    shared_secret = pow(A, server_private.private_numbers().x, p)
    key_hash = hashlib.sha256(shared_secret.to_bytes(256, 'big')).digest()
    aes_key = key_hash[:16]
    
    return aes_key

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

# AES encrypt
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

# Registration
def handle_registration(data, conn):
    cursor = conn.cursor()
    try:
        email = data['email']
        username = data['username']
        password = data['pwd']
        
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

# Login
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

# Verify message signature
def verify_signature(message_data, signature, client_cert):
    try:
        # Reconstruct the signed data
        signed_data = f"{message_data['seqno']}|{message_data['ts']}|{message_data['ct']}".encode()
        digest = hashlib.sha256(signed_data).digest()
        
        # Verify signature
        client_cert.public_key().verify(
            signature,
            digest,
            asym_padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"❌ Signature verification failed: {e}")
        return False

# Chat session
def handle_chat_session(client_socket, session_key, client_cert, server_key, username):
    print(f"\n💬 Chat session started with {username}")
    
    expected_seqno = 0
    transcript = []
    
    try:
        while True:
            # Receive encrypted message
            data = client_socket.recv(4096)
            if not data:
                break
            
            msg = json.loads(data.decode())
            
            if msg['type'] == 'msg':
                # Verify sequence number (replay protection)
                if msg['seqno'] != expected_seqno:
                    print(f"❌ REPLAY: Expected seqno {expected_seqno}, got {msg['seqno']}")
                    client_socket.send(json.dumps({'status': 'error', 'message': 'REPLAY'}).encode())
                    continue
                
                # Verify signature
                import base64
                signature = base64.b64decode(msg['sig'])
                if not verify_signature(msg, signature, client_cert):
                    print("❌ SIG_FAIL: Invalid signature")
                    client_socket.send(json.dumps({'status': 'error', 'message': 'SIG_FAIL'}).encode())
                    continue
                
                # Decrypt message
                ciphertext = base64.b64decode(msg['ct'])
                plaintext = aes_decrypt(ciphertext, session_key).decode()
                
                print(f"📨 [{username}]: {plaintext}")
                
                # Log to transcript
                transcript.append(f"{msg['seqno']}|{msg['ts']}|{msg['ct']}|{msg['sig']}")
                
                expected_seqno += 1
                
                # Echo back (server response)
                response_text = f"Server received: {plaintext}"
                response_ct = aes_encrypt(response_text, session_key)
                response_ct_b64 = base64.b64encode(response_ct).decode()
                
                # Sign response
                response_data = f"{expected_seqno}|{int(time.time() * 1000)}|{response_ct_b64}"
                response_digest = hashlib.sha256(response_data.encode()).digest()
                response_sig = server_key.sign(
                    response_digest,
                    asym_padding.PKCS1v15(),
                    hashes.SHA256()
                )
                
                response_msg = {
                    'type': 'msg',
                    'seqno': expected_seqno,
                    'ts': int(time.time() * 1000),
                    'ct': response_ct_b64,
                    'sig': base64.b64encode(response_sig).decode()
                }
                
                client_socket.send(json.dumps(response_msg).encode())
                expected_seqno += 1
                
            elif msg['type'] == 'end_chat':
                print("📴 Client ended chat session")
                break
                
    except Exception as e:
        print(f"❌ Chat error: {e}")
    
    # Save transcript
    if transcript:
        with open(f'transcripts/server_{username}_{int(time.time())}.txt', 'w') as f:
            f.write('\n'.join(transcript))
        print(f"✅ Transcript saved ({len(transcript)} messages)")
    
    print("💬 Chat session ended\n")

# Main server
def start_server():
    os.makedirs('transcripts', exist_ok=True)
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
            # Certificate exchange
            server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM).decode()
            client_socket.send(json.dumps({'type': 'server_hello', 'cert': server_cert_pem}).encode())
            
            client_hello = json.loads(client_socket.recv(4096).decode())
            valid, client_cert = validate_certificate(client_hello['cert'], ca_cert)
            if not valid:
                client_socket.send(json.dumps({'status': 'error', 'message': 'BAD_CERT'}).encode())
                client_socket.close()
                continue
            
            # DH for auth
            auth_key = perform_dh_server(client_socket)
            print("✅ Auth DH key exchange complete")
            
            # Receive encrypted auth request
            encrypted_msg = client_socket.recv(4096)
            decrypted_data = aes_decrypt(encrypted_msg, auth_key)
            auth_data = json.loads(decrypted_data.decode())
            
            # Handle auth
            if auth_data['type'] == 'register':
                response = handle_registration(auth_data, db_conn)
                client_socket.send(json.dumps(response).encode())
                client_socket.close()
            elif auth_data['type'] == 'login':
                response = handle_login(auth_data, db_conn)
                client_socket.send(json.dumps(response).encode())
                
                if response['status'] == 'success':
                    # Post-login DH for chat session
                    session_key = perform_dh_server(client_socket)
                    print("✅ Chat session DH key exchange complete")
                    
                    # Start chat session
                    handle_chat_session(client_socket, session_key, client_cert, server_key, response['username'])
                
                client_socket.close()
            
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            client_socket.close()

if __name__ == "__main__":
    start_server()