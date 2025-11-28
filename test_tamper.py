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

print("=" * 50)
print("TEST: Tamper Attack (SIG_FAIL)")
print("=" * 50)

# Load certs
with open('certs/client.pem', 'rb') as f:
    client_cert = x509.load_pem_x509_certificate(f.read())
with open('certs/client.key', 'rb') as f:
    client_key = serialization.load_pem_private_key(f.read(), password=None)

# Helper functions
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
    return key_hash[:16]

def aes_encrypt(plaintext, key):
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

# Connect
print("Connecting to server...")
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 9000))

# Cert exchange
server_hello = json.loads(client_socket.recv(4096).decode())
client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode()
client_socket.send(json.dumps({'type': 'client_hello', 'cert': client_cert_pem}).encode())

# Auth DH
auth_key = perform_dh_client(client_socket)

# Login
print("Logging in...")
login_data = {'type': 'login', 'email': 'test1@gmail.com', 'pwd': '123'}
encrypted_data = aes_encrypt(json.dumps(login_data), auth_key)
client_socket.send(encrypted_data)

response = json.loads(client_socket.recv(4096).decode())
print(f"✅ {response['message']}\n")

if response['status'] == 'success':
    # Chat session DH
    session_key = perform_dh_client(client_socket)
    
    # Create message
    message = "This is a test message"
    ct = aes_encrypt(message, session_key)
    ct_b64 = base64.b64encode(ct).decode()
    
    # Sign
    ts = int(time.time() * 1000)
    signed_data = f"0|{ts}|{ct_b64}".encode()
    digest = hashlib.sha256(signed_data).digest()
    signature = client_key.sign(digest, asym_padding.PKCS1v15(), hashes.SHA256())
    
    #⚠️ TAMPER: Flip a bit in ciphertext
    print("🔧 Tampering with ciphertext (flipping bits)...")
    ct_bytes = base64.b64decode(ct_b64)
    tampered_ct = bytearray(ct_bytes)
    tampered_ct[20] ^= 0xFF  # Flip all bits in byte 20
    tampered_ct_b64 = base64.b64encode(bytes(tampered_ct)).decode()
    
    msg = {
        'type': 'msg',
        'seqno': 0,
        'ts': ts,
        'ct': tampered_ct_b64,  # ← TAMPERED!
        'sig': base64.b64encode(signature).decode()
    }
    
    print("📤 Sending TAMPERED message to server...")
    client_socket.send(json.dumps(msg).encode())
    
    # Server should reject
    server_msg = json.loads(client_socket.recv(4096).decode())
    print(f"\n📥 Server response: {server_msg}\n")
    
    if server_msg.get('message') == 'SIG_FAIL':
        print("✅ TEST PASSED: Server detected tampered message (SIG_FAIL)")
    else:
        print("❌ TEST FAILED: Server accepted tampered message")

client_socket.close()
print("=" * 50)