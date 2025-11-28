import socket
import json
from cryptography import x509
from cryptography.hazmat.primitives import serialization

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9000

print("=" * 50)
print("TEST: Invalid Certificate (BAD_CERT)")
print("=" * 50)

# Load FAKE certificate
with open('certs/fake_client.pem', 'rb') as f:
    fake_cert = x509.load_pem_x509_certificate(f.read())

# Connect
print("Connecting to server...")
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))

# Receive server hello
server_hello = json.loads(client_socket.recv(4096).decode())
print("✅ Received server certificate")

# Send FAKE certificate (not signed by our CA)
fake_cert_pem = fake_cert.public_bytes(serialization.Encoding.PEM).decode()
client_socket.send(json.dumps({'type': 'client_hello', 'cert': fake_cert_pem}).encode())

print("📤 Sent FAKE certificate to server")
print("⏳ Waiting for server response...\n")

# Server should reject or close connection
try:
    response = client_socket.recv(4096)
    if response:
        data = json.loads(response.decode())
        print(f"📥 Server response: {data}")
        if 'BAD_CERT' in str(data) or data.get('status') == 'error':
            print("\n✅ TEST PASSED: Server rejected invalid certificate")
        else:
            print("\n❌ TEST FAILED: Server accepted invalid certificate")
    else:
        print("📴 Connection closed by server")
        print("\n✅ TEST PASSED: Server rejected connection")
except Exception as e:
    print(f"📴 Connection failed: {e}")
    print("\n✅ TEST PASSED: Server rejected invalid certificate")

client_socket.close()
print("=" * 50)