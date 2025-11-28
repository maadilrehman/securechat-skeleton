import hashlib
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import os
import json
import sys

print("=" * 60)
print("SESSION RECEIPT GENERATOR")
print("=" * 60)

# Find latest transcript
transcript_dir = 'transcripts'
if not os.path.exists(transcript_dir):
    print("❌ No transcripts folder found")
    exit()

files = [f for f in os.listdir(transcript_dir) if f.startswith('client_') and f.endswith('.txt')]
if not files:
    print("❌ No client transcript files found")
    print("Please run a chat session first: python app\\client.py")
    exit()

latest = sorted(files)[-1]
transcript_path = os.path.join(transcript_dir, latest)

print(f"\n📄 Processing transcript: {latest}")

# Read transcript
with open(transcript_path, 'r') as f:
    lines = f.readlines()

if not lines:
    print("❌ Transcript is empty")
    exit()

print(f"   Messages in transcript: {len(lines)}")

# Compute transcript hash
transcript_content = ''.join(lines).strip()
transcript_hash = hashlib.sha256(transcript_content.encode()).hexdigest()

print(f"\n🔐 Transcript SHA256: {transcript_hash}")

# Load client private key
with open('certs/client.key', 'rb') as f:
    client_key = serialization.load_pem_private_key(f.read(), password=None)

# Sign the transcript hash
signature = client_key.sign(
    transcript_hash.encode(),
    asym_padding.PKCS1v15(),
    hashes.SHA256()
)

print("✍️  Signing transcript hash with client private key...")

# Create receipt
receipt = {
    'type': 'receipt',
    'peer': 'client',
    'first_seq': 0,
    'last_seq': len(lines) - 1,
    'message_count': len(lines),
    'transcript_sha256': transcript_hash,
    'sig': base64.b64encode(signature).decode()
}

# Save receipt
receipt_path = transcript_path.replace('.txt', '_receipt.json')
with open(receipt_path, 'w') as f:
    json.dump(receipt, f, indent=2)

print(f"\n✅ SessionReceipt saved: {os.path.basename(receipt_path)}")
print("\nReceipt contents:")
print(json.dumps(receipt, indent=2))
print("\n" + "=" * 60)
print("✅ Non-repudiation evidence generated successfully!")
print("=" * 60)