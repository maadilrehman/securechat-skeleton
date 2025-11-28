import hashlib
import base64
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import os
import sys

print("=" * 60)
print("SESSION RECEIPT VERIFIER")
print("=" * 60)

# Find receipt files
transcript_dir = 'transcripts'
receipt_files = [f for f in os.listdir(transcript_dir) if f.endswith('_receipt.json')]

if not receipt_files:
    print("❌ No receipt files found")
    print("Generate one first: python scripts\\generate_receipt.py")
    exit()

# Use latest receipt
receipt_file = sorted(receipt_files)[-1]
receipt_path = os.path.join(transcript_dir, receipt_file)
transcript_file = receipt_file.replace('_receipt.json', '.txt')
transcript_path = os.path.join(transcript_dir, transcript_file)

print(f"\n📄 Verifying receipt: {receipt_file}")
print(f"   Associated transcript: {transcript_file}\n")

# Load receipt
with open(receipt_path, 'r') as f:
    receipt = json.load(f)

print(f"Receipt details:")
print(f"  - Peer: {receipt['peer']}")
print(f"  - Messages: {receipt['first_seq']} to {receipt['last_seq']}")
print(f"  - Transcript hash: {receipt['transcript_sha256'][:16]}...")

# Recompute transcript hash
print("\n🔍 Step 1: Recomputing transcript hash...")
with open(transcript_path, 'r') as f:
    transcript_content = f.read().strip()

computed_hash = hashlib.sha256(transcript_content.encode()).hexdigest()
print(f"   Computed: {computed_hash[:16]}...")
print(f"   Receipt:  {receipt['transcript_sha256'][:16]}...")

if computed_hash != receipt['transcript_sha256']:
    print("\n❌ VERIFICATION FAILED: Transcript has been modified!")
    print("   The transcript hash doesn't match the receipt.")
    exit()

print("   ✅ Hash matches - transcript is intact")

# Verify signature
print("\n🔍 Step 2: Verifying RSA signature...")
with open('certs/client.pem', 'rb') as f:
    client_cert = x509.load_pem_x509_certificate(f.read())

signature = base64.b64decode(receipt['sig'])

try:
    client_cert.public_key().verify(
        signature,
        receipt['transcript_sha256'].encode(),
        asym_padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("   ✅ Signature valid - receipt is authentic")
except Exception as e:
    print(f"\n❌ SIGNATURE VERIFICATION FAILED: {e}")
    exit()

print("\n" + "=" * 60)
print("✅✅ VERIFICATION PASSED ✅✅")
print("=" * 60)
print("\nThis SessionReceipt proves:")
print("  1. The transcript has NOT been modified")
print("  2. The client cryptographically signed this conversation")
print("  3. Non-repudiation is achieved - client cannot deny these messages")
print("=" * 60)