import sys
import os  # Import 'os' at the top
import json

# --- THIS IS THE FIX ---
# Add the project's root directory to the Python path
# This MUST be done *before* we try to import from 'app'
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)
# --- END FIX ---

# Now these imports will work
from app.common import utils
from app.crypto import pki, sign
from cryptography.hazmat.primitives import hashes

def verify_receipt(transcript_path: str, receipt_path: str, cert_path: str):
    """
    Verifies a session receipt against its transcript log and the signer's certificate.
    [cite_start]Implements Section 3, Non-repudiation test [cite: 241-244].
    """
    print("--- Verifying Session ---")
    print(f"  Transcript: {transcript_path}")
    print(f"  Receipt:    {receipt_path}")
    print(f"  Signer Cert: {cert_path}")
    print("-------------------------")

    try:
        # 1. Load all files
        with open(transcript_path, "r") as f:
            transcript_content = f.read()
            
        with open(receipt_path, "r") as f:
            receipt_data = json.load(f)
            
        # We only need the public key from the cert
        cert, _ = pki.load_entity_creds(cert_path, None) # We don't need the private key
        public_key = cert.public_key()
        
        # 2. Re-compute the transcript hash
        computed_hash = utils.sha256_hex(transcript_content.encode('utf-8'))
        
        # 3. Get data from receipt
        receipt_hash = receipt_data['transcript_sha256']
        signature_b64 = receipt_data['sig']
        signature = utils.from_base64(signature_b64)
        
        # 4. Compare hashes
        if computed_hash != receipt_hash:
            print(f"!! HASH MISMATCH !!")
            print(f"  Computed Hash: {computed_hash}")
            print(f"  Receipt Hash:  {receipt_hash}")
            print("\n[ FAILURE ] Transcript has been tampered with.")
            return False
            
        print("[ SUCCESS ] Transcript hash matches receipt.")
        
        # 5. Verify the signature
        hash_bytes = bytes.fromhex(receipt_hash)
        
        if not sign.verify_signature(public_key, signature, hash_bytes):
            print(f"!! INVALID SIGNATURE !!")
            print("\n[ FAILURE ] Receipt signature is not valid.")
            return False
            
        print("[ SUCCESS ] Receipt signature is valid.")
        print("\n-------------------------")
        print("[ OVERALL SUCCESS ] The receipt is a valid cryptographic proof for this transcript.")
        return True

    except FileNotFoundError as e:
        # Fix for the 'fileName' vs 'filename' bug
        print(f"\n[ ERROR ] File not found: {e.filename}")
        print("Please check your file paths and re-run.")
        return False
    except Exception as e:
        print(f"\n[ ERROR ] An error occurred: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 verify.py <transcript_log_path> <receipt_json_path> <signer_cert_path>")
        print("\nExample (verifying client's receipt):")
        print("  python3 verify.py transcripts/client_session_...log transcripts/client_session_...RECEIPT.json certs/client_cert.pem")
        print("\nExample (verifying server's receipt):")
        print("  python3 verify.py transcripts/server_session_...log transcripts/server_session_...RECEIPT.json certs/server_cert.pem")
        sys.exit(1)
        
    verify_receipt(sys.argv[1], sys.argv[2], sys.argv[3])