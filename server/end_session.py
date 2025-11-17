# server/end_session.py
import hashlib, base64, json
from pathlib import Path
from crypto.rsa_utils import load_private_key
TRANSCRIPTS_DIR = Path("transcripts")
transcript_file = TRANSCRIPTS_DIR / "server_transcript.txt"
receipt_file = TRANSCRIPTS_DIR / "server_receipt.json"

def compute_transcript_hash(path: Path) -> str:
    b = path.read_bytes()
    h = hashlib.sha256(b).hexdigest()
    return h

def sign_transcript(priv_key_path: str, transcript_hash_hex: str):
    priv = load_private_key(priv_key_path)
    # sign raw hex-bytes (or raw bytes of hash)
    sig = priv.sign(bytes.fromhex(transcript_hash_hex),
                    padding=__import__('cryptography.hazmat.primitives.asymmetric.padding',fromlist=['PKCS1v15']).PKCS1v15(),
                    algorithm=__import__('cryptography.hazmat.primitives.hashes',fromlist=['SHA256']).SHA256())
    return base64.b64encode(sig).decode()

if __name__ == "__main__":
    pk_path = input("path to server private key (certs/server.key.pem): ").strip()
    if not transcript_file.exists():
        print("No transcript file found at", transcript_file)
        raise SystemExit(1)
    th = compute_transcript_hash(transcript_file)
    sig_b64 = sign_transcript(pk_path, th)
    receipt = {
        "type": "receipt",
        "peer": "server",
        "first seq": None,   # could parse the transcript to determine
        "last seq": None,
        "transcript sha256": th,
        "sig": sig_b64
    }
    Path(receipt_file).write_text(json.dumps(receipt, indent=2))
    print("Saved receipt to", receipt_file)
