# tools/verify_receipt.py
import sys, json, hashlib, base64
from crypto.rsa_utils import load_public_key_from_cert

def verify_receipt(transcript_path, receipt_path, signer_cert_path):
    with open(transcript_path, "rb") as f:
        b = f.read()
    th = hashlib.sha256(b).hexdigest()
    rec = json.load(open(receipt_path))
    if rec["transcript sha256"] != th:
        print("Transcript hash mismatch")
        return
    sig = base64.b64decode(rec["sig"])
    pub = load_public_key_from_cert(signer_cert_path)
    # verify signature over raw hex bytes
    ok = pub.verify(
        sig,
        bytes.fromhex(th),
        __import__('cryptography.hazmat.primitives.asymmetric.padding',fromlist=['PKCS1v15']).PKCS1v15(),
        __import__('cryptography.hazmat.primitives.hashes',fromlist=['SHA256']).SHA256()
    )
    print("Receipt signature verified (no exception means OK)")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: verify_receipt.py transcript.txt receipt.json signer_cert.pem")
        raise SystemExit(1)
    verify_receipt(sys.argv[1], sys.argv[2], sys.argv[3])
