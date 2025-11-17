# tools/verify_message.py
import sys, base64, hashlib, json
from crypto.rsa_utils import load_public_key_from_cert, verify_bytes_rsa
from crypto.aes_utils import aes_decrypt_cbc

def verify_line(line: str, sender_cert_path: str, session_key_hex: str):
    parts = line.strip().split("|")
    if len(parts) < 5:
        print("bad line format")
        return
    seqno, ts, ct_b64, sig_b64, peer_fp = parts[:5]
    ct_blob = base64.b64decode(ct_b64)
    sig = base64.b64decode(sig_b64)
    h = hashlib.sha256()
    h.update(seqno.encode()); h.update(ts.encode()); h.update(ct_blob)
    digest = h.digest()
    pub = load_public_key_from_cert(sender_cert_path)
    if not verify_bytes_rsa(pub, sig, digest):
        print("SIG FAIL")
        return
    K = bytes.fromhex(session_key_hex)
    iv = ct_blob[:16]; ct = ct_blob[16:]
    try:
        pt = aes_decrypt_cbc(K, iv, ct)
    except Exception as e:
        print("DECRYPT FAIL", e); return
    print("OK: seqno", seqno, "ts", ts, "plaintext:", pt.decode())

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: verify_message.py line_file sender_cert.pem session_key_hex")
        raise SystemExit(1)
    line = open(sys.argv[1]).read().strip()
    verify_line(line, sys.argv[2], sys.argv[3])
