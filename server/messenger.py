# server/messenger.py
import json, base64, time
from pathlib import Path
from crypto.aes_utils import aes_decrypt_cbc
from crypto.rsa_utils import load_public_key_from_cert, verify_bytes_rsa
import hashlib

TRANSCRIPTS_DIR = Path("transcripts")
TRANSCRIPTS_DIR.mkdir(exist_ok=True)

class ServerMessenger:
    def __init__(self, session_key: bytes, sender_cert_path: str, own_cert_fingerprint: str):
        self.K = session_key
        self.sender_pub = load_public_key_from_cert(sender_cert_path)
        self.last_seqno = 0
        self.transcript_file = TRANSCRIPTS_DIR / "server_transcript.txt"
        self.tf = open(self.transcript_file, "ab")
        self.own_fp = own_cert_fingerprint

    def process_received_json(self, payload_json: dict) -> str:
        # payload_json is parsed dict
        if payload_json.get("type") != "msg":
            raise ValueError("not a msg")
        seqno = int(payload_json["seqno"])
        ts = int(payload_json["ts"])
        ct_blob = base64.b64decode(payload_json["ct"])
        sig = base64.b64decode(payload_json["sig"])

        # check seqno
        if seqno <= self.last_seqno:
            raise ValueError("REPLAY or out-of-order")
        # verify signature
        h = hashlib.sha256()
        h.update(str(seqno).encode())
        h.update(str(ts).encode())
        h.update(ct_blob)
        digest = h.digest()
        ok = verify_bytes_rsa(self.sender_pub, sig, digest)
        if not ok:
            raise ValueError("SIG FAIL")

        # decrypt
        iv = ct_blob[:16]
        ct = ct_blob[16:]
        try:
            pt = aes_decrypt_cbc(self.K, iv, ct)
        except Exception as e:
            raise ValueError("DECRYPT/UNPAD FAIL: " + str(e))

        # update state and append to transcript (seqno|ts|ct|sig|peer-fingerprint)
        line = f"{seqno}|{ts}|{payload_json['ct']}|{payload_json['sig']}|{self.own_fp}\n".encode('utf-8')
        self.tf.write(line)
        self.tf.flush()
        self.last_seqno = seqno
        return pt.decode('utf-8')

    def close(self):
        self.tf.close()

if __name__ == "__main__":
    K_hex = input("paste session K hex: ").strip()
    K = bytes.fromhex(K_hex)
    sender_cert = input("path to sender cert (e.g., certs/client.cert.pem): ").strip()
    sm = ServerMessenger(K, sender_cert, own_cert_fingerprint="server-fp")
    print("Ready. Paste full JSON (single line) or 'quit'")
    while True:
        s = input("> ")
        if s.strip().lower() == "quit":
            sm.close()
            break
        try:
            payload = json.loads(s)
            pt = sm.process_received_json(payload)
            print("Decrypted message:", pt)
        except Exception as e:
            print("Error processing:", e)
