# client/messenger.py
import json, base64, time, os
from pathlib import Path
from crypto.aes_utils import aes_encrypt_cbc
from crypto.rsa_utils import load_private_key, sign_bytes_rsa
from crypto.dh_utils import derive_aes_key_from_ks  # you will supply K from session

TRANSCRIPTS_DIR = Path("transcripts")
TRANSCRIPTS_DIR.mkdir(exist_ok=True)

class ClientMessenger:
    def __init__(self, session_key: bytes, privkey_path: str, peer_cert_fingerprint: str):
        self.K = session_key  # 16 bytes
        self.priv = load_private_key(privkey_path)
        self.seqno = 0
        self.transcript_file = TRANSCRIPTS_DIR / "client_transcript.txt"
        # open file in append mode
        self.tf = open(self.transcript_file, "ab")

    def _make_msg(self, plaintext: str) -> dict:
        self.seqno += 1
        ts = int(time.time() * 1000)
        enc = aes_encrypt_cbc(self.K, plaintext.encode('utf-8'))
        iv = enc['iv']
        ct = enc['ct']
        ct_blob = iv + ct
        # compute digest
        import hashlib
        h = hashlib.sha256()
        h.update(str(self.seqno).encode())
        h.update(str(ts).encode())
        h.update(ct_blob)
        digest = h.digest()
        sig = sign_bytes_rsa(self.priv, digest)
        payload = {
            "type": "msg",
            "seqno": self.seqno,
            "ts": ts,
            "ct": base64.b64encode(ct_blob).decode(),
            "sig": base64.b64encode(sig).decode()
        }
        # append transcript line: seqno | ts | ct_base64 | sig_base64 | peer-fingerprint
        line = f"{self.seqno}|{ts}|{payload['ct']}|{payload['sig']}|{peer_cert_fingerprint}\n".encode('utf-8')
        self.tf.write(line)
        self.tf.flush()
        return payload

    def close(self):
        self.tf.close()

if __name__ == "__main__":
    # quick demo: supply K hex & your client key path & peer fingerprint
    K_hex = input("paste session K hex: ").strip()
    K = bytes.fromhex(K_hex)
    keypath = input("path to client private key (e.g., certs/client.key.pem): ").strip()
    peer_cert_fingerprint = input("peer certificate fingerprint (hex): ").strip() or "peer-fp"
    cm = ClientMessenger(K, keypath, peer_cert_fingerprint)
    while True:
        txt = input("message (enter to quit): ")
        if not txt:
            cm.close()
            break
        msg = cm._make_msg(txt)
        print("JSON to send:", json.dumps(msg))
