# examples/control_client.py
# ==== FIX IMPORTS WHEN RUN DIRECTLY ====
from pathlib import Path
import sys
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))
# ========================================

import json, base64, time
from crypto.dh_utils import generate_dh_params, derive_aes_key_from_ks, compute_shared_secret
from crypto.aes_utils import aes_encrypt_cbc
from pathlib import Path
# ... rest of your code unchanged
# Load cert (we assume you will send cert PEM as string)
client_cert = Path("certs/client.cert.pem").read_text()
# 1) Create hello with client cert and nonce
nonce = base64.b64encode(b"client-nonce-" + str(int(time.time()*1000)).encode()).decode()
hello = {"type":"hello", "client cert": client_cert, "nonce": nonce}
print("Client hello prepared (cert length):", len(client_cert))

# 2) Do ephemeral DH: generate params and send p,g,A to server (we just simulate locally)
dh = generate_dh_params()
p, g, a, A = dh["p"], dh["g"], dh["priv"], dh["pub"]
# Client would send p,g,A (we simulate server response by computing server side below)

# For demo, we simulate server generating B
from crypto.dh_utils import generate_dh_params as server_gen
srv = server_gen()
B = srv["pub"]
# compute shared secret on client
Ks = compute_shared_secret(B, a, p)
K = derive_aes_key_from_ks(Ks)  # 16-byte AES key
print("Derived AES key (hex):", K.hex())

# 3) Prepare registration JSON (client side) — should be encrypted under K
reg = {"type":"register", "email":"msalmansaleem08@gmail.com", "username":"salmansaleem08",
       "pwd": "PLACEHOLDER_PLAINTEXT_PASSWORD", "salt": None}
pt = json.dumps(reg).encode('utf-8')

enc = aes_encrypt_cbc(K, pt)
payload = {
    "type": "encrypted", 
    "iv": base64.b64encode(enc['iv']).decode(),
    "ct": base64.b64encode(enc['ct']).decode()
}
print("Encrypted payload ready:", payload)
# In real client, send payload to server
