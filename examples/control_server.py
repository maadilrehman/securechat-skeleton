# examples/control_server.py
# ==== FIX IMPORTS WHEN RUN DIRECTLY ====
from pathlib import Path
import sys
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))
# ========================================

import json, base64, time
from crypto.dh_utils import generate_dh_params, derive_aes_key_from_ks, compute_shared_secret
from crypto.aes_utils import aes_encrypt_cbc , aes_encrypt_cbc , aes_decrypt_cbc
from pathlib import Path
# Load server cert
server_cert = Path("certs/server.cert.pem").read_text()

# For demo, suppose server received client's A and responded with B (we simulated in client)
# In a real run you would store p/g from client and compute B with your private b.

# Here we just mimic decryption part using the same K computed earlier by client
# For true test, run client script and copy printed K.hex() here to set K via hex
K_hex = input("paste derived AES key hex from client run: ").strip()
K = bytes.fromhex(K_hex)

# Now server receives the encrypted payload JSON (we will ask user to paste iv & ct)
iv_b64 = input("paste iv (base64) from client payload: ").strip()
ct_b64 = input("paste ct (base64) from client payload: ").strip()

iv = base64.b64decode(iv_b64)
ct = base64.b64decode(ct_b64)

pt = aes_decrypt_cbc(K, iv, ct)
print("Decrypted registration JSON:", pt.decode())
