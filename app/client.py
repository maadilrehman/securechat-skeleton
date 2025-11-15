# app/client.py
import argparse, json, os, socket, hashlib
from pathlib import Path
from app.common.protocol import (
    T_HELLO, T_SRV_HELLO, T_DH_CLIENT, T_DH_SERVER, T_AUTH_BLOB, T_AUTH_OK, T_AUTH_ERR,
    T_MSG, T_CLOSE, send_json, recv_json
)
from app.common.utils import b64e, b64d, now_ms, signable_digest
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from app.crypto.dh import DEFAULT_PARAMS, make_keypair, derive_key
from app.crypto.pki import verify_cert_with_ca
from app.crypto.sign import rsa_sign_sha256, rsa_verify_sha256
from app.storage.transcript import Transcript

CERTS = Path("certs")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--register", action="store_true")
    ap.add_argument("--email", required=True)
    ap.add_argument("--username")
    ap.add_argument("--password", required=True)
    ap.add_argument("--server-cn", default="localhost")
    args = ap.parse_args()

    ca_pem = (CERTS/"root_ca_cert.pem").read_bytes()
    me_cert_pem = (CERTS/"client_cert.pem").read_bytes()
    me_key_pem  = (CERTS/"client_key.pem").read_bytes()

    s = socket.create_connection((args.host, args.port))

    # 1) hello -> server hello (+ verify server cert)
    nonce = os.urandom(16)
    send_json(s, {"type": T_HELLO, "client cert": me_cert_pem.decode(), "nonce": b64e(nonce)})
    sh = recv_json(s); assert sh["type"] == T_SRV_HELLO
    srv_cert_pem = sh["server cert"].encode()
    verify_cert_with_ca(srv_cert_pem, ca_pem, expected_cn=args.server_cn)

    # 2) temp DH -> AES for credentials
    a, A = make_keypair(DEFAULT_PARAMS)
    send_json(s, {"type": T_DH_CLIENT, "g": DEFAULT_PARAMS.g, "p": DEFAULT_PARAMS.p, "A": A})
    resp = recv_json(s); assert resp["type"] == T_DH_SERVER
    Ktmp = derive_key(DEFAULT_PARAMS, a, resp["B"])

    if args.register:
        payload = {"type": "register", "email": args.email, "username": args.username,
                   "pwd": b64e(args.password.encode())}
    else:
        payload = {"type": "login", "email": args.email, "pwd": b64e(args.password.encode())}

    ct = aes_encrypt_ecb(Ktmp, json.dumps(payload).encode())
    send_json(s, {"type": T_AUTH_BLOB, "ct": b64e(ct)})
    auth = recv_json(s)
    if auth.get("type") != T_AUTH_OK:
        raise SystemExit(f"Auth failed: {auth}")

    # 3) post-auth DH -> session key
    a2, A2 = make_keypair(DEFAULT_PARAMS)
    send_json(s, {"type": T_DH_CLIENT, "g": DEFAULT_PARAMS.g, "p": DEFAULT_PARAMS.p, "A": A2})
    resp2 = recv_json(s); assert resp2["type"] == T_DH_SERVER
    K = derive_key(DEFAULT_PARAMS, a2, resp2["B"])

    # 4) chat
    tr = Transcript("client")
    seq = 1
    peer_fp = hashlib.sha256(srv_cert_pem).hexdigest()
    print("Connected. Type messages; 'exit' to quit.")

    while True:
        line = input("> ")
        if line.strip().lower() in {"exit", "quit"}:
            break
        ts = now_ms()
        ct = aes_encrypt_ecb(K, line.encode())
        ct_b64 = b64e(ct)
        h = signable_digest(seq, ts, ct_b64)
        sig_b64 = b64e(rsa_sign_sha256(me_key_pem, h))
        msg = {"type": T_MSG, "seqno": seq, "ts": ts, "ct": ct_b64, "sig": sig_b64}
        send_json(s, msg)
        tr.append({**msg, "peer": peer_fp})
        seq += 1

        rx = recv_json(s)
        if rx["type"] == T_MSG:
            h2 = signable_digest(rx["seqno"], rx["ts"], rx["ct"])
            rsa_verify_sha256(srv_cert_pem, h2, b64d(rx["sig"]))
            pt = aes_decrypt_ecb(K, b64d(rx["ct"]))
            print("<", pt.decode())
            tr.append({**rx, "peer": peer_fp})
        else:
            print(rx)

    # 5) teardown (sign transcript; offline verify with script)
    sig = rsa_sign_sha256(me_key_pem, tr.fingerprint())
    tr.write_receipt("client", 1, seq - 1, sig)
    send_json(s, {"type": T_CLOSE})
    s.close()

if __name__ == "__main__":
    main()
