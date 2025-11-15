# app/server.py
import argparse, json, socket, threading, hashlib, base64
from pathlib import Path
from app.common.protocol import (
    T_HELLO, T_SRV_HELLO, T_DH_CLIENT, T_DH_SERVER, T_AUTH_BLOB, T_AUTH_OK, T_AUTH_ERR,
    T_MSG, T_ERR, T_REPLAY, T_SIG_FAIL, T_DEC_FAIL, T_CLOSE,
    send_json, recv_json
)
from app.common.utils import b64e, b64d, now_ms, signable_digest
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from app.crypto.dh import DHParams, DEFAULT_PARAMS, make_keypair, derive_key
from app.crypto.pki import verify_cert_with_ca
from app.crypto.sign import rsa_sign_sha256, rsa_verify_sha256
from app.storage.db import create_user, auth_user
from app.storage.transcript import Transcript

CERTS = Path("certs")

def handle_client(conn: socket.socket, addr):
    try:
        ca_pem = (CERTS/"root_ca_cert.pem").read_bytes()
        srv_cert_pem = (CERTS/"server_cert.pem").read_bytes()
        srv_key_pem  = (CERTS/"server_key.pem").read_bytes()

        # 1) hello <-> server hello
        h = recv_json(conn); assert h["type"] == T_HELLO
        client_cert_pem = h["client cert"].encode()
        verify_cert_with_ca(client_cert_pem, ca_pem, expected_cn=None)
        send_json(conn, {"type": T_SRV_HELLO, "server cert": srv_cert_pem.decode(), "nonce": h["nonce"]})

        # 2) temp DH for credentials
        dc = recv_json(conn); assert dc["type"] == T_DH_CLIENT
        params = DHParams(p=dc["p"], g=dc["g"])
        b, B = make_keypair(params)
        send_json(conn, {"type": T_DH_SERVER, "B": B})
        Ktmp = derive_key(params, b, dc["A"])

        blob = recv_json(conn); assert blob["type"] == T_AUTH_BLOB
        auth = json.loads(aes_decrypt_ecb(Ktmp, b64d(blob["ct"])).decode())

        if auth["type"] == "register":
            ok = create_user(auth["email"], auth["username"], base64.b64decode(auth["pwd"]).decode())
            if not ok:
                send_json(conn, {"type": T_AUTH_ERR, "why": "exists"}); return
            send_json(conn, {"type": T_AUTH_OK, "mode": "register"})
        elif auth["type"] == "login":
            uname = auth_user(auth["email"], base64.b64decode(auth["pwd"]).decode())
            if not uname:
                send_json(conn, {"type": T_AUTH_ERR, "why": "bad credentials"}); return
            send_json(conn, {"type": T_AUTH_OK, "mode": "login", "username": uname})
        else:
            send_json(conn, {"type": T_AUTH_ERR, "why": "bad auth type"}); return

        # 3) post-auth DH -> session key
        dc2 = recv_json(conn); assert dc2["type"] == T_DH_CLIENT
        params2 = DHParams(p=dc2["p"], g=dc2["g"])
        b2, B2 = make_keypair(params2)
        send_json(conn, {"type": T_DH_SERVER, "B": B2})
        K = derive_key(params2, b2, dc2["A"])

        # 4) chat loop with replay defense
        tr = Transcript("server")
        peer_fp = hashlib.sha256(client_cert_pem).hexdigest()
        last_seq = 0

        while True:
            m = recv_json(conn)
            if m["type"] == T_CLOSE:
                break
            if m["type"] != T_MSG:
                send_json(conn, {"type": T_ERR, "why": "bad type"}); continue

            if not (m["seqno"] > last_seq):   # replay protection
                send_json(conn, {"type": T_REPLAY}); continue
            last_seq = m["seqno"]

            try:
                hdig = signable_digest(m["seqno"], m["ts"], m["ct"])
                rsa_verify_sha256(client_cert_pem, hdig, b64d(m["sig"]))
            except Exception:
                send_json(conn, {"type": T_SIG_FAIL}); continue

            try:
                pt = aes_decrypt_ecb(K, b64d(m["ct"]))
            except Exception:
                send_json(conn, {"type": T_DEC_FAIL}); continue

            tr.append({**m, "peer": peer_fp})

            # echo back (signed)
            ts = now_ms()
            ct2 = aes_encrypt_ecb(K, pt)
            ct2_b64 = b64e(ct2)
            h2 = signable_digest(m["seqno"], ts, ct2_b64)
            sig2 = b64e(rsa_sign_sha256(srv_key_pem, h2))
            send_json(conn, {"type": T_MSG, "seqno": m["seqno"], "ts": ts, "ct": ct2_b64, "sig": sig2})

        # 5) teardown: sign transcript
        sig = rsa_sign_sha256(srv_key_pem, tr.fingerprint())
        tr.write_receipt("server", 1, last_seq, sig)

    except Exception as e:
        try: send_json(conn, {"type": T_ERR, "why": str(e)})
        except Exception: pass
    finally:
        conn.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(5)
    print(f"listening on {args.host}:{args.port}")

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
