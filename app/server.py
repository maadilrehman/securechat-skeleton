# app/server.py  (debug version)
import socket
import threading
import os
import base64
import json
import hmac
import hashlib
import traceback

from app.common import protocol as proto
from app.crypto import pki, dh as dhmod, aes as aesmod
from app.storage import db as store

CERTS_DIR = "certs"
CA_CERT_PATH = os.path.join(CERTS_DIR, "ca.cert.pem")
SERVER_CERT_PATH = os.path.join(CERTS_DIR, "server.local.cert.pem")

HOST = "127.0.0.1"
PORT = 9000


def constant_time_hex_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.lower(), b.lower())


def handle_client(conn, addr, ca_cert):
    print(f"[+] connection from {addr}")
    f = conn.makefile("rwb")

    try:
        # ------------------------------
        # 1) Receive hello
        # ------------------------------
        line = f.readline()
        if not line:
            print("[-] no hello received")
            return

        msg = proto.unpack_message(line)
        if msg.get("type") != "hello":
            print("[-] expected hello, got", msg)
            return

        client_pem = msg.get("client_cert")
        if not client_pem:
            print("[-] missing client_cert")
            return

        try:
            client_cert = pki.load_cert_pem_bytes(client_pem.encode())
            pki.verify_certificate_chain(client_cert, ca_cert, expected_hostname=None)
        except Exception as e:
            f.write(proto.pack_message({"type": "bad_cert", "reason": str(e)}))
            f.flush()
            print("[-] client cert verify fail:", e)
            return

        # ------------------------------
        # 2) Send server_hello
        # ------------------------------
        with open(SERVER_CERT_PATH, "rb") as sf:
            server_pem = sf.read().decode()

        server_nonce = base64.b64encode(os.urandom(16)).decode()
        sh = {
            "type": "server_hello",
            "server_cert": server_pem,
            "nonce": server_nonce
        }
        f.write(proto.pack_message(sh))
        f.flush()

        # ------------------------------
        # 3) DH exchange
        # ------------------------------
        line = f.readline()
        if not line:
            print("[-] no dh_client received")
            return

        dh_msg = proto.unpack_message(line)
        if dh_msg.get("type") != "dh_client":
            print("[-] expected dh_client, got", dh_msg)
            return

        p = int(dh_msg["p"])
        g = int(dh_msg["g"])
        A = int(dh_msg["A"])

        b = dhmod.gen_dh_private()
        B = dhmod.compute_public(g, b, p)

        f.write(proto.pack_message({"type": "dh_server", "B": str(B)}))
        f.flush()

        Ks = dhmod.compute_shared_secret(A, b, p)
        K = dhmod.ks_to_aes128_key(Ks)
        print("[*] session key derived (hex):", K.hex())

        f.write(proto.pack_message({"type": "handshake_complete"}))
        f.flush()

        # ------------------------------
        # Main encrypted message loop
        # ------------------------------
        last_seq = -1
        db_ok = False

        while True:
            line = f.readline()
            if not line:
                print("[*] client disconnected")
                break

            outer = proto.unpack_message(line)
            if outer.get("type") != "enc":
                f.write(proto.pack_message({"type": "err", "reason": "expected_enc"}))
                f.flush()
                continue

            seqno = int(outer.get("seqno", -1))
            if seqno <= last_seq:
                f.write(proto.pack_message({"type": "err", "code": "REPLAY"}))
                f.flush()
                print("[-] replay attack blocked:", seqno)
                continue

            last_seq = seqno

            # decrypt
            try:
                ct_bytes = aesmod.b64dec(outer["ct"])
                pt = aesmod.decrypt_ecb_pkcs7(K, ct_bytes)
                payload = json.loads(pt.decode())
            except Exception as e:
                print("[-] decrypt or JSON error:", e)
                traceback.print_exc()
                f.write(proto.pack_message({"type": "err", "code": "DECRYPT_FAIL"}))
                f.flush()
                continue

            # ------------------------------
            # DB connectivity test (first time only)
            # ------------------------------
            if not db_ok:
                print("[*] DB connectivity test...")
                try:
                    _ = store.get_user_by_email("__ping__")
                    db_ok = True
                    print("[*] DB OK")
                except Exception as e:
                    print("[-] DB connection failed:", e)
                    traceback.print_exc()
                    f.write(proto.pack_message({
                        "type": "err",
                        "code": "DB_CONN_FAIL",
                        "reason": str(e),
                    }))
                    f.flush()
                    continue

            print("[*] received payload:", payload)

            # ------------------------------
            # Handle REGISTER
            # ------------------------------
            if payload.get("type") == "register":
                email = payload.get("email")
                username = payload.get("username")
                password = payload.get("password")

                if not email or not username or not password:
                    f.write(proto.pack_message({
                        "type": "register_resp",
                        "ok": False,
                        "reason": "missing_fields"
                    }))
                    f.flush()
                    continue

                print(f"[*] register attempt email={email}, user={username}")

                try:
                    existing = store.get_user_by_email(email)
                    print("[*] DB returned existing:", existing)
                except Exception as e:
                    print("[-] DB error in get_user:", e)
                    traceback.print_exc()
                    f.write(proto.pack_message({"type": "register_resp", "ok": False, "reason": "db_error"}))
                    f.flush()
                    continue

                if existing:
                    f.write(proto.pack_message({"type": "register_resp", "ok": False, "reason": "email_exists"}))
                    f.flush()
                    continue

                salt = os.urandom(16)
                pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()

                try:
                    ok = store.insert_user(email, username, salt, pwd_hash)
                    print("[*] insert_user returned:", ok)
                except Exception as e:
                    print("[-] DB error in insert:", e)
                    traceback.print_exc()
                    f.write(proto.pack_message({"type": "register_resp", "ok": False, "reason": "db_error"}))
                    f.flush()
                    continue

                if ok:
                    f.write(proto.pack_message({"type": "register_resp", "ok": True}))
                    f.flush()
                    print("[+] registered:", username)
                else:
                    f.write(proto.pack_message({"type": "register_resp", "ok": False, "reason": "username_exists"}))
                    f.flush()

            # ------------------------------
            # Handle LOGIN
            # ------------------------------
            elif payload.get("type") == "login":
                email = payload.get("email")
                password = payload.get("password")

                if not email or not password:
                    f.write(proto.pack_message({"type": "login_resp", "ok": False, "reason": "missing_fields"}))
                    f.flush()
                    continue

                try:
                    user = store.get_user_by_email(email)
                except Exception as e:
                    print("[-] DB error in login:", e)
                    traceback.print_exc()
                    f.write(proto.pack_message({"type": "login_resp", "ok": False, "reason": "db_error"}))
                    f.flush()
                    continue

                if not user:
                    f.write(proto.pack_message({"type": "login_resp", "ok": False, "reason": "no_such_user"}))
                    f.flush()
                    continue

                salt = user["salt"]
                stored_hash = user["pwd_hash"]

                calc = hashlib.sha256(salt + password.encode()).hexdigest()

                if constant_time_hex_equals(calc, stored_hash):
                    f.write(proto.pack_message({
                        "type": "login_resp",
                        "ok": True,
                        "username": user["username"]
                    }))
                    f.flush()
                    print("[+] login ok:", user["username"])
                else:
                    f.write(proto.pack_message({"type": "login_resp", "ok": False, "reason": "bad_credentials"}))
                    f.flush()

            else:
                f.write(proto.pack_message({"type": "err", "code": "UNKNOWN_TYPE"}))
                f.flush()

    except Exception as e:
        print("[-] UNHANDLED EXCEPTION IN CLIENT HANDLER:", e)
        traceback.print_exc()

    finally:
        try:
            f.close()
        except:
            pass
        conn.close()
        print(f"[*] connection closed for {addr}")


def main():
    ca_cert = pki.load_cert_from_file(CA_CERT_PATH)
    fp = pki.cert_fingerprint_sha256(ca_cert)
    print("[*] loaded CA cert fingerprint:", fp)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)

    print(f"[+] server listening on {HOST}:{PORT}")

    while True:
        conn, addr = sock.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr, ca_cert), daemon=True)
        t.start()


if __name__ == "__main__":
    main()

