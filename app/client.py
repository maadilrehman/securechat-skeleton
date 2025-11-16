# app/client.py
import socket
import os
import base64
import json
from app.common import protocol as proto
from app.crypto import pki, dh as dhmod, aes as aesmod

CERTS_DIR = "certs"
CA_CERT_PATH = os.path.join(CERTS_DIR, "ca.cert.pem")
CLIENT_CERT_PATH = os.path.join(CERTS_DIR, "client.local.cert.pem")

HOST = "127.0.0.1"
PORT = 9000

def do_handshake(f, ca_cert, client_pem):
    nonce = base64.b64encode(os.urandom(16)).decode()
    hello = {"type": "hello", "client_cert": client_pem, "nonce": nonce}
    f.write(proto.pack_message(hello)); f.flush()

    line = f.readline()
    resp = proto.unpack_message(line)
    if resp.get("type") == "bad_cert":
        raise Exception("server rejected client cert: " + str(resp.get("reason")))
    server_pem = resp.get("server_cert")
    server_cert = pki.load_cert_pem_bytes(server_pem.encode())
    pki.verify_certificate_chain(server_cert, ca_cert, expected_hostname="server.local")

    # DH
    p = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F
    g = 5
    a = dhmod.gen_dh_private()
    A = dhmod.compute_public(g, a, p)
    f.write(proto.pack_message({"type":"dh_client","p": str(p), "g": str(g), "A": str(A)})); f.flush()

    line = f.readline()
    dh_resp = proto.unpack_message(line)
    B = int(dh_resp["B"])
    Ks = dhmod.compute_shared_secret(B, a, p)
    K = dhmod.ks_to_aes128_key(Ks)
    # read handshake_complete
    f.readline()
    return K

def send_encrypted_and_receive(f, K: bytes, payload: dict, seqno: int):
    pt = json.dumps(payload, separators=(",", ":")).encode()
    ct = aesmod.encrypt_ecb_pkcs7(K, pt)
    outer = {"type":"enc", "seqno": seqno, "ct": aesmod.b64enc(ct)}
    f.write(proto.pack_message(outer)); f.flush()
    line = f.readline()
    if not line:
        return None
    return proto.unpack_message(line)

def main():
    ca_cert = pki.load_cert_from_file(CA_CERT_PATH)
    with open(CLIENT_CERT_PATH, "rb") as f:
        client_pem = f.read().decode()

    s = socket.create_connection((HOST, PORT))
    f = s.makefile("rwb")
    try:
        K = do_handshake(f, ca_cert, client_pem)
        print("[*] session key derived (hex):", K.hex())
        seqno = 1
        while True:
            print("\nChoose: 1) register  2) login  3) quit")
            c = input("Choice> ").strip()
            if c == "1":
                email = input("email> ").strip()
                username = input("username> ").strip()
                password = input("password> ").strip()
                payload = {"type":"register","email":email,"username":username,"password":password}
                resp = send_encrypted_and_receive(f, K, payload, seqno); seqno += 1
                print("server ->", resp)
            elif c == "2":
                email = input("email> ").strip()
                password = input("password> ").strip()
                payload = {"type":"login","email":email,"password":password}
                resp = send_encrypted_and_receive(f, K, payload, seqno); seqno += 1
                print("server ->", resp)
                if resp and resp.get("ok"):
                    print("[+] logged in as", resp.get("username"))
            elif c == "3":
                break
            else:
                print("invalid choice")
    finally:
        try:
            f.close()
        except:
            pass
        s.close()

if __name__ == "__main__":
    main()
