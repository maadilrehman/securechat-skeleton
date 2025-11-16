# app/crypto/dh.py
import secrets
from hashlib import sha256

def gen_dh_private(qbits=2048):
    # use a reasonably large private exponent
    return secrets.randbelow(2**256 - 1)  # small but OK for assignment use-case

def compute_public(g: int, a: int, p: int) -> int:
    return pow(g, a, p)

def compute_shared_secret(peer_pub: int, priv: int, p: int) -> int:
    return pow(peer_pub, priv, p)

def ks_to_aes128_key(ks_int: int) -> bytes:
    # big-endian bytes of Ks
    ks_bytes = ks_int.to_bytes((ks_int.bit_length() + 7) // 8 or 1, byteorder="big")
    h = sha256(ks_bytes).digest()
    return h[:16]  # truncate to 16 bytes
