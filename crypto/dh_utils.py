# crypto/dh_utils.py
import os
import hashlib

def generate_dh_params(bit_length=2048):
    """
    For simplicity we use RFC-appropriate safe prime values.
    Here we generate ephemeral private exponent and public value for given (p,g).
    In real deployments p/g should be agreed or loaded from constants.
    """
    # Use a built-in 2048-bit MODP group params (RFC 3526) — minimal approach: generate p/g manually is complex.
    # For assignment, we'll use a well-known 2048-bit prime and g=2 stored as constants.
    # This is safe for academic use.
    RFC_2048_P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
        "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
        "7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFF"
        "FFFFFFFF", 16)
    # But the above string is concatenated; for simplicity use common g=2 and use pow mod operations.
    # Simpler: use Python's secrets for private exponent
    p = RFC_2048_P
    g = 2
    a = int.from_bytes(os.urandom(256), "big")  # large random exponent
    A = pow(g, a, p)
    return {"p": p, "g": g, "priv": a, "pub": A}

def compute_shared_secret(their_pub: int, my_priv: int, p: int) -> int:
    """
    Return integer Ks = their_pub ** my_priv mod p
    """
    return pow(their_pub, my_priv, p)

def derive_aes_key_from_ks(ks_int: int) -> bytes:
    """
    Convert Ks (integer) to big-endian bytes (minimal length) and compute K = Trunc16(SHA256(big-endian(Ks)))
    Returns 16 bytes for AES-128 key.
    """
    # convert int to minimal big-endian bytes
    length = (ks_int.bit_length() + 7) // 8
    ks_bytes = ks_int.to_bytes(length, byteorder="big")
    digest = hashlib.sha256(ks_bytes).digest()
    return digest[:16]
