# crypto/aes_utils.py
from Crypto.Cipher import AES
import os
import hashlib

BLOCK_SIZE = 16

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(padded: bytes) -> bytes:
    if len(padded) == 0 or len(padded) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padding length")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")
    return padded[:-pad_len]

def aes_encrypt_cbc(key: bytes, plaintext: bytes) -> dict:
    """
    Returns dict with iv and ciphertext as bytes.
    """
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(plaintext))
    return {"iv": iv, "ct": ct}

def aes_decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(pt_padded)
