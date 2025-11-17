# server/auth_utils.py
import os
import hashlib
import hmac

def gen_salt(n=16):
    return os.urandom(n)

def hash_pwd(salt: bytes, password: str) -> str:
    # returns hex string of SHA256(salt || password)
    if isinstance(password, str):
        password = password.encode('utf-8')
    h = hashlib.sha256()
    h.update(salt)
    h.update(password)
    return h.hexdigest()

def constant_time_compare(a: str, b: str) -> bool:
    # use hmac.compare_digest to avoid timing attacks
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    return hmac.compare_digest(a, b)
