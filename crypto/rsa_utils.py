# crypto/rsa_utils.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path
import base64

def load_private_key(path: str):
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)

def load_public_key_from_cert(cert_path: str):
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    return cert.public_key()

def sign_bytes_rsa(private_key, data: bytes) -> bytes:
    sig = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return sig

def verify_bytes_rsa(public_key, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
