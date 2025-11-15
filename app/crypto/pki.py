# app/crypto/pki.py
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

def verify_cert_with_ca(cert_pem: bytes, ca_pem: bytes, expected_cn: str | None):
    cert = x509.load_pem_x509_certificate(cert_pem)
    ca = x509.load_pem_x509_certificate(ca_pem)

    ca.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes,
        padding.PKCS1v15(), cert.signature_hash_algorithm
    )

    now = datetime.now(timezone.utc)
    if not (cert.not_valid_before <= now <= cert.not_valid_after):
        raise ValueError("BAD CERT: expired/not yet valid")

    if expected_cn is not None:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cn != expected_cn:
            raise ValueError(f"BAD CERT: CN mismatch ({cn} != {expected_cn})")

    return cert
