# app/crypto/pki.py
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone
import binascii

class BadCertificate(Exception):
    pass

def load_cert_pem_bytes(pem_bytes: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_bytes)

def load_cert_from_file(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    fp = cert.fingerprint(hashes.SHA256())
    return binascii.hexlify(fp).decode()

def check_cert_validity(cert: x509.Certificate) -> None:
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    # ensure aware datetimes
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    if now < not_before:
        raise BadCertificate(f"Certificate not yet valid (not_before={not_before})")
    if now > not_after:
        raise BadCertificate(f"Certificate expired (not_after={not_after})")

def match_hostname_cn_or_san(cert: x509.Certificate, expected_hostname: str) -> bool:
    # try SAN DNS names first
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
        if expected_hostname in sans:
            return True
    except x509.ExtensionNotFound:
        pass
    # fallback to Common Name
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        cn = cn_attrs[0].value
        if cn == expected_hostname:
            return True
    return False

def verify_cert_signed_by(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    ca_pub = ca_cert.public_key()
    try:
        ca_pub.verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise BadCertificate(f"Signature verification failed: {e}")

def verify_certificate_chain(cert: x509.Certificate, ca_cert: x509.Certificate, expected_hostname: str = None) -> None:
    """
    High-level validation:
      - validity period
      - signature by CA
      - optional hostname/SAN/CN match
    Raises BadCertificate on failure.
    """
    check_cert_validity(cert)
    verify_cert_signed_by(cert, ca_cert)
    if expected_hostname:
        if not match_hostname_cn_or_san(cert, expected_hostname):
            raise BadCertificate(f"Hostname/CN mismatch: expected {expected_hostname}")
