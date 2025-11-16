# scripts/gen_ca.py
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "certs"
OUT.mkdir(parents=True, exist_ok=True)

# filenames
ca_key_file = OUT / "ca.key.pem"
ca_cert_file = OUT / "ca.cert.pem"

def create_root_ca():
    # generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    # subject and issuer same for root CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"YourProvince"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"YourCity"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MySecureChatCA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"MySecureChatRootCA"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=True,
            key_agreement=False,
            content_commitment=True,
            data_encipherment=False,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ), critical=True)
        .sign(key, hashes.SHA256())
    )

    # write private key (PEM) - keep file local, permission-limited
    with open(ca_key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # write cert
    with open(ca_cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Root CA key: {ca_key_file}")
    print(f"Root CA cert: {ca_cert_file}")

if __name__ == "__main__":
    create_root_ca()
