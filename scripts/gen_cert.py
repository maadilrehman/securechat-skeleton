# scripts/gen_cert.py
import argparse
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import datetime

BASE = Path(__file__).resolve().parents[1]
OUT = BASE / "certs"
OUT.mkdir(parents=True, exist_ok=True)

CA_KEY = OUT / "ca.key.pem"
CA_CERT = OUT / "ca.cert.pem"

def load_ca():
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert

def create_cert(name: str, common_name: str = None):
    name = name.lower()
    key_file = OUT / f"{name}.key.pem"
    cert_file = OUT / f"{name}.cert.pem"

    # generate RSA key (2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"YourProvince"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"YourCity"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MySecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name or name),
    ])

    ca_key, ca_cert = load_ca()
    now = datetime.datetime.utcnow()

    cert_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - datetime.timedelta(minutes=1)
    ).not_valid_after(
        now + datetime.timedelta(days=365)  # 1 year validity
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            key_agreement=True,
            content_commitment=True,
            data_encipherment=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False
    )

    cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # write key and cert
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Created key: {key_file}")
    print(f"Created cert: {cert_file}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--name", required=True, help="short name for the cert (server/client)")
    p.add_argument("--cn", required=False, help="Common Name (CN)")
    args = p.parse_args()
    create_cert(args.name, args.cn)
