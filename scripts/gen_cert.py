import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    NameOID,
    CertificateBuilder,
    random_serial_number,
)
from cryptography.x509.oid import NameOID
import datetime
from cryptography import x509

certs_path = os.path.join(os.path.dirname(__file__), "..", "certs")
os.makedirs(certs_path, exist_ok=True)

# Load Root CA
with open(os.path.join(certs_path, "rootCA.key"), "rb") as f:
    root_key = serialization.load_pem_private_key(f.read(), password=None)
with open(os.path.join(certs_path, "rootCA.pem"), "rb") as f:
    root_cert = x509.load_pem_x509_certificate(f.read())

def generate_cert(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    cert = CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(root_key, hashes.SHA256())
    
    # Save key
    with open(os.path.join(certs_path, f"{name}.key"), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Save cert
    with open(os.path.join(certs_path, f"{name}.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"{name} cert generated.")

# Generate Server & Client
generate_cert("server")
generate_cert("client")
