from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID
import cryptography.x509 as x509
import datetime
import os

os.makedirs("../certs", exist_ok=True)

# Generate self-signed (untrusted) certificate
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"FAKE CLIENT"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now()
).not_valid_after(
    datetime.datetime.now() + datetime.timedelta(days=1)
).sign(private_key, hashes.SHA256())

# Save fake cert
with open("../certs/fake_client.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

with open("../certs/fake_client.key", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

print("✅ Fake certificate created at certs/fake_client.pem")