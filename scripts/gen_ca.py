from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID
import cryptography.x509 as x509
import datetime
import os

# create certs/ folder if not exists
os.makedirs("../certs", exist_ok=True)

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Save private key locally (do NOT commit)
with open("../certs/rootCA.key", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Generate self-signed certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
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
    datetime.datetime.utcnow()
).not_valid_after(
    # valid for 10 years
    datetime.datetime.utcnow() + datetime.timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).sign(private_key, hashes.SHA256())

# Save certificate
with open("../certs/rootCA.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("Root CA generated successfully in certs/")
