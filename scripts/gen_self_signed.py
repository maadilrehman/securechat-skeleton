import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

print("Generating 'bad' self-signed client certificate...")

# 1. Generate a new private key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# 2. Define the identity (subject)
# We'll use the correct CN "client"
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"client"),
])

# 3. Build and self-sign the certificate
cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer # It signs itself
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
).sign(private_key, hashes.SHA256()) # Signs with its own key

# 4. Save the bad key and cert
# We save them directly in the root folder to not mix them up
with open("bad_client_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("bad_client_cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("Created bad_client_key.pem and bad_client_cert.pem.")