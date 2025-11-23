import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

print("Generating CA private key and certificate...")

# 1. Generate a new RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# 2. Define the identity (subject) of our CA
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat Inc."),
    x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
])

# 3. Build the certificate
cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    # Set validity for 10 years
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).sign(private_key, hashes.SHA256())

# 4. Save the private key to a file (in PEM format)

print("Saving CA private key to 'certs/ca_key.pem'...")
with open("certs/ca_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# 5. Save the certificate to a file (in PEM format)

print("Saving CA certificate to 'certs/ca_cert.pem'...")
with open("certs/ca_cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("CA setup complete. You are now a Certificate Authority!")