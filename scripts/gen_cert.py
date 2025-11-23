import datetime
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# --- This is a helper function to load the CA ---
def load_ca():
    """Loads the CA key and certificate from the 'certs/' directory."""
    try:
        with open("certs/ca_key.pem", "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        
        with open("certs/ca_cert.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
            
        return ca_key, ca_cert
    except FileNotFoundError:
        print("Error: CA key or certificate not found.")
        print("Please run 'python3 scripts/gen_ca.py' first.")
        sys.exit(1)
# -------------------------------------------------

def generate_entity_cert(entity_name):
    """
    Generates a new key pair and a signed certificate for an entity 
    (e.g., 'server' or 'client').
    """
    
    print(f"Loading SecureChat Root CA...")
    ca_key, ca_cert = load_ca()
    
    # 1. Generate a new RSA private key for the entity
    print(f"Generating new private key for '{entity_name}'...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Define the identity (subject) of the entity
    # We set the Common Name (CN) to the entity_name
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat Inc."),
        x509.NameAttribute(NameOID.COMMON_NAME, entity_name),
    ])

    # 3. Build the certificate
    # The issuer is the CA's subject
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject  # The issuer is the CA
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Set validity for 1 year
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        # Use SubjectAlternativeName to store the hostname, good for validation
        x509.SubjectAlternativeName([x509.DNSName(entity_name)]),
        critical=False,
    ).sign(ca_key, hashes.SHA256()) # Sign the certificate with the CA's private key

    # 4. Save the entity's private key
    key_path = f"certs/{entity_name}_key.pem"
    print(f"Saving entity private key to '{key_path}'...")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 5. Save the entity's signed certificate
    cert_path = f"certs/{entity_name}_cert.pem"
    print(f"Saving entity certificate to '{cert_path}'...")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Successfully generated key and certificate for '{entity_name}'.")

# --- Main execution ---
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/gen_cert.py <entity_name>")
        print("Example: python3 scripts/gen_cert.py server")
        print("Example: python3 scripts/gen_cert.py client")
        sys.exit(1)
        
    entity_name = sys.argv[1].lower()
    
    if entity_name not in ['server', 'client']:
        print(f"Error: Invalid entity name '{entity_name}'. Must be 'server' or 'client'.")
        sys.exit(1)
        
    generate_entity_cert(entity_name)