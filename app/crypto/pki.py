import sys
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature

# --- Certificate Loading Functions ---

def load_ca_cert(path="certs/ca_cert.pem"):
    """Loads the CA's public certificate from a PEM file."""
    try:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
    except Exception as e:
        print(f"Error loading CA certificate: {e}")
        sys.exit(1)

def load_entity_creds(cert_path, key_path):
    """Loads an entity's (client/server) certificate and private key."""
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
            
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
            
        return cert, key
    except Exception as e:
        print(f"Error loading entity credentials ({cert_path}, {key_path}): {e}")
        sys.exit(1)

def serialize_cert(cert):
    """Converts a certificate object into a PEM string."""
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def deserialize_cert(cert_pem):
    """Converts a PEM string back into a certificate object."""
    return x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))

# --- Certificate Validation Function (Section 2.1) ---

def validate_certificate(cert_to_validate, ca_cert, expected_cn=None):
    """
    Validates a received certificate.
    
    This function performs all checks required by Section 2.1:
    1. Signature chain validity (is it signed by our CA?)
    2. Expiry date and validity period
    3. Common Name (CN) match (if provided)
    """
    
    # 1. Check Signature
    # We use the CA's public key to verify the certificate's signature.
    try:
        ca_cert.public_key().verify(
            cert_to_validate.signature,
            cert_to_validate.tbs_certificate_bytes,
            padding.PKCS1v15(), # Standard for X.509
            cert_to_validate.signature_hash_algorithm,
        )
        print("PKI: Certificate signature is valid.")
    except InvalidSignature:
        print("PKI: !! BAD_CERT (Invalid Signature) !!")
        return False
    except Exception as e:
        print(f"PKI: !! Error verifying signature: {e} !!")
        return False

    # 2. Check Expiry / Validity Period
    now = datetime.datetime.now(datetime.timezone.utc)
    if now < cert_to_validate.not_valid_before_utc:
        print("PKI: !! BAD_CERT (Certificate not yet valid) !!")
        return False
    if now > cert_to_validate.not_valid_after_utc:
        print("PKI: !! BAD_CERT (Certificate expired) !!")
        return False
    print("PKI: Certificate validity period is OK.")
        
    # 3. Check Common Name (CN)
    if expected_cn:
        # Extract CN from the certificate's subject
        cn_attributes = cert_to_validate.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )
        if not cn_attributes or cn_attributes[0].value != expected_cn:
            print(f"PKI: !! BAD_CERT (CN mismatch. Expected '{expected_cn}', got '{cn_attributes[0].value}') !!")
            return False
        print(f"PKI: Certificate CN ('{expected_cn}') is OK.")
    
    # If all checks pass
    print("PKI: Certificate validation successful.")
    return True