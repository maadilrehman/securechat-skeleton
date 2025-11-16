from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.exceptions import InvalidSignature

def sign_data(private_key: RSAPrivateKey, data: bytes) -> bytes:
    """
    Signs arbitrary data (like a hash) using the given RSA private key.
    
    This implements RSA_SIGN(h) from the assignment[cite: 207].
    We use PKCS#1 v1.5 padding as it's the standard for this.
    """
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()  # Note: The assignment says sign(h), where h=SHA256(...)
                         # This function will sign the hash 'h' itself.
                         # When we call this, we must pass the *hash*, not the raw data.
    )

def verify_signature(public_key: RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """
    Verifies a signature against the original data (hash) using the public key.
    
    This implements the verification step[cite: 213].
    Returns True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256() # Same note as above.
        )
        # If verify() returns without an exception, the signature is valid.
        return True
    except InvalidSignature:
        # The signature was tampered with or signed by the wrong key.
        return False
    except Exception as e:
        # Other potential errors
        print(f"Error during signature verification: {e}")
        return False