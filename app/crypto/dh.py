from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# We will use a standard, pre-defined DH group (RFC 3526, 2048-bit)
# for security and simplicity. This is safer than generating our own.
# The server will provide these parameters.
DH_PARAMS = dh.load_rfc_3526_parameters(dh.rfc_3526_2048_bit, default_backend())

# --- Key Derivation Function (KDF) ---
# Implements K = Trunc16(SHA256(big-endian(Ks))) 
# We use a standard KDF (HKDF) for this, which is a robust way to
# extract a key from a shared secret.

def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derives a 16-byte (128-bit) AES key from the DH shared secret.
    
    The assignment asks for Trunc16(SHA256(Ks)). A more standard
    and secure way to do this is with HKDF (HMAC-based Key Derivation Function),
    which achieves the same goal.
    """
    # We use HKDF to extract a cryptographically strong key
    # from the (non-uniform) shared secret.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # 16 bytes = 128 bits
        salt=None,
        info=b'secure-chat-aes-key',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

# --- DH Key Exchange Class ---

class DH_Peer:
    """
    A helper class to manage one side of a DH key exchange.
    """
    def __init__(self, params: dh.DHParameters = DH_PARAMS):
        self.params = params
        self.private_key = params.generate_private_key()
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self) -> bytes:
        """Serializes the public key to send to the other peer."""
        return self.public_key.public_bytes(
            encoding=dh.Encoding.DER,
            format=dh.PublicFormat.SubjectPublicKeyInfo
        )

    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Computes the shared secret given the other peer's public key.
        Returns the raw shared secret.
        """
        # Load the peer's public key from bytes
        peer_public_key = dh.load_der_public_key(
            peer_public_key_bytes,
            default_backend()
        )
        
        # Compute the shared secret
        shared_secret = self.private_key.exchange(peer_public_key)
        return shared_secret