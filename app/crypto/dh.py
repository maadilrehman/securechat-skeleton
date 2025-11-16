from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# --- THIS IS THE FIX ---
# RFC 3526 - 2048-bit MODP Group (Group 14)
# We hardcode the standard 'p' and 'g' values so both
# client and server use the *exact same* parameters.

P_GROUP_14 = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
G_GROUP_14 = 2

# Create DHParameterNumbers object from these numbers
DH_NUMBERS = dh.DHParameterNumbers(P_GROUP_14, G_GROUP_14)

# Generate the parameters object. This is what both peers will use.
DH_PARAMS = DH_NUMBERS.parameters(default_backend())
# --- END FIX ---


def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derives a 16-byte (128-bit) AES key from the DH shared secret.
    """
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
        # All peers will now correctly use the same DH_PARAMS
        self.params = params
        self.private_key = self.params.generate_private_key()
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self) -> bytes:
        """Serializes the public key to send to the other peer."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Computes the shared secret given the other peer's public key.
        Returns the raw shared secret.
        """
        peer_public_key = serialization.load_der_public_key(
            peer_public_key_bytes
        )
        
        # This will now work, as both keys share the same parameters
        shared_secret = self.private_key.exchange(peer_public_key)
        return shared_secret