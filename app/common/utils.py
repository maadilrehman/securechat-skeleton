import base64
import os
import time
from cryptography.hazmat.primitives import hashes

def now_ms() -> int:
    """Returns the current time as a Unix timestamp in milliseconds."""
    return int(time.time() * 1000)

def sha256_hex(data: bytes) -> str:
    """Computes the SHA-256 hash of 'data' and returns it as a hex string."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()

def to_base64(data: bytes) -> str:
    """Encodes bytes into a URL-safe, padding-free base64 string."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def from_base64(s: str) -> bytes:
    """Decodes a URL-safe, padding-free base64 string back into bytes."""
    # Add padding back if necessary
    padding = b'=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode('utf-8') + padding)

def generate_nonce(length: int = 16) -> bytes:
    """Generates a cryptographically secure random nonce."""
    return os.urandom(length)