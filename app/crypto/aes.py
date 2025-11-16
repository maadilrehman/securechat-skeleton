from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# ---
# WARNING: The assignment's skeleton README specifies ECB mode.
# ECB (Electronic Codebook) mode is NOT secure and should NEVER be
# used in a real application. It is deterministic and does not hide
# data patterns.
#
# We are implementing it here *only* because it is specified by the
# assignment's skeleton file structure. A secure application
# would use a mode like GCM or CBC with a random IV.
# ---

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using AES-128-ECB with PKCS#7 padding.
    
    Args:
        key: The 16-byte (128-bit) AES key.
        plaintext: The raw bytes to encrypt.
        
    Returns:
        The encrypted ciphertext as bytes.
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes (128 bits) for AES-128")

    # Create an AES-128 cipher in ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Apply PKCS#7 padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    # Encrypt the padded data
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext

def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts ciphertext using AES-128-ECB with PKCS#7 padding.
    
    Args:
        key: The 16-byte (128-bit) AES key.
        ciphertext: The encrypted bytes to decrypt.
        
    Returns:
        The original plaintext as bytes.
        
    Raises:
        ValueError: If the padding is invalid (indicating a bad key or corrupt data).
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes (128 bits) for AES-128")

    # Create an AES-128 cipher in ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    except ValueError:
        # This happens if the padding is incorrect (e.g., wrong key)
        raise ValueError("Decryption failed: Invalid padding.")
    
    return plaintext