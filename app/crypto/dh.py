"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend


def generate_params(key_size: int = 2048) -> tuple:
    """
    Generate DH parameters (p, g).
    
    Args:
        key_size: Size of the prime modulus in bits (default 2048)
        
    Returns:
        Tuple of (p, g) as integers
    """
    parameters = dh.generate_parameters(generator=2, key_size=key_size, backend=default_backend())
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    return (p, g)


def generate_private_key(p: int) -> int:
    """
    Generate a random private key.
    
    Args:
        p: Prime modulus
        
    Returns:
        Random private key as integer (1 < private_key < p-1)
    """
    # Generate random bytes and convert to integer in valid range
    byte_length = (p.bit_length() + 7) // 8
    while True:
        private_key = int.from_bytes(os.urandom(byte_length), byteorder='big')
        if 1 < private_key < p - 1:
            return private_key


def compute_public_key(private_key: int, p: int, g: int) -> int:
    """
    Compute public key: public = g^private mod p.
    
    Args:
        private_key: Private key
        p: Prime modulus
        g: Generator
        
    Returns:
        Public key as integer
    """
    return pow(g, private_key, p)


def compute_shared_secret(private_key: int, peer_public_key: int, p: int) -> int:
    """
    Compute shared secret: Ks = peer_public^private mod p.
    
    Args:
        private_key: Own private key
        peer_public_key: Peer's public key
        p: Prime modulus
        
    Returns:
        Shared secret as integer
    """
    return pow(peer_public_key, private_key, p)


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive 16-byte AES key from shared secret using Trunc16(SHA256(big_endian(Ks))).
    
    Args:
        shared_secret: Shared secret as integer
        
    Returns:
        16-byte AES key
    """
    # Convert shared secret to big-endian bytes
    byte_length = (shared_secret.bit_length() + 7) // 8
    ks_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    
    # Hash with SHA-256
    hash_digest = hashlib.sha256(ks_bytes).digest()
    
    # Take first 16 bytes for AES-128
    return hash_digest[:16]
