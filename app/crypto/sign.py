"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def sign(data: bytes, private_key) -> bytes:
    """
    Sign data using RSA PKCS#1 v1.5 with SHA-256.
    
    Args:
        data: Data to sign
        private_key: RSA private key object from cryptography library
        
    Returns:
        Signature bytes
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def verify(data: bytes, signature: bytes, public_key) -> bool:
    """
    Verify RSA PKCS#1 v1.5 signature with SHA-256.
    
    Args:
        data: Original data that was signed
        signature: Signature bytes to verify
        public_key: RSA public key object from cryptography library
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
