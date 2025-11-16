"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID, ExtensionOID


def load_certificate(pem_data: bytes):
    """
    Load X.509 certificate from PEM bytes.
    
    Args:
        pem_data: PEM-encoded certificate bytes
        
    Returns:
        Certificate object
    """
    return x509.load_pem_x509_certificate(pem_data, default_backend())


def load_private_key(pem_data: bytes, password=None):
    """
    Load RSA private key from PEM bytes.
    
    Args:
        pem_data: PEM-encoded private key bytes
        password: Optional password for encrypted keys
        
    Returns:
        Private key object
    """
    return serialization.load_pem_private_key(
        pem_data,
        password=password,
        backend=default_backend()
    )


def validate_certificate(cert, ca_cert, expected_cn: str = None) -> bool:
    """
    Validate X.509 certificate.
    
    Checks:
    1. Certificate is signed by the CA
    2. Certificate is within validity period
    3. CN matches expected_cn (if provided)
    
    Args:
        cert: Certificate to validate
        ca_cert: CA certificate
        expected_cn: Expected Common Name (optional)
        
    Returns:
        True if valid, False otherwise
    """
    try:
        # 1. Verify CA signature
        ca_public_key = ca_cert.public_key()
        # For RSA signatures with PKCS1v15 padding
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes

        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Certificate validation error: {e}")
        return False
    
    # 2. Check validity period
    now = datetime.datetime.now(datetime.timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        return False
    
    # 3. Check CN if expected_cn is provided
    if expected_cn:
        # Try to get CN from subject
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attrs:
                cn = cn_attrs[0].value
                if cn == expected_cn:
                    return True
        except Exception:
            pass
        
        # Try to get from SAN (SubjectAlternativeName)
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
            if expected_cn in san_names:
                return True
        except x509.ExtensionNotFound:
            pass
        except Exception:
            pass
        
        # If expected_cn was provided but not matched
        return False
    
    return True


def get_public_key(cert):
    """
    Extract public key from certificate.
    
    Args:
        cert: Certificate object
        
    Returns:
        Public key object
    """
    return cert.public_key()


def cert_to_pem(cert) -> bytes:
    """
    Convert certificate to PEM bytes.
    
    Args:
        cert: Certificate object
        
    Returns:
        PEM-encoded certificate bytes
    """
    return cert.public_bytes(serialization.Encoding.PEM)


def get_cert_fingerprint(cert) -> str:
    """
    Get certificate fingerprint (SHA-256 hash).
    
    Args:
        cert: Certificate object
        
    Returns:
        Hex string of certificate fingerprint
    """
    fingerprint = cert.fingerprint(hashes.SHA256())
    return fingerprint.hex()
