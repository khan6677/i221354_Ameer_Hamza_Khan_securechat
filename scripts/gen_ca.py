"""Create Root CA (RSA + self-signed X.509) using cryptography."""

import argparse
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_ca(ca_name: str, output_dir: str = "certs"):
    """
    Generate a self-signed Root CA certificate and private key.
    
    Args:
        ca_name: Common Name for the CA (e.g., "FAST-NU Root CA")
        output_dir: Directory to save the CA certificate and key
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate RSA private key (2048 bits)
    print(f"Generating RSA 2048-bit key pair for CA...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
    ])
    
    # Build certificate
    print(f"Creating self-signed X.509 certificate...")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    # Save private key
    key_path = os.path.join(output_dir, "ca.key")
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print(f"✓ CA private key saved to: {key_path}")
    
    # Save certificate
    cert_path = os.path.join(output_dir, "ca.crt")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"✓ CA certificate saved to: {cert_path}")

    print(f"\n✅ Root CA '{ca_name}' created successfully!")


def main():
    parser = argparse.ArgumentParser(description="Generate Root CA certificate")
    parser.add_argument("--name", required=True, help="CA Common Name (e.g., 'FAST-NU Root CA')")
    parser.add_argument("--out", default="certs", help="Output directory (default: certs)")
    
    args = parser.parse_args()
    generate_ca(args.name, args.out)


if __name__ == "__main__":
    main()
