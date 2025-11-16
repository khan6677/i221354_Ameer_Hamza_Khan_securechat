"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import argparse
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def issue_certificate(cn: str, output_prefix: str, ca_cert_path: str = "certs/ca.crt", ca_key_path: str = "certs/ca.key"):
    """
    Issue a certificate signed by the Root CA.
    
    Args:
        cn: Common Name for the certificate (e.g., "server.local", "client.local")
        output_prefix: Output file prefix (e.g., "certs/server" -> server.key, server.crt)
        ca_cert_path: Path to CA certificate
        ca_key_path: Path to CA private key
    """
    # Load CA certificate and private key
    print(f"Loading CA certificate from {ca_cert_path}...")
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    print(f"Loading CA private key from {ca_key_path}...")
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # Generate RSA private key for the entity
    print(f"Generating RSA 2048-bit key pair for '{cn}'...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
    ])
    
    # Build certificate
    print(f"Creating X.509 certificate signed by CA...")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 1 year
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(cn),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )
    
    # Ensure output directory exists
    output_dir = os.path.dirname(output_prefix)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # Save private key
    key_path = f"{output_prefix}.key"
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print(f"✓ Private key saved to: {key_path}")
    
    # Save certificate
    cert_path = f"{output_prefix}.crt"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"✓ Certificate saved to: {cert_path}")

    print(f"\n✅ Certificate for '{cn}' issued successfully!")


def main():
    parser = argparse.ArgumentParser(description="Issue certificate signed by Root CA")
    parser.add_argument("--cn", required=True, help="Common Name (e.g., 'server.local', 'client.local')")
    parser.add_argument("--out", required=True, help="Output prefix (e.g., 'certs/server')")
    parser.add_argument("--ca-cert", default="certs/ca.crt", help="CA certificate path (default: certs/ca.crt)")
    parser.add_argument("--ca-key", default="certs/ca.key", help="CA private key path (default: certs/ca.key)")
    
    args = parser.parse_args()
    issue_certificate(args.cn, args.out, args.ca_cert, args.ca_key)


if __name__ == "__main__":
    main()
