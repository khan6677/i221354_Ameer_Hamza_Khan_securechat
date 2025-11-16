#!/usr/bin/env python3
"""
Test 3: SIG_FAIL - Tampering Detection Test (Simplified)
This demonstrates how tampering is detected without full protocol.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.crypto import sign
from app.common.utils import sha256_hex, b64e, b64d
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def main():
    print("🧪 Test 3: SIG_FAIL - Tampering Detection Test")
    print("=" * 50)
    print()
    
    # Generate a test key pair
    print("🔑 Generating test RSA key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    print("✅ Key pair generated")
    print()
    
    # Create a message
    seqno = 1
    ts = 1234567890
    ct_b64 = "SGVsbG8sIHRoaXMgaXMgYSB0ZXN0IG1lc3NhZ2U="  # Base64 encoded ciphertext
    
    print(f"📦 Original message:")
    print(f"   seqno: {seqno}")
    print(f"   ts: {ts}")
    print(f"   ct: {ct_b64}")
    print()
    
    # Compute digest and sign (same as server/client)
    print("🔐 Computing digest and signature...")
    digest_data = f"{seqno}{ts}{ct_b64}".encode('utf-8')
    digest = sha256_hex(digest_data).encode('utf-8')
    sig = sign.sign(digest, private_key)
    sig_b64 = b64e(sig)
    
    print(f"   Digest: {digest.decode('utf-8')[:64]}...")
    print(f"   Signature: {sig_b64[:64]}...")
    print()
    
    # Verify original signature
    print("✅ Verifying original signature...")
    is_valid = sign.verify(digest, sig, public_key)
    print(f"   Result: {'VALID ✅' if is_valid else 'INVALID ❌'}")
    print()
    
    # NOW TAMPER: Change one character in ciphertext
    print("🔨 TAMPERING: Changing one character in ciphertext...")
    ct_tampered = ct_b64[:-1] + ('A' if ct_b64[-1] != 'A' else 'B')
    print(f"   Original ct: {ct_b64}")
    print(f"   Tampered ct: {ct_tampered}")
    print()
    
    # Try to verify with tampered ciphertext
    print("🔍 Verifying signature with tampered ciphertext...")
    digest_tampered_data = f"{seqno}{ts}{ct_tampered}".encode('utf-8')
    digest_tampered = sha256_hex(digest_tampered_data).encode('utf-8')
    
    print(f"   Original digest: {digest.decode('utf-8')[:64]}...")
    print(f"   Tampered digest: {digest_tampered.decode('utf-8')[:64]}...")
    print()
    
    # Verify with original signature but tampered data
    is_valid_tampered = sign.verify(digest_tampered, sig, public_key)
    print(f"   Result: {'VALID ✅' if is_valid_tampered else 'INVALID ❌'}")
    print()
    
    # Summary
    print("=" * 50)
    if not is_valid_tampered and is_valid:
        print("✅ SUCCESS: Tampering detected!")
        print("   - Original message signature: VALID")
        print("   - Tampered message signature: INVALID")
        print()
        print("This proves INTEGRITY protection:")
        print("Any modification to the ciphertext changes the digest,")
        print("causing signature verification to fail (SIG_FAIL).")
    else:
        print("❌ FAIL: Tampering not detected")
    print()

if __name__ == "__main__":
    main()

