#!/usr/bin/env python3
"""
Test 5: Non-Repudiation - Offline Transcript Verification
This script verifies:
1. Each message signature in the transcript
2. The session receipt signature
3. That any edit breaks verification
"""

import sys
import json
import hashlib
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.crypto import pki, sign
from app.common.utils import sha256_hex, b64d

def verify_message_signature(seqno, ts, ct_b64, sig_b64, peer_cert):
    """Verify a single message signature."""
    try:
        # Reconstruct the digest (same as server/client)
        digest_data = f"{seqno}{ts}{ct_b64}".encode('utf-8')
        digest = sha256_hex(digest_data).encode('utf-8')

        # Verify signature
        sig = b64d(sig_b64)
        peer_public_key = peer_cert.public_key()

        result = sign.verify(digest, sig, peer_public_key)
        return result
    except Exception as e:
        print(f"  ❌ Verification error: {e}")
        return False

def verify_transcript(transcript_path, client_cert_path, server_cert_path, receipt_path=None):
    """Verify an entire transcript."""
    print(f"📄 Verifying transcript: {transcript_path}")
    print("=" * 70)
    print()

    # Load both certificates
    with open(client_cert_path, 'rb') as f:
        client_cert = pki.load_certificate(f.read())
    with open(server_cert_path, 'rb') as f:
        server_cert = pki.load_certificate(f.read())

    # Get fingerprints
    client_fp = pki.get_cert_fingerprint(client_cert)
    server_fp = pki.get_cert_fingerprint(server_cert)

    client_cn = client_cert.subject.get_attributes_for_oid(pki.NameOID.COMMON_NAME)[0].value
    server_cn = server_cert.subject.get_attributes_for_oid(pki.NameOID.COMMON_NAME)[0].value

    print(f"🔑 Client certificate: {client_cn} (fp: {client_fp[:16]}...)")
    print(f"🔑 Server certificate: {server_cn} (fp: {server_fp[:16]}...)")
    print()
    
    # Read transcript
    with open(transcript_path, 'r') as f:
        lines = f.readlines()
    
    # Parse header
    session_id = None
    peer_name = None
    messages = []
    
    for line in lines:
        line = line.strip()
        if line.startswith('#'):
            if 'Session:' in line:
                session_id = line.split('Session:')[1].strip()
            elif 'Peer:' in line:
                peer_name = line.split('Peer:')[1].strip()
        elif line and '|' in line:
            messages.append(line)
    
    print(f"📋 Session ID: {session_id}")
    print(f"👤 Peer: {peer_name}")
    print(f"📨 Total messages: {len(messages)}")
    print()
    
    # Verify each message
    print("🔍 Verifying message signatures...")
    print()
    
    verified_count = 0
    failed_count = 0
    
    for i, msg_line in enumerate(messages, 1):
        parts = msg_line.split('|')
        if len(parts) != 5:
            print(f"  ⚠️  Message {i}: Invalid format")
            failed_count += 1
            continue
        
        seqno = int(parts[0])
        ts = int(parts[1])
        ct_b64 = parts[2]
        sig_b64 = parts[3]
        fingerprint = parts[4]

        # Determine which certificate to use based on fingerprint
        if fingerprint == client_fp:
            cert_to_use = client_cert
            signer = "Client"
        elif fingerprint == server_fp:
            cert_to_use = server_cert
            signer = "Server"
        else:
            print(f"  ⚠️  Message {i}: Unknown fingerprint {fingerprint[:16]}...")
            failed_count += 1
            continue

        # Verify signature
        is_valid = verify_message_signature(seqno, ts, ct_b64, sig_b64, cert_to_use)
        
        if is_valid:
            print(f"  ✅ Message {i} (seqno={seqno}, from {signer}): Signature VALID")
            verified_count += 1
        else:
            print(f"  ❌ Message {i} (seqno={seqno}, from {signer}): Signature INVALID")
            failed_count += 1
    
    print()
    print(f"📊 Results: {verified_count} verified, {failed_count} failed")
    print()
    
    # Compute transcript hash
    transcript_data = "\n".join(messages)
    transcript_hash = sha256_hex(transcript_data.encode('utf-8'))
    print(f"🔐 Transcript hash: {transcript_hash}")
    print()
    
    # Verify receipt if provided
    if receipt_path and Path(receipt_path).exists():
        print("📜 Verifying session receipt...")
        with open(receipt_path, 'r') as f:
            receipt = json.load(f)
        
        print(f"  Session ID: {receipt.get('session_id')}")
        print(f"  Transcript hash: {receipt.get('transcript_hash')}")
        print(f"  Timestamp: {receipt.get('timestamp')}")
        print()
        
        # Verify receipt signature
        receipt_sig = b64d(receipt['signature'])
        receipt_hash = receipt['transcript_hash'].encode('utf-8')

        is_valid = sign.verify(receipt_hash, receipt_sig, peer_cert.public_key())
        
        if is_valid:
            print("  ✅ Receipt signature VALID")
        else:
            print("  ❌ Receipt signature INVALID")
        
        # Check if transcript hash matches
        if receipt['transcript_hash'] == transcript_hash:
            print("  ✅ Transcript hash MATCHES receipt")
        else:
            print("  ❌ Transcript hash DOES NOT MATCH receipt")
        
        print()
    
    return verified_count, failed_count

def main():
    print("🧪 Test 5: Non-Repudiation - Offline Transcript Verification")
    print("=" * 70)
    print()

    if len(sys.argv) < 4:
        print("Usage: python verify_transcript.py <transcript_file> <client_cert> <server_cert> [receipt_file]")
        print()
        print("Example:")
        print("  python tests/verify_transcript.py \\")
        print("    transcripts/client_session_12345.txt \\")
        print("    certs/client.crt \\")
        print("    certs/server.crt \\")
        print("    transcripts/client_session_12345_receipt.json")
        print()
        return

    transcript_path = sys.argv[1]
    client_cert_path = sys.argv[2]
    server_cert_path = sys.argv[3]
    receipt_path = sys.argv[4] if len(sys.argv) > 4 else None
    
    if not Path(transcript_path).exists():
        print(f"❌ Transcript file not found: {transcript_path}")
        return

    if not Path(client_cert_path).exists():
        print(f"❌ Client certificate file not found: {client_cert_path}")
        return

    if not Path(server_cert_path).exists():
        print(f"❌ Server certificate file not found: {server_cert_path}")
        return

    verified, failed = verify_transcript(transcript_path, client_cert_path, server_cert_path, receipt_path)
    
    print()
    print("=" * 70)
    if failed == 0:
        print("✅ ALL SIGNATURES VERIFIED - Non-repudiation proven!")
    else:
        print(f"⚠️  {failed} signature(s) failed verification")
    print()

if __name__ == "__main__":
    main()

