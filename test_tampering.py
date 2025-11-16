#!/usr/bin/env python3
"""
Test 3: SIG_FAIL - Tampering Detection Test
This script connects to the server and sends a tampered message
to test signature verification.
"""

import socket
import json
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.crypto import pki, aes, dh, sign
from app.common.utils import sha256_hex, b64e
from app.common.protocol import ClientHelloMessage, DHClientMessage
from dotenv import load_dotenv

load_dotenv()

def send_json(sock, data):
    """Send JSON message over socket."""
    message = json.dumps(data) + "\n"
    sock.sendall(message.encode('utf-8'))

def recv_json(sock):
    """Receive JSON message from socket."""
    buffer = b""
    while b"\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed")
        buffer += chunk
    
    line = buffer.split(b"\n")[0]
    return json.loads(line.decode('utf-8'))

def main():
    print("🧪 Test 3: SIG_FAIL - Tampering Detection Test")
    print("=" * 50)
    print()
    
    # Load certificates
    with open(os.getenv("CA_CERT_PATH"), 'rb') as f:
        ca_cert = pki.load_certificate(f.read())
    
    with open(os.getenv("CLIENT_CERT_PATH"), 'rb') as f:
        client_cert = pki.load_certificate(f.read())
        client_cert_pem = f.read()
    
    with open(os.getenv("CLIENT_KEY_PATH"), 'rb') as f:
        client_key = pki.load_private_key(f.read())
    
    # Connect to server
    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", 8000))
    
    print(f"📡 Connecting to {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print("✅ Connected")
    print()
    
    # Phase 1: Certificate Exchange
    print("Phase 1: Certificate Exchange")
    client_hello = ClientHelloMessage(
        cert_pem=client_cert_pem.decode('utf-8'),
        nonce=os.urandom(16).hex()
    )
    send_json(sock, client_hello.model_dump())
    
    server_hello = recv_json(sock)
    if server_hello.get('type') == 'error':
        print(f"❌ Error: {server_hello}")
        return
    
    print("✅ Certificate exchange complete")
    print()
    
    # Phase 2: DH Key Exchange (Temporary)
    print("Phase 2: Temporary DH Key Exchange")
    dh_params = dh.generate_dh_parameters()
    dh_private, dh_public = dh.generate_dh_keypair(dh_params)
    
    dh_client = DHClientMessage(
        p=dh_params['p'],
        g=dh_params['g'],
        public_key=dh_public
    )
    send_json(sock, dh_client.model_dump())
    
    dh_server_resp = recv_json(sock)
    print("✅ Temporary DH complete")
    print()
    
    # Skip authentication for this test - just send a tampered message
    print("🔨 Creating a tampered message...")
    print()
    
    # Create a valid message first
    plaintext = "This is a test message"
    key = os.urandom(16)  # Random key for this test
    ct = aes.aes_encrypt(plaintext.encode('utf-8'), key)
    ct_b64 = b64e(ct)

    # Compute valid signature (same as server/client)
    seqno = 1
    ts = 1234567890
    digest_data = f"{seqno}{ts}{ct_b64}".encode('utf-8')
    digest = sha256_hex(digest_data).encode('utf-8')
    sig = sign.sign(digest, client_key)
    sig_b64 = b64e(sig)
    
    # NOW TAMPER: Flip a bit in the base64 ciphertext
    ct_b64_bytes = bytearray(ct_b64.encode('utf-8'))
    ct_b64_bytes[0] ^= 0x01  # Flip the first bit
    ct_tampered_b64 = ct_b64_bytes.decode('utf-8', errors='ignore')

    print(f"Original ciphertext (base64, first 32 chars): {ct_b64[:32]}")
    print(f"Tampered ciphertext (base64, first 32 chars): {ct_tampered_b64[:32]}")
    print()

    # Send tampered message with original signature
    tampered_msg = {
        "type": "msg",
        "seqno": seqno,
        "ts": ts,
        "ct": ct_tampered_b64,
        "sig": sig_b64
    }
    
    print("📤 Sending tampered message to server...")
    send_json(sock, tampered_msg)
    
    # Wait for response
    response = recv_json(sock)
    print()
    print("📥 Server response:")
    print(json.dumps(response, indent=2))
    print()
    
    if response.get('type') == 'error' and response.get('error_code') == 'SIG_FAIL':
        print("✅ SUCCESS: Server detected tampering and rejected with SIG_FAIL!")
    else:
        print("❌ FAIL: Server did not detect tampering")
    
    sock.close()

if __name__ == "__main__":
    main()

