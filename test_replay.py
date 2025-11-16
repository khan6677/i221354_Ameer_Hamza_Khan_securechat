#!/usr/bin/env python3
"""
Test 4: REPLAY - Replay Attack Detection Test
This script captures a message and resends it to test replay protection.
"""

import socket
import json
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

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
    print("🧪 Test 4: REPLAY - Replay Attack Detection Test")
    print("=" * 50)
    print()
    print("📝 Instructions:")
    print("1. Start the server: python -m app.server")
    print("2. Start the client: python -m app.client")
    print("3. Login and send at least 2 messages")
    print("4. Use Wireshark or tcpdump to capture a message")
    print("5. Copy the JSON of the FIRST message")
    print("6. Paste it below when prompted")
    print()
    
    # Get captured message from user
    print("Paste the captured message JSON (one line):")
    captured_msg = input().strip()
    
    try:
        msg_data = json.loads(captured_msg)
    except json.JSONDecodeError:
        print("❌ Invalid JSON")
        return
    
    print()
    print("📦 Captured message:")
    print(json.dumps(msg_data, indent=2))
    print()
    
    # Connect to server
    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", 8000))
    
    print(f"📡 Connecting to {host}:{port}...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print("✅ Connected")
        print()
        
        print("📤 Resending captured message (replay attack)...")
        send_json(sock, msg_data)
        
        # Wait for response
        print("⏳ Waiting for server response...")
        response = recv_json(sock)
        print()
        print("📥 Server response:")
        print(json.dumps(response, indent=2))
        print()
        
        if response.get('type') == 'error' and response.get('error_code') == 'REPLAY':
            print("✅ SUCCESS: Server detected replay attack and rejected with REPLAY error!")
        else:
            print("❌ FAIL: Server did not detect replay attack")
        
        sock.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()

