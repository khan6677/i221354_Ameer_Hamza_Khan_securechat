"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import threading
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.common.protocol import (
    HelloMessage, ServerHelloMessage, RegisterMessage, LoginMessage,
    DHClientMessage, DHServerMessage, ChatMessage, SessionReceipt,
    ErrorMessage, OkMessage
)
from app.crypto import aes, dh, pki, sign
from app.storage.transcript import Transcript, create_receipt

# Load environment variables
load_dotenv()

console = Console()


class SecureChatClient:
    """Secure chat client with PKI and application-layer crypto."""
    
    def __init__(self, server_host: str = "localhost", server_port: int = 5000):
        self.server_host = server_host
        self.server_port = server_port
        self.ca_cert = None
        self.client_cert = None
        self.client_private_key = None
        self.sock = None
        self.session_key = None
        self.seqno = 0
        self.transcript = None
        self.server_cert = None
        self.server_public_key = None
        self.last_recv_seqno = -1
        
        # Load certificates
        self._load_certificates()
    
    def _load_certificates(self):
        """Load CA and client certificates."""
        ca_cert_path = os.getenv("CA_CERT_PATH", "certs/ca.crt")
        client_cert_path = os.getenv("CLIENT_CERT_PATH", "certs/client.crt")
        client_key_path = os.getenv("CLIENT_KEY_PATH", "certs/client.key")
        
        with open(ca_cert_path, "rb") as f:
            self.ca_cert = pki.load_certificate(f.read())
        
        with open(client_cert_path, "rb") as f:
            self.client_cert = pki.load_certificate(f.read())
        
        with open(client_key_path, "rb") as f:
            self.client_private_key = pki.load_private_key(f.read())
        
        console.print("[green]✓[/green] Certificates loaded successfully")
    
    def _send_json(self, data):
        """Send JSON message over socket."""
        message = json.dumps(data) + "\n"
        self.sock.sendall(message.encode('utf-8'))

    def _recv_json(self):
        """Receive JSON message from socket."""
        buffer = b""
        while b"\n" not in buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            buffer += chunk
        
        message = buffer.decode('utf-8').strip()
        return json.loads(message)
    
    def connect(self):
        """Connect to the server and perform handshake."""
        console.print(f"[cyan]Connecting to {self.server_host}:{self.server_port}...[/cyan]")
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_host, self.server_port))
        
        console.print("[green]✓[/green] Connected to server")
        
        # 1. Certificate exchange
        console.print("[yellow]Phase 1: Certificate Exchange[/yellow]")
        
        # Send client hello
        hello = HelloMessage(
            cert_pem=pki.cert_to_pem(self.client_cert).decode('utf-8'),
            nonce=b64e(os.urandom(16))
        )
        self._send_json(hello.model_dump())
        
        # Receive server hello
        server_hello_data = self._recv_json()
        server_hello = ServerHelloMessage(**server_hello_data)
        
        # Load and validate server certificate
        self.server_cert = pki.load_certificate(server_hello.cert_pem.encode('utf-8'))
        if not pki.validate_certificate(self.server_cert, self.ca_cert):
            console.print("[red]✗ BAD_CERT: Server certificate validation failed[/red]")
            raise Exception("Server certificate validation failed")
        
        self.server_public_key = pki.get_public_key(self.server_cert)
        console.print("[green]✓[/green] Server certificate validated")
        
        # 2. Temporary DH for credential encryption
        console.print("[yellow]Phase 2: Temporary DH (for credentials)[/yellow]")
        
        # Generate DH parameters
        p, g = dh.generate_params(2048)
        a = dh.generate_private_key(p)
        A = dh.compute_public_key(a, p, g)
        
        # Send client DH
        dh_client = DHClientMessage(p=str(p), g=str(g), A=str(A))
        self._send_json(dh_client.model_dump())
        
        # Receive server DH
        dh_server_data = self._recv_json()
        dh_server = DHServerMessage(**dh_server_data)
        B = int(dh_server.B)
        
        # Derive temporary AES key
        Ks_temp = dh.compute_shared_secret(a, B, p)
        temp_key = dh.derive_aes_key(Ks_temp)
        console.print("[green]✓[/green] Temporary session key established")
        
        # 3. Registration or Login
        console.print("[yellow]Phase 3: Authentication[/yellow]")
        
        auth_choice = Prompt.ask("Choose action", choices=["register", "login"], default="login")
        
        if auth_choice == "register":
            email = Prompt.ask("Email")
            username = Prompt.ask("Username")
            password = Prompt.ask("Password", password=True)
            
            auth_msg = RegisterMessage(email=email, username=username, password=password)
        else:
            email = Prompt.ask("Email")
            password = Prompt.ask("Password", password=True)
            
            auth_msg = LoginMessage(email=email, password=password)
        
        # Encrypt and send
        auth_json = auth_msg.json().encode('utf-8')
        auth_ct = aes.encrypt(auth_json, temp_key)
        self._send_json({"ct": b64e(auth_ct)})
        
        # Receive response
        response_data = self._recv_json()
        response_ct = b64d(response_data["ct"])
        response_plaintext = aes.decrypt(response_ct, temp_key)
        response = json.loads(response_plaintext.decode('utf-8'))
        
        if response["type"] == "error":
            console.print(f"[red]✗ {response['error_code']}: {response['message']}[/red]")
            raise Exception("Authentication failed")
        
        console.print(f"[green]✓[/green] {response.get('message', 'Authentication successful')}")
        
        # 4. Session DH for chat encryption
        console.print("[yellow]Phase 4: Session DH (for chat)[/yellow]")
        
        # Generate new DH parameters
        p, g = dh.generate_params(2048)
        a = dh.generate_private_key(p)
        A = dh.compute_public_key(a, p, g)
        
        # Send client DH
        dh_client = DHClientMessage(p=str(p), g=str(g), A=str(A))
        self._send_json(dh_client.model_dump())
        
        # Receive server DH
        dh_server_data = self._recv_json()
        dh_server = DHServerMessage(**dh_server_data)
        B = int(dh_server.B)
        
        # Derive session AES key
        Ks_session = dh.compute_shared_secret(a, B, p)
        self.session_key = dh.derive_aes_key(Ks_session)
        console.print("[green]✓[/green] Session key established")
        
        # Initialize transcript
        server_cn = self.server_cert.subject.get_attributes_for_oid(pki.NameOID.COMMON_NAME)[0].value
        self.transcript = Transcript(f"session_{now_ms()}", server_cn)
        
        console.print(Panel.fit("[bold green]Secure chat session established![/bold green]\n"
                                "Type your messages (or /quit to exit)", style="green"))
    
    def send_message(self, text: str):
        """Send an encrypted and signed message."""
        # Increment sequence number
        self.seqno += 1
        
        # Encrypt message
        plaintext = text.encode('utf-8')
        ct = aes.encrypt(plaintext, self.session_key)
        ct_b64 = b64e(ct)
        
        # Get timestamp
        ts = now_ms()
        
        # Compute digest: SHA256(seqno || ts || ct)
        digest_data = f"{self.seqno}{ts}{ct_b64}".encode('utf-8')
        digest = sha256_hex(digest_data).encode('utf-8')
        
        # Sign digest
        signature = sign.sign(digest, self.client_private_key)
        sig_b64 = b64e(signature)
        
        # Create message
        msg = ChatMessage(
            seqno=self.seqno,
            ts=ts,
            ct=ct_b64,
            sig=sig_b64
        )
        
        # Send message
        self._send_json(msg.model_dump())
        
        # Append to transcript
        client_fp = pki.get_cert_fingerprint(self.client_cert)
        self.transcript.append(self.seqno, ts, ct_b64, sig_b64, client_fp)
    
    def receive_messages(self):
        """Receive and process messages from server (runs in background thread)."""
        try:
            while True:
                msg_data = self._recv_json()
                
                if not msg_data:
                    break
                
                if msg_data.get("type") == "msg":
                    msg = ChatMessage(**msg_data)
                    
                    # Check sequence number
                    if msg.seqno <= self.last_recv_seqno:
                        console.print(f"[red]✗ REPLAY detected: seqno {msg.seqno}[/red]")
                        continue
                    
                    # Verify signature
                    digest_data = f"{msg.seqno}{msg.ts}{msg.ct}".encode('utf-8')
                    digest = sha256_hex(digest_data).encode('utf-8')
                    sig_bytes = b64d(msg.sig)
                    
                    if not sign.verify(digest, sig_bytes, self.server_public_key):
                        console.print("[red]✗ SIG_FAIL: Signature verification failed[/red]")
                        continue
                    
                    # Decrypt message
                    ct_bytes = b64d(msg.ct)
                    plaintext = aes.decrypt(ct_bytes, self.session_key)
                    message_text = plaintext.decode('utf-8')
                    
                    # Update sequence number
                    self.last_recv_seqno = msg.seqno
                    
                    # Append to transcript
                    server_fp = pki.get_cert_fingerprint(self.server_cert)
                    self.transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig, server_fp)
                    
                    # Display message
                    server_cn = self.server_cert.subject.get_attributes_for_oid(pki.NameOID.COMMON_NAME)[0].value
                    console.print(f"[blue]{server_cn}[/blue]: {message_text}")
                
                elif msg_data.get("type") == "error":
                    error = ErrorMessage(**msg_data)
                    console.print(f"[red]Server error: {error.error_code} - {error.message}[/red]")
                
                elif msg_data.get("type") == "receipt":
                    # Server sent receipt
                    console.print("[yellow]Received session receipt from server[/yellow]")
                    break
        
        except Exception as e:
            console.print(f"[red]Error receiving messages: {e}[/red]")
    
    def chat(self):
        """Start the chat session."""
        # Start receiver thread
        receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receiver_thread.start()
        
        # Main chat loop
        try:
            while True:
                message = Prompt.ask("[green]You[/green]")
                
                if message.lower() in ["/quit", "/exit"]:
                    console.print("[yellow]Closing session...[/yellow]")
                    
                    # Send quit message
                    self.send_message(message)
                    
                    # Exchange receipts
                    console.print("[yellow]Exchanging session receipts...[/yellow]")
                    
                    # Create and send our receipt
                    server_cn = self.server_cert.subject.get_attributes_for_oid(pki.NameOID.COMMON_NAME)[0].value
                    receipt = create_receipt(self.transcript, self.client_private_key, server_cn)
                    self._send_json(receipt.model_dump())
                    
                    # Save transcript
                    transcript_path = f"transcripts/client_{self.transcript.session_id}.txt"
                    self.transcript.save(transcript_path)
                    console.print(f"[green]✓[/green] Transcript saved to {transcript_path}")
                    
                    # Save receipt
                    receipt_path = f"transcripts/client_{self.transcript.session_id}_receipt.json"
                    os.makedirs(os.path.dirname(receipt_path), exist_ok=True)
                    with open(receipt_path, 'w') as f:
                        import json
                        f.write(json.dumps(receipt.model_dump(), indent=2))
                    console.print(f"[green]✓[/green] Receipt saved to {receipt_path}")
                    
                    break
                
                # Send message
                self.send_message(message)
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Session interrupted[/yellow]")
        
        finally:
            if self.sock:
                self.sock.close()
            console.print("[green]Session closed[/green]")
    
    def start(self):
        """Start the client."""
        try:
            self.connect()
            self.chat()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            import traceback
            traceback.print_exc()


def main():
    console.print(Panel.fit(
        "[bold cyan]SecureChat Client[/bold cyan]\n"
        "Connecting to server...",
        style="cyan"
    ))
    
    client = SecureChatClient(
        server_host=os.getenv("SERVER_HOST", "localhost"),
        server_port=int(os.getenv("SERVER_PORT", 5000))
    )
    client.start()


if __name__ == "__main__":
    main()
