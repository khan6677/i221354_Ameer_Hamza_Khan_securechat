"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.common.protocol import (
    HelloMessage, ServerHelloMessage, RegisterMessage, LoginMessage,
    DHClientMessage, DHServerMessage, ChatMessage, SessionReceipt,
    ErrorMessage, OkMessage
)
from app.crypto import aes, dh, pki, sign
from app.storage.db import register_user, verify_login, get_username
from app.storage.transcript import Transcript, create_receipt

# Load environment variables
load_dotenv()

console = Console()


class SecureChatServer:
    """Secure chat server with PKI and application-layer crypto."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5000):
        self.host = host
        self.port = port
        self.ca_cert = None
        self.server_cert = None
        self.server_private_key = None
        
        # Load certificates
        self._load_certificates()
    
    def _load_certificates(self):
        """Load CA and server certificates."""
        ca_cert_path = os.getenv("CA_CERT_PATH", "certs/ca.crt")
        server_cert_path = os.getenv("SERVER_CERT_PATH", "certs/server.crt")
        server_key_path = os.getenv("SERVER_KEY_PATH", "certs/server.key")
        
        with open(ca_cert_path, "rb") as f:
            self.ca_cert = pki.load_certificate(f.read())
        
        with open(server_cert_path, "rb") as f:
            self.server_cert = pki.load_certificate(f.read())
        
        with open(server_key_path, "rb") as f:
            self.server_private_key = pki.load_private_key(f.read())
        
        console.print("[green]✓[/green] Certificates loaded successfully")
    
    def _send_json(self, conn, data):
        """Send JSON message over socket."""
        message = json.dumps(data) + "\n"
        conn.sendall(message.encode('utf-8'))

    def _recv_json(self, conn):
        """Receive JSON message from socket."""
        buffer = b""
        while b"\n" not in buffer:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            buffer += chunk
        
        message = buffer.decode('utf-8').strip()
        return json.loads(message)
    
    def handle_client(self, conn, addr):
        """Handle a single client connection."""
        console.print(f"\n[cyan]New connection from {addr}[/cyan]")
        
        try:
            # 1. Certificate exchange
            console.print("[yellow]Phase 1: Certificate Exchange[/yellow]")
            
            # Receive client hello
            hello_data = self._recv_json(conn)
            hello = HelloMessage(**hello_data)
            
            # Load and validate client certificate
            client_cert = pki.load_certificate(hello.cert_pem.encode('utf-8'))
            if not pki.validate_certificate(client_cert, self.ca_cert):
                console.print("[red]✗ BAD_CERT: Client certificate validation failed[/red]")
                self._send_json(conn, ErrorMessage(error_code="BAD_CERT", message="Invalid certificate").model_dump())
                return
            
            console.print("[green]✓[/green] Client certificate validated")
            
            # Send server hello
            server_hello = ServerHelloMessage(
                cert_pem=pki.cert_to_pem(self.server_cert).decode('utf-8'),
                nonce=b64e(os.urandom(16))
            )
            self._send_json(conn, server_hello.model_dump())
            
            # 2. Temporary DH for credential encryption
            console.print("[yellow]Phase 2: Temporary DH (for credentials)[/yellow]")
            
            # Receive client DH
            dh_client_data = self._recv_json(conn)
            dh_client = DHClientMessage(**dh_client_data)
            
            p = int(dh_client.p)
            g = int(dh_client.g)
            A = int(dh_client.A)
            
            # Generate server DH key
            b = dh.generate_private_key(p)
            B = dh.compute_public_key(b, p, g)
            
            # Send server DH
            dh_server = DHServerMessage(B=str(B))
            self._send_json(conn, dh_server.model_dump())
            
            # Derive temporary AES key
            Ks_temp = dh.compute_shared_secret(b, A, p)
            temp_key = dh.derive_aes_key(Ks_temp)
            console.print("[green]✓[/green] Temporary session key established")
            
            # 3. Registration or Login
            console.print("[yellow]Phase 3: Authentication[/yellow]")
            
            # Receive encrypted auth message
            auth_data = self._recv_json(conn)
            
            # Decrypt
            ct = b64d(auth_data["ct"])
            plaintext = aes.decrypt(ct, temp_key)
            auth_msg = json.loads(plaintext.decode('utf-8'))
            
            user_email = None
            
            if auth_msg["type"] == "register":
                reg = RegisterMessage(**auth_msg)
                success = register_user(reg.email, reg.username, reg.password)
                if success:
                    console.print(f"[green]✓[/green] User registered: {reg.username}")
                    user_email = reg.email
                    response = OkMessage(message="Registration successful")
                else:
                    console.print("[red]✗[/red] Registration failed")
                    response = ErrorMessage(error_code="AUTH_FAIL", message="Registration failed")
            
            elif auth_msg["type"] == "login":
                login = LoginMessage(**auth_msg)
                if verify_login(login.email, login.password):
                    console.print(f"[green]✓[/green] User logged in: {login.email}")
                    user_email = login.email
                    response = OkMessage(message="Login successful")
                else:
                    console.print("[red]✗[/red] Login failed")
                    response = ErrorMessage(error_code="AUTH_FAIL", message="Invalid credentials")
            else:
                response = ErrorMessage(error_code="AUTH_FAIL", message="Unknown auth type")
            
            # Send encrypted response
            response_json = json.dumps(response.model_dump()).encode('utf-8')
            response_ct = aes.encrypt(response_json, temp_key)
            self._send_json(conn, {"ct": b64e(response_ct)})
            
            if not user_email:
                return
            
            # 4. Session DH for chat encryption
            console.print("[yellow]Phase 4: Session DH (for chat)[/yellow]")
            
            # Receive client DH
            dh_client_data = self._recv_json(conn)
            dh_client = DHClientMessage(**dh_client_data)
            
            p = int(dh_client.p)
            g = int(dh_client.g)
            A = int(dh_client.A)
            
            # Generate server DH key
            b = dh.generate_private_key(p)
            B = dh.compute_public_key(b, p, g)
            
            # Send server DH
            dh_server = DHServerMessage(B=str(B))
            self._send_json(conn, dh_server.model_dump())
            
            # Derive session AES key
            Ks_session = dh.compute_shared_secret(b, A, p)
            session_key = dh.derive_aes_key(Ks_session)
            console.print("[green]✓[/green] Session key established")
            
            # 5. Chat loop
            console.print("[yellow]Phase 5: Secure Chat[/yellow]")
            console.print(Panel.fit("Chat session started. Waiting for messages...", style="green"))
            
            # Initialize transcript
            client_cn = client_cert.subject.get_attributes_for_oid(pki.NameOID.COMMON_NAME)[0].value
            client_fp = pki.get_cert_fingerprint(client_cert)
            transcript = Transcript(f"session_{now_ms()}", client_cn)
            
            last_seqno = -1
            client_public_key = pki.get_public_key(client_cert)
            
            while True:
                msg_data = self._recv_json(conn)
                
                if not msg_data:
                    break
                
                if msg_data.get("type") == "msg":
                    msg = ChatMessage(**msg_data)
                    
                    # Check sequence number (replay protection)
                    if msg.seqno <= last_seqno:
                        console.print(f"[red]✗ REPLAY: seqno {msg.seqno} <= {last_seqno}[/red]")
                        error = ErrorMessage(error_code="REPLAY", message="Sequence number replay detected")
                        self._send_json(conn, error.model_dump())
                        continue
                    
                    # Verify signature
                    digest_data = f"{msg.seqno}{msg.ts}{msg.ct}".encode('utf-8')
                    digest = sha256_hex(digest_data).encode('utf-8')
                    sig_bytes = b64d(msg.sig)
                    
                    if not sign.verify(digest, sig_bytes, client_public_key):
                        console.print("[red]✗ SIG_FAIL: Signature verification failed[/red]")
                        error = ErrorMessage(error_code="SIG_FAIL", message="Signature verification failed")
                        self._send_json(conn, error.model_dump())
                        continue
                    
                    # Decrypt message
                    ct_bytes = b64d(msg.ct)
                    plaintext = aes.decrypt(ct_bytes, session_key)
                    message_text = plaintext.decode('utf-8')
                    
                    # Update sequence number
                    last_seqno = msg.seqno
                    
                    # Append to transcript
                    transcript.append(msg.seqno, msg.ts, msg.ct, msg.sig, client_fp)
                    
                    # Display message
                    console.print(f"[blue]{client_cn}[/blue]: {message_text}")
                    
                    # Check for exit
                    if message_text.lower() in ["/quit", "/exit"]:
                        console.print("[yellow]Client requested to close session[/yellow]")
                        break
                
                elif msg_data.get("type") == "receipt":
                    # Client sent receipt, we should send ours too
                    console.print("[yellow]Exchanging session receipts...[/yellow]")
                    
                    # Create and send our receipt
                    receipt = create_receipt(transcript, self.server_private_key, client_cn)
                    self._send_json(conn, receipt.model_dump())

                    # Save transcript
                    transcript_path = f"transcripts/server_{transcript.session_id}.txt"
                    transcript.save(transcript_path)
                    console.print(f"[green]✓[/green] Transcript saved to {transcript_path}")

                    # Save receipt
                    receipt_path = f"transcripts/server_{transcript.session_id}_receipt.json"
                    os.makedirs(os.path.dirname(receipt_path), exist_ok=True)
                    with open(receipt_path, 'w') as f:
                        f.write(json.dumps(receipt.model_dump(), indent=2))
                    console.print(f"[green]✓[/green] Receipt saved to {receipt_path}")

                    break
            
            console.print("[green]Session closed[/green]")
        
        except Exception as e:
            console.print(f"[red]Error handling client: {e}[/red]")
            import traceback
            traceback.print_exc()
        
        finally:
            conn.close()
    
    def start(self):
        """Start the server."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)
            
            console.print(Panel.fit(
                f"[bold green]SecureChat Server Started[/bold green]\n"
                f"Listening on {self.host}:{self.port}",
                style="green"
            ))
            
            while True:
                conn, addr = s.accept()
                self.handle_client(conn, addr)


def main():
    server = SecureChatServer(
        host=os.getenv("SERVER_BIND_HOST", "0.0.0.0"),
        port=int(os.getenv("SERVER_PORT", 5000))
    )
    server.start()


if __name__ == "__main__":
    main()
