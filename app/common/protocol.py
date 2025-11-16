"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""

from pydantic import BaseModel
from typing import Optional


class HelloMessage(BaseModel):
    """Client hello message with certificate and nonce."""
    type: str = "hello"
    cert_pem: str  # PEM-encoded certificate
    nonce: str  # Base64-encoded nonce


class ServerHelloMessage(BaseModel):
    """Server hello response with certificate and nonce."""
    type: str = "server_hello"
    cert_pem: str  # PEM-encoded certificate
    nonce: str  # Base64-encoded nonce


class RegisterMessage(BaseModel):
    """Registration message (sent encrypted)."""
    type: str = "register"
    email: str
    username: str
    password: str  # Will be hashed with salt on server


class LoginMessage(BaseModel):
    """Login message (sent encrypted)."""
    type: str = "login"
    email: str
    password: str  # Will be verified against salted hash


class DHClientMessage(BaseModel):
    """Client DH parameters and public key."""
    type: str = "dh_client"
    p: str  # Prime modulus (as decimal string)
    g: str  # Generator (as decimal string)
    A: str  # Client public key (as decimal string)


class DHServerMessage(BaseModel):
    """Server DH public key response."""
    type: str = "dh_server"
    B: str  # Server public key (as decimal string)


class ChatMessage(BaseModel):
    """Encrypted and signed chat message."""
    type: str = "msg"
    seqno: int  # Sequence number (strictly increasing)
    ts: int  # Timestamp in milliseconds
    ct: str  # Base64-encoded ciphertext
    sig: str  # Base64-encoded RSA signature


class SessionReceipt(BaseModel):
    """Non-repudiation receipt for session transcript."""
    type: str = "receipt"
    peer: str  # Peer identifier (CN or fingerprint)
    first_seqno: int  # First sequence number in session
    last_seqno: int  # Last sequence number in session
    transcript_hash: str  # Hex-encoded SHA-256 of transcript
    signature: str  # Base64-encoded RSA signature of transcript_hash


class ErrorMessage(BaseModel):
    """Error response message."""
    type: str = "error"
    error_code: str  # e.g., "BAD_CERT", "SIG_FAIL", "REPLAY", "AUTH_FAIL"
    message: str  # Human-readable error description


class OkMessage(BaseModel):
    """Success response message."""
    type: str = "ok"
    message: Optional[str] = None
