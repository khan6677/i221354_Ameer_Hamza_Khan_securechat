"""Append-only transcript + TranscriptHash helpers."""

import os
from typing import List, Optional
from app.common.utils import sha256_hex, b64e, b64d
from app.common.protocol import SessionReceipt
from app.crypto import sign


class Transcript:
    """
    Append-only transcript for session messages.
    
    Format: Each line is "seqno|ts|ct|sig|peer_fingerprint"
    """
    
    def __init__(self, session_id: str, peer_cn: str):
        """
        Initialize a new transcript.
        
        Args:
            session_id: Unique session identifier
            peer_cn: Peer's Common Name
        """
        self.session_id = session_id
        self.peer_cn = peer_cn
        self.lines: List[str] = []
        self.first_seqno: Optional[int] = None
        self.last_seqno: Optional[int] = None
    
    def append(self, seqno: int, ts: int, ct: str, sig: str, peer_fingerprint: str):
        """
        Append a message to the transcript.
        
        Args:
            seqno: Sequence number
            ts: Timestamp in milliseconds
            ct: Base64-encoded ciphertext
            sig: Base64-encoded signature
            peer_fingerprint: Peer certificate fingerprint
        """
        line = f"{seqno}|{ts}|{ct}|{sig}|{peer_fingerprint}"
        self.lines.append(line)
        
        # Track sequence number range
        if self.first_seqno is None:
            self.first_seqno = seqno
        self.last_seqno = seqno
    
    def get_transcript_hash(self) -> str:
        """
        Compute SHA-256 hash of the entire transcript.
        
        Returns:
            Hex-encoded SHA-256 hash
        """
        # Concatenate all lines
        transcript_data = "\n".join(self.lines)
        return sha256_hex(transcript_data.encode('utf-8'))
    
    def save(self, filepath: str):
        """
        Save transcript to file.
        
        Args:
            filepath: Path to save the transcript
        """
        # Ensure directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w') as f:
            f.write(f"# Session: {self.session_id}\n")
            f.write(f"# Peer: {self.peer_cn}\n")
            f.write(f"# Format: seqno|ts|ct|sig|peer_fingerprint\n")
            f.write("\n")
            for line in self.lines:
                f.write(line + "\n")
    
    @staticmethod
    def load(filepath: str) -> 'Transcript':
        """
        Load transcript from file.
        
        Args:
            filepath: Path to the transcript file
            
        Returns:
            Transcript object
        """
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        # Parse header
        session_id = None
        peer_cn = None
        transcript_lines = []
        
        for line in lines:
            line = line.strip()
            if line.startswith("# Session:"):
                session_id = line.split(":", 1)[1].strip()
            elif line.startswith("# Peer:"):
                peer_cn = line.split(":", 1)[1].strip()
            elif line and not line.startswith("#"):
                transcript_lines.append(line)
        
        # Create transcript object
        transcript = Transcript(session_id or "unknown", peer_cn or "unknown")
        
        # Parse transcript lines
        for line in transcript_lines:
            parts = line.split("|")
            if len(parts) == 5:
                seqno, ts, ct, sig, peer_fp = parts
                transcript.append(int(seqno), int(ts), ct, sig, peer_fp)
        
        return transcript


def create_receipt(transcript: Transcript, private_key, peer_cn: str) -> SessionReceipt:
    """
    Create a signed session receipt for non-repudiation.
    
    Args:
        transcript: Transcript object
        private_key: RSA private key for signing
        peer_cn: Peer's Common Name
        
    Returns:
        SessionReceipt object
    """
    # Compute transcript hash
    transcript_hash = transcript.get_transcript_hash()
    
    # Sign the transcript hash
    signature = sign.sign(transcript_hash.encode('utf-8'), private_key)
    
    # Create receipt
    receipt = SessionReceipt(
        peer=peer_cn,
        first_seqno=transcript.first_seqno or 0,
        last_seqno=transcript.last_seqno or 0,
        transcript_hash=transcript_hash,
        signature=b64e(signature)
    )
    
    return receipt


def verify_receipt(receipt: SessionReceipt, transcript: Transcript, public_key) -> bool:
    """
    Verify a session receipt signature.
    
    Args:
        receipt: SessionReceipt object
        transcript: Transcript object
        public_key: RSA public key for verification
        
    Returns:
        True if signature is valid, False otherwise
    """
    # Compute transcript hash
    computed_hash = transcript.get_transcript_hash()
    
    # Check if hash matches
    if computed_hash != receipt.transcript_hash:
        return False
    
    # Verify signature
    signature = b64d(receipt.signature)
    return sign.verify(receipt.transcript_hash.encode('utf-8'), signature, public_key)
