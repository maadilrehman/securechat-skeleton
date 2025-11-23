import os
import time
from cryptography.hazmat.primitives import hashes
from app.common.utils import sha256_hex

# Define the directory to store transcripts
TRANSCRIPT_DIR = "transcripts"
if not os.path.exists(TRANSCRIPT_DIR):
    os.makedirs(TRANSCRIPT_DIR)


class Transcript:
    """
    Manages an append-only session transcript for non-repudiation.
    Implements Section 2.5 requirements.
    """
    def __init__(self, peer_name: str):
        # Create a unique filename for this session
        filename = f"{peer_name}_{int(time.time())}.log"
        self.filepath = os.path.join(TRANSCRIPT_DIR, filename)
        self.first_seq = -1
        self.last_seq = -1
        self.lines = []
        print(f"Transcript: Logging session to '{self.filepath}'")

    def add_message(self, seqno: int, ts: int, ct: str, sig: str, peer_cert_fingerprint: str):
        """
        Adds a single message to the transcript log.
        Formats as: seqno | ts | ct | sig | peer-cert-fingerprint
        [cite: 224]
        """
        # Update sequence tracking
        if self.first_seq == -1:
            self.first_seq = seqno
        self.last_seq = seqno
        
        # Create the log line
        line = f"{seqno}|{ts}|{ct}|{sig}|{peer_cert_fingerprint}\n"
        self.lines.append(line)
        
        # Write to file immediately (append-only)
        try:
            with open(self.filepath, "a") as f:
                f.write(line)
        except Exception as e:
            print(f"Transcript: !! FAILED TO WRITE TO LOG: {e} !!")

    def get_transcript_hash(self) -> str:
        """
        Computes the final hash of the entire transcript.
        Transcript Hash = SHA256(concatenation of all log lines)
        [cite: 226]
        """
        # Concatenate all lines
        full_transcript = "".join(self.lines).encode('utf-8')
        
        # Compute and return the hex hash
        return sha256_hex(full_transcript)