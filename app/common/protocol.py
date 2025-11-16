import json
from pydantic import BaseModel, Field
from typing import Literal

# --- Control Plane (Section 1.1) ---

class HelloClient(BaseModel):
    """
    Client -> Server: Initiates connection, sends certificate, and a nonce.
    [cite: 67]
    """
    type: Literal["hello"] = "hello"
    client_cert: str  # PEM-encoded certificate
    nonce: str        # base64 encoded random bytes

class HelloServer(BaseModel):
    """
    Server -> Client: Responds with its certificate and a nonce.
    [cite: 68]
    """
    type: Literal["server_hello"] = "server_hello"
    server_cert: str  # PEM-encoded certificate
    nonce: str        # base64 encoded random bytes

class Register(BaseModel):
    """
    Client -> Server: Encrypted registration request.
    [cite: 69]
    """
    type: Literal["register"] = "register"
    email: str
    username: str
    pwd: str 

class Login(BaseModel):
    """
    Client -> Server: Encrypted login request.
    [cite: 71]
    """
    type: Literal["login"] = "login"
    email: str
    pwd: str
    nonce: str        # base64 encoded random bytes

class AuthResponse(BaseModel):
    """
    Server -> Client: A generic response for auth success/failure.
    """
    type: Literal["auth_response"] = "auth_response"
    success: bool
    message: str


# --- Key Agreement (Section 1.2) ---

class DHClient(BaseModel):
    """
    Client -> Server: Sends DH public parameters (p, g) and public value A.
    [cite: 88-90]
    """
    type: Literal["dh_client"] = "dh_client"
    g: int
    p: int
    A: int

class DHServer(BaseModel):
    """
    Server -> Client: Responds with its public value B.
    [cite: 91-93]
    """
    type: Literal["dh_server"] = "dh_server"
    B: int


# --- Data Plane (Section 1.3) ---

class Msg(BaseModel):
    """
    Client <-> Server: An encrypted and signed chat message.
    [cite: 110-111]
    """
    type: Literal["msg"] = "msg"
    seqno: int
    ts: int  # Unix timestamp in ms
    ct: str  # base64 encoded ciphertext
    sig: str # base64 encoded signature


# --- Non-Repudiation (Section 1.4) ---

class Receipt(BaseModel):
    """
    Client <-> Server: A signed receipt of the entire transcript.
    [cite: 132-134]
    """
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"]
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex-encoded
    sig: str                # base64-encoded


# --- Helper Function ---

def serialize_message(model: BaseModel) -> bytes:
    """Serializes a Pydantic model into JSON bytes."""
    return model.model_dump_json().encode('utf-8')

def parse_message(data: bytes):
    """
    Parses raw JSON bytes and returns a Python dictionary.
    """
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        print("Protocol: Received invalid JSON.")
        return None