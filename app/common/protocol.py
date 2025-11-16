# app/common/protocol.py
# Simple JSON message helpers - newline delimited JSON framing is used.
import json
import base64
from typing import Dict, Any

def pack_message(obj: Dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode()

def unpack_message(line: bytes) -> Dict[str, Any]:
    return json.loads(line.decode())

def pem_bytes_to_text(pem_bytes: bytes) -> str:
    return pem_bytes.decode()

def b64(s: bytes) -> str:
    return base64.b64encode(s).decode()
