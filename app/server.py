import socket
import json
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes

# Import all our custom modules
from app.crypto import pki, dh, aes, sign
from app.common import protocol, utils
from app.storage import db, transcript

# --- Server Configuration ---
HOST = '127.0.0.1'
PORT = 65432
SERVER_CN = "server.local" # The Common Name on our certificate
CLIENT_CN = "client" # The expected CN from the client

# --- Helper Functions ---

def send_message(sock: socket.socket, model: protocol.BaseModel):
    """Serializes and sends a Pydantic model over the socket."""
    # We add a simple newline delimiter to separate JSON messages
    data = model.model_dump_json() + "\n"
    sock.sendall(data.encode('utf-8'))

def recv_message(sock: socket.socket) -> dict:
    """Receives data until a newline and parses it as JSON."""
    data = b""
    while True:
        # A simple newline-delimited JSON protocol
        chunk = sock.recv(1)
        # Stop on newline (end of message) or empty byte (disconnect)
        if chunk == b'\n' or chunk == b'':
            break
        data += chunk
    if not data:
        return None
    
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        print(f"Error: Received invalid JSON data: {data}")
        return None

# --- Protocol Handlers ---

def handle_cert_exchange(conn: socket.socket, addr, ca_cert, server_cert) -> x509.Certificate:
    """
    Handles the mutual certificate exchange and validation.
    Implements Section 2.1.
    """
    print(f"[{addr}] Starting certificate exchange...")
    
    # 1. Receive client "hello"
    client_hello_data = recv_message(conn)
    if not client_hello_data or client_hello_data.get('type') != 'hello':
        raise Exception("Did not receive a valid client 'hello'")
        
    client_hello = protocol.HelloClient(**client_hello_data)
    client_cert = pki.deserialize_cert(client_hello.client_cert)
    
    # 2. Validate client's certificate
    print(f"[{addr}] Received client certificate. Validating...")
    if not pki.validate_certificate(client_cert, ca_cert, expected_cn=CLIENT_CN):
        raise Exception("Client certificate validation failed.")
        
    print(f"[{addr}] Client certificate is valid.")
    
    # 3. Send server "hello"
    server_hello = protocol.HelloServer(
        server_cert=pki.serialize_cert(server_cert),
        nonce=utils.to_base64(utils.generate_nonce(16))
    )
    send_message(conn, server_hello)
    print(f"[{addr}] Sent server certificate.")
    
    # Return the validated client cert for later use (e.g., signing)
    return client_cert

def perform_temp_dh_exchange(conn: socket.socket, addr) -> bytes:
    """
    Performs a temporary DH exchange to secure the login.
    Implements Section 2.2, steps 2-3.
    """
    print(f"[{addr}] Performing temporary DH exchange...")
    
    # 1. Server generates its DH keys
    server_dh = dh.DH_Peer()
    
    # 2. Send server's public key
    conn.sendall(server_dh.get_public_bytes())
    
    # 3. Receive client's public key
    client_dh_pub_bytes = conn.recv(1024) # Assuming key is < 1KB
    if not client_dh_pub_bytes:
        raise Exception("Client closed connection during DH")
    
    # 4. Compute shared secret and derive AES key
    temp_shared_secret = server_dh.compute_shared_secret(client_dh_pub_bytes)
    temp_aes_key = dh.derive_aes_key(temp_shared_secret)
    
    print(f"[{addr}] Temporary AES key established.")
    return temp_aes_key

def handle_authentication(conn: socket.socket, addr, temp_aes_key: bytes) -> bool:
    """
    Handles the encrypted Registration or Login.
    Implements Section 2.2, steps 4-7.
    """
    print(f"[{addr}] Awaiting encrypted credentials...")
    
    # 1. Receive encrypted credentials
    encrypted_data = recv_message(conn)
    if not encrypted_data or 'payload' not in encrypted_data:
         raise Exception("Invalid encrypted auth payload")
         
    encrypted_payload_b64 = encrypted_data['payload']
    encrypted_payload = utils.from_base64(encrypted_payload_b64)
    
    # 2. Decrypt the payload
    try:
        payload_json = aes.decrypt(temp_aes_key, encrypted_payload)
        auth_data = json.loads(payload_json)
    except Exception as e:
        raise Exception(f"Failed to decrypt auth payload: {e}")
        
    # 3. Process Registration or Login
    success = False
    message = ""
    
    if auth_data.get('type') == 'register':
        print(f"[{addr}] Processing registration for {auth_data['username']}...")
        req = protocol.Register(**auth_data)
        success = db.register_user(req.email, req.username, req.pwd) #
        message = "Registration successful" if success else "Registration failed (user may exist)"
        
    elif auth_data.get('type') == 'login':
        print(f"[{addr}] Processing login for {auth_data['email']}...")
        req = protocol.Login(**auth_data)
        success = db.verify_user(req.email, req.pwd) #
        message = "Login successful" if success else "Login failed (invalid credentials)"
        
    else:
        message = "Invalid auth type"

    # 4. Send encrypted response
    response = protocol.AuthResponse(success=success, message=message)
    encrypted_response_bytes = aes.encrypt(temp_aes_key, protocol.serialize_message(response))
    
    # We must wrap this in a simple dict
    wrapper = {"payload": utils.to_base64(encrypted_response_bytes)}
    conn.sendall((json.dumps(wrapper) + "\n").encode('utf-8'))
    
    print(f"[{addr}] Auth result: {message}")
    return success

def perform_main_dh_exchange(conn: socket.socket, addr) -> bytes:
    """
    Performs the main DH exchange for the chat session.
    Implements Section 2.3.
    """
    print(f"[{addr}] Performing MAIN session key exchange...")
    
    # 1. Server generates its DH keys
    server_dh = dh.DH_Peer()
    
    # 2. Send server's public key
    conn.sendall(server_dh.get_public_bytes())
    
    # 3. Receive client's public key
    client_dh_pub_bytes = conn.recv(1024)
    if not client_dh_pub_bytes:
        raise Exception("Client closed connection during main DH")
    
    # 4. Compute final session key
    session_shared_secret = server_dh.compute_shared_secret(client_dh_pub_bytes)
    session_aes_key = dh.derive_aes_key(session_shared_secret) #
    
    print(f"[{addr}] MAIN session key established.")
    return session_aes_key
    

def handle_chat_loop(conn: socket.socket, addr, session_key: bytes, client_cert: x509.Certificate):
    """
    Handles the main encrypted chat.
    Implements Section 2.4.
    """
    print(f"[{addr}] Starting secure chat loop...")
    client_pub_key = client_cert.public_key()
    session_log = transcript.Transcript(f"server_session_with_{CLIENT_CN}")
    
    last_seen_seqno = -1
    
    while True:
        try:
            msg_data = recv_message(conn)
            if not msg_data:
                print(f"[{addr}] Client disconnected.")
                break
                
            if msg_data.get('type') != 'msg':
                print(f"[{addr}] Received non-msg. Exiting chat loop.")
                break
            
            msg = protocol.Msg(**msg_data)
            
            # 1. Check sequence number (replay protection)
            if msg.seqno <= last_seen_seqno:
                print(f"[{addr}] !! REPLAY (seqno {msg.seqno}) !!")
                continue # Drop the message
            last_seen_seqno = msg.seqno
            
            # 2. Re-compute hash h = SHA256(seqno || ts || ct)
            ct_bytes = utils.from_base64(msg.ct)
            
            digest = hashes.Hash(hashes.SHA256())
            digest.update(str(msg.seqno).encode('utf-8'))
            digest.update(str(msg.ts).encode('utf-8'))
            digest.update(ct_bytes)
            data_hash_bytes = digest.finalize()
            
            # 3. Verify signature
            signature = utils.from_base64(msg.sig)
            
            if not sign.verify_signature(client_pub_key, signature, data_hash_bytes):
                print(f"[{addr}] !! SIG_FAIL: Invalid signature on message {msg.seqno} !!")
                continue # Drop the message
                
            # 4. Decrypt ciphertext
            plaintext = aes.decrypt(session_key, ct_bytes)
            
            print(f"[{CLIENT_CN}]: {plaintext.decode('utf-8')}")
            
            # 5. Add to transcript
            session_log.add_message(
                msg.seqno, msg.ts, msg.ct, msg.sig, 
                "client_fingerprint_todo" # TODO: Add cert fingerprint
            )
            
            # (Server doesn't send messages in this simplified loop)
            
        except Exception as e:
            print(f"[{addr}] Error in chat loop: {e}")
            break
            
    print(f"[{addr}] Chat loop ended.")
    # 6. Generate final transcript hash
    final_hash = session_log.get_transcript_hash()
    print(f"[{addr}] Final Transcript Hash: {final_hash}")
    # (In a full implementation, we'd sign this and create a receipt)


# --- Main Client Handler ---

def handle_client(conn: socket.socket, addr, ca_cert, server_cert, server_key):
    """
    Handles the full lifecycle of a single client connection.
    """
    print(f"[NEW CONNECTION] {addr} connected.")
    
    try:
        # Phase 3.1: Certificate Exchange
        client_cert = handle_cert_exchange(conn, addr, ca_cert, server_cert)
        
        # Phase 3.2: Temp DH Exchange
        temp_aes_key = perform_temp_dh_exchange(conn, addr)
        
        # Phase 3.3: Authentication
        if not handle_authentication(conn, addr, temp_aes_key):
            raise Exception("Authentication failed.")
        
        # Phase 4: Session Key Establishment
        session_key = perform_main_dh_exchange(conn, addr)
        
        # Phase 5: Chat Loop
        handle_chat_loop(conn, addr, session_key, client_cert)
        
    except Exception as e:
        print(f"[{addr}] Error: {e}")
    finally:
        print(f"[CONNECTION CLOSED] {addr}")
        conn.close()

# --- Main Server ---

def main():
    print("--- SecureChat Server ---")
    
    # 1. Load all our required certificates and keys
    print("Loading PKI credentials...")
    ca_cert = pki.load_ca_cert()
    server_cert, server_key = pki.load_entity_creds(
        "certs/server_cert.pem", 
        "certs/server_key.pem"
    )
    
    # 2. Create the server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # This allows us to re-run the server quickly
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Server listening on {HOST}:{PORT}")

        # 3. Wait for connections
        while True:
            try:
                conn, addr = s.accept()
                
                # NOTE: This is a single-threaded server.
                # It can only handle one client at a time.
                handle_client(conn, addr, ca_cert, server_cert, server_key)
                
            except KeyboardInterrupt:
                print("\n[*] Shutting down server...")
                break
            except Exception as e:
                print(f"[SERVER ERROR] {e}")

if __name__ == "__main__":
    main()