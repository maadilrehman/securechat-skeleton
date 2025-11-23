import socket
import json
import sys
import getpass
from cryptography import x509
from cryptography.hazmat.primitives import hashes

# Import all our custom modules
from app.crypto import pki, dh, aes, sign
from app.common import protocol, utils
from app.storage import transcript

# --- Client Configuration ---
HOST = '127.0.0.1'
PORT = 65432
SERVER_CN = "server" # The expected CN from the server
CLIENT_CN = "client.local" # Our own CN

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

def handle_cert_exchange(sock: socket.socket, ca_cert, client_cert) -> x509.Certificate:
    """
    Handles the mutual certificate exchange and validation.
    Implements Section 2.1.
    """
    print("[+] Starting certificate exchange...")
    
    # 1. Send client "hello"
    client_hello = protocol.HelloClient(
        client_cert=pki.serialize_cert(client_cert),
        nonce=utils.to_base64(utils.generate_nonce(16))
    )
    send_message(sock, client_hello)
    print("[+] Sent our certificate.")
    
    # 2. Receive server "hello"
    server_hello_data = recv_message(sock)
    if not server_hello_data or server_hello_data.get('type') != 'server_hello':
        raise Exception("Did not receive a valid server 'hello'")
        
    server_hello = protocol.HelloServer(**server_hello_data)
    server_cert = pki.deserialize_cert(server_hello.server_cert)
    
    # 3. Validate server's certificate
    print("[+] Received server certificate. Validating...")
    if not pki.validate_certificate(server_cert, ca_cert, expected_cn=SERVER_CN):
        raise Exception("Server certificate validation failed.")
        
    print("[+] Server certificate is valid.")
    return server_cert

def perform_temp_dh_exchange(sock: socket.socket) -> bytes:
    """
    Performs a temporary DH exchange to secure the login.
    Implements Section 2.2, steps 2-3.
    """
    print("[+] Performing temporary DH exchange...")
    
    # 1. Client receives server's public key
    server_dh_pub_bytes = sock.recv(1024)
    if not server_dh_pub_bytes:
        raise Exception("Server closed connection during DH")
        
    # 2. Client generates its DH keys
    client_dh = dh.DH_Peer()
    
    # 3. Send client's public key
    sock.sendall(client_dh.get_public_bytes())
    
    # 4. Compute shared secret and derive AES key
    temp_shared_secret = client_dh.compute_shared_secret(server_dh_pub_bytes)
    temp_aes_key = dh.derive_aes_key(temp_shared_secret)
    
    print("[+] Temporary AES key established.")
    return temp_aes_key

def handle_authentication(sock: socket.socket, temp_aes_key: bytes) -> bool:
    """
    Handles the encrypted Registration or Login.
    Implements Section 2.2, steps 4-7.
    """
    print("[+] --- Authentication ---")
    action = input("Do you want to (1) Register or (2) Login? [1/2]: ")
    
    payload = None
    if action == '1':
        email = input("Enter email: ")
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        payload = protocol.Register(email=email, username=username, pwd=password)
    elif action == '2':
        email = input("Enter email: ")
        password = getpass.getpass("Enter password: ")
        payload = protocol.Login(
            email=email, 
            pwd=password,
            nonce=utils.to_base64(utils.generate_nonce(16))
        )
    else:
        print("Invalid choice.")
        return False

    # 1. Encrypt and send the credentials
    encrypted_payload_bytes = aes.encrypt(temp_aes_key, protocol.serialize_message(payload))
    wrapper = {"payload": utils.to_base64(encrypted_payload_bytes)}
    sock.sendall((json.dumps(wrapper) + "\n").encode('utf-8'))

    # 2. Receive and decrypt the response
    encrypted_response_data = recv_message(sock)
    if not encrypted_response_data or 'payload' not in encrypted_response_data:
        raise Exception("Invalid encrypted auth response")
        
    encrypted_response = utils.from_base64(encrypted_response_data['payload'])
    response_json = aes.decrypt(temp_aes_key, encrypted_response)
    response = protocol.AuthResponse(**json.loads(response_json))
    
    print(f"[Server] {response.message}")
    return response.success

def perform_main_dh_exchange(sock: socket.socket) -> bytes:
    """
    Performs the main DH exchange for the chat session.
    Implements Section 2.3.
    """
    print("[+] Performing MAIN session key exchange...")
    
    # 1. Client receives server's public key
    server_dh_pub_bytes = sock.recv(1024)
    if not server_dh_pub_bytes:
        raise Exception("Server closed connection during main DH")
        
    # 2. Client generates its DH keys
    client_dh = dh.DH_Peer()
    
    # 3. Send client's public key
    sock.sendall(client_dh.get_public_bytes())
    
    # 4. Compute final session key
    session_shared_secret = client_dh.compute_shared_secret(server_dh_pub_bytes)
    session_aes_key = dh.derive_aes_key(session_shared_secret)
    
    print("[+] MAIN session key established.")
    return session_aes_key

def handle_chat_loop(sock: socket.socket, session_key: bytes, client_key):
    """
    Handles the main encrypted chat.
    Implements Section 2.4.
    """
    print("[+] --- Secure Chat ---")
    print("Type your messages. Press Enter to send. Type '!!exit' to quit.")
    
    session_log = transcript.Transcript(f"client_session_with_{SERVER_CN}")
    seqno = 0
    
    try:
        while True:
            # Get user input
            message = input(f"[{CLIENT_CN}]> ")
            if message == '!!exit':
                break
                
            # 1. Pad and Encrypt
            plaintext_bytes = message.encode('utf-8')
            ct_bytes = aes.encrypt(session_key, plaintext_bytes)
            
            # 2. Compute hash h = SHA256(seqno || ts || ct) [cite: 206]
            ts = utils.now_ms()
            digest = hashes.Hash(hashes.SHA256())
            digest.update(str(seqno).encode('utf-8'))
            digest.update(str(ts).encode('utf-8'))
            digest.update(ct_bytes)
            data_hash_bytes = digest.finalize()
            
            # 3. Sign the hash [cite: 207]
            signature = sign.sign_data(client_key, data_hash_bytes)

            # --- ADD THIS LINE TO CORRUPT THE SIGNATURE ---
            #signature = signature[:-1] + b'X'
            
            
            # 4. Create and send message
            msg = protocol.Msg(
                seqno=seqno,
                ts=ts,
                ct=utils.to_base64(ct_bytes),
                sig=utils.to_base64(signature)
            )
            send_message(sock, msg)
            # --- ADD THIS LINE TO REPLAY THE MESSAGE ---
            #send_message(sock, msg)
            
            
            # 5. Add to transcript [cite: 224]
            session_log.add_message(
                seqno, ts, msg.ct, msg.sig,
                "server_fingerprint_todo"
            )
            
            seqno += 1
            
            # (In a real client, a separate thread would listen for messages)
            
    except KeyboardInterrupt:
        pass # User pressed Ctrl+C
    except Exception as e:
        print(f"\n[ERROR] Error in chat: {e}")
    finally:
        print("\n[+] Closing chat.")
        # --- NEW CODE FOR PHASE 6 ---
        try:
            # 6. Generate final transcript hash [cite: 226]
            final_hash = session_log.get_transcript_hash()
            print(f"[+] Final Transcript Hash: {final_hash}")

            # 7. Sign the hash [cite: 227]
            hash_bytes = bytes.fromhex(final_hash)
            signature = sign.sign_data(client_key, hash_bytes)

            # 8. Create and save the SessionReceipt [cite: 228-230]
            receipt = protocol.Receipt(
                peer="client",
                first_seq=session_log.first_seq,
                last_seq=session_log.last_seq,
                transcript_sha256=final_hash,
                sig=utils.to_base64(signature)
            )

            receipt_path = f"{session_log.filepath}_RECEIPT.json"
            with open(receipt_path, "w") as f:
                f.write(receipt.model_dump_json(indent=2))
            print(f"[+] Saved SessionReceipt to {receipt_path}")

        except Exception as e:
            print(f"[+] !! FAILED to generate receipt: {e} !!")


# --- Main Client ---

def main():
    print("--- SecureChat Client ---")
    
    # 1. Load all our required certificates and keys
    print("Loading PKI credentials...")
    ca_cert = pki.load_ca_cert()
    client_cert, client_key = pki.load_entity_creds(
        "certs/client_cert.pem", 
        "certs/client_key.pem"

        #To test for bad certificates just comment out below code and comment the above code 

        #"bad_client_cert.pem",
        #"bad_client_key.pem"
    )
    
    try:
        # 2. Create the client socket and connect
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"Connecting to {HOST}:{PORT}...")
            s.connect((HOST, PORT))
            print("[+] Connected!")
            
            # Phase 3.1: Certificate Exchange
            server_cert = handle_cert_exchange(s, ca_cert, client_cert)
            
            # Phase 3.2: Temp DH Exchange
            temp_aes_key = perform_temp_dh_exchange(s)
            
            # Phase 3.3: Authentication
            if not handle_authentication(s, temp_aes_key):
                raise Exception("Authentication failed. Exiting.")
            
            # Phase 4: Session Key Establishment
            session_key = perform_main_dh_exchange(s)
            
            # Phase 5: Chat Loop
            handle_chat_loop(s, session_key, client_key)

    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        print("[+] Client shutting down.")

if __name__ == "__main__":
    main()