# SecureChat - Encrypted Chat System

**Student:** [Your Name]  
**Roll Number:** [Your Roll Number]  
**GitHub:** https://github.com/Navairaa/securechat-skeleton

## Project Overview

A secure client-server chat system implementing:
- X.509 Certificate-based mutual authentication
- Diffie-Hellman key exchange
- AES-128 encrypted messaging
- RSA digital signatures per message
- Replay protection via sequence numbers
- Non-repudiation via SessionReceipts

---

## Setup Instructions

### 1. Prerequisites
- Python 3.8+
- MySQL 8.0
- Git

### 2. Installation
```bash
# Clone repository
git clone https://github.com/Navairaa/securechat-skeleton.git
cd securechat-skeleton

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install cryptography pyOpenSSL pymysql python-dotenv mysql-connector-python pycryptodome
```

### 3. Database Setup
```sql
CREATE DATABASE securechat;
USE securechat;

CREATE TABLE users (
    email VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) UNIQUE,
    salt BINARY(16),
    pwd_hash CHAR(64)
);
```

Update `app/auth.py` with your MySQL password (line 7).

### 4. Generate Certificates
```bash
# Generate root CA
python scripts/gen_ca.py

# Generate server and client certificates
python scripts/gen_cert.py
```

---

## Running the Application

### Start Server
```bash
python app/server.py
```

### Start Client (in new terminal)
```bash
python app/client.py
```

Choose:
1. Register - Create new account
2. Login & Chat - Authenticate and start encrypted chat
3. Exit

---

## Testing

### 1. Wireshark Capture
- Start Wireshark, capture loopback traffic
- Filter: `tcp.port == 9000`
- Run chat session
- Verify: No plaintext visible

### 2. Invalid Certificate Test
```bash
python scripts/gen_fake_cert.py
python test_bad_cert.py
```
Expected: Server rejects with BAD_CERT

### 3. Tamper Test
```bash
python test_tamper.py
```
Expected: Server detects SIG_FAIL

### 4. Replay Test
```bash
python test_replay.py
```
Expected: Server detects REPLAY

### 5. Non-Repudiation
```bash
# After a chat session
python scripts/generate_receipt.py
python scripts/verify_receipt.py
```
Expected: Verification passes

---

## File Structure
```
securechat-skeleton/
├── app/
│   ├── server.py          # Server application
│   ├── client.py          # Client application
│   └── auth.py            # Authentication logic
├── scripts/
│   ├── gen_ca.py          # Generate root CA
│   ├── gen_cert.py        # Generate certificates
│   ├── generate_receipt.py # Create SessionReceipt
│   └── verify_receipt.py   # Verify SessionReceipt
├── certs/                 # Certificates (not committed)
├── transcripts/           # Chat logs and receipts
├── test_bad_cert.py       # Certificate rejection test
├── test_tamper.py         # Signature verification test
├── test_replay.py         # Replay detection test
└── README.md
```

---

## Security Features

| Feature | Implementation |
|---------|----------------|
| **Confidentiality** | AES-128 encryption with PKCS#7 padding |
| **Integrity** | SHA-256 hash + RSA signatures per message |
| **Authenticity** | X.509 mutual certificate validation |
| **Non-Repudiation** | Signed transcripts + SessionReceipts |
| **Replay Protection** | Strict sequence number enforcement |
| **Credential Security** | Salted SHA-256 hashing, encrypted transmission |

---

## Sample Output

### Registration
```
=== REGISTRATION ===
Email: test@example.com
Username: testuser
Password: ****

Registration successful
```

### Chat Session
```
==================================================
CHAT SESSION (type 'exit' to end)
==================================================
You: Hello!
Server: Server received: Hello!

You: This is encrypted
Server: Server received: This is encrypted
```

---

## Known Issues
- Deprecation warnings for datetime (safe to ignore)
- Server handles one client at a time (sequential, not concurrent)

---

## References
- SEED Security Lab - PKI
- Cryptography library documentation
- Course lecture materials