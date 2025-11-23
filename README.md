# Secure Client-Server Chat System

**Course:** Information Security (Fall 2025)  
**University:** National University of Computer and Emerging Sciences (FAST-NUCES)  
**Author:** Saifullah

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)

---

## 1. Project Overview

This project is a complete, from-scratch implementation of a secure client-server chat system for the Information Security assignment. [cite_start]The primary objective is to build a cryptographic protocol that achieves all **CIANR** (Confidentiality, Integrity, Authenticity, and Non-Repudiation) goals without relying on any high-level abstractions like TLS/SSL[cite: 17, 265].

All security controls, including certificate exchange, key agreement, and authenticated encryption, are implemented at the application layer.

### Key Security Features

* [cite_start]**Public Key Infrastructure (PKI):** A custom Root Certificate Authority (CA) is used to issue and sign RSA-2048 X.509 certificates for the client and server [cite: 153-154].
* [cite_start]**Mutual Authentication:** The server and client perform a mutual certificate exchange and validation upon connection, preventing unauthorized access and MitM attacks [cite: 159-166].
* [cite_start]**Confidentiality:** All sensitive payloads (login credentials and chat messages) are encrypted using **AES-128** with a key derived from a secure Diffie-Hellman exchange[cite: 105, 178].
* **Secure Credential Handling:** User passwords are never stored in plaintext. [cite_start]They are stored in a MySQL database as a salted **SHA-256 hash** [cite: 172, 181-182].
* **Secure Key Exchange:** The protocol uses a **two-phase Diffie-Hellman (DH)** exchange:
    1.  [cite_start]A temporary DH exchange to establish an ephemeral key for encrypting login credentials[cite: 175].
    2.  [cite_start]A main DH exchange after login to establish the long-lived session key for the chat[cite: 193].
* **Integrity & Authenticity:** Every chat message is individually signed with the sender's RSA private key. [cite_start]The signature is computed over a hash of the message's sequence number, timestamp, and ciphertext[cite: 107, 111].
* [cite_start]**Replay Protection:** The server enforces a strictly increasing sequence number (`seqno`) for all messages, rejecting any replayed or out-of-order packets[cite: 113, 212].
* **Non-Repudiation:** Both client and server maintain an append-only transcript of the session. [cite_start]At closure, a final hash of this transcript is signed to create a verifiable `SessionReceipt`[cite: 128, 130].

---

## 2. Project Structure

The project follows a modular structure to separate concerns:

```
securechat-skeleton/
├── app/
│   ├── common/
│   │   ├── protocol.py   # Pydantic models for all JSON messages
│   │   └── utils.py      # Helper functions (hashing, base64, etc.)
│   ├── crypto/
│   │   ├── aes.py        # AES-128 encryption/decryption
│   │   ├── dh.py         # Diffie-Hellman key exchange
│   │   ├── pki.py        # X.509 certificate validation
│   │   └── sign.py       # RSA signature generation/verification
│   ├── storage/
│   │   ├── db.py         # MySQL database connection and user logic
│   │   └── transcript.py # Session transcript and receipt logic
│   ├── client.py         # Main client application logic
│   └── server.py         # Main server application logic
├── certs/
│   └── .gitignore        # (Holds generated keys/certs, ignored by Git)
├── scripts/
│   ├── gen_ca.py         # Script to create the Root CA
│   ├── gen_cert.py       # Script to issue client/server certificates
│   └── gen_self_signed.py # (For testing)
├── transcripts/
│   └── .gitignore        # (Holds generated logs/receipts, ignored by Git)
├── .env                  # (Local environment variables, ignored by Git)
├── .env.example          # Example environment file
├── requirements.txt      # Python dependencies
├── schema_dump.sql       # MySQL database schema
├── verify.py             # Script for Non-Repudiation test
└── README.md             # This file
```

---

## 3. Tech Stack

* **Python 3.11+**
* **`cryptography`**: For all cryptographic primitives (RSA, AES, DH, SHA-256, X.509).
* **`pydantic`**: For robust JSON protocol message definition and validation.
* **`mysql-connector-python`**: For connecting to the MySQL/MariaDB database.
* **`python-dotenv`**: For securely managing database credentials.

---

## 4. Setup and Installation

Follow these steps to set up and run the project locally.

### Step 1: Clone the Repository

```bash
# !!! REPLACE WITH YOUR GITHUB REPO URL !!!
git clone [https://github.com/YOUR-USERNAME/securechat-skeleton.git](https://github.com/YOUR-USERNAME/securechat-skeleton.git)
cd securechat-skeleton
```

### Step 2: Set Up Python Environment

```bash
# Create a virtual environment
python3 -m venv venv

# Activate the environment
source venv/bin/activate

# Install all required dependencies
pip install -r requirements.txt
```

### Step 3: Set Up the Database (MariaDB/MySQL)

1.  Ensure you have a MySQL or MariaDB server running.
2.  Log in as the root user:
    ```bash
    sudo mysql -u root -p
    ```
3.  Create the database:
    ```sql
    CREATE DATABASE secure_chat;
    exit;
    ```
4.  Load the table schema from the dump file:
    ```bash
    mysql -u root -p secure_chat < schema_dump.sql
    ```

### Step 4: Configure Environment

1.  Copy the example environment file:
    ```bash
    cp .env.example .env
    ```
2.  Edit the `.env` file with your database password:
    ```ini
    # .env
    DB_USER=root
    DB_PASSWORD=YOUR_ROOT_PASSWORD_HERE
    DB_HOST=127.0.0.1
    DB_NAME=secure_chat
    ```

### Step 5: Generate Certificates

Run the PKI scripts in order to create your Root CA and issue certificates.

```bash
# 1. Create the Root CA
python3 scripts/gen_ca.py

# 2. Issue the server certificate
python3 scripts/gen_cert.py server

# 3. Issue the client certificate
python3 scripts/gen_cert.py client
```
The `certs/` folder will now contain all 6 required `.pem` files.

---

## 5. Execution

You will need two separate terminals, both with the virtual environment activated (`source venv/bin/activate`).

### Terminal 1: Run the Server

```bash
python3 -m app.server
```
**Expected Output:**
```
--- SecureChat Server ---
Loading PKI credentials...
[*] Server listening on 127.0.0.1:65432
```

### Terminal 2: Run the Client

```bash
python3 -m app.client
```
**Expected Output:**
The client will connect, perform the certificate exchange, and then prompt you for action.

```
--- SecureChat Client ---
Loading PKI credentials...
Connecting to 127.0.0.1:65432...
[+] Connected!
...
[+] Temporary AES key established.
[+] --- Authentication ---
Do you want to (1) Register or (2) Login? [1/2]:
```

1.  You must **Register** a user first.
2.  After registration, restart the client and **Login** with your new credentials.
3.  You will then be able to send encrypted and signed messages to the server.
4.  Type `!!exit` to end the chat and generate the `SessionReceipt`.

---

## 6. Testing & Evidence

The system was validated against all test cases required by the assignment.

Detailed analysis and screenshots for all tests are available in the **`TestReport.docx`** file.

* **Wireshark Test:** Confirmed all login and chat payloads are encrypted.
* **Invalid Certificate Test:** Server correctly logged `BAD_CERT` and rejected a self-signed certificate.
* **Tampering Test:** Server correctly logged `SIG_FAIL` and rejected a message with a corrupted signature.
* **Replay Test:** Server correctly logged `REPLAY` and rejected a message with a duplicate sequence number.
* **Non-Repudiation Test:** The `verify.py` script successfully validated the signed `SessionReceipt` against the transcript and detected tampering in a modified log.