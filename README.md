# 🔐 Secure Chat System – CIANR Implementation

### **Information Security – Assignment A02**

**Submitted by:** Muhammad Salman Saleem (22I-0904)

**GitHub Repository:**
➡️ [https://github.com/salmansaleem08/securechat-skeleton](https://github.com/salmansaleem08/securechat-skeleton)

---

## 🧩 1. Project Description

This project implements a complete **secure client–server chat system** using **application‑layer cryptography**, without TLS/SSL.

It demonstrates:

* **Confidentiality** – AES‑128 Encryption
* **Integrity** – SHA‑256 Hashing
* **Authenticity** – X.509 Certificates + RSA Signatures
* **Non‑Repudiation** – Signed Session Receipt
* **Replay Protection** – Sequence Numbers + Timestamps

All cryptographic operations are manually implemented using Python libraries.

### 🔐 Security Workflow

1️⃣ Certificate Exchange (Control Plane)
2️⃣ Temporary DH → AES Key (Encrypted Registration/Login)
3️⃣ Session DH → Final AES Key (Chat Encryption)
4️⃣ Encrypted & Signed Messaging
5️⃣ Transcript Logging
6️⃣ Signed Receipt for Non‑Repudiation

---

## ⚙️ 2. System Requirements

### **Software**

| Component              | Version                         |
| ---------------------- | ------------------------------- |
| Windows 11             | ✔️                              |
| Python                 | 3.10+                           |
| MySQL                  | 8.x                             |
| Wireshark              | Latest                          |
| Npcap Loopback Adapter | Required for localhost captures |

### **Python Libraries**

Install using:

```
pip install -r requirements.txt
```

Modules include:

* cryptography
* pymysql
* python-dotenv
* base64
* json
* socket

---

## 📂 3. Project Structure (Detailed)

```
securechat-skeleton/
│
├── certs/                 # CA, server, client certificates & keys
│
├── scripts/
│   ├── gen_ca.py          # Generate Root CA
│   ├── gen_cert.py        # Issue X.509 certificates
│
├── crypto/
│   ├── aes_utils.py       # AES-128 CBC
│   ├── rsa_utils.py       # RSA sign/verify
│   ├── dh_utils.py        # Diffie–Hellman
│   └── hash_utils.py      # SHA-256
│
├── network/
│   ├── connection.py      # TCP networking
│   ├── server_main.py     # Server
│   └── client_main.py     # Client
│
├── server/
│   ├── auth_utils.py      # Hashing + salt
│   ├── login.py           # Encrypted login
│   └── register.py        # Encrypted registration
│
├── client/
│   └── messenger.py       # Encrypted messaging
│
├── transcripts/
│   ├── server_transcript.txt
│   ├── client_transcript.txt
│   └── receipt.json
│
├── tools/
│   └── verify_receipt.py  # Verify non-repudiation receipt
│
├── db/
│   ├── schema.sql         # MySQL
│   └── init_db.py         # Initialize DB
│
└── README.md
```

---

## 🔧 4. Configuration

### **4.1 Environment Setup**

Create `.env`:

```
copy .env.example .env
```

Set values:

```
DB_HOST=localhost
DB_USER=root
DB_PASS=yourpassword
DB_NAME=securechat
```

---

## 🔑 5. PKI Setup (Root CA + Certificates)

### **5.1 Generate Root CA**

```
python scripts/gen_ca.py
```

Creates:

* ca.key.pem
* ca.cert.pem

### **5.2 Issue Server Certificate**

```
python scripts/gen_cert.py --name server --cn "localhost"
```

### **5.3 Issue Client Certificate**

```
python scripts/gen_cert.py --name client --cn "client.local"
```

---

## 🛢 6. Database Setup (MySQL)

### **6.1 Create database**

```
CREATE DATABASE securechat;
```

### **6.2 Apply schema**

```
python db/init_db.py
```

Creates table:

```
email | username | salt | pwd_hash
```

---

## 💬 7. Running the Secure Chat System

### **7.1 Start Server**

```
python network/server_main.py
```

### **7.2 Start Client**

```
python network/client_main.py
```

---

## 🔐 8. Protocol Workflow (With Sample Inputs/Outputs)

### **8.1 Certificate Exchange**

Client → Server:

```
{
 "type": "hello",
 "client_cert": "<PEM>",
 "nonce": "Base64Nonce"
}
```

Server → Client:

```
{
 "type": "server_hello",
 "server_cert": "<PEM>",
 "nonce": "Base64Nonce"
}
```

### **8.2 Temporary Diffie–Hellman → K_temp**

DH Client:

```
{"A": 8, "p": 23, "g": 5}
```

DH Server:

```
{"B": 19}
```

Shared secret → SHA-256 → Truncated 16 bytes → **K_temp**.

### **8.3 Encrypted Registration/Login**

Encrypted:

```
{
 "type":"auth_encrypted",
 "iv":"base64",
 "ct":"base64"
}
```

### **8.4 Session DH → K_session**

```
K_session = Trunc16(SHA256(DH_shared_secret))
```

---

## ✉️ 9. Encrypted Messaging

```
{
 "type":"msg",
 "seqno":12,
 "ts":1731790000,
 "ct":"base64",
 "sig":"base64"
}
```

---

## 🧾 10. Non-Repudiation (Transcript + Receipt)

Transcript example:

```
12 | 1731790000 | ct | sig | fingerprint
```

Receipt:

```
{
 "first_seq": 1,
 "last_seq": 36,
 "transcript_sha256": "ab34d8...",
 "sig": "base64"
}
```

Verify:

```
python tools/verify_receipt.py transcripts/server_transcript.txt transcripts/server_receipt.json certs/server.cert.pem
```

---

## 🧪 11. Testing & Validation

| Test                   | Result |
| ---------------------- | ------ |
| Certificate validation | ✔ PASS |
| Invalid cert rejection | ✔ PASS |
| Temp DH handshake      | ✔ PASS |
| Encrypted login        | ✔ PASS |
| AES messaging          | ✔ PASS |
| RSA signatures         | ✔ PASS |
| Replay detection       | ✔ PASS |
| Tamper detection       | ✔ PASS |
| Receipt validation     | ✔ PASS |
| Wireshark inspection   | ✔ PASS |

---

## 🎯 12. Key Features Summary

* ✔ Custom Root CA
* ✔ X.509 certificate validation
* ✔ AES‑128 encryption
* ✔ Salted SHA‑256 passwords
* ✔ DH key exchange (Temp + Session)
* ✔ RSA signatures
* ✔ Replay protection
* ✔ Non‑repudiation receipts
* ✔ Transcript verification tool
* ✔ Wireshark testing

---

## 📌 13. Known Limitations

* Console-based UI
* No certificate revocation (no CRL/OCSP)
* Not for production use
* Single session per client

---

## 👨‍💻 14. Author

**Muhammad Salman Saleem**
Roll Number: **22I-0904**
FAST NUCES – Islamabad Campus
Information Security – Fall 2025

---

## 📜 15. License

**Academic use only.** Do not use provided keys/certificates in real-world systems.
