# 🔐 Secure Chat System (CIANR)

### **Client–Server Secure Communication Protocol**

**Author:** Muhammad Salman Saleem (22I-0904)
**Course:** Information Security — Assignment A02

---

## 📌 Overview

This project implements a **fully secure chat system** using modern cryptographic techniques **without relying on TLS/SSL**. All security mechanisms are implemented at the **application layer**.

The system ensures:

* **Confidentiality**
* **Integrity**
* **Authenticity**
* **Non-Repudiation**
* **Replay Protection**

Collectively known as **CIANR**.

### ✔ Key Security Features

* Custom **Root Certificate Authority (CA)**
* **X.509 certificate** creation & validation
* **AES-128 encrypted** registration & login
* Salted **SHA-256 password hashing**
* **Two-stage Diffie–Hellman (DH)** key exchange
* Encrypted + **RSA-signed messages**
* Replay prevention using **sequence numbers**
* **Non-repudiation** using signed session receipts
* Verified via **Wireshark** (no plaintext leakage)

---

## 📁 Project Structure

```
securechat-skeleton/
│
├── certs/                 # Certificates & private keys
│
├── scripts/
│   ├── gen_ca.py          # Create Root CA
│   ├── gen_cert.py        # Issue certificates
│
├── crypto/
│   ├── aes_utils.py       # AES-128 CBC + PKCS#7
│   ├── dh_utils.py        # Diffie–Hellman utilities
│   ├── rsa_utils.py       # RSA signatures
│   └── hash_utils.py      # SHA-256 utilities
│
├── db/
│   ├── schema.sql         # MySQL schema
│   └── init_db.py         # Initialize DB
│
├── server/
│   ├── server_main.py     # Main server program
│   ├── register.py        # User registration
│   ├── login.py           # Login handler
│   └── auth_utils.py      # Salt + hashing
│
├── client/
│   ├── client_main.py     # Client program
│   └── messenger.py       # Message encryption + signing
│
├── network/
│   ├── connection.py      # TCP socket wrapper
│
├── transcripts/
│   ├── client_transcript.txt
│   ├── server_transcript.txt
│   └── receipts/
│
├── tools/
│   ├── verify_receipt.py  # Receipt verification
│
└── README.md
```

---

## 🏗 Installation

### **1️⃣ Clone the repository**

```
git clone https://github.com/<your-username>/securechat-skeleton
cd securechat-skeleton
```

### **2️⃣ Create virtual environment**

```
python -m venv .venv
.venv\Scripts\activate   # For Windows
```

### **3️⃣ Install dependencies**

```
pip install -r requirements.txt
```

### **4️⃣ Setup environment file (.env)**

```
copy .env.example .env
```

Fill in:

* MySQL host
* Username
* Password
* Database name

---

## 🔑 PKI Setup (Root CA + Certificates)

### **Generate Root Certificate Authority**

```
python scripts/gen_ca.py
```

Creates:

* `certs/ca.key.pem`
* `certs/ca.cert.pem`

### **Generate Server Certificate**

```
python scripts/gen_cert.py --name server --cn "localhost"
```

### **Generate Client Certificate**

```
python scripts/gen_cert.py --name client --cn "client.local"
```

> All private keys stay inside `certs/` and are ignored by Git.

---

## 🛢 Database Setup

### **Create database:**

```
CREATE DATABASE securechat;
```

### **Import schema:**

```
python db/init_db.py
```

This creates the users table:

```
users(email, username, salt, pwd_hash)
```

---

## 🔐 Registration & Login (Encrypted)

### Security Steps:

1. Temporary DH exchange → **K_temp**
2. Credentials encrypted with **AES-128 CBC**
3. Password hashed: `SHA256(salt || password)`

### Run Registration

```
python server/register.py
```

### Run Login

```
python server/login.py
```

---

## 🗝 Session Key Exchange

After login, a second DH exchange produces:

```
K_session = Trunc16(SHA256(DH_shared_secret))
```

This key encrypts all chat messages.

---

## 💬 Encrypted Messaging (CIAN)

Every message transmitted includes:

* AES-128 ciphertext (`ct`)
* SHA-256 hash: `h = SHA256(seqno || ts || ct)`
* RSA signature: `sig = SIGN(h)`

### **Message JSON format:**

```
{
  "type": "msg",
  "seqno": 12,
  "ts": 1731780000,
  "ct": "base64",
  "sig": "base64"
}
```

---

## 🚀 Run Chat Application

### **Start server:**

```
python network/server_main.py
```

### **Start client:**

```
python network/client_main.py
```

Then:

* Login / Register
* Chat securely
* End session → receipt generated

---

## 🧾 Non-Repudiation

Both parties keep transcripts:

```
seqno | ts | ct | sig | cert-fingerprint
```

A final signed receipt is generated:

```
{
  "first_seq": 1,
  "last_seq": 14,
  "transcript_sha256": "<hex>",
  "sig": "<RSA signature>"
}
```

### **Verify receipt:**

```
python tools/verify_receipt.py transcripts/server_transcript.txt transcripts/server_receipt.json certs/server.cert.pem
```

---

## 🧪 Testing & Wireshark Evidence

| Test                               | Status |
| ---------------------------------- | ------ |
| Certificate validation             | ✔ PASS |
| Invalid certificate detection      | ✔ PASS |
| Encrypted registration             | ✔ PASS |
| Encrypted login                    | ✔ PASS |
| Temporary DH exchange              | ✔ PASS |
| Session DH exchange                | ✔ PASS |
| AES encrypted chat                 | ✔ PASS |
| RSA signature verification         | ✔ PASS |
| Replay attack detection            | ✔ PASS |
| Tamper detection                   | ✔ PASS |
| Transcript + receipt               | ✔ PASS |
| Offline receipt verification       | ✔ PASS |
| Zero plaintext leakage (Wireshark) | ✔ PASS |

All screenshots are included in the Test Report.

---

## 🎯 Features Summary

* ✔ Custom PKI (CA + X.509 certs)
* ✔ AES-128 encryption
* ✔ Salted SHA-256 hashing
* ✔ Two-stage Diffie–Hellman
* ✔ RSA digital signatures
* ✔ Replay protection
* ✔ Secure transcript + receipts
* ✔ Manual tamper/replay testing
* ✔ No plaintext leakage (verified)

---

## 👨‍💻 Author

**Muhammad Salman Saleem**
FAST NUCES — Roll No: **22I-0904**

---

## 📜 License

This project is created for academic purposes for **Information Security — Assignment A02**.
Do **not** reuse keys, salts, or certificates in production.
