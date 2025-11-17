# SecureChat – End-to-End Encrypted Client/Server Messaging System

A secure chat application implemented using raw cryptographic primitives **without TLS**.  
Developed for **CS-3002: Information Security – Assignment 2**.

**Author:** Hammad Amer  
**Roll No:** 22i-0877

---

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Setup & Installation](#setup--installation)
- [Database Schema](#database-schema)
- [Generating Certificates & DH Parameters](#generating-certificates--dh-parameters)
- [Running the System](#running-the-system)
- [How the Protocol Works (High-level)](#how-the-protocol-works-high-level)
- [Testing Procedures (Wireshark, Tampering, Replay, Receipt)](#testing-procedures-wireshark-tampering-replay-receipt)
- [MySQL Dumps](#mysql-dumps)
- [Files Produced (transcripts & receipts)](#files-produced-transcripts--receipts)
- [Security Notes & Best Practices](#security-notes--best-practices)
- [Author](#author)
- [License & Purpose](#license--purpose)

---

## Features

- Custom PKI (self-signed CA, client & server certificates)  
- Mutual certificate authentication  
- Ephemeral Diffie–Hellman key exchange (DH)  
- AES-128 CBC encryption for message confidentiality  
- RSA signatures for integrity and non-repudiation  
- Replay-attack prevention using monotonically increasing sequence numbers  
- Session transcripts + digitally signed receipts for non-repudiation

---

## Project Structure

```
securechat-skeleton/
│
├── app/
│   ├── server.py          # Server application (main)
│   ├── client.py          # Client application (main)
│   └── security_utils.py  # Crypto primitives (DH, AES, RSA, hashing)
│
├── certs/                 # Generated keys & certs
│   ├── ca.key
│   ├── ca.crt.pem
│   ├── server.key
│   ├── server.crt.pem
│   ├── client.key
│   └── client.crt.pem
│
├── scripts/
│   ├── gen_ca.py
│   ├── gen_cert.py
│   └── gen_dh_params.py
│
├── verify_transcript.py   # Verifies signed receipts against transcripts
├── config.py              # Database credentials (gitignored)
├── README.md              # This file
└── requirements.txt       # Python dependencies (optional)
```

---

## Prerequisites

System packages (Debian/Ubuntu/Kali):
```bash
sudo apt update
sudo apt -y upgrade
sudo apt install -y git mariadb-server python3-venv
```

Python packages (inside virtualenv):
```bash
python3 -m venv venv
source venv/bin/activate
pip install cryptography mysql-connector-python
```

---

## Setup & Installation

1. Clone repository (if not already):
```bash
git clone https://github.com/adilnadeem02/securechat-skeleton.git
cd securechat-skeleton
```

2. Create a Python virtual environment and install packages:
```bash
python3 -m venv venv
source venv/bin/activate
pip install cryptography mysql-connector-python
```

3. Secure MariaDB (recommended):
```bash
sudo mariadb-secure-installation
```
Recommended choices:
- Set root password → **Yes**
- Remove anonymous users → **Yes**
- Disallow remote root login → **Yes**
- Remove test DB → **Yes**

4. Create database and table (adjust names if necessary):
```bash
sudo mariadb -u root -p <<'SQL'
CREATE DATABASE IF NOT EXISTS secure_chat;
USE secure_chat;
CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    PRIMARY KEY (email)
);
SQL
```

5. Add your DB credentials to `config.py` (create file if missing) and keep it in `.gitignore`:
```python
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'YOUR_DB_PASSWORD',
    'database': 'secure_chat'
}
```

---

## Database Schema

The primary table used by the application:

```sql
CREATE TABLE users (
    email VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    PRIMARY KEY (email)
);
```

---

## Generating Certificates & DH Parameters

Run the helper scripts from project root:

1. Generate root CA (4096-bit key):
```bash
python3 scripts/gen_ca.py
```

2. Issue server certificate (Common Name should match what server expects, usually `localhost`):
```bash
python3 scripts/gen_cert.py server localhost
```

3. Issue client certificate (Common Name should match what server checks, e.g. `client.user`):
```bash
python3 scripts/gen_cert.py client client.user
```

4. Generate Diffie–Hellman (DH) parameters (2048-bit — may be slow):
```bash
python3 scripts/gen_dh_params.py
```

> Note: `gen_dh_params.py` may take from ~10s to a few minutes depending on CPU. You can also use RFC group 14 fixed parameters to avoid the long generation step.

---

## Running the System

> **Important:** Run commands from the project root so imports resolve correctly.

1. Ensure `app` is treated as a package (create `__init__.py` if missing):
```bash
touch app/__init__.py
```

2. Start server (recommended: run as module so Python's package system works):
```bash
python3 -m app.server
```
You should see:
```
DB: connected
Server listening on localhost:65432
```

3. In another terminal (same project root), start client:
```bash
python3 -m app.client
```

4. Follow interactive prompts: `register` → `login` → send chat messages → `logout`.

---

## How the Protocol Works (High-level)

1. **Mutual Certificate Exchange**  
   - Server sends its X.509 certificate; client verifies it against the CA.  
   - Client sends its certificate; server verifies it against the CA.

2. **Control-Plane DH**  
   - Ephemeral DH exchange to establish a temporary AES control key used for registration/login messages.

3. **Registration / Login**  
   - Client generates 16-byte salt and computes `pwd_hash = SHA256(salt || password)`.  
   - Server stores salt + hash. For login, client requests salt and submits the same computed hash.

4. **Session DH**  
   - After authentication, a second DH exchange establishes the session AES key used for encrypted chat.

5. **Message Format & Protection**  
   - Each chat message is encrypted using AES-128-CBC (IV + ciphertext).  
   - Client computes `digest = SHA256(seq_no || timestamp || ciphertext)`, signs `digest` with RSA private key, and sends `(seq_no, ts, ciphertext, signature)` (ciphertext and signature hex-encoded).  
   - Server verifies signature, checks sequence monotonicity, then decrypts message.

6. **Transcript & Non-Repudiation**  
   - Both sides append all session events to transcript files. On logout they hash the transcript and sign the hash, producing `SessionReceipt.json`. These receipts are verifiable offline with `verify_transcript.py`.

---

## Testing Procedures (Wireshark, Tampering, Replay, Receipt)

### Test 1 — Wireshark (Confidentiality)
- Start Wireshark and choose the loopback interface (`lo`).
- Apply filter: `tcp.port == 65432`.
- Perform a full session (`register`, `login`, `chat`, `logout`).
- Verify packet payloads are non-readable (hex view). This confirms encryption.

### Test 2 — Invalid Certificate Rejection (Authenticity)
- Create a self-signed certificate (not signed by the project's CA):
  ```bash
  openssl req -x509 -newkey rsa:2048 -nodes -keyout bad.key -out bad.crt.pem -subj "/CN=BadClient"
  ```
- Replace `certs/client.crt.pem` and `certs/client.key` with the bad cert/key temporarily.
- Run client; server should reject the certificate during handshake and log a verification failure.

### Test 3 — Message Tampering Detection (Integrity)
- Modify client to corrupt one byte of the hex-encoded signature before sending (or intercept and flip a byte).
- Send a message; server should detect signature mismatch and ignore the message.

### Test 4 — Replay Attack Handling (Integrity)
- Send the same encrypted, signed message twice with identical `seqno`.
- Server should accept the first and reject the second with a replay detection log.

### Test 5 — Receipt Verification (Non-Repudiation)
- After a session, both client and server will save receipts and transcripts.
- Verify:
  ```bash
  python3 verify_transcript.py client_receipt.json client_transcript.log
  ```
- For tampering test: append a line to the transcript and re-run the verification — it should report a hash mismatch.

---

## MySQL Dumps

Export schema only (no data):
```bash
mysqldump -u root -p --no-data secure_chat > schema_dump.sql
```

Export data only (INSERT statements):
```bash
mysqldump -u root -p --no-create-info secure_chat > sample_records.sql
```

Full dump (schema + data):
```bash
mysqldump -u root -p secure_chat > full_dump.sql
```

---

## Files Produced (transcripts & receipts)

During/after sessions the following files are generated:

- `client_transcript.log` — transcript of client-side events
- `server_transcript_<ip>_<port>.log` — transcript of server-side events
- `client_receipt.json` — signed receipt by client over its transcript
- `server_receipt_<ip>_<port>.json` — signed receipt by server over its transcript

Use `verify_transcript.py` to validate a receipt against its transcript.

---

## Security Notes & Best Practices

- This project is for educational purposes. For production use, rely on well-tested protocols (e.g., TLS) and vetted libraries.
- **Never commit private keys** (`certs/*.key`) or DB passwords to public repositories.
- Protect `config.py` (database credentials) and add it to `.gitignore`.
- Use sufficiently strong passwords and store them safely.
- Validate certificate CN and other identity fields as needed for your deployment.

---

## Author

**Hammad Amer**  
Roll No. **22i-0877**

---

## License & Purpose

This project was created for an academic assignment and is intended for learning and demonstration only. Use responsibly and do not reuse private keys or test data in production.
