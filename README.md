
# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository is the **official code skeleton** for your Assignment #2.  
You will build a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.


## 🧩 Overview

You are provided only with the **project skeleton and file hierarchy**.  
Each file contains docstrings and `TODO` markers describing what to implement.

Your task is to:
- Implement the **application-layer protocol**.
- Integrate cryptographic primitives correctly to satisfy the assignment spec.
- Produce evidence of security properties via Wireshark, replay/tamper tests, and signed session receipts.

## 🏗️ Folder Structure
```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark evidence checklist
├─ certs/.keep               # Local certs/keys (gitignored)
├─ transcripts/.keep         # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Minimal dependencies
└─ .github/workflows/ci.yml  # Compile-only sanity check (no execution)
```

## ⚙️ Setup Instructions

1. **Fork this repository** to your own GitHub account(using official nu email).  
   All development and commits must be performed in your fork.

2. **Set up environment**:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```

3. **Initialize MySQL** (recommended via Docker):
   ```bash
   docker run -d --name securechat-db        -e MYSQL_ROOT_PASSWORD=rootpass        -e MYSQL_DATABASE=securechat        -e MYSQL_USER=scuser        -e MYSQL_PASSWORD=scpass        -p 3306:3306 mysql:8
   ```

4. **Create tables**:
   ```bash
   python -m app.storage.db --init
   ```

5. **Generate certificates** (after implementing the scripts):
   ```bash
   python scripts/gen_ca.py --name "FAST-NU Root CA"
   python scripts/gen_cert.py --cn server.local --out certs/server
   python scripts/gen_cert.py --cn client.local --out certs/client
   ```

6. **Run components** (after implementation):
   ```bash
   python -m app.server
   # in another terminal:
   python -m app.client
   ```

## 🚫 Important Rules

- **Do not use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations must occur **explicitly** at the application layer.

- You are **not required** to implement AES, RSA, or DH math, Use any of the available libraries.
- Do **not commit secrets** (certs, private keys, salts, `.env` values).
- Your commits must reflect progressive development — at least **10 meaningful commits**.

## 🧾 Deliverables

When submitting on Google Classroom (GCR):

1. A ZIP of your **GitHub fork** (repository).
2. MySQL schema dump and a few sample records.
3. Updated **README.md** explaining setup, usage, and test outputs.
4. `RollNumber-FullName-Report-A02.docx`
5. `RollNumber-FullName-TestReport-A02.docx`

## 🧪 Test Evidence Checklist

✔ Wireshark capture (encrypted payloads only)  
✔ Invalid/self-signed cert rejected (`BAD_CERT`)  
✔ Tamper test → signature verification fails (`SIG_FAIL`)  
✔ Replay test → rejected by seqno (`REPLAY`)  
✔ Non-repudiation → exported transcript + signed SessionReceipt verified offline  

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.10+
- MySQL 8.0
- Docker (optional, for MySQL)

### Step 1: Environment Setup

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env  # Or use the provided .env file
```

### Step 2: Start MySQL Database

**Option A: Using Homebrew MySQL (Recommended for macOS)**

```bash
# Install MySQL
brew install mysql

# Start MySQL service
brew services start mysql

# Run automated setup script
./scripts/setup_mysql.sh
```

Or manually:
```bash
# Secure installation
mysql_secure_installation

# Login and create database
mysql -u root -p

# Run these SQL commands:
CREATE DATABASE securechat;
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

**Option B: Using Docker**
```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8
```

📖 **Detailed MySQL setup guide:** See [SETUP_MYSQL.md](SETUP_MYSQL.md)

### Step 3: Initialize Database

```bash
python -m app.storage.db --init
```

Expected output:
```
✅ Database initialized successfully!
   Table 'users' created with schema:
   - email VARCHAR(255) PRIMARY KEY
   - username VARCHAR(255) UNIQUE
   - salt VARBINARY(16)
   - pwd_hash CHAR(64)
```

### Step 4: Generate Certificates

```bash
# Generate Root CA
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Generate server certificate
python scripts/gen_cert.py --cn server.local --out certs/server

# Generate client certificate
python scripts/gen_cert.py --cn client.local --out certs/client
```

Expected output for each command:
```
Generating RSA 2048-bit key pair...
Creating X.509 certificate...
✓ Private key saved to: certs/...
✓ Certificate saved to: certs/...
✅ Certificate created successfully!
```

### Step 5: Run the Application

**Terminal 1 - Start Server:**
```bash
python -m app.server
```

**Terminal 2 - Start Client:**
```bash
python -m app.client
```

---

## 📋 Usage Instructions

### First Time User (Registration)

1. Start the client
2. Choose `register` when prompted
3. Enter email, username, and password
4. Start chatting!

### Returning User (Login)

1. Start the client
2. Choose `login` when prompted (default)
3. Enter email and password
4. Start chatting!

### Chat Commands

- Type any message to send
- `/quit` or `/exit` - Close session and exchange receipts

---

## 🧪 Testing Security Properties

### Test 1: Encrypted Communication (Wireshark)

1. Start Wireshark and capture on loopback interface (lo0 on macOS)
2. Filter: `tcp.port == 5000`
3. Start server and client, send messages
4. **Expected:** All message payloads are base64-encoded ciphertext, no plaintext visible

### Test 2: Invalid Certificate (BAD_CERT)

```bash
# Create a self-signed certificate (not signed by CA)
openssl req -x509 -newkey rsa:2048 -keyout bad.key -out bad.crt -days 365 -nodes -subj "/CN=bad.local"

# Temporarily replace client.crt with bad.crt
cp certs/client.crt certs/client.crt.backup
cp bad.crt certs/client.crt

# Run client - should fail with BAD_CERT error
python -m app.client
```

**Expected output:**
```
✗ BAD_CERT: Client certificate validation failed
```

### Test 3: Signature Tampering (SIG_FAIL)

To test this, you would need to modify the client code temporarily to flip a bit in the ciphertext before sending. This will cause signature verification to fail on the server.

**Expected server output:**
```
✗ SIG_FAIL: Signature verification failed
```

### Test 4: Replay Attack (REPLAY)

To test replay protection:
1. Capture a message JSON from Wireshark
2. Resend the same message with the same sequence number
3. Server should reject it

**Expected server output:**
```
✗ REPLAY: seqno X <= Y
```

### Test 5: Non-Repudiation (Session Receipt)

After a chat session ends:

1. Check `transcripts/` directory for saved transcripts
2. Check for `*_receipt.json` files
3. Verify receipt signature matches transcript hash

**Files created:**
- `transcripts/client_session_XXXXX.txt` - Client transcript
- `transcripts/client_session_XXXXX_receipt.json` - Client receipt
- `transcripts/server_session_XXXXX.txt` - Server transcript

---

## 🔐 Security Properties Implemented

### ✅ Confidentiality
- **AES-128 ECB** with PKCS#7 padding for message encryption
- **Two-phase DH key exchange:**
  - Temporary key for credentials (registration/login)
  - Session key for chat messages
- Key derivation: `K = Trunc16(SHA256(big_endian(Ks)))`

### ✅ Integrity
- **SHA-256** digest of `seqno || ts || ciphertext`
- Digest is signed with RSA private key
- Any tampering causes signature verification to fail

### ✅ Authenticity
- **X.509 certificates** issued by Root CA
- **Mutual certificate validation:**
  - CA signature verification
  - Validity period check
  - CN/SAN matching
- **RSA PKCS#1 v1.5** signatures on all messages

### ✅ Non-Repudiation
- **Append-only transcripts** with format: `seqno|ts|ct|sig|peer_fingerprint`
- **Transcript hash:** SHA-256 of entire transcript
- **Session receipts:** Signed transcript hash exchanged at session end
- Receipts can be verified offline using peer's public key

### ✅ Replay Protection
- **Strictly increasing sequence numbers**
- Server/client reject messages with `seqno <= last_seqno`
- Timestamp validation (messages with old timestamps can be rejected)

---

## 📁 Project Structure

```
securechat-skeleton-main/
├── app/
│   ├── client.py              ✅ Client application (full protocol)
│   ├── server.py              ✅ Server application (full protocol)
│   ├── common/
│   │   ├── protocol.py        ✅ Pydantic message models
│   │   └── utils.py           ✅ Helper functions
│   ├── crypto/
│   │   ├── aes.py             ✅ AES-128 ECB + PKCS#7
│   │   ├── dh.py              ✅ Diffie-Hellman + key derivation
│   │   ├── pki.py             ✅ X.509 certificate validation
│   │   └── sign.py            ✅ RSA PKCS#1 v1.5 signatures
│   └── storage/
│       ├── db.py              ✅ MySQL user authentication
│       └── transcript.py      ✅ Append-only transcripts
├── scripts/
│   ├── gen_ca.py              ✅ Root CA generation
│   └── gen_cert.py            ✅ Certificate issuance
├── certs/                     (gitignored - generated locally)
├── transcripts/               (gitignored - session logs)
├── .env                       ✅ Environment configuration
└── requirements.txt           ✅ Python dependencies
```

---

## 🐛 Troubleshooting

### MySQL Connection Error
```
Error: Can't connect to MySQL server
```
**Solution:** Ensure MySQL is running and credentials in `.env` match your setup.

### Certificate Not Found
```
FileNotFoundError: [Errno 2] No such file or directory: 'certs/ca.crt'
```
**Solution:** Run the certificate generation scripts (Step 4 above).

### Import Errors
```
ModuleNotFoundError: No module named 'app'
```
**Solution:** Ensure you're running from the project root directory and virtual environment is activated.

### Port Already in Use
```
OSError: [Errno 48] Address already in use
```
**Solution:** Change `SERVER_PORT` in `.env` or kill the process using port 5000.

---

## 📝 Assignment Deliverables Checklist

- [x] Implemented all cryptographic primitives (AES, DH, RSA, PKI)
- [x] Implemented protocol message models
- [x] Implemented client and server applications
- [x] MySQL user authentication with salted SHA-256
- [x] Append-only transcripts with signed receipts
- [x] Certificate generation scripts
- [x] Replay protection (sequence numbers)
- [x] Signature verification (tamper detection)
- [x] Certificate validation (BAD_CERT errors)
- [x] Non-repudiation (session receipts)
- [X] Wireshark capture evidence
- [X] Test report with all security property tests
- [X] MySQL schema dump
- [X] Final report document

---

## 👨‍💻 Development Notes

### Code Quality
- All modules follow PEP8 style guidelines
- Comprehensive docstrings for all functions
- Type hints where applicable
- Error handling with clear error codes

### Security Considerations
- **NO TLS/SSL** - All crypto at application layer as required
- Private keys stored unencrypted (assignment context only)
- Certificates in `certs/` are gitignored
- Environment variables for sensitive configuration

### Testing Approach
- Manual testing with Wireshark for encryption verification
- Tamper tests by modifying ciphertext
- Replay tests by resending captured messages
- Certificate validation tests with invalid certs

---

## 📚 References

- Python `cryptography` library documentation
- RFC 8017 (PKCS#1 v1.5)
- X.509 Certificate standards
- Diffie-Hellman key exchange
- AES encryption modes

