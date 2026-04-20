# 🔐 File Encryption & Secure File Sharing System

A web-based file encryption system built with **Flask + Fernet (AES)** encryption.

## Prerequisites

- Python 3.8 or higher
- pip

## Installation & Setup

### Step 1 — Install dependencies
```bash
pip install flask cryptography
```

### Step 2 — Run the application
```bash
python app.py
```

### Step 3 — Open in browser
```
http://127.0.0.1:5000
```

---

## 📁 Project Structure
```
file-encryption-system/
│
├── app.py                  ← Flask backend (auth + encrypt + decrypt routes)
├── templates/
│   ├── index.html          ← Dashboard (upload / encrypt / decrypt / file explorer)
│   ├── login.html          ← Login page
│   ├── register.html       ← Registration page
│   └── 404.html            ← Error page
│
├── static/
│   └── style.css           ← Dark glassmorphism UI styles
│
├── uploads/                ← Temporary uploaded files
├── encrypted/              ← AES-encrypted output files
└── decrypted/              ← Restored/decrypted files
```

---

## ⚙️ How It Works

1. **Register / Login** — Session-based authentication (in-memory for demo)
2. **Upload** — Upload any file (txt, pdf, image, docx, zip, etc.) — max 16 MB
3. **Encrypt** — A Fernet key (AES-128-CBC + HMAC-SHA256) is auto-generated and the file is encrypted. The key is shown **once** — save it!
4. **Download** — Encrypted file is unreadable binary; download it safely.
5. **Decrypt** — Paste the key to restore the original file.

---

## 🔒 Security Notes

| Feature | Detail |
|---|---|
| Encryption algorithm | Fernet (AES-128-CBC with HMAC-SHA256) |
| Key generation | `Fernet.generate_key()` — cryptographically secure |
| Key storage | Never saved on server — shown to user once |
| Password hashing | `werkzeug.security` (PBKDF2-SHA256) |
| File integrity | SHA-256 hash computed before & after encryption |
| Wrong key handling | `InvalidToken` exception caught gracefully |
| Upload validation | Extension whitelist + 16 MB size limit |

---

## 📦 Dependencies

```
flask
cryptography
werkzeug (included with flask)
```
