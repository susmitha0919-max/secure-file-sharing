# Secure File Sharing Using Encryption

A web application that lets users upload files, encrypts them with AES
before storing them, and lets the owner grant specific other users
permission to decrypt and download them.

---

## 1. Project Plan

| Layer                | Choice                                   | Why |
|-----------------------|-------------------------------------------|-----|
| Programming Language  | **Python 3**                              | Simple, readable, excellent library support for both web (Flask) and cryptography. Great for a project write-up/viva too. |
| Web Framework          | **Flask**                                 | Lightweight, quick to set up, perfect for a focused project like this (vs. a heavier framework like Django). |
| Database                | **SQLite** (via SQLAlchemy)               | Zero setup — it's just a file, no server to install. SQLAlchemy means you can switch to **MySQL/PostgreSQL** later by changing one line in `config.py`, with no other code changes. |
| Encryption Algorithm    | **AES** (128-bit, via the `Fernet` recipe from Python's `cryptography` library) | AES is the industry-standard symmetric cipher. Fernet wraps AES-CBC with an HMAC integrity check, so tampering/corruption is automatically detected — safer than hand-rolling AES yourself. |
| Authentication           | **Flask-Login** + salted password hashing (Werkzeug) | Standard, well-tested session-based login system. |
| Frontend                  | **HTML + Bootstrap 5** (via Jinja2 templates) | Clean UI with minimal custom CSS needed. |

### Architecture (Envelope Encryption)

```
                 ┌─────────────────────────────────────────────┐
                 │                 UPLOAD                        │
Original File →  │ 1. Generate random AES key (per file)         │
                 │ 2. Encrypt file with that key                 │
                 │ 3. Encrypt that key with the MASTER_KEY        │
                 │ 4. Save encrypted file → disk                  │
                 │ 5. Save wrapped key + metadata → database       │
                 └─────────────────────────────────────────────┘

                 ┌─────────────────────────────────────────────┐
                 │                DOWNLOAD                        │
Authorized user → │ 1. Check user is owner OR has been granted access │
                 │ 2. Read encrypted file from disk                │
                 │ 3. Unwrap the per-file key using MASTER_KEY       │
                 │ 4. Decrypt the file in memory                     │
                 │ 5. Stream decrypted bytes to the browser            │
                 │    (never written back to disk unencrypted)         │
                 └─────────────────────────────────────────────┘
```

This gives you the three things the project brief asks for:

- **Confidentiality** — files are stored on disk only in AES-encrypted form.
- **Secure transmission** — decryption happens only in memory, right before
  streaming the download response; deploy behind HTTPS for a secure transport
  layer end-to-end.
- **Controlled access** — a file can only be decrypted by its owner or by a
  user the owner has explicitly granted access to, tracked in the
  `file_access` database table. Access can also be revoked at any time.

---

## 2. Project Structure

```
secure_file_sharing/
├── app.py                # Main Flask app: all routes/pages
├── config.py              # App settings, database path, master key
├── models.py               # Database tables (User, FileRecord, FileAccess)
├── crypto_utils.py          # All AES encryption/decryption logic
├── requirements.txt          # Python dependencies
├── instance/                  # SQLite database file gets created here
├── uploads/                    # Encrypted files are stored here
├── static/
│   └── style.css                # Small custom styling
└── templates/
    ├── base.html                  # Shared layout + navbar
    ├── login.html
    ├── register.html
    ├── dashboard.html               # Your files + files shared with you
    ├── upload.html
    └── share.html                     # Manage who can access a file
```

---

## 3. How to Run It

**Step 1 — Install dependencies** (Python 3.9+ recommended):

```bash
pip install -r requirements.txt
```

**Step 2 — Run the app:**

```bash
python app.py
```

The database tables are created automatically the first time you run it.

**Step 3 — Open your browser:**

```
http://127.0.0.1:5000
```

---

## 4. How to Use It

1. **Register** two (or more) accounts — e.g. `alice` and `bob` — so you have
   an owner and a recipient to test sharing with.
2. **Log in as alice**, go to **Upload**, and upload any file. It is
   immediately AES-encrypted and stored.
3. On the **Dashboard**, click **Share** next to the file, type in
   `bob`, and click **Grant Access**.
4. **Log out**, then **log in as bob**. Under "Shared With Me" on the
   dashboard, bob will see the file and can click **Download** — the
   server decrypts it on the fly and bob receives the original file.
5. If a third user (not granted access) tries to visit the download
   URL directly, the app blocks them with an "unauthorized" message.
6. Back as `alice`, you can **Revoke** bob's access at any time from the
   Share page, or **Delete** the file entirely.

---

## 5. Security Notes / Before Using This for Anything Real

This project demonstrates the core concepts clearly for learning purposes.
If you ever wanted to make it production-grade, you would additionally:

- Move `SECRET_KEY` and `MASTER_KEY` out of `config.py` and into
  environment variables (never commit real keys to source control).
- Deploy behind HTTPS (e.g. with Nginx + a TLS certificate) so traffic
  between browser and server is encrypted in transit too.
- Add rate-limiting on login attempts to reduce brute-force risk.
- Add file-type/size validation and antivirus scanning on upload.
- Consider key rotation and an audit log of every download/decryption
  event for compliance-sensitive use cases.

---

## 6. Possible Extensions (if you want to expand the project later)

- Email notifications when a file is shared with you.
- File expiry dates (auto-delete or auto-revoke after N days).
- Two-factor authentication at login.
- Per-file download logs (who downloaded what, and when).
- Switch storage backend to AWS S3 for larger-scale deployments.
