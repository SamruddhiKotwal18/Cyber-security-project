"""
============================================================
  🔐 File Encryption & Secure File Sharing System
  Backend: Flask + Fernet (AES) Encryption
============================================================
"""

import os
import hashlib
import secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory, jsonify
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken

# ─────────────────────────────────────────────────────────
#  App configuration
# ─────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)   # Random secret key each startup

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER    = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "encrypted")
DECRYPTED_FOLDER = os.path.join(BASE_DIR, "decrypted")

# Session config
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 minutes

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "gif",
    "docx", "xlsx", "pptx", "csv", "zip", "mp3", "mp4"
}

app.config["UPLOAD_FOLDER"]    = UPLOAD_FOLDER
app.config["ENCRYPTED_FOLDER"] = ENCRYPTED_FOLDER
app.config["DECRYPTED_FOLDER"] = DECRYPTED_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024   # 16 MB limit

# Create directories if they don't exist
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# ─────────────────────────────────────────────────────────
#  Simulated in-memory user "database"
#  In production, replace with a real DB (SQLite / PostgreSQL)
# ─────────────────────────────────────────────────────────
USERS = {}   # { username: hashed_password }


# ─────────────────────────────────────────────────────────
#  Helper utilities
# ─────────────────────────────────────────────────────────
def allowed_file(filename: str) -> bool:
    """Return True if the file extension is in the allowed set."""
    return (
        "." in filename and
        filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def sha256_hash(filepath: str) -> str:
    """Compute SHA-256 hash of a file for integrity verification."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def login_required(f):
    """Decorator that redirects unauthenticated users to the login page."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            flash("⚠️  Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────
#  Auth Routes
# ─────────────────────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration endpoint."""
    if "username" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm  = request.form.get("confirm_password", "").strip()

        # --- Validation ---
        if not username or not password:
            flash("❌ Username and password are required.", "error")
            return render_template("register.html")

        if len(username) < 3:
            flash("❌ Username must be at least 3 characters.", "error")
            return render_template("register.html")

        if len(password) < 6:
            flash("❌ Password must be at least 6 characters.", "error")
            return render_template("register.html")

        if password != confirm:
            flash("❌ Passwords do not match.", "error")
            return render_template("register.html")

        if username in USERS:
            flash("❌ Username already exists. Please choose another.", "error")
            return render_template("register.html")

        # Hash password, save user
        USERS[username] = generate_password_hash(password)
        flash("✅ Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login endpoint."""
    if "username" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user_hash = USERS.get(username)
        if user_hash and check_password_hash(user_hash, password):
            session.permanent = True
            session["username"] = username
            flash(f"👋 Welcome back, {username}!", "success")
            return redirect(url_for("index"))
        else:
            flash("❌ Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Clear session and redirect to login."""
    session.clear()
    flash("✅ You have been logged out.", "success")
    return redirect(url_for("login"))


# ─────────────────────────────────────────────────────────
#  Dashboard / Home
# ─────────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    """Main dashboard."""
    return render_template("index.html", username=session["username"])


# ─────────────────────────────────────────────────────────
#  File Upload
# ─────────────────────────────────────────────────────────
@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    """
    Handle file upload.
    Saves the file to /uploads and returns the filename + SHA-256 hash.
    """
    if "file" not in request.files:
        flash("❌ No file part in the request.", "error")
        return redirect(url_for("index"))

    file = request.files["file"]

    if file.filename == "":
        flash("❌ No file selected.", "error")
        return redirect(url_for("index"))

    if not allowed_file(file.filename):
        flash(
            f"❌ File type not allowed. Supported: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
            "error"
        )
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    # Prefix with timestamp to avoid collisions
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"{timestamp}_{filename}"

    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    file_hash = sha256_hash(filepath)
    file_size = os.path.getsize(filepath)

    session["last_uploaded"] = filename
    flash(
        f"✅ File '{filename}' uploaded successfully! "
        f"Size: {file_size:,} bytes | SHA-256: {file_hash[:16]}…",
        "success"
    )
    return redirect(url_for("index"))


# ─────────────────────────────────────────────────────────
#  File Encryption
# ─────────────────────────────────────────────────────────
@app.route("/encrypt", methods=["POST"])
@login_required
def encrypt_file():
    """
    Encrypt the specified uploaded file using Fernet (AES-128-CBC).
    Returns the encryption key in the flash message.
    The key is NOT stored on the server — users must save it themselves.
    """
    filename = request.form.get("filename", "").strip()

    if not filename:
        flash("❌ No filename provided for encryption.", "error")
        return redirect(url_for("index"))

    src_path = os.path.join(UPLOAD_FOLDER, secure_filename(filename))

    if not os.path.exists(src_path):
        flash(f"❌ File '{filename}' not found in uploads.", "error")
        return redirect(url_for("index"))

    # --- Generate a strong Fernet key (AES-128 CBC + HMAC-SHA256) ---
    key    = Fernet.generate_key()          # bytes
    fernet = Fernet(key)

    # Read, encrypt, write
    with open(src_path, "rb") as f:
        plaintext = f.read()

    ciphertext = fernet.encrypt(plaintext)

    enc_filename = f"ENC_{filename}"
    enc_path     = os.path.join(ENCRYPTED_FOLDER, enc_filename)
    with open(enc_path, "wb") as f:
        f.write(ciphertext)

    # Compute hashes for integrity info
    original_hash  = sha256_hash(src_path)
    encrypted_hash = sha256_hash(enc_path)

    # Decode key to string for display
    key_str = key.decode("utf-8")

    # Store last encrypted filename in session (not the key!)
    session["last_encrypted"] = enc_filename

    flash(
        f"🔐 Encryption successful! | "
        f"Encrypted file: {enc_filename} | "
        f"🔑 KEY (save this!): {key_str} | "
        f"Original SHA-256: {original_hash[:16]}… | "
        f"Encrypted SHA-256: {encrypted_hash[:16]}…",
        "encrypt_success"
    )
    return redirect(url_for("index"))


# ─────────────────────────────────────────────────────────
#  File Download
# ─────────────────────────────────────────────────────────
@app.route("/download/encrypted/<filename>")
@login_required
def download_encrypted(filename):
    """Serve an encrypted file for download."""
    safe_name = secure_filename(filename)
    filepath  = os.path.join(ENCRYPTED_FOLDER, safe_name)
    if not os.path.exists(filepath):
        flash(f"❌ Encrypted file '{filename}' not found.", "error")
        return redirect(url_for("index"))
    return send_from_directory(ENCRYPTED_FOLDER, safe_name, as_attachment=True)


@app.route("/download/decrypted/<filename>")
@login_required
def download_decrypted(filename):
    """Serve a decrypted file for download."""
    safe_name = secure_filename(filename)
    filepath  = os.path.join(DECRYPTED_FOLDER, safe_name)
    if not os.path.exists(filepath):
        flash(f"❌ Decrypted file '{filename}' not found.", "error")
        return redirect(url_for("index"))
    return send_from_directory(DECRYPTED_FOLDER, safe_name, as_attachment=True)


# ─────────────────────────────────────────────────────────
#  File Decryption
# ─────────────────────────────────────────────────────────
@app.route("/decrypt", methods=["POST"])
@login_required
def decrypt_file():
    """
    Decrypt an encrypted file using the user-provided Fernet key.
    Saves the result to /decrypted.
    """
    filename   = request.form.get("enc_filename", "").strip()
    key_input  = request.form.get("decrypt_key", "").strip()

    if not filename or not key_input:
        flash("❌ Both filename and decryption key are required.", "error")
        return redirect(url_for("index"))

    enc_path = os.path.join(ENCRYPTED_FOLDER, secure_filename(filename))
    if not os.path.exists(enc_path):
        flash(f"❌ Encrypted file '{filename}' not found.", "error")
        return redirect(url_for("index"))

    # Validate & use the key
    try:
        key    = key_input.encode("utf-8")
        fernet = Fernet(key)
    except Exception:
        flash("❌ Invalid key format. Please paste the exact key provided at encryption.", "error")
        return redirect(url_for("index"))

    try:
        with open(enc_path, "rb") as f:
            ciphertext = f.read()

        plaintext = fernet.decrypt(ciphertext)   # Raises InvalidToken on wrong key
    except InvalidToken:
        flash("❌ Decryption failed! Wrong key or corrupted file.", "error")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"❌ Unexpected error during decryption: {e}", "error")
        return redirect(url_for("index"))

    # Strip "ENC_" prefix to restore original-ish name
    dec_filename = filename[4:] if filename.startswith("ENC_") else f"DEC_{filename}"
    dec_path = os.path.join(DECRYPTED_FOLDER, secure_filename(dec_filename))
    with open(dec_path, "wb") as f:
        f.write(plaintext)

    dec_hash = sha256_hash(dec_path)
    session["last_decrypted"] = dec_filename

    flash(
        f"✅ Decryption successful! | "
        f"Restored file: {dec_filename} | "
        f"SHA-256: {dec_hash[:16]}…",
        "success"
    )
    return redirect(url_for("index"))


# ─────────────────────────────────────────────────────────
#  File Listing API (for dashboard refresh)
# ─────────────────────────────────────────────────────────
@app.route("/api/files")
@login_required
def api_files():
    """Return JSON listing of files in all three folders."""
    def list_folder(path):
        if not os.path.exists(path):
            return []
        entries = []
        for fn in os.listdir(path):
            fp = os.path.join(path, fn)
            if os.path.isfile(fp):
                entries.append({
                    "name": fn,
                    "size": os.path.getsize(fp),
                    "modified": datetime.fromtimestamp(
                        os.path.getmtime(fp)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                })
        return sorted(entries, key=lambda x: x["modified"], reverse=True)

    return jsonify({
        "uploads":   list_folder(UPLOAD_FOLDER),
        "encrypted": list_folder(ENCRYPTED_FOLDER),
        "decrypted": list_folder(DECRYPTED_FOLDER),
    })


# ─────────────────────────────────────────────────────────
#  Error handlers
# ─────────────────────────────────────────────────────────
@app.errorhandler(413)
def file_too_large(e):
    flash("❌ File too large! Maximum allowed size is 16 MB.", "error")
    return redirect(url_for("index"))


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


# ─────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  File Encryption & Secure Sharing System")
    print("  Running at: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
