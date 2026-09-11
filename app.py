"""
app.py

Main Flask application for the "Secure File Sharing Using Encryption"
project.

What this file does:
    - Sets up the Flask app, database, and login manager
    - Defines every route (page/URL) the user can visit:
        /register           create a new account
        /login               log in
        /logout              log out
        /dashboard           see your own files + files shared with you
        /upload              upload + encrypt a new file
        /share/<file_id>     grant another user access to one of your files
        /download/<file_id>  decrypt (if authorized) and download a file
        /delete/<file_id>    delete one of your own files

Run this file with:
    python app.py

Then open your browser at:
    http://127.0.0.1:5000
"""

import os
import uuid

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from io import BytesIO
from werkzeug.utils import secure_filename

from config import Config
from crypto_utils import (
    decrypt_file_bytes,
    encrypt_file_bytes,
    generate_file_key,
    unwrap_key,
    wrap_key,
)
from models import FileAccess, FileRecord, User, db

# ---------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------

app = Flask(__name__)
app.config.from_object(Config)

# Make sure the folders the app depends on actually exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), "instance"), exist_ok=True)

db.init_app(app)

# Create database tables automatically, whether the app is started with
# "python app.py" (local development) or imported by a production server
# such as gunicorn (used on platforms like Render/PythonAnywhere).
with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login uses this to reload a user object from the session."""
    return User.query.get(int(user_id))


# ---------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------

@app.route("/")
def index():
    """Landing page: send logged-in users to their dashboard, others to login."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Create a new user account."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # --- basic validation ---
        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return redirect(url_for("register"))

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            flash("Username or email is already registered.", "danger")
            return redirect(url_for("register"))

        # --- create the user ---
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log an existing user in."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

        login_user(user)
        flash(f"Welcome back, {user.username}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Log the current user out."""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    """
    Show:
        - files the current user owns (uploaded)
        - files that have been shared WITH the current user by others
    """
    my_files = (
        FileRecord.query.filter_by(owner_id=current_user.id)
        .order_by(FileRecord.upload_time.desc())
        .all()
    )

    shared_with_me = (
        db.session.query(FileRecord)
        .join(FileAccess, FileAccess.file_id == FileRecord.id)
        .filter(FileAccess.user_id == current_user.id)
        .order_by(FileRecord.upload_time.desc())
        .all()
    )

    return render_template(
        "dashboard.html", my_files=my_files, shared_with_me=shared_with_me
    )


# ---------------------------------------------------------------------
# Upload (encrypt) a file
# ---------------------------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Handle uploading a new file: encrypt it and store it safely."""
    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if uploaded_file is None or uploaded_file.filename == "":
            flash("Please choose a file to upload.", "danger")
            return redirect(url_for("upload"))

        # Sanitize the original filename (prevents path traversal attacks)
        original_filename = secure_filename(uploaded_file.filename)

        # Read the raw bytes of the uploaded file into memory
        plain_bytes = uploaded_file.read()
        file_size = len(plain_bytes)

        # 1. Generate a brand-new random AES key just for this file
        file_key = generate_file_key()

        # 2. Encrypt the file's contents using that key
        encrypted_bytes = encrypt_file_bytes(plain_bytes, file_key)

        # 3. Encrypt ("wrap") the per-file key using the master key,
        #    so it is safe to store in the database
        wrapped_key = wrap_key(file_key, app.config["MASTER_KEY"])

        # 4. Choose a random, unpredictable filename to store on disk,
        #    so files cannot be guessed or overwritten by name clashes
        stored_filename = f"{uuid.uuid4().hex}.enc"
        stored_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_filename)

        with open(stored_path, "wb") as output_file:
            output_file.write(encrypted_bytes)

        # 5. Save the metadata (NOT the file itself) to the database
        new_record = FileRecord(
            original_filename=original_filename,
            stored_filename=stored_filename,
            encrypted_key=wrapped_key,
            owner_id=current_user.id,
            file_size=file_size,
        )
        db.session.add(new_record)
        db.session.commit()

        flash(f'"{original_filename}" was encrypted and uploaded successfully.', "success")
        return redirect(url_for("dashboard"))

    return render_template("upload.html")


# ---------------------------------------------------------------------
# Share a file with another user
# ---------------------------------------------------------------------

@app.route("/share/<int:file_id>", methods=["GET", "POST"])
@login_required
def share(file_id):
    """Let the OWNER of a file grant download/decrypt access to someone else."""
    file_record = FileRecord.query.get_or_404(file_id)

    # Only the owner is allowed to share their own file
    if file_record.owner_id != current_user.id:
        flash("You are not allowed to share this file.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        recipient_username = request.form.get("recipient_username", "").strip()

        recipient_user = User.query.filter_by(username=recipient_username).first()

        if recipient_user is None:
            flash("No user found with that username.", "danger")
            return redirect(url_for("share", file_id=file_id))

        if recipient_user.id == current_user.id:
            flash("You already own this file.", "info")
            return redirect(url_for("share", file_id=file_id))

        already_shared = FileAccess.query.filter_by(
            file_id=file_record.id, user_id=recipient_user.id
        ).first()

        if already_shared:
            flash(f"This file is already shared with {recipient_user.username}.", "info")
            return redirect(url_for("share", file_id=file_id))

        access_grant = FileAccess(file_id=file_record.id, user_id=recipient_user.id)
        db.session.add(access_grant)
        db.session.commit()

        flash(f"Access granted to {recipient_user.username}.", "success")
        return redirect(url_for("share", file_id=file_id))

    current_grants = FileAccess.query.filter_by(file_id=file_record.id).all()
    return render_template(
        "share.html", file_record=file_record, current_grants=current_grants
    )


@app.route("/revoke/<int:access_id>", methods=["POST"])
@login_required
def revoke(access_id):
    """Let a file owner remove a previously granted access."""
    access_grant = FileAccess.query.get_or_404(access_id)
    file_record = FileRecord.query.get_or_404(access_grant.file_id)

    if file_record.owner_id != current_user.id:
        flash("You are not allowed to modify sharing for this file.", "danger")
        return redirect(url_for("dashboard"))

    db.session.delete(access_grant)
    db.session.commit()
    flash("Access has been revoked.", "info")
    return redirect(url_for("share", file_id=file_record.id))


# ---------------------------------------------------------------------
# Download (decrypt) a file
# ---------------------------------------------------------------------

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    """
    Decrypt and send a file to the browser, but ONLY if the current
    user is either:
        - the owner of the file, OR
        - a recipient the owner has explicitly granted access to
    """
    file_record = FileRecord.query.get_or_404(file_id)

    is_owner = file_record.owner_id == current_user.id
    has_access_grant = FileAccess.query.filter_by(
        file_id=file_record.id, user_id=current_user.id
    ).first() is not None

    if not (is_owner or has_access_grant):
        flash("You are not authorized to access this file.", "danger")
        return redirect(url_for("dashboard"))

    stored_path = os.path.join(app.config["UPLOAD_FOLDER"], file_record.stored_filename)

    if not os.path.exists(stored_path):
        flash("The encrypted file could not be found on the server.", "danger")
        return redirect(url_for("dashboard"))

    # 1. Read the encrypted bytes from disk
    with open(stored_path, "rb") as encrypted_file:
        encrypted_bytes = encrypted_file.read()

    # 2. Unwrap (decrypt) the per-file key using the master key
    file_key = unwrap_key(file_record.encrypted_key, app.config["MASTER_KEY"])

    # 3. Decrypt the actual file content using the recovered key
    try:
        decrypted_bytes = decrypt_file_bytes(encrypted_bytes, file_key)
    except ValueError as error:
        flash(str(error), "danger")
        return redirect(url_for("dashboard"))

    # 4. Stream the decrypted bytes straight to the user's browser as a
    #    download, WITHOUT ever writing a decrypted copy back to disk
    return send_file(
        BytesIO(decrypted_bytes),
        as_attachment=True,
        download_name=file_record.original_filename,
    )


# ---------------------------------------------------------------------
# Delete a file
# ---------------------------------------------------------------------

@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete(file_id):
    """Permanently delete a file (owner only): removes DB record and disk file."""
    file_record = FileRecord.query.get_or_404(file_id)

    if file_record.owner_id != current_user.id:
        flash("You are not allowed to delete this file.", "danger")
        return redirect(url_for("dashboard"))

    stored_path = os.path.join(app.config["UPLOAD_FOLDER"], file_record.stored_filename)
    if os.path.exists(stored_path):
        os.remove(stored_path)

    db.session.delete(file_record)
    db.session.commit()

    flash("File deleted permanently.", "info")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------

if __name__ == "__main__":
    # host="0.0.0.0" makes the app reachable from outside the container/VM
    # it's running in — required on platforms like Replit. It also still
    # works fine for plain local development on your own computer.
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
