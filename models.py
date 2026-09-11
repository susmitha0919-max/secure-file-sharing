"""
models.py

Defines the database tables (models) used by the application:

    User       -> registered users who can log in
    FileRecord -> metadata about every uploaded (encrypted) file
    FileAccess -> "who is allowed to see which file" access-control list

The actual file bytes are NEVER stored in the database. Only encrypted
files are stored on disk (see UPLOAD_FOLDER in config.py), and this
database stores just the information needed to find, decrypt, and
control access to those files.
"""

from datetime import datetime

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

# db is created here and initialised on the Flask app inside app.py
db = SQLAlchemy()


class User(db.Model, UserMixin):
    """
    Represents a registered user of the system.
    Passwords are never stored in plain text, only their secure hash.
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # A user can own many files
    files = db.relationship(
        "FileRecord", backref="owner", lazy=True, foreign_keys="FileRecord.owner_id"
    )

    def set_password(self, plain_password):
        """Hash and store the given plain-text password securely."""
        self.password_hash = generate_password_hash(plain_password)

    def check_password(self, plain_password):
        """Check a plain-text password against the stored hash."""
        return check_password_hash(self.password_hash, plain_password)

    def __repr__(self):
        return f"<User {self.username}>"


class FileRecord(db.Model):
    """
    Stores metadata for every file that has been uploaded and encrypted.

    Fields:
        original_filename : the name of the file as the user uploaded it
        stored_filename    : the random, unique name used on disk
                              (prevents filename clashes / guessing)
        encrypted_key      : the file's own AES (Fernet) key, itself
                              encrypted using the application MASTER_KEY
                              before being saved here (envelope encryption)
        owner_id            : which user uploaded/owns this file
        upload_time         : when the file was uploaded
        file_size           : original file size in bytes, for display
    """

    __tablename__ = "file_records"

    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    encrypted_key = db.Column(db.LargeBinary, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    file_size = db.Column(db.Integer, default=0)

    # A file can be shared with many users
    access_grants = db.relationship(
        "FileAccess", backref="file", lazy=True, cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<FileRecord {self.original_filename}>"


class FileAccess(db.Model):
    """
    Access-control record: grants ONE recipient user permission to
    view/download/decrypt ONE specific file.

    A row existing here is what makes a recipient "authorized".
    If there is no row for (file_id, user_id), that user cannot
    decrypt or download the file, even if they know it exists.
    """

    __tablename__ = "file_access"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file_records.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Convenience relationship back to the recipient User object
    recipient = db.relationship("User", foreign_keys=[user_id])

    __table_args__ = (
        db.UniqueConstraint("file_id", "user_id", name="unique_file_user_access"),
    )

    def __repr__(self):
        return f"<FileAccess file={self.file_id} user={self.user_id}>"
