"""
config.py

Central configuration for the Secure File Sharing application.

IMPORTANT (Security Note):
---------------------------
In this project, SECRET_KEY and MASTER_KEY are hard-coded so the
application runs immediately after download, for learning/demo purposes.

Before deploying this project anywhere real, you should:
    1. Generate new random keys.
    2. Store them as environment variables (never in source code).
    3. Load them using os.environ.get("SECRET_KEY") instead of a fixed string.

To generate a new Fernet master key, run this in a Python shell:
    from cryptography.fernet import Fernet
    print(Fernet.generate_key())
"""

import os

# Base directory of the project (folder where this file lives)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Used by Flask to sign session cookies and CSRF tokens.
    SECRET_KEY = "change-this-secret-key-in-production-987654321"

    # Database connection string. SQLite is used here because it needs
    # no separate database server and is perfect for small/medium apps.
    # For larger production systems, you can switch to PostgreSQL or MySQL
    # by changing this single line, e.g.:
    #   "postgresql://user:password@localhost/secure_file_sharing"
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(
        BASE_DIR, "instance", "secure_file_sharing.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Folder where the ENCRYPTED files are physically stored on disk.
    # Files are NEVER stored in plain/readable form here.
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

    # Maximum allowed upload size (here: 50 MB). Adjust as needed.
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024

    # Master key used to encrypt/decrypt the PER-FILE AES keys before
    # they are stored in the database. This is what is sometimes called
    # "envelope encryption": each file gets its own random AES key,
    # and that key itself is protected using this master key.
    #
    # This must be a valid Fernet key (32 url-safe base64-encoded bytes).
    MASTER_KEY = b"0yAab_viTFa5H4YHaKOm2vkD6VsWwGMgs731FVPm_SQ="
