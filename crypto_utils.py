"""
crypto_utils.py

All encryption and decryption logic for the project lives in this one
file, so it is easy to review, easy to explain, and easy to swap out
later if you want a different algorithm.

Algorithm used: AES (via the "Fernet" recipe from the `cryptography`
library).

Why Fernet?
    Fernet is a well-tested, high-level recipe built on top of:
        - AES-128 in CBC mode for encryption (confidentiality)
        - HMAC using SHA256 for authentication (integrity/tamper-check)
        - A timestamp, to support optional expiry
    This means we get real AES encryption AND automatic protection
    against tampered/corrupted ciphertext, without having to manually
    manage IVs, padding, or MACs ourselves (a common source of bugs
    and vulnerabilities in hand-rolled AES code).

Key design used in this project ("envelope encryption"):
    1. Every uploaded file gets its OWN randomly generated AES key
       (generate_file_key).
    2. The file is encrypted with that unique key (encrypt_file_bytes).
    3. That per-file key is then itself encrypted using one central
       MASTER_KEY (wrap_key) before being stored in the database.
    4. To decrypt a file later, the server:
         a. Loads the wrapped key from the database
         b. Unwraps it using the MASTER_KEY (unwrap_key)
         c. Uses the recovered per-file key to decrypt the file bytes
            (decrypt_file_bytes)

This way, even if someone obtained a raw copy of the encrypted files on
disk, they cannot read them without also having the MASTER_KEY AND
database access AND being an authorized user in the FileAccess table.
"""

from cryptography.fernet import Fernet, InvalidToken


def generate_file_key():
    """
    Generate a brand-new random AES key for a single file.
    Returns raw key bytes suitable for Fernet.
    """
    return Fernet.generate_key()


def encrypt_file_bytes(plain_bytes, file_key):
    """
    Encrypt raw file bytes using the given per-file AES key.

    Parameters:
        plain_bytes : bytes  - the original, unencrypted file content
        file_key    : bytes  - the AES key generated for this file

    Returns:
        bytes - the encrypted (ciphertext) file content
    """
    fernet = Fernet(file_key)
    encrypted_bytes = fernet.encrypt(plain_bytes)
    return encrypted_bytes


def decrypt_file_bytes(encrypted_bytes, file_key):
    """
    Decrypt file bytes that were produced by encrypt_file_bytes().

    Parameters:
        encrypted_bytes : bytes - the ciphertext read from disk
        file_key        : bytes - the same AES key used to encrypt it

    Returns:
        bytes - the original, decrypted file content

    Raises:
        ValueError - if the key is wrong or the data has been tampered
                     with / corrupted (integrity check failure).
    """
    fernet = Fernet(file_key)
    try:
        decrypted_bytes = fernet.decrypt(encrypted_bytes)
    except InvalidToken:
        raise ValueError(
            "Decryption failed: wrong key, or the file has been "
            "corrupted or tampered with."
        )
    return decrypted_bytes


def wrap_key(file_key, master_key):
    """
    Encrypt (wrap) a per-file AES key using the application's master key,
    so it is safe to store in the database.

    Parameters:
        file_key   : bytes - the per-file AES key to protect
        master_key : bytes - the application's master Fernet key

    Returns:
        bytes - the encrypted ("wrapped") version of file_key
    """
    master_fernet = Fernet(master_key)
    wrapped_key = master_fernet.encrypt(file_key)
    return wrapped_key


def unwrap_key(wrapped_key, master_key):
    """
    Decrypt (unwrap) a per-file AES key that was protected with wrap_key().

    Parameters:
        wrapped_key : bytes - the encrypted key, as stored in the database
        master_key  : bytes - the application's master Fernet key

    Returns:
        bytes - the original, usable per-file AES key
    """
    master_fernet = Fernet(master_key)
    original_key = master_fernet.decrypt(wrapped_key)
    return original_key
