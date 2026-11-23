"""
Vault file:  magic "PVLT" (4) | format version (2) | counter (8) | salt (16) | nonce (12)
             | GCM tag (16) | ciphertext
The first 42 bytes are the header, authenticated as AAD.

Meta file (<vault>.meta, JSON): password_hash, counter, sha256 of the vault file.
"""

import hashlib
import json
import os
import re
import struct
import tempfile

from cryptography.exceptions import InvalidTag

from auth import check_master_password, hash_master_password
from crypto import decrypt, derive_key, encrypt, wipe

MAGIC = b"PVLT"
FORMAT_VERSION = 1
# > big-endian, 4s magic, H 2-byte version, Q 8-byte counter, 16s salt, 12s nonce
HEADER = struct.Struct(">4sHQ16s12s")
TAG_SIZE = 16
LABEL_PATTERN = re.compile(r"[A-Za-z0-9._@-]{1,64}")
MAX_USERNAME_LENGTH = 256
MAX_PASSWORD_LENGTH = 4096


class VaultError(Exception):
    pass


def check_label(label):
    if not isinstance(label, str) or not LABEL_PATTERN.fullmatch(label):
        raise VaultError("Label may only use letters, digits and . _ @ - (max 64 characters).")
    return label


def check_username(username):
    if (
        not isinstance(username, str)
        or len(username) > MAX_USERNAME_LENGTH
        or not username.isprintable()
    ):
        raise VaultError("Username must be at most 256 printable characters.")
    return username


def check_password(password, min_length=1):
    if (
        not isinstance(password, str)
        or len(password) < min_length
        or len(password) > MAX_PASSWORD_LENGTH
        or not password.isprintable()
    ):
        raise VaultError(f"Password must be {min_length}-{MAX_PASSWORD_LENGTH} printable characters.")
    return password


def validate_entries(entries):
    if not isinstance(entries, dict):
        raise VaultError("Vault contents are invalid.")
    for label, entry in entries.items():
        check_label(label)
        if not isinstance(entry, dict) or set(entry) != {"username", "password"}:
            raise VaultError("Vault contents are invalid.")
        check_username(entry["username"])
        check_password(entry["password"])


def write_file_safely(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def read_meta(path):
    try:
        with open(path + ".meta") as f:
            return json.load(f)
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        raise VaultError("Vault metadata file is missing or broken.")


def parse_vault_file(data):
    if len(data) < HEADER.size + TAG_SIZE:
        raise VaultError("Not a valid vault file.")
    header = data[:HEADER.size]
    magic, version, counter, salt, nonce = HEADER.unpack(header)
    if magic != MAGIC or version != FORMAT_VERSION:
        raise VaultError("Not a valid vault file.")
    tag = data[HEADER.size:HEADER.size + TAG_SIZE]
    ciphertext = data[HEADER.size + TAG_SIZE:]
    # AESGCM expects the tag at the end of the ciphertext
    return header, counter, salt, nonce, ciphertext + tag


class Vault:
    def __init__(self, path, password_hash, key, salt, counter, entries):
        self.path = path
        self.password_hash = password_hash
        self.key = key
        self.salt = salt
        self.counter = counter
        self.entries = entries
        self.locked = False

    # Allows "with Vault.open(...) as vault:", which calls lock() at the end
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.lock()

    def lock(self):
        wipe(self.key)
        self.entries.clear()
        self.locked = True

    @classmethod
    def create(cls, path, master_password):
        check_password(master_password, 12)
        # 0o700 = only the owner can open the vault folder
        os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
        salt = os.urandom(16)
        key = derive_key(master_password, salt)
        vault = cls(path, hash_master_password(master_password), key, salt, 0, {})
        vault.save()
        return vault

    @classmethod
    def open(cls, path, master_password):
        check_password(master_password)
        # 1. Check the master password against the stored Argon2id hash
        meta = read_meta(path)
        if (
            not isinstance(meta, dict)
            or not isinstance(meta.get("password_hash"), str)
            or not isinstance(meta.get("counter"), int)
            or isinstance(meta.get("counter"), bool)
            or meta["counter"] < 0
            or not isinstance(meta.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", meta["sha256"])
        ):
            raise VaultError("Vault metadata file is missing or broken.")
        if not check_master_password(meta["password_hash"], master_password):
            raise VaultError("Wrong master password.")

        # 2. Rollback check: the file must be the last one we saved
        with open(path, "rb") as f:
            data = f.read()
        header, counter, salt, nonce, ciphertext = parse_vault_file(data)
        if counter < meta["counter"]:
            raise VaultError("This is an older copy of the vault. Refusing to open.")
        if hashlib.sha256(data).hexdigest() != meta["sha256"]:
            raise VaultError("Vault file does not match the last saved version. Refusing to open.")

        # 3. Derive the key and decrypt, GCM fails if anything was changed
        key = derive_key(master_password, salt)
        try:
            plaintext = bytearray(decrypt(key, nonce, ciphertext, header))
            try:
                entries = json.loads(plaintext.decode("utf-8"))
                validate_entries(entries)
            finally:
                wipe(plaintext)
        except InvalidTag as error:
            wipe(key)
            raise VaultError("Vault file was modified. Refusing to open.") from error
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, VaultError) as error:
            wipe(key)
            raise VaultError("Vault contents are invalid.") from error
        return cls(path, meta["password_hash"], key, salt, counter, entries)

    def save(self):
        if self.locked:
            raise VaultError("Vault is locked.")
        validate_entries(self.entries)
        counter = self.counter + 1
        nonce = os.urandom(12)  # a new nonce every time, never reused with the same key
        header = HEADER.pack(MAGIC, FORMAT_VERSION, counter, self.salt, nonce)
        plaintext = bytearray(json.dumps(self.entries).encode())
        try:
            sealed = encrypt(self.key, nonce, plaintext, header)
        finally:
            wipe(plaintext)
        # AESGCM returns ciphertext + tag, the file stores the tag first
        ciphertext, tag = sealed[:-TAG_SIZE], sealed[-TAG_SIZE:]

        data = header + tag + ciphertext
        write_file_safely(self.path, data)
        # Remember the latest counter and file hash for the rollback check
        meta = {
            "password_hash": self.password_hash,
            "counter": counter,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        write_file_safely(self.path + ".meta", json.dumps(meta, indent=2).encode())
        self.counter = counter
