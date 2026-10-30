"""
Vault file:  magic "PVLT" (4) | format version (2) | counter (8) | salt (16) | nonce (12)
             | GCM tag (16) | ciphertext
The first 42 bytes are the header, authenticated as AAD.

Meta file (<vault>.meta, JSON): password_hash, counter, sha256 of the vault file.
"""

import hashlib
import json
import os
import struct

from cryptography.exceptions import InvalidTag

from auth import check_master_password, hash_master_password
from crypto import decrypt, derive_key, encrypt, wipe

MAGIC = b"PVLT"
FORMAT_VERSION = 1
# > big-endian, 4s magic, H 2-byte version, Q 8-byte counter, 16s salt, 12s nonce
HEADER = struct.Struct(">4sHQ16s12s")
TAG_SIZE = 16


class VaultError(Exception):
    pass


def write_file_safely(path, data):
    # Write to a temp file first and then swap it in, so a crash
    # in the middle never leaves a half-written vault.
    tmp_path = path + ".tmp"
    # 0o600 = only the owner can read and write the file
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp_path, path)


def read_meta(path):
    try:
        with open(path + ".meta") as f:
            return json.load(f)
    except (OSError, ValueError):
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

    # Allows "with Vault.open(...) as vault:", which calls lock() at the end
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.lock()

    def lock(self):
        wipe(self.key)
        self.entries = {}

    @classmethod
    def create(cls, path, master_password):
        # 0o700 = only the owner can open the vault folder
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        salt = os.urandom(16)
        key = derive_key(master_password, salt)
        vault = cls(path, hash_master_password(master_password), key, salt, 0, {})
        vault.save()
        return vault

    @classmethod
    def open(cls, path, master_password):
        # 1. Check the master password against the stored Argon2id hash
        meta = read_meta(path)
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
        except InvalidTag:
            wipe(key)
            raise VaultError("Vault file was modified. Refusing to open.")
        entries = json.loads(plaintext)
        wipe(plaintext)
        return cls(path, meta["password_hash"], key, salt, counter, entries)

    def save(self):
        self.counter += 1
        nonce = os.urandom(12)  # a new nonce every time, never reused with the same key
        header = HEADER.pack(MAGIC, FORMAT_VERSION, self.counter, self.salt, nonce)
        plaintext = bytearray(json.dumps(self.entries).encode())
        sealed = encrypt(self.key, nonce, plaintext, header)
        wipe(plaintext)
        # AESGCM returns ciphertext + tag, the file stores the tag first
        ciphertext, tag = sealed[:-TAG_SIZE], sealed[-TAG_SIZE:]

        data = header + tag + ciphertext
        write_file_safely(self.path, data)
        # Remember the latest counter and file hash for the rollback check
        meta = {
            "password_hash": self.password_hash,
            "counter": self.counter,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        write_file_safely(self.path + ".meta", json.dumps(meta, indent=2).encode())
