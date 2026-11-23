import json
import os
import tempfile
import unittest

from storage import (
    Vault,
    VaultError,
    check_label,
    check_password,
    check_username,
)

MASTER = "correct horse battery staple"


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "test.pvlt")
        vault = Vault.create(self.path, MASTER)
        vault.entries["github"] = {"username": "alice", "password": "SecretPw123"}
        vault.save()

    def test_open_with_correct_password(self):
        vault = Vault.open(self.path, MASTER)
        self.assertEqual(vault.entries["github"]["password"], "SecretPw123")

    def test_wrong_password_is_rejected(self):
        with self.assertRaises(VaultError):
            Vault.open(self.path, "wrong password")

    def test_password_not_stored_in_cleartext(self):
        with open(self.path, "rb") as f:
            data = f.read()
        self.assertNotIn(b"SecretPw123", data)
        self.assertNotIn(b"alice", data)

    def test_modified_file_is_rejected(self):
        with open(self.path, "rb") as f:
            data = bytearray(f.read())
        data[-1] ^= 1  # flip one bit in the ciphertext
        with open(self.path, "wb") as f:
            f.write(data)
        with self.assertRaises(VaultError):
            Vault.open(self.path, MASTER)

    def test_old_copy_is_rejected(self):
        with open(self.path, "rb") as f:
            old_copy = f.read()
        vault = Vault.open(self.path, MASTER)
        vault.entries["gitlab"] = {"username": "bob", "password": "pw"}
        vault.save()
        with open(self.path, "wb") as f:
            f.write(old_copy)  # attacker puts the older vault back
        with self.assertRaises(VaultError):
            Vault.open(self.path, MASTER)

    def test_lock_wipes_key(self):
        vault = Vault.open(self.path, MASTER)
        vault.lock()
        self.assertEqual(vault.key, bytearray(32))

    def test_broken_metadata_returns_safe_vault_error(self):
        with open(self.path + ".meta", "w") as metadata:
            json.dump([], metadata)
        with self.assertRaises(VaultError):
            Vault.open(self.path, MASTER)

    def test_input_validation_rejects_bad_fields(self):
        for label in ("bad label", "x" * 65, ""):
            with self.subTest(label=label), self.assertRaises(VaultError):
                check_label(label)
        for username in ("line\nbreak", "x" * 257, None):
            with self.subTest(username=username), self.assertRaises(VaultError):
                check_username(username)
        for password in ("", "line\nbreak", "x" * 4097, None):
            with self.subTest(password=password), self.assertRaises(VaultError):
                check_password(password)
        self.assertEqual(check_label("x" * 64), "x" * 64)
        self.assertEqual(check_username("x" * 256), "x" * 256)
        self.assertEqual(check_password("x" * 4096), "x" * 4096)

    def test_invalid_entry_is_not_saved(self):
        vault = Vault.open(self.path, MASTER)
        counter = vault.counter
        vault.entries["bad label"] = {"username": "alice", "password": "secret"}
        with self.assertRaises(VaultError):
            vault.save()
        self.assertEqual(vault.counter, counter)


if __name__ == "__main__":
    unittest.main()
