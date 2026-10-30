import os
import tempfile
import unittest

from storage import Vault, VaultError

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


if __name__ == "__main__":
    unittest.main()
