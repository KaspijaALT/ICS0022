from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=1)


def hash_master_password(password):
    return hasher.hash(password)


def check_master_password(stored_hash, password):
    try:
        return hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False
