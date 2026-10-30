from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(password, salt):
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,  # 64 MiB
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )
    return bytearray(key)


def encrypt(key, nonce, plaintext, header):
    return AESGCM(key).encrypt(nonce, plaintext, header)


def decrypt(key, nonce, ciphertext, header):
    return AESGCM(key).decrypt(nonce, ciphertext, header)


def wipe(buffer):
    for i in range(len(buffer)):
        buffer[i] = 0
