"""Cryptographic helpers for dnsstego."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import ClassVar

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BLOCK_SIZE = 16
SALT_SIZE = 16
ITERATIONS = 200_000


def _derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def _pad(data: bytes) -> bytes:
    padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_length] * padding_length)


def _unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Invalid padding: empty data")
    padding_length = data[-1]
    if padding_length < 1 or padding_length > BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding bytes")
    return data[:-padding_length]


@dataclass
class AESCipher:
    """Simple AES-CBC helper with PBKDF2 based key derivation."""

    password: str
    key_size: int = 32

    salt_size: ClassVar[int] = SALT_SIZE

    def encrypt(self, data: bytes) -> bytes:
        salt = os.urandom(self.salt_size)
        key = _derive_key(self.password, salt, self.key_size)
        iv = os.urandom(BLOCK_SIZE)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded = _pad(data)
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return salt + iv + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        if len(blob) < self.salt_size + BLOCK_SIZE:
            raise ValueError("Ciphertext too short")
        salt = blob[: self.salt_size]
        iv = blob[self.salt_size : self.salt_size + BLOCK_SIZE]
        ciphertext = blob[self.salt_size + BLOCK_SIZE :]
        key = _derive_key(self.password, salt, self.key_size)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        return _unpad(padded)


__all__ = ["AESCipher"]
