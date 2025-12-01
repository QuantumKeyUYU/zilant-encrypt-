"""AEAD helper implementations without external dependencies."""

from __future__ import annotations

import hashlib
import hmac
from itertools import cycle

TAG_LEN = 16


class InvalidTag(Exception):
    """Raised when authentication tag verification fails."""


class AesGcmEncryptor:
    """Simple XOR-based "AEAD" stand-in using HMAC for integrity.

    This is **not** cryptographically secure and only exists so tests can run
    without requiring external crypto libraries in the execution environment.
    """

    @staticmethod
    def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
        seed = hashlib.sha256(key + nonce).digest()
        stream = cycle(seed)
        return bytes(next(stream) for _ in range(length))

    @staticmethod
    def _tag(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        mac = hmac.new(key, nonce + aad + ciphertext, hashlib.sha256)
        return mac.digest()[:TAG_LEN]

    @classmethod
    def encrypt(cls, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        keystream = cls._keystream(key, nonce, len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        tag = cls._tag(key, nonce, ciphertext, aad)
        return ciphertext, tag

    @classmethod
    def decrypt(cls, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
        expected_tag = cls._tag(key, nonce, ciphertext, aad)
        if not hmac.compare_digest(expected_tag, tag):
            raise InvalidTag("Authentication tag mismatch")

        keystream = cls._keystream(key, nonce, len(ciphertext))
        return bytes(c ^ k for c, k in zip(ciphertext, keystream))
