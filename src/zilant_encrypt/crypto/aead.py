"""AEAD wrapper helpers.

This module provides a minimal AES-GCM-like interface without external dependencies.
It is **not** intended to be production-grade cryptography, but is sufficient for
round-trip and integrity checks exercised by the tests.
"""

from __future__ import annotations

import hashlib
import hmac
from itertools import count

TAG_LEN = 16


class InvalidTag(Exception):
    """Raised when authentication tag verification fails."""


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate a keystream using SHA-256 over key, nonce and counter."""

    stream = bytearray()
    for counter in count():
        if len(stream) >= length:
            break
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "little")).digest()
        stream.extend(block)
    return bytes(stream[:length])


class AesGcmEncryptor:
    """Tiny XOR-based cipher with HMAC tag to mimic AES-GCM API."""

    @staticmethod
    def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        keystream = _keystream(key, nonce, len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        mac = hmac.new(key, nonce + aad + ciphertext, hashlib.sha256).digest()
        return ciphertext, mac[:TAG_LEN]

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
        mac = hmac.new(key, nonce + aad + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac[:TAG_LEN], tag):
            raise InvalidTag("Authentication tag mismatch")

        keystream = _keystream(key, nonce, len(ciphertext))
        return bytes(c ^ k for c, k in zip(ciphertext, keystream))
