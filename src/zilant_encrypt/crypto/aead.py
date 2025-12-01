"""AEAD wrapper helpers without external dependencies.

This module provides a minimal authenticated encryption scheme
for testing purposes using SHA-256 and HMAC. It is **not** a
replacement for real-world AES-GCM security but mirrors the
interface used by the rest of the codebase.
"""

from __future__ import annotations

import hashlib
import hmac

TAG_LEN = 16


class InvalidTag(Exception):
    """Raised when authentication tag verification fails."""


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate a pseudo-random keystream using SHA-256."""

    blocks: list[bytes] = []
    counter = 0
    while len(b"".join(blocks)) < length:
        counter_bytes = counter.to_bytes(4, "little")
        blocks.append(hashlib.sha256(key + nonce + counter_bytes).digest())
        counter += 1
    return b"".join(blocks)[:length]


class AesGcmEncryptor:
    """Thin wrapper providing encrypt/decrypt interface."""

    @staticmethod
    def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        keystream = _keystream(key, nonce, len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))

        tag_material = aad + ciphertext + nonce
        tag_full = hmac.new(key, tag_material, hashlib.sha256).digest()
        return ciphertext, tag_full[:TAG_LEN]

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
        tag_material = aad + ciphertext + nonce
        expected_tag = hmac.new(key, tag_material, hashlib.sha256).digest()[:TAG_LEN]
        if not hmac.compare_digest(expected_tag, tag):
            raise InvalidTag("Authentication failed")

        keystream = _keystream(key, nonce, len(ciphertext))
        return bytes(c ^ k for c, k in zip(ciphertext, keystream))
