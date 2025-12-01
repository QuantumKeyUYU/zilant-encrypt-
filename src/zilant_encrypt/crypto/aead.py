"""AEAD wrapper helpers."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TAG_LEN = 16


class AesGcmEncryptor:
    """Thin wrapper over AESGCM to enforce nonce/tag handling."""

    @staticmethod
    def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
        return ciphertext_with_tag[:-TAG_LEN], ciphertext_with_tag[-TAG_LEN:]

    @staticmethod
    def decrypt(
        key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes
    ) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, aad)
