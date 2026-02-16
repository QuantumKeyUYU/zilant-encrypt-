"""Keyfile support for additional key material."""
from __future__ import annotations

import hashlib
from pathlib import Path

KEYFILE_HASH_LEN = 32


def derive_keyfile_material(keyfile_path: Path) -> bytes:
    """Read a keyfile and derive 32 bytes of key material via SHA-256.

    The keyfile contents are hashed so that any file can serve as a keyfile
    regardless of its size. The result is combined with the password-derived
    key via XOR in the key management layer.
    """
    if not keyfile_path.exists():
        raise FileNotFoundError(f"Keyfile not found: {keyfile_path}")

    hasher = hashlib.sha256()
    with keyfile_path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.digest()


def combine_key_with_keyfile(derived_key: bytes, keyfile_material: bytes) -> bytes:
    """Combine a password-derived key with keyfile material using XOR."""
    if len(derived_key) != KEYFILE_HASH_LEN or len(keyfile_material) != KEYFILE_HASH_LEN:
        raise ValueError("Both keys must be 32 bytes")
    return bytes(a ^ b for a, b in zip(derived_key, keyfile_material))
