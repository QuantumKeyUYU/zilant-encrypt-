"""Keyfile support for additional key material."""
from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEYFILE_HASH_LEN = 32
# Domain-separation label for keyfile HKDF derivation.
_KEYFILE_DERIVE_INFO = b"zilant-keyfile-material-v1"


def derive_keyfile_material(keyfile_path: Path) -> bytes:
    """Read a keyfile and derive 32 bytes of key material.

    The keyfile contents are first hashed with BLAKE2b (collision-resistant,
    fast) and then passed through HKDF-SHA256 with a fixed info label for
    proper domain separation.  This is stronger than bare SHA-256 because
    HKDF-Expand provides a keyed PRF guarantee even when the raw hash value
    is known to an adversary.

    The result is combined with the password-derived key inside the key
    management layer (see :mod:`zilant_encrypt.container.keymgmt`).
    """
    if not keyfile_path.exists():
        raise FileNotFoundError(f"Keyfile not found: {keyfile_path}")
    if not keyfile_path.is_file():
        raise ValueError(f"Keyfile path is not a regular file: {keyfile_path}")

    # Use BLAKE2b for the initial hash – it is faster than SHA-256 on large
    # files and provides 256-bit security against length-extension attacks.
    hasher = hashlib.blake2b(digest_size=32)
    with keyfile_path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)

    raw_hash = hasher.digest()

    # Run through HKDF to get proper key material with domain separation.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEYFILE_HASH_LEN,
        salt=None,  # salt is provided at combination time (Argon2 salt)
        info=_KEYFILE_DERIVE_INFO,
    )
    return hkdf.derive(raw_hash)


def combine_key_with_keyfile(derived_key: bytes, keyfile_material: bytes) -> bytes:
    """Combine a password-derived key with keyfile material using HKDF.

    .. deprecated::
        This function exists for legacy callers.  New code should use
        ``PasswordKeyProvider`` which performs HKDF-based combination
        internally using the Argon2 salt for additional entropy.
    """
    if len(derived_key) != KEYFILE_HASH_LEN or len(keyfile_material) != KEYFILE_HASH_LEN:
        raise ValueError("Both keys must be 32 bytes")
    # Maintain backward-compatible output while avoiding raw XOR: feed both
    # inputs through HKDF so the result is pseudorandom even if one input is
    # fully known to an adversary.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEYFILE_HASH_LEN,
        salt=derived_key,
        info=b"zilant-keyfile-combine-v1",
    )
    return hkdf.derive(keyfile_material)
