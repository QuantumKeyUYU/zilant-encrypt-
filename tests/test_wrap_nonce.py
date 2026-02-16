"""Tests for HKDF-based wrap nonce derivation."""
from __future__ import annotations

import os

from zilant_encrypt.container.keymgmt import WRAP_NONCE, derive_wrap_nonce


def test_derive_wrap_nonce_returns_12_bytes() -> None:
    salt = os.urandom(16)
    nonce = derive_wrap_nonce(salt)
    assert len(nonce) == 12


def test_derive_wrap_nonce_deterministic() -> None:
    salt = b"fixed-salt-16byt"
    n1 = derive_wrap_nonce(salt)
    n2 = derive_wrap_nonce(salt)
    assert n1 == n2


def test_derive_wrap_nonce_different_salts_differ() -> None:
    n1 = derive_wrap_nonce(b"salt-aaaaaaaaaa16")
    n2 = derive_wrap_nonce(b"salt-bbbbbbbbbb16")
    assert n1 != n2


def test_derive_wrap_nonce_differs_from_legacy() -> None:
    """HKDF-derived nonce must not accidentally equal the legacy zero nonce."""
    salt = b"any-salt-16bytes"
    nonce = derive_wrap_nonce(salt)
    assert nonce != WRAP_NONCE
