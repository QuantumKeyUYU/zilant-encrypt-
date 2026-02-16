"""Tests for keyfile support."""
from __future__ import annotations

from pathlib import Path

import pytest

from zilant_encrypt.crypto.keyfile import combine_key_with_keyfile, derive_keyfile_material


def test_derive_keyfile_returns_32_bytes(tmp_path: Path) -> None:
    kf = tmp_path / "key.bin"
    kf.write_bytes(b"some secret keyfile content")
    material = derive_keyfile_material(kf)
    assert len(material) == 32


def test_derive_keyfile_deterministic(tmp_path: Path) -> None:
    kf = tmp_path / "key.bin"
    kf.write_bytes(b"deterministic content")
    m1 = derive_keyfile_material(kf)
    m2 = derive_keyfile_material(kf)
    assert m1 == m2


def test_derive_keyfile_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        derive_keyfile_material(tmp_path / "nonexistent")


def test_combine_key_with_keyfile_xor() -> None:
    key = bytes(range(32))
    kf = bytes(range(32, 64))
    result = combine_key_with_keyfile(key, kf)
    assert len(result) == 32
    assert result != key
    assert result != kf
    # XOR is reversible
    restored = combine_key_with_keyfile(result, kf)
    assert restored == key


def test_combine_key_wrong_length() -> None:
    with pytest.raises(ValueError):
        combine_key_with_keyfile(b"short", b"short")
