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


def test_combine_key_with_keyfile() -> None:
    """combine_key_with_keyfile must return 32 bytes distinct from both inputs
    and must be deterministic (same inputs -> same output)."""
    key = bytes(range(32))
    kf = bytes(range(32, 64))
    result = combine_key_with_keyfile(key, kf)
    assert len(result) == 32
    assert result != key
    assert result != kf
    # Deterministic: same inputs produce same output
    result2 = combine_key_with_keyfile(key, kf)
    assert result == result2
    # Different inputs produce different output
    result3 = combine_key_with_keyfile(key, bytes(range(64, 96)))
    assert result != result3


def test_combine_key_wrong_length() -> None:
    with pytest.raises(ValueError):
        combine_key_with_keyfile(b"short", b"short")
