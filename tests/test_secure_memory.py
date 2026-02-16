"""Tests for secure memory utilities."""
from __future__ import annotations

from zilant_encrypt.crypto.secure_memory import SecureBuffer, mlock_available, secure_zeroize


def test_secure_buffer_zeroes_on_close() -> None:
    buf = SecureBuffer(32)
    with buf as data:
        data[:] = b"\xff" * 32
        assert data == bytearray(b"\xff" * 32)
    # After close, buffer should be zeroed
    assert buf.buffer == bytearray(32)


def test_secure_buffer_context_manager() -> None:
    with SecureBuffer(16) as data:
        data[:] = b"secret_material!"
        assert len(data) == 16


def test_secure_zeroize_basic() -> None:
    buf = bytearray(b"sensitive data here!")
    secure_zeroize(buf)
    assert buf == bytearray(len(buf))


def test_secure_zeroize_none() -> None:
    # Should not raise
    secure_zeroize(None)


def test_mlock_available_returns_bool() -> None:
    result = mlock_available()
    assert isinstance(result, bool)
