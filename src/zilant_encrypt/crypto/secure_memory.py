"""Secure memory utilities for sensitive key material.

Provides best-effort memory locking (mlock) and secure zeroing to prevent
key material from being swapped to disk or lingering in memory after use.
Falls back gracefully on platforms/environments where mlock is not available.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import logging
import platform

logger = logging.getLogger(__name__)

_MLOCK_AVAILABLE = False
_libc: ctypes.CDLL | None = None

# Try to load libc for mlock/munlock
if platform.system() != "Windows":
    try:
        _libc_name = ctypes.util.find_library("c")
        if _libc_name:
            _libc = ctypes.CDLL(_libc_name, use_errno=True)
            _MLOCK_AVAILABLE = True
    except OSError:
        pass


def mlock_available() -> bool:
    """Return True if mlock is available on this platform."""
    return _MLOCK_AVAILABLE


class SecureBuffer:
    """A bytearray-like buffer that attempts to mlock memory and zeroes on close.

    Usage::

        with SecureBuffer(32) as buf:
            buf[:] = key_material
            use_key(bytes(buf))
        # Memory is zeroed and munlocked here

    On platforms where mlock is unavailable, behaves as a plain bytearray
    with guaranteed zeroing on close.
    """

    def __init__(self, size: int) -> None:
        self._buffer = bytearray(size)
        self._size = size
        self._locked = False

        if _MLOCK_AVAILABLE and _libc is not None:
            try:
                addr = (ctypes.c_char * size).from_buffer(self._buffer)
                result = _libc.mlock(ctypes.addressof(addr), size)
                if result == 0:
                    self._locked = True
                else:
                    errno = ctypes.get_errno()
                    logger.debug("mlock failed (errno=%d), proceeding without lock", errno)
            except Exception:  # noqa: BLE001
                logger.debug("mlock unavailable, proceeding without lock")

    def __enter__(self) -> bytearray:
        return self._buffer

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Securely zero the buffer and unlock memory."""
        # Zero the buffer
        for i in range(self._size):
            self._buffer[i] = 0

        # Munlock if we locked it
        if self._locked and _libc is not None:
            try:
                addr = (ctypes.c_char * self._size).from_buffer(self._buffer)
                _libc.munlock(ctypes.addressof(addr), self._size)
            except Exception:  # noqa: BLE001
                pass
            self._locked = False

    @property
    def buffer(self) -> bytearray:
        return self._buffer


def secure_zeroize(data: bytearray | None) -> None:
    """Zero a bytearray in-place with compiler-barrier.

    Uses a volatile-style write pattern to reduce the chance that
    the compiler optimizes away the zeroing.
    """
    if data is None:
        return
    length = len(data)
    for i in range(length):
        data[i] = 0
    # Read back to create a data dependency the optimizer can't remove
    if length > 0:
        _ = data[0]
