"""Compatibility facade — re-exports public container API.

Prefer importing from ``zilant_encrypt.container`` directly.
This module exists for backward compatibility with tests and internal usage.
"""
from __future__ import annotations

# Re-export everything from the canonical __init__
from zilant_encrypt.container import *  # noqa: F401, F403
from zilant_encrypt.container import __all__ as _container_all

# Also re-export internal helpers that existing tests rely on
from zilant_encrypt.container.core import (
    _decrypt_volume,
    _derive_file_key,
    _ensure_output,
)
from zilant_encrypt.container.keymgmt import (
    _validate_argon_params,
    _validate_decrypt_argon_params,
    _zeroize,
)
from zilant_encrypt.container.overview import (
    _ciphertext_length_for_descriptor,
    _load_overview,
    _select_descriptors,
)
from zilant_encrypt.container.payload import (
    _build_payload_header,
    _decrypt_stream,
    _encrypt_stream,
    _NullWriter,
    _PayloadSource,
    _PayloadWriter,
)
from zilant_encrypt.container.format import RESERVED_LEN
from zilant_encrypt.crypto.aead import TAG_LEN, AesGcmEncryptor

__all__ = [
    *_container_all,
    # Internal helpers for tests
    "AesGcmEncryptor",
    "RESERVED_LEN",
    "TAG_LEN",
    "_NullWriter",
    "_PayloadSource",
    "_PayloadWriter",
    "_build_payload_header",
    "_ciphertext_length_for_descriptor",
    "_decrypt_stream",
    "_decrypt_volume",
    "_derive_file_key",
    "_encrypt_stream",
    "_ensure_output",
    "_load_overview",
    "_select_descriptors",
    "_validate_argon_params",
    "_validate_decrypt_argon_params",
    "_zeroize",
]
