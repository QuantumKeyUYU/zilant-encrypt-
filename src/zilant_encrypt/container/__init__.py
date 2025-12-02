"""Public container API re-exported for external users.

The objects listed in ``__all__`` form the supported public surface for
Python consumers in v0.2. Everything else in :mod:`zilant_encrypt.container`
is considered internal and may change without notice.
"""
from __future__ import annotations

from zilant_encrypt.container.core import (
    ARGON_MEM_MAX_KIB,
    ARGON_MEM_MIN_KIB,
    ARGON_PARALLELISM_MAX,
    ARGON_PARALLELISM_MIN,
    ARGON_TIME_MAX,
    ARGON_TIME_MIN,
    ContainerOverview,
    ModeLiteral,
    PayloadMeta,
    VolumeLayout,
    build_volume_descriptor,
    check_container,
    decrypt_auto_volume,
    decrypt_file,
    encrypt_file,
    encrypt_with_decoy,
    normalize_mode,
    resolve_argon_params,
)
from zilant_encrypt.container.format import KEY_MODE_PASSWORD_ONLY, KEY_MODE_PQ_HYBRID, read_header_from_stream
from zilant_encrypt.container.keymgmt import PasswordKeyProvider, WrappedKey, WRAP_NONCE
from zilant_encrypt.container.payload import (
    MAX_PAYLOAD_META_LEN,
    PAYLOAD_MAGIC,
    PAYLOAD_META_LEN_SIZE,
    PAYLOAD_VERSION,
    STREAM_CHUNK_SIZE,
)
from zilant_encrypt.crypto.kdf import Argon2Params

__all__ = [
    "ARGON_MEM_MAX_KIB",
    "ARGON_MEM_MIN_KIB",
    "ARGON_PARALLELISM_MAX",
    "ARGON_PARALLELISM_MIN",
    "ARGON_TIME_MAX",
    "ARGON_TIME_MIN",
    "Argon2Params",
    "ContainerOverview",
    "KEY_MODE_PASSWORD_ONLY",
    "KEY_MODE_PQ_HYBRID",
    "MAX_PAYLOAD_META_LEN",
    "ModeLiteral",
    "PAYLOAD_MAGIC",
    "PAYLOAD_META_LEN_SIZE",
    "PAYLOAD_VERSION",
    "PasswordKeyProvider",
    "PayloadMeta",
    "STREAM_CHUNK_SIZE",
    "VolumeLayout",
    "WrappedKey",
    "WRAP_NONCE",
    "build_volume_descriptor",
    "check_container",
    "decrypt_auto_volume",
    "decrypt_file",
    "encrypt_file",
    "encrypt_with_decoy",
    "normalize_mode",
    "read_header_from_stream",
    "resolve_argon_params",
]
