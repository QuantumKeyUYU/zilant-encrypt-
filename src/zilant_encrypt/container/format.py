"""Container header format helpers."""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct

from zilant_encrypt.errors import ContainerFormatError, UnsupportedFeatureError

MAGIC = b"ZILENC"
VERSION = 1
HEADER_LEN = 128
KEY_MODE_PASSWORD_ONLY = 0
KEY_MODE_PQ_HYBRID = 1

MAGIC_LEN = 6
VERSION_LEN = 1
SALT_LEN = 16
NONCE_LEN = 12
WRAPPED_KEY_MAX_LEN = 32
WRAPPED_KEY_TAG_LEN = 16
RESERVED_LEN = 28

_HEADER_STRUCT = Struct(
    "<6sBBH16sIII12sH32s16s28s",
)  # totals 128 bytes

@dataclass(frozen=True)
class ContainerHeader:
    key_mode: int
    header_flags: int
    salt_argon2: bytes
    argon_mem_cost: int
    argon_time_cost: int
    argon_parallelism: int
    nonce_aes_gcm: bytes
    wrapped_key_len: int
    wrapped_file_key: bytes
    wrapped_key_tag: bytes
    reserved: bytes

    def to_bytes(self) -> bytes:
        return build_header(
            key_mode=self.key_mode,
            header_flags=self.header_flags,
            salt_argon2=self.salt_argon2,
            argon_mem_cost=self.argon_mem_cost,
            argon_time_cost=self.argon_time_cost,
            argon_parallelism=self.argon_parallelism,
            nonce_aes_gcm=self.nonce_aes_gcm,
            wrapped_key=self.wrapped_file_key,
            wrapped_key_tag=self.wrapped_key_tag,
            reserved=self.reserved,
        )


def build_header(  # noqa: PLR0913
    *,
    key_mode: int,
    header_flags: int,
    salt_argon2: bytes,
    argon_mem_cost: int,
    argon_time_cost: int,
    argon_parallelism: int,
    nonce_aes_gcm: bytes,
    wrapped_key: bytes,
    wrapped_key_tag: bytes,
    reserved: bytes | None = None,
) -> bytes:
    """Build container header bytes."""

    if len(salt_argon2) != SALT_LEN:
        raise ContainerFormatError("salt_argon2 must be 16 bytes")
    if len(nonce_aes_gcm) != NONCE_LEN:
        raise ContainerFormatError("nonce_aes_gcm must be 12 bytes")
    if len(wrapped_key) > WRAPPED_KEY_MAX_LEN:
        raise ContainerFormatError("wrapped_key must be at most 32 bytes")
    if len(wrapped_key_tag) != WRAPPED_KEY_TAG_LEN:
        raise ContainerFormatError("wrapped_key_tag must be 16 bytes")
    reserved_bytes = reserved if reserved is not None else bytes(RESERVED_LEN)
    if len(reserved_bytes) != RESERVED_LEN:
        raise ContainerFormatError("reserved must be 28 bytes")

    if key_mode not in (KEY_MODE_PASSWORD_ONLY, KEY_MODE_PQ_HYBRID):
        raise ContainerFormatError("Unknown key_mode")

    wrapped_key_padded = wrapped_key.ljust(32, b"\x00")
    wrapped_key_len = len(wrapped_key)

    packed = _HEADER_STRUCT.pack(
        MAGIC,
        VERSION,
        key_mode,
        header_flags,
        salt_argon2,
        argon_mem_cost,
        argon_time_cost,
        argon_parallelism,
        nonce_aes_gcm,
        wrapped_key_len,
        wrapped_key_padded,
        wrapped_key_tag,
        reserved_bytes,
    )

    if len(packed) != HEADER_LEN:
        raise ContainerFormatError("Header length mismatch")
    return packed


def parse_header(data: bytes) -> ContainerHeader:
    """Parse and validate header bytes."""

    if len(data) < HEADER_LEN:
        raise ContainerFormatError("Header too short")
    if len(data) != HEADER_LEN:
        raise ContainerFormatError("Invalid header length")

    (
        magic,
        version,
        key_mode,
        header_flags,
        salt_argon2,
        argon_mem_cost,
        argon_time_cost,
        argon_parallelism,
        nonce_aes_gcm,
        wrapped_key_len,
        wrapped_key_padded,
        wrapped_key_tag,
        reserved,
    ) = _HEADER_STRUCT.unpack(data)

    if magic != MAGIC:
        raise ContainerFormatError("Invalid magic")
    if version != VERSION:
        raise ContainerFormatError("Unsupported version")

    if key_mode != KEY_MODE_PASSWORD_ONLY:
        raise UnsupportedFeatureError("Only password-based containers are supported")

    if not (0 <= wrapped_key_len <= WRAPPED_KEY_MAX_LEN):
        raise ContainerFormatError("Invalid wrapped_key_len")

    wrapped_key = wrapped_key_padded[:wrapped_key_len]

    return ContainerHeader(
        key_mode=key_mode,
        header_flags=header_flags,
        salt_argon2=salt_argon2,
        argon_mem_cost=argon_mem_cost,
        argon_time_cost=argon_time_cost,
        argon_parallelism=argon_parallelism,
        nonce_aes_gcm=nonce_aes_gcm,
        wrapped_key_len=wrapped_key_len,
        wrapped_file_key=wrapped_key,
        wrapped_key_tag=wrapped_key_tag,
        reserved=reserved,
    )


def header_aad(header_bytes: bytes) -> bytes:
    """Return header bytes used as AAD (everything except magic+version)."""

    if len(header_bytes) != HEADER_LEN:
        raise ContainerFormatError("Header must be fully formed")
    return header_bytes[MAGIC_LEN + VERSION_LEN :]
