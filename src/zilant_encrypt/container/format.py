"""Binary format helpers for Zilant Encrypt containers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from zilant_encrypt.errors import ContainerFormatError, UnsupportedFeatureError

MAGIC: Final = b"ZILANT"
VERSION: Final = 1
KEY_MODE_PASSWORD_ONLY: Final = 0
HEADER_LEN: Final = 97


@dataclass
class Header:
    """Parsed container header."""

    key_mode: int
    header_flags: int
    salt_argon2: bytes
    argon_mem_cost: int
    argon_time_cost: int
    argon_parallelism: int
    nonce_aes_gcm: bytes
    wrapped_file_key: bytes
    wrapped_key_tag: bytes


def build_header(
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
) -> bytes:
    """Build a binary header for a Zilant container."""

    header = bytearray()
    header.extend(MAGIC)
    header.append(VERSION)
    header.append(key_mode)
    header.append(header_flags)
    header.extend(salt_argon2)
    header.extend(argon_mem_cost.to_bytes(4, "little"))
    header.extend(argon_time_cost.to_bytes(4, "little"))
    header.extend(argon_parallelism.to_bytes(4, "little"))
    header.extend(nonce_aes_gcm)
    header.extend(wrapped_key)
    header.extend(wrapped_key_tag)

    if len(header) != HEADER_LEN:
        raise ContainerFormatError("Header length mismatch")

    return bytes(header)


def _expect_length(value: bytes, expected: int, label: str) -> None:
    if len(value) != expected:
        raise ContainerFormatError(f"{label} length must be {expected} bytes")


def parse_header(data: bytes) -> Header:
    """Parse container header from raw bytes."""

    if len(data) != HEADER_LEN:
        raise ContainerFormatError("Недопустимая длина заголовка")

    if data[: len(MAGIC)] != MAGIC:
        raise ContainerFormatError("Неверная сигнатура контейнера")

    version = data[len(MAGIC)]
    if version != VERSION:
        raise UnsupportedFeatureError("Неподдерживаемая версия контейнера")

    key_mode = data[len(MAGIC) + 1]
    if key_mode != KEY_MODE_PASSWORD_ONLY:
        raise UnsupportedFeatureError("Неподдерживаемый режим ключа")

    header_flags = data[len(MAGIC) + 2]

    offset = len(MAGIC) + 3
    salt_argon2 = data[offset : offset + 16]
    _expect_length(salt_argon2, 16, "Salt")
    offset += 16

    argon_mem_cost = int.from_bytes(data[offset : offset + 4], "little")
    offset += 4
    argon_time_cost = int.from_bytes(data[offset : offset + 4], "little")
    offset += 4
    argon_parallelism = int.from_bytes(data[offset : offset + 4], "little")
    offset += 4

    nonce_aes_gcm = data[offset : offset + 12]
    _expect_length(nonce_aes_gcm, 12, "Nonce")
    offset += 12

    wrapped_key = data[offset : offset + 32]
    _expect_length(wrapped_key, 32, "Wrapped key")
    offset += 32

    wrapped_key_tag = data[offset : offset + 16]
    _expect_length(wrapped_key_tag, 16, "Tag")

    return Header(
        key_mode=key_mode,
        header_flags=header_flags,
        salt_argon2=salt_argon2,
        argon_mem_cost=argon_mem_cost,
        argon_time_cost=argon_time_cost,
        argon_parallelism=argon_parallelism,
        nonce_aes_gcm=nonce_aes_gcm,
        wrapped_file_key=wrapped_key,
        wrapped_key_tag=wrapped_key_tag,
    )
