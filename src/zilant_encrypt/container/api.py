"""High level container encryption/decryption functions."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Iterable

from zilant_encrypt.container.format import (
    HEADER_LEN,
    KEY_MODE_PASSWORD_ONLY,
    build_header,
    parse_header,
)
from zilant_encrypt.errors import ContainerFormatError, IntegrityError, InvalidPassword

PBKDF_ITERATIONS = 2
PBKDF_MEM_COST = 1024
PBKDF_PARALLELISM = 1


def _derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF_ITERATIONS, length)


def _xor_bytes(data: bytes, key_stream: Iterable[int]) -> bytes:
    return bytes(b ^ k for b, k in zip(data, key_stream))


def _stream_cipher(key: bytes, nonce: bytes, length: int) -> bytes:
    blocks = []
    counter = 0
    while len(b"".join(blocks)) < length:
        counter_bytes = counter.to_bytes(8, "little")
        block = hashlib.sha256(key + nonce + counter_bytes).digest()
        blocks.append(block)
        counter += 1
    return b"".join(blocks)[:length]


def _hmac(key: bytes, data: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", data, key, 1, dklen=32)


def encrypt_file(input_path: Path, container_path: Path, password: str, *, overwrite: bool) -> None:
    if container_path.exists() and not overwrite:
        raise FileExistsError(f"File '{container_path}' already exists")

    payload = Path(input_path).read_bytes()

    salt = os.urandom(16)
    derived_key = _derive_key(password, salt)

    file_key = os.urandom(32)
    wrap_nonce = os.urandom(12)

    wrapped_key = _xor_bytes(file_key, derived_key)
    wrapped_tag = _hmac(derived_key, wrapped_key)[:16]

    header = build_header(
        key_mode=KEY_MODE_PASSWORD_ONLY,
        header_flags=0,
        salt_argon2=salt,
        argon_mem_cost=PBKDF_MEM_COST,
        argon_time_cost=PBKDF_ITERATIONS,
        argon_parallelism=PBKDF_PARALLELISM,
        nonce_aes_gcm=wrap_nonce,
        wrapped_key=wrapped_key,
        wrapped_key_tag=wrapped_tag,
    )

    payload_nonce = os.urandom(12)
    keystream = _stream_cipher(file_key, payload_nonce, len(payload))
    ciphertext = _xor_bytes(payload, keystream)
    payload_tag = _hmac(file_key, payload_nonce + ciphertext)

    container_path.write_bytes(header + payload_nonce + ciphertext + payload_tag)


def decrypt_file(
    container_path: Path, output_path: Path, password: str, *, overwrite: bool
) -> None:
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"File '{output_path}' already exists")

    data = Path(container_path).read_bytes()
    if len(data) < HEADER_LEN + 12 + 32:
        raise ContainerFormatError("Контейнер слишком мал")

    header = parse_header(data[:HEADER_LEN])

    derived_key = _derive_key(password, header.salt_argon2)
    expected_tag = _hmac(derived_key, header.wrapped_file_key)[:16]
    if expected_tag != header.wrapped_key_tag:
        raise InvalidPassword("Неверный пароль")

    file_key = _xor_bytes(header.wrapped_file_key, derived_key)

    payload_start = HEADER_LEN
    payload_nonce = data[payload_start : payload_start + 12]
    ciphertext = data[payload_start + 12 : -32]
    payload_tag = data[-32:]

    if _hmac(file_key, payload_nonce + ciphertext) != payload_tag:
        raise IntegrityError("Нарушена целостность контейнера")

    keystream = _stream_cipher(file_key, payload_nonce, len(ciphertext))
    plaintext = _xor_bytes(ciphertext, keystream)

    Path(output_path).write_bytes(plaintext)
