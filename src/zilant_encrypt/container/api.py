"""High-level API for encrypting and decrypting containers."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import tempfile
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag

from zilant_encrypt.container.format import (
    HEADER_LEN,
    KEY_MODE_PASSWORD_ONLY,
    build_header,
    header_aad,
    parse_header,
)
from zilant_encrypt.crypto.aead import AesGcmEncryptor, TAG_LEN
from zilant_encrypt.crypto.kdf import Argon2Params, derive_key_from_password, recommended_params
from zilant_encrypt.errors import (
    ContainerFormatError,
    IntegrityError,
    InvalidPassword,
    UnsupportedFeatureError,
)

WRAP_NONCE = b"\x00" * 12


@dataclass(frozen=True)
class WrappedKey:
    data: bytes
    tag: bytes


@runtime_checkable
class KeyProvider(Protocol):
    def wrap_file_key(self, file_key: bytes) -> WrappedKey: ...

    def unwrap_file_key(self, wrapped: WrappedKey) -> bytes: ...


class PasswordKeyProvider:
    """Password-based key provider using Argon2id."""

    def __init__(self, password: str, salt: bytes, params: Argon2Params) -> None:
        self.password = password
        self.salt = salt
        self.params = params
        self._password_key: bytes | None = None

    def _ensure_key(self) -> bytes:
        if self._password_key is None:
            self._password_key = derive_key_from_password(
                self.password,
                self.salt,
                mem_cost=self.params.mem_cost_kib,
                time_cost=self.params.time_cost,
                parallelism=self.params.parallelism,
            )
        return self._password_key

    def wrap_file_key(self, file_key: bytes) -> WrappedKey:
        key = self._ensure_key()
        ciphertext, tag = AesGcmEncryptor.encrypt(key, WRAP_NONCE, file_key, b"")
        return WrappedKey(data=ciphertext, tag=tag)

    def unwrap_file_key(self, wrapped: WrappedKey) -> bytes:
        key = self._ensure_key()
        try:
            return AesGcmEncryptor.decrypt(key, WRAP_NONCE, wrapped.data, wrapped.tag, b"")
        except InvalidTag as exc:
            raise InvalidPassword("Unable to unwrap file key") from exc


class _PayloadSource:
    def __init__(self, path: Path) -> None:
        self.original = path
        self.temp_dir: tempfile.TemporaryDirectory[str] | None = None
        self.path = path

    def __enter__(self) -> Path:
        if self.original.is_dir():
            self.temp_dir = tempfile.TemporaryDirectory()
            archive_path = Path(self.temp_dir.name) / f"{self.original.name}.zip"
            shutil.make_archive(
                base_name=str(archive_path.with_suffix("")),
                format="zip",
                root_dir=self.original,
            )
            self.path = archive_path
        return self.path

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
        if self.temp_dir:
            self.temp_dir.cleanup()


class _PasswordOnlyProviderFactory:
    def __init__(self, password: str, params: Argon2Params, salt: bytes):
        self.password = password
        self.params = params
        self.salt = salt

    def build(self) -> PasswordKeyProvider:
        return PasswordKeyProvider(self.password, self.salt, self.params)


# TODO: introduce HybridPQKeyProvider when PQ KEM is ready.


def _ensure_output(path: Path, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing file: {path}")
    if path.exists() and overwrite:
        path.unlink()


def encrypt_file(
    in_path: Path,
    out_path: Path,
    password: str,
    *,
    overwrite: bool = False,
) -> None:
    """Encrypt input file or directory into a .zil container."""

    _ensure_output(out_path, overwrite)

    argon_params = recommended_params()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    file_key = os.urandom(32)

    provider = _PasswordOnlyProviderFactory(password, argon_params, salt).build()
    wrapped_key = provider.wrap_file_key(file_key)

    header_bytes = build_header(
        key_mode=KEY_MODE_PASSWORD_ONLY,
        header_flags=0,
        salt_argon2=salt,
        argon_mem_cost=argon_params.mem_cost_kib,
        argon_time_cost=argon_params.time_cost,
        argon_parallelism=argon_params.parallelism,
        nonce_aes_gcm=nonce,
        wrapped_key=wrapped_key.data,
        wrapped_key_tag=wrapped_key.tag,
    )
    aad = header_aad(header_bytes)

    with _PayloadSource(in_path) as payload_path:
        plaintext = payload_path.read_bytes()

    ciphertext, tag = AesGcmEncryptor.encrypt(file_key, nonce, plaintext, aad)

    with out_path.open("xb") as f:
        f.write(header_bytes)
        f.write(ciphertext)
        f.write(tag)


def decrypt_file(
    container_path: Path,
    out_path: Path,
    password: str,
    *,
    overwrite: bool = False,
) -> None:
    """Decrypt a container to an output file."""

    _ensure_output(out_path, overwrite)

    data = container_path.read_bytes()
    header_bytes = data[:HEADER_LEN]
    body = data[HEADER_LEN:]

    header = parse_header(header_bytes)
    aad = header_aad(header_bytes)

    if header.key_mode != KEY_MODE_PASSWORD_ONLY:
        raise UnsupportedFeatureError("Only password-only containers supported in MVP")

    if len(body) < TAG_LEN:
        raise ContainerFormatError("Container missing authentication tag")

    ciphertext, tag = body[:-TAG_LEN], body[-TAG_LEN:]

    params = Argon2Params(
        mem_cost_kib=header.argon_mem_cost,
        time_cost=header.argon_time_cost,
        parallelism=header.argon_parallelism,
    )
    provider = PasswordKeyProvider(password, header.salt_argon2, params)

    file_key = provider.unwrap_file_key(WrappedKey(data=header.wrapped_file_key, tag=header.wrapped_key_tag))

    try:
        plaintext = AesGcmEncryptor.decrypt(file_key, header.nonce_aes_gcm, ciphertext, tag, aad)
    except InvalidTag as exc:
        raise IntegrityError("Container failed integrity check") from exc

    with out_path.open("xb") as f:
        f.write(plaintext)
