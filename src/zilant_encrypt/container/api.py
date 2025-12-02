"""High-level API for encrypting and decrypting containers."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import IO, Literal, Optional, Protocol, Type, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from zilant_encrypt.container.format import (
    HEADER_LEN,
    KEY_MODE_PASSWORD_ONLY,
    build_header,
    header_aad,
    parse_header,
)
from zilant_encrypt.crypto.aead import TAG_LEN, AesGcmEncryptor
from zilant_encrypt.crypto.kdf import Argon2Params, derive_key_from_password, recommended_params
from zilant_encrypt.errors import (
    ContainerFormatError,
    IntegrityError,
    InvalidPassword,
    UnsupportedFeatureError,
)

WRAP_NONCE = b"\x00" * 12
PAYLOAD_MAGIC = b"ZPAY"
PAYLOAD_VERSION = 1
PAYLOAD_META_LEN_SIZE = 4
STREAM_CHUNK_SIZE = 1024 * 64


@dataclass(frozen=True)
class WrappedKey:
    data: bytes
    tag: bytes


@dataclass(frozen=True)
class PayloadMeta:
    kind: Literal["file", "directory"]
    name: str


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
        self.meta = PayloadMeta(kind="file", name=path.name)

    def __enter__(self) -> Path:
        if self.original.is_dir():
            self.temp_dir = tempfile.TemporaryDirectory()
            try:
                archive_path = Path(self.temp_dir.name) / f"{self.original.name}.zip"
                shutil.make_archive(
                    base_name=str(archive_path.with_suffix("")),
                    format="zip",
                    root_dir=self.original,
                )
                self.path = archive_path
                self.meta = PayloadMeta(kind="directory", name=self.original.name)
            except Exception:  # noqa: BLE001
                if self.temp_dir is not None:
                    self.temp_dir.cleanup()
                raise
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> bool:
        if self.temp_dir:
            self.temp_dir.cleanup()
        return False


class _PasswordOnlyProviderFactory:
    def __init__(self, password: str, params: Argon2Params, salt: bytes) -> None:
        self.password = password
        self.params = params
        self.salt = salt

    def build(self) -> PasswordKeyProvider:
        return PasswordKeyProvider(self.password, self.salt, self.params)


# TODO: introduce HybridPQKeyProvider when PQ KEM is ready.


def _ensure_output(path: Path, overwrite: bool) -> None:
    if path.exists():
        if not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing file: {path}")
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)


def _build_payload_header(meta: PayloadMeta) -> bytes:
    payload_meta = {"type": meta.kind, "name": meta.name}
    encoded_meta = json.dumps(payload_meta, ensure_ascii=False).encode("utf-8")
    meta_len = len(encoded_meta).to_bytes(PAYLOAD_META_LEN_SIZE, "little")
    return PAYLOAD_MAGIC + bytes([PAYLOAD_VERSION]) + meta_len + encoded_meta


class _PayloadWriter:
    def __init__(self, out_path: Path) -> None:
        self.out_path = out_path
        self.meta: PayloadMeta | None = None
        self._buffer = bytearray()
        self._file_handle: IO[bytes] | None = None
        self._temp_zip: tempfile.NamedTemporaryFile | None = None

    def _parse_meta(self) -> None:
        if len(self._buffer) < len(PAYLOAD_MAGIC):
            return

        if self.meta is None and not bytes(self._buffer).startswith(PAYLOAD_MAGIC):
            self.meta = PayloadMeta(kind="file", name=self.out_path.name)
            remaining = bytes(self._buffer)
            self._buffer.clear()
            if remaining:
                self._write_payload(remaining)
            return

        minimum_header = len(PAYLOAD_MAGIC) + 1 + PAYLOAD_META_LEN_SIZE
        if len(self._buffer) < minimum_header:
            return

        if not bytes(self._buffer).startswith(PAYLOAD_MAGIC):
            return

        version = self._buffer[len(PAYLOAD_MAGIC)]
        if version != PAYLOAD_VERSION:
            raise ContainerFormatError("Unsupported payload metadata version")

        length_start = len(PAYLOAD_MAGIC) + 1
        length_end = length_start + PAYLOAD_META_LEN_SIZE
        meta_len = int.from_bytes(self._buffer[length_start:length_end], "little")
        total_header = minimum_header + meta_len
        if len(self._buffer) < total_header:
            return

        meta_payload = bytes(self._buffer[length_end:total_header])
        try:
            meta_dict = json.loads(meta_payload.decode("utf-8"))
        except json.JSONDecodeError as exc:  # noqa: TRY003
            raise ContainerFormatError("Invalid payload metadata") from exc

        kind = meta_dict.get("type")
        name = meta_dict.get("name") or self.out_path.name
        if kind not in {"file", "directory"}:
            raise ContainerFormatError("Unknown payload type")

        self.meta = PayloadMeta(kind=kind, name=name)
        remaining = bytes(self._buffer[total_header:])
        self._buffer.clear()
        if remaining:
            self._write_payload(remaining)

    def _ensure_file_handle(self) -> IO[bytes]:
        if self._file_handle is None:
            self._file_handle = self.out_path.open("xb")
        return self._file_handle

    def _ensure_temp_zip(self) -> tempfile.NamedTemporaryFile:
        if self._temp_zip is None:
            self._temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        return self._temp_zip

    def _write_payload(self, data: bytes) -> None:
        if self.meta is None:
            self._buffer.extend(data)
            self._parse_meta()
            return

        if self.meta.kind == "file":
            handle = self._ensure_file_handle()
            handle.write(data)
        else:
            handle = self._ensure_temp_zip()
            handle.write(data)

    def feed(self, data: bytes) -> None:
        if not data:
            return
        if self.meta is None:
            self._buffer.extend(data)
            self._parse_meta()
        else:
            self._write_payload(data)

    def finalize(self) -> None:
        if self.meta is None:
            self.meta = PayloadMeta(kind="file", name=self.out_path.name)
            self._write_payload(bytes(self._buffer))
            self._buffer.clear()

        if self.meta.kind == "file":
            if self._file_handle is None:
                self._file_handle = self.out_path.open("xb")
            self._file_handle.flush()
            self._file_handle.close()
        else:
            temp_zip = self._ensure_temp_zip()
            temp_zip.flush()
            temp_zip.close()
            self.out_path.mkdir(parents=True, exist_ok=True)
            try:
                shutil.unpack_archive(temp_zip.name, self.out_path)
            finally:
                Path(temp_zip.name).unlink(missing_ok=True)


def _encrypt_stream(
    in_file: IO[bytes],
    out_file: IO[bytes],
    key: bytes,
    nonce: bytes,
    aad: bytes,
    *,
    initial: bytes = b"",
) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(aad)

    if initial:
        initial_chunk = encryptor.update(initial)
        if initial_chunk:
            out_file.write(initial_chunk)

    while True:
        chunk = in_file.read(STREAM_CHUNK_SIZE)
        if not chunk:
            break
        ciphertext = encryptor.update(chunk)
        if ciphertext:
            out_file.write(ciphertext)

    final_chunk = encryptor.finalize()
    if final_chunk:
        out_file.write(final_chunk)
    return encryptor.tag


def _decrypt_stream(
    in_file: IO[bytes],
    writer: _PayloadWriter,
    key: bytes,
    nonce: bytes,
    aad: bytes,
    ciphertext_len: int,
) -> None:
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
    decryptor.authenticate_additional_data(aad)

    remaining = ciphertext_len
    while remaining > 0:
        chunk = in_file.read(min(STREAM_CHUNK_SIZE, remaining))
        if not chunk:
            raise ContainerFormatError("Container truncated before authentication tag")
        remaining -= len(chunk)
        plaintext = decryptor.update(chunk)
        if plaintext:
            writer.feed(plaintext)

    tag = in_file.read(TAG_LEN)
    if len(tag) != TAG_LEN:
        raise ContainerFormatError("Container missing authentication tag")

    try:
        final_chunk = decryptor.finalize_with_tag(tag)
    except InvalidTag as exc:
        raise IntegrityError("Container failed integrity check") from exc

    if final_chunk:
        writer.feed(final_chunk)
    writer.finalize()


def encrypt_file(
    in_path: Path,
    out_path: Path,
    password: str,
    *,
    overwrite: bool = False,
) -> None:
    """Encrypt input file or directory into a .zil container."""

    if not in_path.exists():
        raise FileNotFoundError(in_path)
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

    with _PayloadSource(in_path) as payload_source:
        payload_header = _build_payload_header(payload_source.meta)
        with payload_source.path.open("rb") as payload_file, out_path.open("xb") as f:
            f.write(header_bytes)
            tag = _encrypt_stream(payload_file, f, file_key, nonce, aad, initial=payload_header)
            f.write(tag)


def decrypt_file(
    container_path: Path,
    out_path: Path,
    password: str,
    *,
    overwrite: bool = False,
) -> None:
    """Decrypt a container to an output file."""

    if not container_path.exists():
        raise FileNotFoundError(container_path)

    file_size = container_path.stat().st_size
    if file_size < HEADER_LEN + TAG_LEN:
        raise ContainerFormatError("Container too small")

    _ensure_output(out_path, overwrite)

    with container_path.open("rb") as f:
        header_bytes = f.read(HEADER_LEN)
        if len(header_bytes) != HEADER_LEN:
            raise ContainerFormatError("Container missing header")

        header = parse_header(header_bytes)
        aad = header_aad(header_bytes)

        if header.key_mode != KEY_MODE_PASSWORD_ONLY:
            raise UnsupportedFeatureError("Only password-only containers supported in MVP")

        if header.wrapped_key_len != 32:
            raise ContainerFormatError("Unexpected wrapped key length")

        ciphertext_len = file_size - HEADER_LEN - TAG_LEN
        decrypt_params = Argon2Params(
            mem_cost_kib=header.argon_mem_cost,
            time_cost=header.argon_time_cost,
            parallelism=header.argon_parallelism,
        )
        provider = PasswordKeyProvider(password, header.salt_argon2, decrypt_params)
        file_key = provider.unwrap_file_key(
            WrappedKey(data=header.wrapped_file_key, tag=header.wrapped_key_tag),
        )

        writer = _PayloadWriter(out_path)
        _decrypt_stream(
            f,
            writer,
            file_key,
            header.nonce_aes_gcm,
            aad,
            ciphertext_len,
        )
