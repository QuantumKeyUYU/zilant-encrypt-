"""Payload handling helpers (metadata, streaming encryption/decryption)."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import IO, Any, Literal, Optional, Protocol, Type

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from zilant_encrypt.crypto.aead import TAG_LEN as AEAD_TAG_LEN
from zilant_encrypt.errors import ContainerFormatError, IntegrityError

PAYLOAD_MAGIC = b"ZPAY"
PAYLOAD_VERSION = 1
PAYLOAD_META_LEN_SIZE = 4
MAX_PAYLOAD_META_LEN = 64 * 1024
STREAM_CHUNK_SIZE = 1024 * 64


@dataclass(frozen=True)
class PayloadMeta:
    kind: Literal["file", "directory"]
    name: str


class _PayloadSource:
    def __init__(self, path: Path) -> None:
        self.original = path
        self.temp_dir: tempfile.TemporaryDirectory[str] | None = None
        self.path = path
        self.meta = PayloadMeta(kind="file", name=path.name)

    def __enter__(self) -> _PayloadSource:
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
    ) -> Literal[False]:
        if self.temp_dir:
            self.temp_dir.cleanup()
        return False


class PayloadWriterProtocol(Protocol):
    def feed(self, data: bytes) -> None: ...

    def finalize(self) -> None: ...


class _NullWriter:
    def feed(self, data: bytes) -> None:  # pragma: no cover - trivial sink
        del data

    def finalize(self) -> None:  # pragma: no cover - trivial sink
        return None


@dataclass
class _PayloadWriter:
    out_path: Path
    meta: PayloadMeta | None = None
    _buffer: bytearray = field(default_factory=bytearray)
    _file_handle: IO[bytes] | None = None
    _temp_zip: Any | None = None

    def _ensure_temp_zip(self) -> IO[bytes]:
        if self._temp_zip is None:
            self._temp_zip = tempfile.NamedTemporaryFile(delete=False)
        return self._temp_zip

    def _write_payload(self, data: bytes) -> None:
        if self.meta is None:
            self._buffer.extend(data)
            self._parse_meta()
            return

        if self.meta.kind == "file":
            if self._file_handle is None:
                self._file_handle = self.out_path.open("xb")
            self._file_handle.write(data)
        else:
            temp_zip = self._ensure_temp_zip()
            temp_zip.write(data)

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
        if meta_len > MAX_PAYLOAD_META_LEN:
            raise ContainerFormatError("Payload metadata too large")
        total_header = minimum_header + meta_len
        if len(self._buffer) < total_header:
            return

        meta_payload = bytes(self._buffer[length_end:total_header])
        try:
            meta_dict = json.loads(meta_payload.decode("utf-8"))
        except json.JSONDecodeError as exc:  # noqa: TRY003
            raise ContainerFormatError("Invalid payload metadata") from exc

        if not isinstance(meta_dict, dict):
            raise ContainerFormatError("Invalid payload metadata")

        meta_type = meta_dict.get("type")
        meta_name = meta_dict.get("name")
        if meta_type not in ("file", "directory"):
            raise ContainerFormatError("Invalid payload metadata")
        if not isinstance(meta_name, str) or not meta_name:
            raise ContainerFormatError("Invalid payload metadata")

        self.meta = PayloadMeta(kind=meta_type, name=meta_name)
        payload = bytes(self._buffer[total_header:])
        self._buffer.clear()
        if payload:
            self._write_payload(payload)

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
                base_path = self.out_path.resolve()
                with zipfile.ZipFile(temp_zip.name) as archive:
                    for member in archive.infolist():
                        member_path = Path(member.filename)
                        if member_path.is_absolute():
                            raise ContainerFormatError("Archive entry has invalid path")
                        resolved_member = (base_path / member_path).resolve()
                        if resolved_member != base_path and not str(resolved_member).startswith(str(base_path) + os.sep):
                            raise ContainerFormatError("Archive entry escapes target directory")
                    archive.extractall(self.out_path)
            finally:
                Path(temp_zip.name).unlink(missing_ok=True)


def _build_payload_header(meta: PayloadMeta) -> bytes:
    payload_meta = {"type": meta.kind, "name": meta.name}
    encoded_meta = json.dumps(payload_meta, ensure_ascii=False).encode("utf-8")
    meta_len = len(encoded_meta).to_bytes(PAYLOAD_META_LEN_SIZE, "little")
    return PAYLOAD_MAGIC + bytes([PAYLOAD_VERSION]) + meta_len + encoded_meta


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
    writer: PayloadWriterProtocol,
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

    tag = in_file.read(AEAD_TAG_LEN)
    if len(tag) != AEAD_TAG_LEN:
        raise ContainerFormatError("Container missing authentication tag")

    try:
        final_chunk = decryptor.finalize_with_tag(tag)
    except InvalidTag as exc:
        raise IntegrityError("Container failed integrity check") from exc

    if final_chunk:
        writer.feed(final_chunk)
    writer.finalize()


__all__ = [
    "MAX_PAYLOAD_META_LEN",
    "PAYLOAD_MAGIC",
    "PAYLOAD_META_LEN_SIZE",
    "PAYLOAD_VERSION",
    "PayloadMeta",
    "STREAM_CHUNK_SIZE",
    "_NullWriter",
    "_PayloadSource",
    "_PayloadWriter",
    "_build_payload_header",
    "_decrypt_stream",
    "_encrypt_stream",
]
