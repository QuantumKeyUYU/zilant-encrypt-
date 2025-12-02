"""High-level API for encrypting and decrypting containers."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from types import TracebackType
from typing import IO, Any, Literal, Optional, Protocol, Type, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zilant_encrypt.container.format import (
    HEADER_V1_LEN,
    KEY_MODE_PASSWORD_ONLY,
    KEY_MODE_PQ_HYBRID,
    MAX_VOLUMES,
    PQ_PLACEHOLDER_CIPHERTEXT_LEN,
    PQ_PLACEHOLDER_SECRET_LEN,
    RESERVED_LEN,
    VERSION_V3,
    WRAPPED_KEY_TAG_LEN,
    ContainerHeader,
    VolumeDescriptor,
    build_header,
    read_header_from_stream,
)
from zilant_encrypt.crypto import pq
from zilant_encrypt.crypto.aead import TAG_LEN, AesGcmEncryptor
from zilant_encrypt.crypto.kdf import Argon2Params, derive_key_from_password, recommended_params
from zilant_encrypt.errors import (
    ContainerFormatError,
    IntegrityError,
    InvalidPassword,
    PqSupportError,
    UnsupportedFeatureError,
)

WRAP_NONCE = b"\x00" * 12
PAYLOAD_MAGIC = b"ZPAY"
PAYLOAD_VERSION = 1
PAYLOAD_META_LEN_SIZE = 4
STREAM_CHUNK_SIZE = 1024 * 64
ARGON_MEM_MIN_KIB = 32 * 1024
ARGON_MEM_MAX_KIB = 2 * 1024 * 1024
ARGON_TIME_MIN = 1
ARGON_TIME_MAX = 10
ARGON_PARALLELISM_MIN = 1
ARGON_PARALLELISM_MAX = 8



@dataclass(frozen=True)
class VolumeLayout:
    descriptor: VolumeDescriptor
    ciphertext_len: int


@dataclass(frozen=True)
class ContainerOverview:
    header: ContainerHeader
    descriptors: list[VolumeDescriptor]
    header_bytes: bytes
    layouts: list[VolumeLayout]
    file_size: int
    pq_available: bool


@dataclass(frozen=True)
class WrappedKey:
    data: bytes
    tag: bytes


@dataclass(frozen=True)
class PayloadMeta:
    kind: Literal["file", "directory"]
    name: str


def _validate_argon_params(params: Argon2Params) -> Argon2Params:
    if not (ARGON_MEM_MIN_KIB <= params.mem_cost_kib <= ARGON_MEM_MAX_KIB):
        raise UnsupportedFeatureError(
            f"Argon2 memory must be between {ARGON_MEM_MIN_KIB} and {ARGON_MEM_MAX_KIB} KiB",
        )
    if not (ARGON_TIME_MIN <= params.time_cost <= ARGON_TIME_MAX):
        raise UnsupportedFeatureError(
            f"Argon2 time cost must be between {ARGON_TIME_MIN} and {ARGON_TIME_MAX}",
        )
    if not (ARGON_PARALLELISM_MIN <= params.parallelism <= ARGON_PARALLELISM_MAX):
        raise UnsupportedFeatureError(
            "Argon2 parallelism must be between "
            f"{ARGON_PARALLELISM_MIN} and {ARGON_PARALLELISM_MAX}",
        )
    return params


def resolve_argon_params(
    *,
    mem_kib: int | None = None,
    time_cost: int | None = None,
    parallelism: int | None = None,
    base: Argon2Params | None = None,
) -> Argon2Params:
    """Build validated Argon2 parameters using overrides when provided."""
    defaults = base or recommended_params()
    candidate = Argon2Params(
        mem_cost_kib=mem_kib if mem_kib is not None else defaults.mem_cost_kib,
        time_cost=time_cost if time_cost is not None else defaults.time_cost,
        parallelism=parallelism if parallelism is not None else defaults.parallelism,
    )
    return _validate_argon_params(candidate)


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


class _PasswordOnlyProviderFactory:
    def __init__(self, password: str, params: Argon2Params, salt: bytes) -> None:
        self.password = password
        self.params = params
        self.salt = salt

    def build(self) -> PasswordKeyProvider:
        return PasswordKeyProvider(self.password, self.salt, self.params)


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


def _ciphertext_length_for_descriptor(
    descriptor: VolumeDescriptor,
    all_descriptors: list[VolumeDescriptor],
    file_size: int,
) -> int:
    if descriptor.payload_offset <= 0 or descriptor.payload_length < 0:
        raise ContainerFormatError("invalid descriptor layout")

    if descriptor.payload_length:
        return descriptor.payload_length

    ordered = sorted(all_descriptors, key=lambda d: d.payload_offset)
    for idx, desc in enumerate(ordered):
        if desc.volume_id == descriptor.volume_id:
            next_offset = ordered[idx + 1].payload_offset if idx + 1 < len(ordered) else file_size
            length = next_offset - desc.payload_offset - TAG_LEN
            if length < 0:
                raise ContainerFormatError("invalid descriptor layout")
            return length

    raise ContainerFormatError("invalid descriptor layout")


class _PayloadWriter:
    def __init__(self, out_path: Path) -> None:
        self.out_path = out_path
        self.meta: PayloadMeta | None = None
        self._buffer = bytearray()
        self._file_handle: IO[bytes] | None = None
        # Use Any for _temp_zip to avoid complex private type imports from tempfile
        self._temp_zip: Any | None = None

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

    def _ensure_temp_zip(self) -> Any:
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


def _compute_volume_layouts(
    descriptors: list[VolumeDescriptor], header_len: int, file_size: int
) -> list[VolumeLayout]:
    if len(descriptors) > MAX_VOLUMES:
        raise ContainerFormatError(f"Container has too many volumes (max {MAX_VOLUMES})")

    ordered = sorted(descriptors, key=lambda d: d.payload_offset)
    layouts: list[VolumeLayout] = []
    previous_end = header_len

    for idx, desc in enumerate(ordered):
        if desc.payload_offset < header_len:
            raise ContainerFormatError("Payload offset overlaps header")

        next_offset = ordered[idx + 1].payload_offset if idx + 1 < len(ordered) else file_size
        length = desc.payload_length or (next_offset - desc.payload_offset - TAG_LEN)
        if length < 0:
            raise ContainerFormatError("Invalid payload length")

        end = desc.payload_offset + length + TAG_LEN
        if end > file_size:
            raise ContainerFormatError("Payload exceeds container size")
        if desc.payload_offset < previous_end:
            raise ContainerFormatError("Volume payload ranges overlap")

        layouts.append(VolumeLayout(descriptor=desc, ciphertext_len=length))
        previous_end = end

    return layouts


def _load_overview(container_path: Path) -> ContainerOverview:
    container = Path(container_path)
    if not container.exists():
        raise FileNotFoundError(container)

    file_size = container.stat().st_size
    if file_size < HEADER_V1_LEN + TAG_LEN:
        raise ContainerFormatError("Container too small")

    with container.open("rb") as f:
        header, descriptors, header_bytes = read_header_from_stream(f)

    layouts = _compute_volume_layouts(descriptors, header.header_len, file_size)
    return ContainerOverview(
        header=header,
        descriptors=descriptors,
        header_bytes=header_bytes,
        layouts=layouts,
        file_size=file_size,
        pq_available=pq.available(),
    )


def _select_descriptors(descriptors: list[VolumeDescriptor], volume: str) -> list[VolumeDescriptor]:
    if volume == "all":
        return descriptors

    target_id = 0 if volume == "main" else 1
    selected = [desc for desc in descriptors if desc.volume_id == target_id]
    if not selected:
        raise ContainerFormatError(f"Requested volume '{volume}' is not present in the container")
    return selected


def _derive_file_key(
    descriptor: VolumeDescriptor, password: str, mode: ModeLiteral | None
) -> bytes:
    expected_mode = "pq-hybrid" if descriptor.key_mode == KEY_MODE_PQ_HYBRID else "password"
    if mode is not None and mode != expected_mode:
        raise UnsupportedFeatureError("requested check mode does not match volume key_mode")

    decrypt_params = Argon2Params(
        mem_cost_kib=descriptor.argon_mem_cost,
        time_cost=descriptor.argon_time_cost,
        parallelism=descriptor.argon_parallelism,
    )

    if descriptor.key_mode == KEY_MODE_PASSWORD_ONLY:
        provider = PasswordKeyProvider(password, descriptor.salt_argon2, decrypt_params)
        return provider.unwrap_file_key(
            WrappedKey(data=descriptor.wrapped_key, tag=descriptor.wrapped_key_tag),
        )

    if descriptor.key_mode == KEY_MODE_PQ_HYBRID:
        if not pq.available():
            raise PqSupportError("PQ-hybrid containers require oqs support")
        if (
            descriptor.pq_wrapped_secret is None
            or descriptor.pq_ciphertext is None
            or descriptor.pq_wrapped_secret_tag is None
        ):
            raise ContainerFormatError("PQ header missing required fields")

        password_key = derive_key_from_password(
            password,
            descriptor.salt_argon2,
            mem_cost=decrypt_params.mem_cost_kib,
            time_cost=decrypt_params.time_cost,
            parallelism=decrypt_params.parallelism,
        )
        try:
            kem_secret = AesGcmEncryptor.decrypt(
                password_key,
                WRAP_NONCE,
                descriptor.pq_wrapped_secret,
                descriptor.pq_wrapped_secret_tag,
                b"",
            )
        except InvalidTag as exc:
            raise InvalidPassword("Unable to unwrap KEM secret key") from exc

        shared_secret = pq.decapsulate(descriptor.pq_ciphertext, kem_secret)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"zilant-pq-hybrid",
        )
        master_key = hkdf.derive(shared_secret + password_key)
        try:
            return AesGcmEncryptor.decrypt(
                master_key,
                WRAP_NONCE,
                descriptor.wrapped_key,
                descriptor.wrapped_key_tag,
                b"",
            )
        except InvalidTag as exc:
            raise InvalidPassword("Unable to unwrap file key") from exc

    raise UnsupportedFeatureError("Unsupported key mode")


def check_container(
    container_path: os.PathLike[str] | str,
    *,
    password: str | None = None,
    mode: ModeLiteral | None = None,
    volume: Literal["main", "decoy", "all"] = "all",
) -> tuple[ContainerOverview, list[int]]:
    """Validate container structure and optionally verify tags for selected volumes.

    Returns a tuple of (overview, validated_volume_ids).
    """
    overview = _load_overview(Path(container_path))
    requested_mode = None if mode is None else normalize_mode(mode)

    if password is None:
        return overview, []

    selected = _select_descriptors(overview.descriptors, volume)
    validated: list[int] = []

    with Path(container_path).open("rb") as f:
        for desc in selected:
            file_key = _derive_file_key(desc, password, requested_mode)
            # Use 'layout' instead of 'l'
            layout = next((layout for layout in overview.layouts if layout.descriptor.volume_id == desc.volume_id), None)
            if layout is None:
                raise ContainerFormatError("Missing layout information for volume")
            f.seek(desc.payload_offset)
            _decrypt_stream(
                f,
                _NullWriter(),
                file_key,
                desc.nonce_aes_gcm,
                overview.header_bytes,
                layout.ciphertext_len,
            )
            validated.append(desc.volume_id)

    return overview, validated


def encrypt_file(
    in_path: Path,
    out_path: Path,
    password: str,
    *,
    overwrite: bool = False,
    mode: ModeLiteral | None = None,
    volume: Literal["main", "decoy"] = "main",
    argon_params: Argon2Params | None = None,
) -> None:
    """Encrypt input file or directory into a .zil container."""
    if not in_path.exists():
        raise FileNotFoundError(in_path)
    is_new = not out_path.exists()

    if is_new or volume == "main":
        _ensure_output(out_path, overwrite)

    argon_params = resolve_argon_params(base=argon_params)

    requested_mode = None if mode is None else normalize_mode(mode)
    if requested_mode is None and not (volume == "decoy" and not is_new):
        requested_mode = "password"

    if requested_mode == "pq-hybrid" and not pq.available():
        raise PqSupportError("PQ-hybrid mode is not available (oqs not installed)")

    if volume == "decoy":
        raise UnsupportedFeatureError(
            "Adding a decoy volume requires rebuilding the container with encrypt_with_decoy to preserve header integrity",
        )

    salt = os.urandom(16)
    nonce = os.urandom(12)
    file_key = os.urandom(32)

    mode_name = requested_mode or "password"

    if mode_name == "password":
        provider = _PasswordOnlyProviderFactory(password, argon_params, salt).build()
        wrapped_key = provider.wrap_file_key(file_key)
        placeholder_ciphertext = os.urandom(PQ_PLACEHOLDER_CIPHERTEXT_LEN)
        placeholder_secret = os.urandom(PQ_PLACEHOLDER_SECRET_LEN)
        placeholder_secret_tag = os.urandom(WRAPPED_KEY_TAG_LEN)
        reserved_bytes = bytes(RESERVED_LEN)
        descriptor = VolumeDescriptor(
            volume_id=0,
            key_mode=KEY_MODE_PASSWORD_ONLY,
            flags=0,
            payload_offset=0,
            payload_length=0,
            salt_argon2=salt,
            argon_mem_cost=argon_params.mem_cost_kib,
            argon_time_cost=argon_params.time_cost,
            argon_parallelism=argon_params.parallelism,
            nonce_aes_gcm=nonce,
            wrapped_key=wrapped_key.data,
            wrapped_key_tag=wrapped_key.tag,
            reserved=reserved_bytes,
            pq_ciphertext=placeholder_ciphertext,
            pq_wrapped_secret=placeholder_secret,
            pq_wrapped_secret_tag=placeholder_secret_tag,
        )
    elif mode_name == "pq-hybrid":
        if not pq.available():
            raise PqSupportError("PQ-hybrid mode is not available (oqs not installed)")
        password_key = derive_key_from_password(
            password,
            salt,
            mem_cost=argon_params.mem_cost_kib,
            time_cost=argon_params.time_cost,
            parallelism=argon_params.parallelism,
        )
        public_key, secret_key = pq.generate_kem_keypair()
        kem_ciphertext, shared_secret = pq.encapsulate(public_key)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"zilant-pq-hybrid",
        )
        master_key = hkdf.derive(shared_secret + password_key)

        wrapped_key_data, wrapped_key_tag = AesGcmEncryptor.encrypt(master_key, WRAP_NONCE, file_key, b"")
        wrapped_secret, wrapped_secret_tag = AesGcmEncryptor.encrypt(password_key, WRAP_NONCE, secret_key, b"")
        reserved_bytes = bytes(RESERVED_LEN)

        descriptor = VolumeDescriptor(
            volume_id=0,
            key_mode=KEY_MODE_PQ_HYBRID,
            flags=0,
            payload_offset=0,
            payload_length=0,
            salt_argon2=salt,
            argon_mem_cost=argon_params.mem_cost_kib,
            argon_time_cost=argon_params.time_cost,
            argon_parallelism=argon_params.parallelism,
            nonce_aes_gcm=nonce,
            wrapped_key=wrapped_key_data,
            wrapped_key_tag=wrapped_key_tag,
            reserved=reserved_bytes,
            pq_ciphertext=kem_ciphertext,
            pq_wrapped_secret=wrapped_secret,
            pq_wrapped_secret_tag=wrapped_secret_tag,
        )
    else:
        raise UnsupportedFeatureError(f"Unknown encryption mode: {mode_name}")

    with _PayloadSource(in_path) as payload_source:
        payload_header = _build_payload_header(payload_source.meta)
        plaintext_len = len(payload_header) + payload_source.path.stat().st_size

        descriptor = replace(
            descriptor,
            payload_length=plaintext_len,
        )

        temp_header = build_header(
            key_mode=descriptor.key_mode,
            header_flags=descriptor.flags,
            salt_argon2=descriptor.salt_argon2,
            argon_mem_cost=descriptor.argon_mem_cost,
            argon_time_cost=descriptor.argon_time_cost,
            argon_parallelism=descriptor.argon_parallelism,
            nonce_aes_gcm=descriptor.nonce_aes_gcm,
            wrapped_key=descriptor.wrapped_key,
            wrapped_key_tag=descriptor.wrapped_key_tag,
            reserved=descriptor.reserved,
            version=VERSION_V3,
            pq_ciphertext=descriptor.pq_ciphertext,
            pq_wrapped_secret=descriptor.pq_wrapped_secret,
            pq_wrapped_secret_tag=descriptor.pq_wrapped_secret_tag,
            volume_descriptors=[descriptor],
            common_meta={},
        )

        descriptor = replace(descriptor, payload_offset=len(temp_header))

        header_bytes = build_header(
            key_mode=descriptor.key_mode,
            header_flags=descriptor.flags,
            salt_argon2=descriptor.salt_argon2,
            argon_mem_cost=descriptor.argon_mem_cost,
            argon_time_cost=descriptor.argon_time_cost,
            argon_parallelism=descriptor.argon_parallelism,
            nonce_aes_gcm=descriptor.nonce_aes_gcm,
            wrapped_key=descriptor.wrapped_key,
            wrapped_key_tag=descriptor.wrapped_key_tag,
            reserved=descriptor.reserved,
            version=VERSION_V3,
            pq_ciphertext=descriptor.pq_ciphertext,
            pq_wrapped_secret=descriptor.pq_wrapped_secret,
            pq_wrapped_secret_tag=descriptor.pq_wrapped_secret_tag,
            volume_descriptors=[descriptor],
            common_meta={},
        )

        aad = header_bytes

        with payload_source.path.open("rb") as payload_file, out_path.open("xb") as f:
            f.write(header_bytes)
            tag = _encrypt_stream(payload_file, f, file_key, nonce, aad, initial=payload_header)
            f.write(tag)


def encrypt_with_decoy(
    input_path_main: os.PathLike[str] | str,
    container_path: os.PathLike[str] | str,
    *,
    main_password: str,
    decoy_password: str,
    input_path_decoy: os.PathLike[str] | str | None = None,
    mode: ModeLiteral = "password",
    overwrite: bool = False,
    argon_params: Argon2Params | None = None,
) -> None:
    """Create a container with both main and decoy volumes in one call."""
    main_path = Path(input_path_main)
    decoy_path = Path(input_path_decoy) if input_path_decoy is not None else main_path
    out_path = Path(container_path)

    if out_path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing file: {out_path}")

    effective_mode = normalize_mode(mode)
    if effective_mode == "pq-hybrid" and not pq.available():
        raise PqSupportError("PQ-hybrid mode is not available (oqs not installed)")

    argon_params = resolve_argon_params(base=argon_params)

    with _PayloadSource(main_path) as main_payload, _PayloadSource(decoy_path) as decoy_payload:
        main_header = _build_payload_header(main_payload.meta)
        decoy_header = _build_payload_header(decoy_payload.meta)

        main_plain_len = len(main_header) + main_payload.path.stat().st_size
        decoy_plain_len = len(decoy_header) + decoy_payload.path.stat().st_size

        main_salt = os.urandom(16)
        main_nonce = os.urandom(12)
        main_file_key = os.urandom(32)

        decoy_salt = os.urandom(16)
        decoy_nonce = os.urandom(12)
        decoy_file_key = os.urandom(32)

        descriptors: list[VolumeDescriptor] = []

        if effective_mode == "password":
            main_provider = _PasswordOnlyProviderFactory(main_password, argon_params, main_salt).build()
            main_wrapped = main_provider.wrap_file_key(main_file_key)
            decoy_provider = _PasswordOnlyProviderFactory(decoy_password, argon_params, decoy_salt).build()
            decoy_wrapped = decoy_provider.wrap_file_key(decoy_file_key)
            main_placeholder_ciphertext = os.urandom(PQ_PLACEHOLDER_CIPHERTEXT_LEN)
            main_placeholder_secret = os.urandom(PQ_PLACEHOLDER_SECRET_LEN)
            main_placeholder_tag = os.urandom(WRAPPED_KEY_TAG_LEN)
            decoy_placeholder_ciphertext = os.urandom(PQ_PLACEHOLDER_CIPHERTEXT_LEN)
            decoy_placeholder_secret = os.urandom(PQ_PLACEHOLDER_SECRET_LEN)
            decoy_placeholder_tag = os.urandom(WRAPPED_KEY_TAG_LEN)
            main_reserved = bytes(RESERVED_LEN)
            decoy_reserved = bytes(RESERVED_LEN)

            descriptors.append(
                VolumeDescriptor(
                    volume_id=0,
                    key_mode=KEY_MODE_PASSWORD_ONLY,
                    flags=0,
                    payload_offset=0,
                    payload_length=main_plain_len,
                    salt_argon2=main_salt,
                    argon_mem_cost=argon_params.mem_cost_kib,
                    argon_time_cost=argon_params.time_cost,
                    argon_parallelism=argon_params.parallelism,
                    nonce_aes_gcm=main_nonce,
                    wrapped_key=main_wrapped.data,
                    wrapped_key_tag=main_wrapped.tag,
                    reserved=main_reserved,
                    pq_ciphertext=main_placeholder_ciphertext,
                    pq_wrapped_secret=main_placeholder_secret,
                    pq_wrapped_secret_tag=main_placeholder_tag,
                )
            )
            descriptors.append(
                VolumeDescriptor(
                    volume_id=1,
                    key_mode=KEY_MODE_PASSWORD_ONLY,
                    flags=0,
                    payload_offset=0,
                    payload_length=decoy_plain_len,
                    salt_argon2=decoy_salt,
                    argon_mem_cost=argon_params.mem_cost_kib,
                    argon_time_cost=argon_params.time_cost,
                    argon_parallelism=argon_params.parallelism,
                    nonce_aes_gcm=decoy_nonce,
                    wrapped_key=decoy_wrapped.data,
                    wrapped_key_tag=decoy_wrapped.tag,
                    reserved=decoy_reserved,
                    pq_ciphertext=decoy_placeholder_ciphertext,
                    pq_wrapped_secret=decoy_placeholder_secret,
                    pq_wrapped_secret_tag=decoy_placeholder_tag,
                )
            )
        else:
            password_key_main = derive_key_from_password(
                main_password,
                main_salt,
                mem_cost=argon_params.mem_cost_kib,
                time_cost=argon_params.time_cost,
                parallelism=argon_params.parallelism,
            )
            password_key_decoy = derive_key_from_password(
                decoy_password,
                decoy_salt,
                mem_cost=argon_params.mem_cost_kib,
                time_cost=argon_params.time_cost,
                parallelism=argon_params.parallelism,
            )

            public_key, secret_key = pq.generate_kem_keypair()
            kem_ciphertext, shared_secret = pq.encapsulate(public_key)

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"zilant-pq-hybrid",
            )
            master_key = hkdf.derive(shared_secret + password_key_main)
            decoy_master_key = hkdf.derive(shared_secret + password_key_decoy)

            main_wrapped_key, main_wrapped_tag = AesGcmEncryptor.encrypt(
                master_key, WRAP_NONCE, main_file_key, b"",
            )
            decoy_wrapped_key, decoy_wrapped_tag = AesGcmEncryptor.encrypt(
                decoy_master_key, WRAP_NONCE, decoy_file_key, b"",
            )
            wrapped_secret, wrapped_secret_tag = AesGcmEncryptor.encrypt(password_key_main, WRAP_NONCE, secret_key, b"")
            decoy_wrapped_secret, decoy_wrapped_secret_tag = AesGcmEncryptor.encrypt(
                password_key_decoy, WRAP_NONCE, secret_key, b"",
            )
            main_reserved = bytes(RESERVED_LEN)
            decoy_reserved = bytes(RESERVED_LEN)

            descriptors.append(
                VolumeDescriptor(
                    volume_id=0,
                    key_mode=KEY_MODE_PQ_HYBRID,
                    flags=0,
                    payload_offset=0,
                    payload_length=main_plain_len,
                    salt_argon2=main_salt,
                    argon_mem_cost=argon_params.mem_cost_kib,
                    argon_time_cost=argon_params.time_cost,
                    argon_parallelism=argon_params.parallelism,
                    nonce_aes_gcm=main_nonce,
                    wrapped_key=main_wrapped_key,
                    wrapped_key_tag=main_wrapped_tag,
                    reserved=main_reserved,
                    pq_ciphertext=kem_ciphertext,
                    pq_wrapped_secret=wrapped_secret,
                    pq_wrapped_secret_tag=wrapped_secret_tag,
                )
            )
            descriptors.append(
                VolumeDescriptor(
                    volume_id=1,
                    key_mode=KEY_MODE_PQ_HYBRID,
                    flags=0,
                    payload_offset=0,
                    payload_length=decoy_plain_len,
                    salt_argon2=decoy_salt,
                    argon_mem_cost=argon_params.mem_cost_kib,
                    argon_time_cost=argon_params.time_cost,
                    argon_parallelism=argon_params.parallelism,
                    nonce_aes_gcm=decoy_nonce,
                    wrapped_key=decoy_wrapped_key,
                    wrapped_key_tag=decoy_wrapped_tag,
                    reserved=decoy_reserved,
                    pq_ciphertext=kem_ciphertext,
                    pq_wrapped_secret=decoy_wrapped_secret,
                    pq_wrapped_secret_tag=decoy_wrapped_secret_tag,
                )
            )

        temp_header = build_header(
            key_mode=descriptors[0].key_mode,
            header_flags=0,
            salt_argon2=descriptors[0].salt_argon2,
            argon_mem_cost=descriptors[0].argon_mem_cost,
            argon_time_cost=descriptors[0].argon_time_cost,
            argon_parallelism=descriptors[0].argon_parallelism,
            nonce_aes_gcm=descriptors[0].nonce_aes_gcm,
            wrapped_key=descriptors[0].wrapped_key,
            wrapped_key_tag=descriptors[0].wrapped_key_tag,
            reserved=descriptors[0].reserved,
            version=VERSION_V3,
            pq_ciphertext=descriptors[0].pq_ciphertext,
            pq_wrapped_secret=descriptors[0].pq_wrapped_secret,
            pq_wrapped_secret_tag=descriptors[0].pq_wrapped_secret_tag,
            volume_descriptors=descriptors,
            common_meta={},
        )

        header_len = len(temp_header)
        descriptors = [
            replace(
                descriptors[0],
                payload_offset=header_len,
            ),
            replace(
                descriptors[1],
                payload_offset=header_len + main_plain_len + TAG_LEN,
            ),
        ]

        header_bytes = build_header(
            key_mode=descriptors[0].key_mode,
            header_flags=descriptors[0].flags,
            salt_argon2=descriptors[0].salt_argon2,
            argon_mem_cost=descriptors[0].argon_mem_cost,
            argon_time_cost=descriptors[0].argon_time_cost,
            argon_parallelism=descriptors[0].argon_parallelism,
            nonce_aes_gcm=descriptors[0].nonce_aes_gcm,
            wrapped_key=descriptors[0].wrapped_key,
            wrapped_key_tag=descriptors[0].wrapped_key_tag,
            reserved=descriptors[0].reserved,
            version=VERSION_V3,
            pq_ciphertext=descriptors[0].pq_ciphertext,
            pq_wrapped_secret=descriptors[0].pq_wrapped_secret,
            pq_wrapped_secret_tag=descriptors[0].pq_wrapped_secret_tag,
            volume_descriptors=descriptors,
            common_meta={},
        )

        aad = header_bytes
        with out_path.open("xb") as dest:
            dest.write(header_bytes)
            with main_payload.path.open("rb") as payload_file:
                tag = _encrypt_stream(
                    payload_file,
                    dest,
                    main_file_key,
                    descriptors[0].nonce_aes_gcm,
                    aad,
                    initial=main_header,
                )
                dest.write(tag)

            with decoy_payload.path.open("rb") as payload_file:
                tag = _encrypt_stream(
                    payload_file,
                    dest,
                    decoy_file_key,
                    descriptors[1].nonce_aes_gcm,
                    aad,
                    initial=decoy_header,
                )
                dest.write(tag)


def decrypt_file(
    container_path: Path,
    out_path: Path,
    password: str,
    *,
    overwrite: bool = False,
    mode: ModeLiteral | None = None,
    volume: Literal["main", "decoy"] = "main",
) -> None:
    """Decrypt a container to an output file."""
    if not container_path.exists():
        raise FileNotFoundError(container_path)

    file_size = container_path.stat().st_size
    if file_size < HEADER_V1_LEN + TAG_LEN:
        raise ContainerFormatError("Container too small")

    _ensure_output(out_path, overwrite)

    with container_path.open("rb") as f:
        header, descriptors, header_bytes = read_header_from_stream(f)
        aad = header_bytes

        target_volume = 0 if volume == "main" else 1
        descriptor = next((d for d in descriptors if d.volume_id == target_volume), None)
        if descriptor is None:
            raise ContainerFormatError(f"Volume id {target_volume} not found")

        main_descriptor = next((d for d in descriptors if d.volume_id == 0), None)
        if main_descriptor is not None and any(d.key_mode != main_descriptor.key_mode for d in descriptors):
            raise UnsupportedFeatureError("all volumes in a container must share the same key_mode")

        decrypt_params = Argon2Params(
            mem_cost_kib=descriptor.argon_mem_cost,
            time_cost=descriptor.argon_time_cost,
            parallelism=descriptor.argon_parallelism,
        )

        expected_mode = "pq-hybrid" if descriptor.key_mode == KEY_MODE_PQ_HYBRID else "password"
        requested_mode = None if mode is None else normalize_mode(mode)
        if requested_mode is not None and requested_mode != expected_mode:
            raise UnsupportedFeatureError("requested decrypt mode does not match volume key_mode")

        effective_mode = requested_mode or expected_mode
        ciphertext_len = _ciphertext_length_for_descriptor(descriptor, descriptors, file_size)
        if ciphertext_len < 0:
            raise ContainerFormatError("Invalid payload length")

        if descriptor.key_mode == KEY_MODE_PASSWORD_ONLY:
            if effective_mode != "password":
                raise UnsupportedFeatureError("requested decrypt mode does not match volume key_mode")
            provider = PasswordKeyProvider(password, descriptor.salt_argon2, decrypt_params)
            file_key = provider.unwrap_file_key(
                WrappedKey(data=descriptor.wrapped_key, tag=descriptor.wrapped_key_tag),
            )
        elif descriptor.key_mode == KEY_MODE_PQ_HYBRID:
            if effective_mode != "pq-hybrid":
                raise UnsupportedFeatureError("requested decrypt mode does not match volume key_mode")
            if not pq.available():
                raise PqSupportError("PQ-hybrid containers require oqs support")
            password_key = derive_key_from_password(
                password,
                descriptor.salt_argon2,
                mem_cost=decrypt_params.mem_cost_kib,
                time_cost=decrypt_params.time_cost,
                parallelism=decrypt_params.parallelism,
            )
            if (
                descriptor.pq_wrapped_secret is None
                or descriptor.pq_ciphertext is None
                or descriptor.pq_wrapped_secret_tag is None
            ):
                raise ContainerFormatError("PQ header missing required fields")
            try:
                kem_secret = AesGcmEncryptor.decrypt(
                    password_key,
                    WRAP_NONCE,
                    descriptor.pq_wrapped_secret,
                    descriptor.pq_wrapped_secret_tag,
                    b"",
                )
            except InvalidTag as exc:
                raise InvalidPassword("Unable to unwrap KEM secret key") from exc

            shared_secret = pq.decapsulate(descriptor.pq_ciphertext, kem_secret)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"zilant-pq-hybrid",
            )
            master_key = hkdf.derive(shared_secret + password_key)
            try:
                file_key = AesGcmEncryptor.decrypt(
                    master_key,
                    WRAP_NONCE,
                    descriptor.wrapped_key,
                    descriptor.wrapped_key_tag,
                    b"",
                )
            except InvalidTag as exc:
                raise InvalidPassword("Unable to unwrap file key") from exc
        else:
            raise UnsupportedFeatureError("Unsupported key mode")

        writer = _PayloadWriter(out_path)
        f.seek(descriptor.payload_offset)
        _decrypt_stream(
            f,
            writer,
            file_key,
            descriptor.nonce_aes_gcm,
            aad,
            ciphertext_len,
        )


def decrypt_auto_volume(
    container_path: os.PathLike[str] | str,
    out_path: os.PathLike[str] | str,
    *,
    password: str,
    mode: ModeLiteral | None = None,
    overwrite: bool = False,
) -> tuple[int, str]:
    """Attempt to decrypt any volume that matches the provided password.

    Returns a tuple of (volume_id, volume_name) for the successfully decrypted
    volume. Raises :class:`InvalidPassword` if none of the volumes could be
    decrypted with the given password.
    """
    container = Path(container_path)
    output = Path(out_path)

    if not container.exists():
        raise FileNotFoundError(container)

    file_size = container.stat().st_size
    if file_size < HEADER_V1_LEN + TAG_LEN:
        raise ContainerFormatError("Container too small")

    effective_mode = None if mode is None else normalize_mode(mode)

    with container.open("rb") as f:
        header, descriptors, header_bytes = read_header_from_stream(f)
        aad = header_bytes

        main_descriptor = next((d for d in descriptors if d.volume_id == 0), None)
        if main_descriptor is not None and any(d.key_mode != main_descriptor.key_mode for d in descriptors):
            raise UnsupportedFeatureError("all volumes in a container must share the same key_mode")

        # Iterate in descriptor order; if multiple volumes decrypt, prefer the
        # one with the smallest volume_id (main first).
        ordered = sorted(descriptors, key=lambda d: d.volume_id)
        successful: tuple[int, str] | None = None

        for descriptor in ordered:
            expected_mode = "pq-hybrid" if descriptor.key_mode == KEY_MODE_PQ_HYBRID else "password"
            if effective_mode is not None and effective_mode != expected_mode:
                continue

            decrypt_params = Argon2Params(
                mem_cost_kib=descriptor.argon_mem_cost,
                time_cost=descriptor.argon_time_cost,
                parallelism=descriptor.argon_parallelism,
            )
            ciphertext_len = _ciphertext_length_for_descriptor(descriptor, descriptors, file_size)
            if ciphertext_len < 0:
                raise ContainerFormatError("Invalid payload length")

            try:
                if descriptor.key_mode == KEY_MODE_PASSWORD_ONLY:
                    if effective_mode is not None and effective_mode != "password":
                        continue
                    provider = PasswordKeyProvider(password, descriptor.salt_argon2, decrypt_params)
                    file_key = provider.unwrap_file_key(
                        WrappedKey(data=descriptor.wrapped_key, tag=descriptor.wrapped_key_tag),
                    )
                elif descriptor.key_mode == KEY_MODE_PQ_HYBRID:
                    if effective_mode is not None and effective_mode != "pq-hybrid":
                        continue
                    if not pq.available():
                        raise PqSupportError("PQ-hybrid containers require oqs support")
                    if (
                        descriptor.pq_wrapped_secret is None
                        or descriptor.pq_ciphertext is None
                        or descriptor.pq_wrapped_secret_tag is None
                    ):
                        raise ContainerFormatError("PQ header missing required fields")
                    password_key = derive_key_from_password(
                        password,
                        descriptor.salt_argon2,
                        mem_cost=decrypt_params.mem_cost_kib,
                        time_cost=decrypt_params.time_cost,
                        parallelism=decrypt_params.parallelism,
                    )
                    try:
                        kem_secret = AesGcmEncryptor.decrypt(
                            password_key,
                            WRAP_NONCE,
                            descriptor.pq_wrapped_secret,
                            descriptor.pq_wrapped_secret_tag,
                            b"",
                        )
                    except InvalidTag as exc:
                        raise InvalidPassword("Unable to unwrap KEM secret key") from exc

                    shared_secret = pq.decapsulate(descriptor.pq_ciphertext, kem_secret)
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b"zilant-pq-hybrid",
                    )
                    master_key = hkdf.derive(shared_secret + password_key)
                    try:
                        file_key = AesGcmEncryptor.decrypt(
                            master_key,
                            WRAP_NONCE,
                            descriptor.wrapped_key,
                            descriptor.wrapped_key_tag,
                            b"",
                        )
                    except InvalidTag as exc:
                        raise InvalidPassword("Unable to unwrap file key") from exc
                else:
                    raise UnsupportedFeatureError("Unsupported key mode")

                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_out = Path(temp_dir) / "payload"
                    writer = _PayloadWriter(temp_out)
                    f.seek(descriptor.payload_offset)
                    _decrypt_stream(
                        f,
                        writer,
                        file_key,
                        descriptor.nonce_aes_gcm,
                        aad,
                        ciphertext_len,
                    )

                    _ensure_output(output, overwrite)
                    if temp_out.is_dir():
                        shutil.move(str(temp_out), output)
                    else:
                        output.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(temp_out), output)

                volume_name = "main" if descriptor.volume_id == 0 else "decoy" if descriptor.volume_id == 1 else f"id={descriptor.volume_id}"
                successful = (descriptor.volume_id, volume_name)
                break

            except (InvalidPassword, IntegrityError):
                continue

        if successful is None:
            raise InvalidPassword("Unable to decrypt any volume with the provided password")

        return successful
ModeLiteral = Literal["password", "pq-hybrid"]


def normalize_mode(mode: str | None) -> ModeLiteral:
    """Normalize user-provided mode strings.

    Accepts ``None`` and treats it as ``"password"`` for convenience. Legacy
    values using an underscore are mapped to the hyphenated form.
    """

    if mode is None or mode.lower() == "password":
        return "password"

    normalized = mode.lower().replace("_", "-")
    if normalized == "pq-hybrid":
        return "pq-hybrid"

    raise UnsupportedFeatureError(f"Unknown encryption mode: {mode}")
