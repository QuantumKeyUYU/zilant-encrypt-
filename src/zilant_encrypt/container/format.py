"""Container header format helpers."""

from __future__ import annotations

from dataclasses import dataclass
import os
from struct import Struct

from typing import Iterable

from zilant_encrypt.errors import ContainerFormatError, UnsupportedFeatureError

MAGIC = b"ZILENC"
VERSION_V1 = 1
VERSION_PQ_HYBRID = 2
VERSION_V3 = 3
HEADER_V1_LEN = 128
HEADER_LEN = HEADER_V1_LEN  # backwards compatibility
KEY_MODE_PASSWORD_ONLY = 0x01
KEY_MODE_PQ_HYBRID = 0x02
MAX_VOLUMES = 2

MAGIC_LEN = 6
VERSION_LEN = 1
SALT_LEN = 16
NONCE_LEN = 12
WRAPPED_KEY_MAX_LEN = 32
WRAPPED_KEY_TAG_LEN = 16
RESERVED_LEN = 28
PAYLOAD_TAG_LEN = 16

_HEADER_STRUCT_V1 = Struct(
    "<6sBBH16sIII12sH32s16s28s",
)  # totals 128 bytes

# V2 header is variable length. It keeps the core fields from v1 and adds PQ
# metadata lengths plus tags. The actual wrapped key, KEM ciphertext and
# wrapped secret key are stored immediately after the fixed part.
_HEADER_STRUCT_V2 = Struct(
    "<6sBBH16sIII12sH16sHH16sH",
)

_VOLUME_META_V3_COMMON_STRUCT = Struct(
    "<H16sIII12sH16sHH16s28s",
)

_VOLUME_META_V3_PASSWORD_STRUCT = Struct(
    "<H16sIII12sH32s16s28s",
)

_VOLUME_META_V3_PQ_STRUCT = Struct(
    "<H16sIII12sH16sHH16s",
)

PQ_PLACEHOLDER_CIPHERTEXT_LEN = 1088
PQ_PLACEHOLDER_SECRET_LEN = 2400

_HEADER_STRUCT_V3_PREFIX = Struct("<6sBHI")
_VOLUME_DESCRIPTOR_STRUCT = Struct("<BBHQQI")


@dataclass(frozen=True)
class VolumeDescriptor:
    volume_id: int
    key_mode: int
    flags: int
    payload_offset: int
    payload_length: int
    salt_argon2: bytes
    argon_mem_cost: int
    argon_time_cost: int
    argon_parallelism: int
    nonce_aes_gcm: bytes
    wrapped_key: bytes
    wrapped_key_tag: bytes
    reserved: bytes
    pq_ciphertext: bytes | None = None
    pq_wrapped_secret: bytes | None = None
    pq_wrapped_secret_tag: bytes | None = None


@dataclass(frozen=True)
class ContainerHeader:
    version: int
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
    header_len: int
    pq_ciphertext: bytes | None = None
    pq_wrapped_secret: bytes | None = None
    pq_wrapped_secret_tag: bytes | None = None

    def to_bytes(self) -> bytes:
        volume = VolumeDescriptor(
            volume_id=0,
            key_mode=self.key_mode,
            flags=self.header_flags,
            payload_offset=self.header_len,
            payload_length=0,
            salt_argon2=self.salt_argon2,
            argon_mem_cost=self.argon_mem_cost,
            argon_time_cost=self.argon_time_cost,
            argon_parallelism=self.argon_parallelism,
            nonce_aes_gcm=self.nonce_aes_gcm,
            wrapped_key=self.wrapped_file_key,
            wrapped_key_tag=self.wrapped_key_tag,
            reserved=self.reserved,
            pq_ciphertext=self.pq_ciphertext,
            pq_wrapped_secret=self.pq_wrapped_secret,
            pq_wrapped_secret_tag=self.pq_wrapped_secret_tag,
        )
        if self.version == VERSION_V3:
            return build_header_v3([volume], {})

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
            version=self.version,
            pq_ciphertext=self.pq_ciphertext,
            pq_wrapped_secret=self.pq_wrapped_secret,
            pq_wrapped_secret_tag=self.pq_wrapped_secret_tag,
        )


def _validate_common_inputs(
    *,
    salt_argon2: bytes,
    nonce_aes_gcm: bytes,
    wrapped_key: bytes,
    wrapped_key_tag: bytes,
    reserved: bytes | None,
    key_mode: int,
) -> bytes:
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
    if any(reserved_bytes):
        raise ContainerFormatError("reserved bytes must be zero")
    if key_mode not in (KEY_MODE_PASSWORD_ONLY, KEY_MODE_PQ_HYBRID):
        raise ContainerFormatError("Unknown key_mode")
    return reserved_bytes


def _build_header_v1(
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
    reserved_bytes: bytes,
) -> bytes:
    if key_mode != KEY_MODE_PASSWORD_ONLY:
        raise ContainerFormatError("V1 headers support password-only mode only")
    wrapped_key_padded = wrapped_key.ljust(32, b"\x00")
    wrapped_key_len = len(wrapped_key)

    packed = _HEADER_STRUCT_V1.pack(
        MAGIC,
        VERSION_V1,
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

    if len(packed) != HEADER_V1_LEN:
        raise ContainerFormatError("Header length mismatch")
    return packed


def _build_header_v2(
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
    reserved_bytes: bytes,
    pq_ciphertext: bytes | None,
    pq_wrapped_secret: bytes | None,
    pq_wrapped_secret_tag: bytes | None,
) -> bytes:
    if key_mode != KEY_MODE_PQ_HYBRID:
        raise ContainerFormatError("PQ hybrid headers must use PQ key mode")
    if pq_ciphertext is None or pq_wrapped_secret is None or pq_wrapped_secret_tag is None:
        raise ContainerFormatError("PQ header is missing required fields")

    wrapped_key_len = len(wrapped_key)
    header_len = (
        _HEADER_STRUCT_V2.size
        + wrapped_key_len
        + len(pq_ciphertext)
        + len(pq_wrapped_secret)
    )

    packed = _HEADER_STRUCT_V2.pack(
        MAGIC,
        VERSION_PQ_HYBRID,
        key_mode,
        header_flags,
        salt_argon2,
        argon_mem_cost,
        argon_time_cost,
        argon_parallelism,
        nonce_aes_gcm,
        wrapped_key_len,
        wrapped_key_tag,
        len(pq_ciphertext),
        len(pq_wrapped_secret),
        pq_wrapped_secret_tag,
        header_len,
    )

    return b"".join([packed, wrapped_key, pq_ciphertext, pq_wrapped_secret])


def _build_volume_meta(desc: VolumeDescriptor) -> bytes:
    reserved_bytes = _validate_common_inputs(
        salt_argon2=desc.salt_argon2,
        nonce_aes_gcm=desc.nonce_aes_gcm,
        wrapped_key=desc.wrapped_key,
        wrapped_key_tag=desc.wrapped_key_tag,
        reserved=desc.reserved,
        key_mode=desc.key_mode,
    )

    pq_ciphertext = desc.pq_ciphertext
    pq_wrapped_secret = desc.pq_wrapped_secret
    pq_wrapped_secret_tag = desc.pq_wrapped_secret_tag

    if desc.key_mode == KEY_MODE_PQ_HYBRID:
        if (
            pq_ciphertext is None
            or pq_wrapped_secret is None
            or pq_wrapped_secret_tag is None
        ):
            raise ContainerFormatError("PQ volume is missing required fields")
    else:
        pq_ciphertext = pq_ciphertext or os.urandom(PQ_PLACEHOLDER_CIPHERTEXT_LEN)
        pq_wrapped_secret = pq_wrapped_secret or os.urandom(PQ_PLACEHOLDER_SECRET_LEN)
        pq_wrapped_secret_tag = pq_wrapped_secret_tag or os.urandom(WRAPPED_KEY_TAG_LEN)

    if pq_wrapped_secret_tag is None or len(pq_wrapped_secret_tag) != WRAPPED_KEY_TAG_LEN:
        raise ContainerFormatError("pq_wrapped_secret_tag must be 16 bytes")

    wrapped_key_len = len(desc.wrapped_key)
    if wrapped_key_len > WRAPPED_KEY_MAX_LEN:
        raise ContainerFormatError("Invalid wrapped_key_len")
    wrapped_key_padded = desc.wrapped_key.ljust(WRAPPED_KEY_MAX_LEN, b"\x00")

    return b"".join(
        [
            _VOLUME_META_V3_COMMON_STRUCT.pack(
                desc.flags,
                desc.salt_argon2,
                desc.argon_mem_cost,
                desc.argon_time_cost,
                desc.argon_parallelism,
                desc.nonce_aes_gcm,
                wrapped_key_len,
                desc.wrapped_key_tag,
                len(pq_ciphertext or b""),
                len(pq_wrapped_secret or b""),
                pq_wrapped_secret_tag,
                reserved_bytes,
            ),
            wrapped_key_padded,
            pq_ciphertext or b"",
            pq_wrapped_secret or b"",
        ]
    )


def _validate_volume_layout(descriptors: list[VolumeDescriptor]) -> None:
    if len(descriptors) > MAX_VOLUMES:
        raise ContainerFormatError(f"Container has too many volumes (max {MAX_VOLUMES})")

    if any(desc.payload_offset == 0 or desc.payload_length == 0 for desc in descriptors):
        return

    ordered = sorted(descriptors, key=lambda d: d.payload_offset)
    for first, second in zip(ordered, ordered[1:]):
        first_end = first.payload_offset + first.payload_length + PAYLOAD_TAG_LEN
        if second.payload_offset < first_end:
            raise ContainerFormatError("Volume payload regions overlap")


def build_header_v3(
    volume_descriptors: Iterable[VolumeDescriptor],
    common_meta: dict,  # noqa: ARG001
) -> bytes:
    descriptors = list(volume_descriptors)
    if not descriptors:
        raise ContainerFormatError("At least one volume descriptor is required")
    _validate_volume_layout(descriptors)

    meta_blobs = [
        _build_volume_meta(desc)
        for desc in descriptors
    ]

    header_len = (
        _HEADER_STRUCT_V3_PREFIX.size
        + _VOLUME_DESCRIPTOR_STRUCT.size * len(descriptors)
        + sum(len(blob) for blob in meta_blobs)
    )

    descriptor_table = bytearray()
    for desc, blob in zip(descriptors, meta_blobs):
        payload_offset = desc.payload_offset or header_len
        descriptor_table.extend(
            _VOLUME_DESCRIPTOR_STRUCT.pack(
                desc.volume_id,
                desc.key_mode,
                desc.flags,
                payload_offset,
                desc.payload_length,
                len(blob),
            )
        )

    prefix = _HEADER_STRUCT_V3_PREFIX.pack(
        MAGIC,
        VERSION_V3,
        len(descriptors),
        header_len,
    )

    return b"".join([prefix, descriptor_table, *meta_blobs])


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
    version: int = VERSION_V1,
    pq_ciphertext: bytes | None = None,
    pq_wrapped_secret: bytes | None = None,
    pq_wrapped_secret_tag: bytes | None = None,
    volume_descriptors: Iterable[VolumeDescriptor] | None = None,
    common_meta: dict | None = None,
) -> bytes:
    """Build container header bytes for the requested version."""

    reserved_bytes = _validate_common_inputs(
        salt_argon2=salt_argon2,
        nonce_aes_gcm=nonce_aes_gcm,
        wrapped_key=wrapped_key,
        wrapped_key_tag=wrapped_key_tag,
        reserved=reserved,
        key_mode=key_mode,
    )

    if version == VERSION_V1:
        return _build_header_v1(
            key_mode=key_mode,
            header_flags=header_flags,
            salt_argon2=salt_argon2,
            argon_mem_cost=argon_mem_cost,
            argon_time_cost=argon_time_cost,
            argon_parallelism=argon_parallelism,
            nonce_aes_gcm=nonce_aes_gcm,
            wrapped_key=wrapped_key,
            wrapped_key_tag=wrapped_key_tag,
            reserved_bytes=reserved_bytes,
        )

    if version == VERSION_PQ_HYBRID:
        return _build_header_v2(
            key_mode=key_mode,
            header_flags=header_flags,
            salt_argon2=salt_argon2,
            argon_mem_cost=argon_mem_cost,
            argon_time_cost=argon_time_cost,
            argon_parallelism=argon_parallelism,
            nonce_aes_gcm=nonce_aes_gcm,
            wrapped_key=wrapped_key,
            wrapped_key_tag=wrapped_key_tag,
            reserved_bytes=reserved_bytes,
            pq_ciphertext=pq_ciphertext,
            pq_wrapped_secret=pq_wrapped_secret,
            pq_wrapped_secret_tag=pq_wrapped_secret_tag,
        )

    if version == VERSION_V3:
        if volume_descriptors is None:
            raise ContainerFormatError("volume_descriptors must be provided for v3 headers")
        return build_header_v3(list(volume_descriptors), common_meta or {})

    raise ContainerFormatError("Unsupported header version")


def _parse_header_v1(data: bytes) -> tuple[ContainerHeader, list[VolumeDescriptor]]:
    if len(data) != HEADER_V1_LEN:
        raise ContainerFormatError("Invalid header length for v1")
    (
        _magic,
        _version,
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
    ) = _HEADER_STRUCT_V1.unpack(data)

    if key_mode not in (KEY_MODE_PASSWORD_ONLY, KEY_MODE_PQ_HYBRID):
        raise UnsupportedFeatureError("Unsupported key mode")
    if key_mode != KEY_MODE_PASSWORD_ONLY:
        raise UnsupportedFeatureError("Only password-based containers are supported")

    if header_flags != 0:
        raise UnsupportedFeatureError("Header flags set for unsupported features")

    if not (0 <= wrapped_key_len <= WRAPPED_KEY_MAX_LEN):
        raise ContainerFormatError("Invalid wrapped_key_len")

    if any(reserved):
        raise UnsupportedFeatureError("Reserved header bytes are non-zero")

    wrapped_key = wrapped_key_padded[:wrapped_key_len]

    header = ContainerHeader(
        version=VERSION_V1,
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
        header_len=HEADER_V1_LEN,
    )

    descriptor = VolumeDescriptor(
        volume_id=0,
        key_mode=key_mode,
        flags=header_flags,
        payload_offset=HEADER_V1_LEN,
        payload_length=0,
        salt_argon2=salt_argon2,
        argon_mem_cost=argon_mem_cost,
        argon_time_cost=argon_time_cost,
        argon_parallelism=argon_parallelism,
        nonce_aes_gcm=nonce_aes_gcm,
        wrapped_key=wrapped_key,
        wrapped_key_tag=wrapped_key_tag,
        reserved=reserved,
    )

    return header, [descriptor]


def _parse_header_v2(data: bytes) -> tuple[ContainerHeader, list[VolumeDescriptor]]:
    if len(data) < _HEADER_STRUCT_V2.size:
        raise ContainerFormatError("Header too short for v2")

    (
        _magic,
        _version,
        key_mode,
        header_flags,
        salt_argon2,
        argon_mem_cost,
        argon_time_cost,
        argon_parallelism,
        nonce_aes_gcm,
        wrapped_key_len,
        wrapped_key_tag,
        pq_ciphertext_len,
        pq_wrapped_secret_len,
        pq_wrapped_secret_tag,
        header_len,
    ) = _HEADER_STRUCT_V2.unpack(data[: _HEADER_STRUCT_V2.size])

    if key_mode not in (KEY_MODE_PASSWORD_ONLY, KEY_MODE_PQ_HYBRID):
        raise UnsupportedFeatureError("Unsupported key mode")
    if key_mode != KEY_MODE_PQ_HYBRID:
        raise UnsupportedFeatureError("Only PQ hybrid containers use version 2")

    if header_flags != 0:
        raise UnsupportedFeatureError("Header flags set for unsupported features")

    expected_len = _HEADER_STRUCT_V2.size + wrapped_key_len + pq_ciphertext_len + pq_wrapped_secret_len
    if header_len != expected_len or len(data) != expected_len:
        raise ContainerFormatError("Invalid header length")

    if not (0 <= wrapped_key_len <= WRAPPED_KEY_MAX_LEN):
        raise ContainerFormatError("Invalid wrapped_key_len")

    offset = _HEADER_STRUCT_V2.size
    wrapped_key = data[offset : offset + wrapped_key_len]
    offset += wrapped_key_len
    pq_ciphertext = data[offset : offset + pq_ciphertext_len]
    offset += pq_ciphertext_len
    pq_wrapped_secret = data[offset : offset + pq_wrapped_secret_len]

    header = ContainerHeader(
        version=VERSION_PQ_HYBRID,
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
        reserved=bytes(RESERVED_LEN),
        header_len=header_len,
        pq_ciphertext=pq_ciphertext,
        pq_wrapped_secret=pq_wrapped_secret,
        pq_wrapped_secret_tag=pq_wrapped_secret_tag,
    )

    descriptor = VolumeDescriptor(
        volume_id=0,
        key_mode=key_mode,
        flags=header_flags,
        payload_offset=header_len,
        payload_length=0,
        salt_argon2=salt_argon2,
        argon_mem_cost=argon_mem_cost,
        argon_time_cost=argon_time_cost,
        argon_parallelism=argon_parallelism,
        nonce_aes_gcm=nonce_aes_gcm,
        wrapped_key=wrapped_key,
        wrapped_key_tag=wrapped_key_tag,
        reserved=bytes(RESERVED_LEN),
        pq_ciphertext=pq_ciphertext,
        pq_wrapped_secret=pq_wrapped_secret,
        pq_wrapped_secret_tag=pq_wrapped_secret_tag,
    )

    return header, [descriptor]


def header_aad(header_bytes: bytes) -> bytes:
    """Return header bytes used as AAD (everything except magic+version)."""

    if len(header_bytes) < MAGIC_LEN + VERSION_LEN:
        raise ContainerFormatError("Header must be fully formed")
    return header_bytes[MAGIC_LEN + VERSION_LEN :]


def _parse_volume_meta_common(
    data: bytes, header_flags: int, key_mode: int
) -> tuple[VolumeDescriptor, int]:
    if len(data) < _VOLUME_META_V3_COMMON_STRUCT.size:
        raise ContainerFormatError("Volume metadata too small for v3")

    (
        flags,
        salt_argon2,
        argon_mem_cost,
        argon_time_cost,
        argon_parallelism,
        nonce_aes_gcm,
        wrapped_key_len,
        wrapped_key_tag,
        pq_ciphertext_len,
        pq_wrapped_secret_len,
        pq_wrapped_secret_tag,
        reserved,
    ) = _VOLUME_META_V3_COMMON_STRUCT.unpack(
        data[: _VOLUME_META_V3_COMMON_STRUCT.size]
    )

    if flags != header_flags:
        header_flags = flags
    if header_flags != 0:
        raise UnsupportedFeatureError("Header flags set for unsupported features")
    if not (0 <= wrapped_key_len <= WRAPPED_KEY_MAX_LEN):
        raise ContainerFormatError("Invalid wrapped_key_len")
    if len(pq_wrapped_secret_tag) != WRAPPED_KEY_TAG_LEN:
        raise ContainerFormatError("Invalid PQ tag length")

    offset = _VOLUME_META_V3_COMMON_STRUCT.size
    padded_len = max(WRAPPED_KEY_MAX_LEN, wrapped_key_len)
    end = offset + padded_len + pq_ciphertext_len + pq_wrapped_secret_len
    if len(data) < end:
        raise ContainerFormatError("Volume metadata shorter than declared lengths")
    if any(reserved):
        raise ContainerFormatError("Reserved bytes must be zero")

    wrapped_key_padded = data[offset : offset + padded_len]
    offset += padded_len
    wrapped_key = wrapped_key_padded[:wrapped_key_len]
    pq_ciphertext = data[offset : offset + pq_ciphertext_len]
    offset += pq_ciphertext_len
    pq_wrapped_secret = data[offset : offset + pq_wrapped_secret_len]
    offset += pq_wrapped_secret_len

    descriptor = VolumeDescriptor(
        volume_id=0,
        key_mode=key_mode,
        flags=header_flags,
        payload_offset=0,
        payload_length=0,
        salt_argon2=salt_argon2,
        argon_mem_cost=argon_mem_cost,
        argon_time_cost=argon_time_cost,
        argon_parallelism=argon_parallelism,
        nonce_aes_gcm=nonce_aes_gcm,
        wrapped_key=wrapped_key,
        wrapped_key_tag=wrapped_key_tag,
        reserved=reserved,
        pq_ciphertext=pq_ciphertext if pq_ciphertext_len else None,
        pq_wrapped_secret=pq_wrapped_secret if pq_wrapped_secret_len else None,
        pq_wrapped_secret_tag=pq_wrapped_secret_tag,
    )
    return descriptor, end


def _parse_volume_meta_password_legacy(data: bytes, header_flags: int) -> tuple[VolumeDescriptor, int]:
    if len(data) < _VOLUME_META_V3_PASSWORD_STRUCT.size:
        raise ContainerFormatError("Volume metadata too small for password mode")

    (
        flags,
        salt_argon2,
        argon_mem_cost,
        argon_time_cost,
        argon_parallelism,
        nonce_aes_gcm,
        wrapped_key_len,
        wrapped_key_padded,
        wrapped_key_tag,
        reserved,
    ) = _VOLUME_META_V3_PASSWORD_STRUCT.unpack(
        data[: _VOLUME_META_V3_PASSWORD_STRUCT.size]
    )

    if flags != header_flags:
        header_flags = flags
    if header_flags != 0:
        raise UnsupportedFeatureError("Header flags set for unsupported features")

    if not (0 <= wrapped_key_len <= WRAPPED_KEY_MAX_LEN):
        raise ContainerFormatError("Invalid wrapped_key_len")

    wrapped_key = wrapped_key_padded[:wrapped_key_len]
    if any(reserved):
        raise ContainerFormatError("Reserved bytes must be zero")

    descriptor = VolumeDescriptor(
        volume_id=0,
        key_mode=KEY_MODE_PASSWORD_ONLY,
        flags=header_flags,
        payload_offset=0,
        payload_length=0,
        salt_argon2=salt_argon2,
        argon_mem_cost=argon_mem_cost,
        argon_time_cost=argon_time_cost,
        argon_parallelism=argon_parallelism,
        nonce_aes_gcm=nonce_aes_gcm,
        wrapped_key=wrapped_key,
        wrapped_key_tag=wrapped_key_tag,
        reserved=reserved,
    )
    return descriptor, _VOLUME_META_V3_PASSWORD_STRUCT.size


def _parse_volume_meta_pq_legacy(data: bytes, header_flags: int) -> tuple[VolumeDescriptor, int]:
    if len(data) < _VOLUME_META_V3_PQ_STRUCT.size:
        raise ContainerFormatError("Volume metadata too small for pq mode")

    (
        flags,
        salt_argon2,
        argon_mem_cost,
        argon_time_cost,
        argon_parallelism,
        nonce_aes_gcm,
        wrapped_key_len,
        wrapped_key_tag,
        pq_ciphertext_len,
        pq_wrapped_secret_len,
        pq_wrapped_secret_tag,
    ) = _VOLUME_META_V3_PQ_STRUCT.unpack(data[: _VOLUME_META_V3_PQ_STRUCT.size])

    if flags != header_flags:
        header_flags = flags
    if header_flags != 0:
        raise UnsupportedFeatureError("Header flags set for unsupported features")

    offset = _VOLUME_META_V3_PQ_STRUCT.size
    end = offset + wrapped_key_len + pq_ciphertext_len + pq_wrapped_secret_len
    if len(data) < end:
        raise ContainerFormatError("Volume metadata shorter than declared lengths")

    wrapped_key = data[offset : offset + wrapped_key_len]
    offset += wrapped_key_len
    pq_ciphertext = data[offset : offset + pq_ciphertext_len]
    offset += pq_ciphertext_len
    pq_wrapped_secret = data[offset : offset + pq_wrapped_secret_len]
    offset += pq_wrapped_secret_len

    if wrapped_key_len > WRAPPED_KEY_MAX_LEN:
        raise ContainerFormatError("Invalid wrapped_key_len")

    descriptor = VolumeDescriptor(
        volume_id=0,
        key_mode=KEY_MODE_PQ_HYBRID,
        flags=header_flags,
        payload_offset=0,
        payload_length=0,
        salt_argon2=salt_argon2,
        argon_mem_cost=argon_mem_cost,
        argon_time_cost=argon_time_cost,
        argon_parallelism=argon_parallelism,
        nonce_aes_gcm=nonce_aes_gcm,
        wrapped_key=wrapped_key,
        wrapped_key_tag=wrapped_key_tag,
        reserved=bytes(RESERVED_LEN),
        pq_ciphertext=pq_ciphertext,
        pq_wrapped_secret=pq_wrapped_secret,
        pq_wrapped_secret_tag=pq_wrapped_secret_tag,
    )

    return descriptor, end


def parse_header_v3(data: bytes) -> tuple[ContainerHeader, list[VolumeDescriptor]]:
    if len(data) < _HEADER_STRUCT_V3_PREFIX.size:
        raise ContainerFormatError("Header too short for v3")

    (
        magic,
        version,
        volume_count,
        header_len,
    ) = _HEADER_STRUCT_V3_PREFIX.unpack(data[: _HEADER_STRUCT_V3_PREFIX.size])

    if magic != MAGIC:
        raise ContainerFormatError("Invalid magic")
    if version != VERSION_V3:
        raise ContainerFormatError("Invalid version for v3 parser")
    if len(data) != header_len:
        raise ContainerFormatError("Invalid header length for v3")

    descriptors: list[VolumeDescriptor] = []
    descriptor_table_end = _HEADER_STRUCT_V3_PREFIX.size + volume_count * _VOLUME_DESCRIPTOR_STRUCT.size
    if len(data) < descriptor_table_end:
        raise ContainerFormatError("Header shorter than descriptor table")

    metas = data[descriptor_table_end:]
    meta_offset = 0
    for idx in range(volume_count):
        start = _HEADER_STRUCT_V3_PREFIX.size + idx * _VOLUME_DESCRIPTOR_STRUCT.size
        (
            volume_id,
            key_mode,
            flags,
            payload_offset,
            payload_length,
            meta_len,
        ) = _VOLUME_DESCRIPTOR_STRUCT.unpack(
            data[start : start + _VOLUME_DESCRIPTOR_STRUCT.size]
        )

        meta_data = metas[meta_offset : meta_offset + meta_len]
        if len(meta_data) != meta_len:
            raise ContainerFormatError("Volume metadata shorter than declared")

        try:
            descriptor, consumed = _parse_volume_meta_common(meta_data, flags, key_mode)
        except (ContainerFormatError, UnsupportedFeatureError):
            if key_mode == KEY_MODE_PASSWORD_ONLY:
                descriptor, consumed = _parse_volume_meta_password_legacy(meta_data, flags)
            elif key_mode == KEY_MODE_PQ_HYBRID:
                descriptor, consumed = _parse_volume_meta_pq_legacy(meta_data, flags)
            else:
                raise UnsupportedFeatureError("Unsupported key mode")

        if consumed != meta_len:
            raise ContainerFormatError("Volume metadata length mismatch")

        descriptor = VolumeDescriptor(
            volume_id=volume_id,
            key_mode=descriptor.key_mode,
            flags=descriptor.flags,
            payload_offset=payload_offset,
            payload_length=payload_length,
            salt_argon2=descriptor.salt_argon2,
            argon_mem_cost=descriptor.argon_mem_cost,
            argon_time_cost=descriptor.argon_time_cost,
            argon_parallelism=descriptor.argon_parallelism,
            nonce_aes_gcm=descriptor.nonce_aes_gcm,
            wrapped_key=descriptor.wrapped_key,
            wrapped_key_tag=descriptor.wrapped_key_tag,
            reserved=descriptor.reserved,
            pq_ciphertext=descriptor.pq_ciphertext,
            pq_wrapped_secret=descriptor.pq_wrapped_secret,
            pq_wrapped_secret_tag=descriptor.pq_wrapped_secret_tag,
        )
        descriptors.append(descriptor)
        meta_offset += meta_len

    if meta_offset != len(metas):
        raise ContainerFormatError("Unexpected trailing metadata")

    if not descriptors:
        raise ContainerFormatError("No descriptors found")

    _validate_volume_layout(descriptors)

    main = descriptors[0]
    header = ContainerHeader(
        version=VERSION_V3,
        key_mode=main.key_mode,
        header_flags=main.flags,
        salt_argon2=main.salt_argon2,
        argon_mem_cost=main.argon_mem_cost,
        argon_time_cost=main.argon_time_cost,
        argon_parallelism=main.argon_parallelism,
        nonce_aes_gcm=main.nonce_aes_gcm,
        wrapped_key_len=len(main.wrapped_key),
        wrapped_file_key=main.wrapped_key,
        wrapped_key_tag=main.wrapped_key_tag,
        reserved=main.reserved,
        header_len=header_len,
        pq_ciphertext=main.pq_ciphertext,
        pq_wrapped_secret=main.pq_wrapped_secret,
        pq_wrapped_secret_tag=main.pq_wrapped_secret_tag,
    )

    return header, descriptors


def parse_header(data: bytes) -> tuple[ContainerHeader, list[VolumeDescriptor]]:
    """Parse and validate header bytes."""

    if len(data) < MAGIC_LEN + VERSION_LEN:
        raise ContainerFormatError("Header too short")

    magic = data[:MAGIC_LEN]
    version = data[MAGIC_LEN]

    if magic != MAGIC:
        raise ContainerFormatError("Invalid magic")

    if version == VERSION_V1:
        return _parse_header_v1(data)

    if version == VERSION_PQ_HYBRID:
        return _parse_header_v2(data)

    if version == VERSION_V3:
        return parse_header_v3(data)

    raise ContainerFormatError("Unsupported version")


def read_header_from_stream(file_obj) -> tuple[ContainerHeader, list[VolumeDescriptor], bytes]:
    """Read and parse a container header from a binary stream."""

    prefix = file_obj.read(_HEADER_STRUCT_V3_PREFIX.size)
    if len(prefix) < MAGIC_LEN + VERSION_LEN:
        raise ContainerFormatError("Container too small for header")

    version = prefix[MAGIC_LEN]
    if version == VERSION_V1:
        remaining = file_obj.read(HEADER_V1_LEN - len(prefix))
        header_bytes = prefix + remaining
        if len(header_bytes) != HEADER_V1_LEN:
            raise ContainerFormatError("Container missing header bytes")
    elif version == VERSION_PQ_HYBRID:
        need = _HEADER_STRUCT_V2.size
        if len(prefix) < need:
            prefix += file_obj.read(need - len(prefix))
        if len(prefix) < need:
            raise ContainerFormatError("Container too small for v2 header")
        fixed = prefix[:need]
        (
            _magic,
            _version,
            _key_mode,
            _header_flags,
            _salt,
            _argon_mem_cost,
            _argon_time_cost,
            _argon_parallelism,
            _nonce,
            _wrapped_len,
            _wrapped_tag,
            pq_ciphertext_len,
            pq_wrapped_secret_len,
            _pq_wrapped_tag,
            header_len,
        ) = _HEADER_STRUCT_V2.unpack(fixed)
        if header_len < _HEADER_STRUCT_V2.size:
            raise ContainerFormatError("Invalid header length")
        remaining_len = header_len - len(prefix)
        rest = file_obj.read(remaining_len)
        header_bytes = prefix + rest
        if len(header_bytes) != header_len:
            raise ContainerFormatError("Container missing header bytes")
    elif version == VERSION_V3:
        if len(prefix) < _HEADER_STRUCT_V3_PREFIX.size:
            raise ContainerFormatError("Container too small for v3 header")
        (_magic, _version, _volume_count, header_len) = _HEADER_STRUCT_V3_PREFIX.unpack(
            prefix
        )
        remaining_len = header_len - len(prefix)
        rest = file_obj.read(remaining_len)
        header_bytes = prefix + rest
        if len(header_bytes) != header_len:
            raise ContainerFormatError("Container missing header bytes")
    else:
        raise ContainerFormatError("Unsupported container version")

    header, descriptors = parse_header(header_bytes)
    return header, descriptors, header_bytes
