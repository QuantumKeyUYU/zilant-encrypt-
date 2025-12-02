"""Container header format helpers."""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct

from zilant_encrypt.errors import ContainerFormatError, UnsupportedFeatureError

MAGIC = b"ZILENC"
VERSION_V1 = 1
VERSION_PQ_HYBRID = 2
HEADER_V1_LEN = 128
HEADER_LEN = HEADER_V1_LEN  # backwards compatibility
KEY_MODE_PASSWORD_ONLY = 0x01
KEY_MODE_PQ_HYBRID = 0x02

MAGIC_LEN = 6
VERSION_LEN = 1
SALT_LEN = 16
NONCE_LEN = 12
WRAPPED_KEY_MAX_LEN = 32
WRAPPED_KEY_TAG_LEN = 16
RESERVED_LEN = 28

_HEADER_STRUCT_V1 = Struct(
    "<6sBBH16sIII12sH32s16s28s",
)  # totals 128 bytes

# V2 header is variable length. It keeps the core fields from v1 and adds PQ
# metadata lengths plus tags. The actual wrapped key, KEM ciphertext and
# wrapped secret key are stored immediately after the fixed part.
_HEADER_STRUCT_V2 = Struct(
    "<6sBBH16sIII12sH16sHH16sH",
)


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
) -> bytes:
    """Build container header bytes for the requested version."""

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

    if version == VERSION_V1:
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

    if version != VERSION_PQ_HYBRID:
        raise ContainerFormatError("Unsupported header version")

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


def parse_header(data: bytes) -> ContainerHeader:
    """Parse and validate header bytes."""

    if len(data) < MAGIC_LEN + VERSION_LEN:
        raise ContainerFormatError("Header too short")

    magic = data[:MAGIC_LEN]
    version = data[MAGIC_LEN]

    if magic != MAGIC:
        raise ContainerFormatError("Invalid magic")

    if version == VERSION_V1:
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

        return ContainerHeader(
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

    if version != VERSION_PQ_HYBRID:
        raise ContainerFormatError("Unsupported version")

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

    return ContainerHeader(
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


def header_aad(header_bytes: bytes) -> bytes:
    """Return header bytes used as AAD (everything except magic+version)."""

    if len(header_bytes) < MAGIC_LEN + VERSION_LEN:
        raise ContainerFormatError("Header must be fully formed")
    return header_bytes[MAGIC_LEN + VERSION_LEN :]


def read_header_from_stream(file_obj) -> tuple[ContainerHeader, bytes]:
    """Read and parse a container header from a binary stream."""

    prefix = file_obj.read(_HEADER_STRUCT_V2.size)
    if len(prefix) < MAGIC_LEN + VERSION_LEN:
        raise ContainerFormatError("Container too small for header")

    version = prefix[MAGIC_LEN]
    if version == VERSION_V1:
        remaining = file_obj.read(HEADER_V1_LEN - len(prefix))
        header_bytes = prefix + remaining
        if len(header_bytes) != HEADER_V1_LEN:
            raise ContainerFormatError("Container missing header bytes")
    elif version == VERSION_PQ_HYBRID:
        if len(prefix) < _HEADER_STRUCT_V2.size:
            # header too small even for fixed part
            raise ContainerFormatError("Container too small for v2 header")
        fixed = prefix
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
        remaining_len = header_len - _HEADER_STRUCT_V2.size
        rest = file_obj.read(remaining_len)
        header_bytes = fixed + rest
        if len(header_bytes) != header_len:
            raise ContainerFormatError("Container missing header bytes")
    else:
        raise ContainerFormatError("Unsupported container version")

    return parse_header(header_bytes), header_bytes
