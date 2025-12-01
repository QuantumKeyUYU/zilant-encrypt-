import pytest

from zilant_encrypt.container.format import (
    HEADER_LEN,
    KEY_MODE_PASSWORD_ONLY,
    build_header,
    parse_header,
)
from zilant_encrypt.errors import ContainerFormatError, UnsupportedFeatureError

PAYLOAD_SIZE = 1024


def test_build_and_parse_header() -> None:
    header_bytes = build_header(
        key_mode=KEY_MODE_PASSWORD_ONLY,
        header_flags=0,
        salt_argon2=b"\x01" * 16,
        argon_mem_cost=PAYLOAD_SIZE,
        argon_time_cost=2,
        argon_parallelism=1,
        nonce_aes_gcm=b"\x02" * 12,
        wrapped_key=b"\x03" * 32,
        wrapped_key_tag=b"\x04" * 16,
    )

    assert len(header_bytes) == HEADER_LEN

    parsed = parse_header(header_bytes)
    assert parsed.salt_argon2 == b"\x01" * 16
    assert parsed.argon_mem_cost == PAYLOAD_SIZE
    assert parsed.nonce_aes_gcm == b"\x02" * 12
    assert parsed.wrapped_file_key == b"\x03" * 32
    assert parsed.wrapped_key_tag == b"\x04" * 16


def test_invalid_magic() -> None:
    header_bytes = bytearray(
        build_header(
            key_mode=KEY_MODE_PASSWORD_ONLY,
            header_flags=0,
            salt_argon2=b"\x01" * 16,
            argon_mem_cost=PAYLOAD_SIZE,
            argon_time_cost=2,
            argon_parallelism=1,
            nonce_aes_gcm=b"\x02" * 12,
            wrapped_key=b"\x03" * 32,
            wrapped_key_tag=b"\x04" * 16,
        )
    )
    header_bytes[0:6] = b"BADMAG"

    with pytest.raises(ContainerFormatError):
        parse_header(bytes(header_bytes))


def test_unsupported_key_mode() -> None:
    header_bytes = bytearray(
        build_header(
            key_mode=KEY_MODE_PASSWORD_ONLY,
            header_flags=0,
            salt_argon2=b"\x01" * 16,
            argon_mem_cost=PAYLOAD_SIZE,
            argon_time_cost=2,
            argon_parallelism=1,
            nonce_aes_gcm=b"\x02" * 12,
            wrapped_key=b"\x03" * 32,
            wrapped_key_tag=b"\x04" * 16,
        )
    )
    header_bytes[7] = 1  # set key_mode to PQ hybrid

    with pytest.raises(UnsupportedFeatureError):
        parse_header(bytes(header_bytes))
