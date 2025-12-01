import pytest

from zilant_encrypt.container.format import (
    HEADER_LEN,
    KEY_MODE_PASSWORD_ONLY,
    build_header,
    parse_header,
)
from zilant_encrypt.errors import ContainerFormatError, UnsupportedFeatureError

ARGON_MEM_COST = 1024


def _build_sample_header() -> bytes:
    """Собрать валидный заголовок контейнера для использования в тестах."""
    return build_header(
        key_mode=KEY_MODE_PASSWORD_ONLY,
        header_flags=0,
        salt_argon2=b"\x01" * 16,
        argon_mem_cost=ARGON_MEM_COST,
        argon_time_cost=2,
        argon_parallelism=1,
        nonce_aes_gcm=b"\x02" * 12,
        wrapped_key=b"\x03" * 32,
        wrapped_key_tag=b"\x04" * 16,
    )


def test_build_and_parse_header() -> None:
    """Построенный заголовок должен корректно парситься."""
    header_bytes = _build_sample_header()

    # длина фиксированная
    assert len(header_bytes) == HEADER_LEN

    parsed = parse_header(header_bytes)

    # базовые поля должны совпасть с тем, что передавали в build_header
    assert parsed.salt_argon2 == b"\x01" * 16
    assert parsed.argon_mem_cost == ARGON_MEM_COST
    assert parsed.nonce_aes_gcm == b"\x02" * 12
    assert parsed.wrapped_file_key == b"\x03" * 32
    assert parsed.wrapped_key_tag == b"\x04" * 16


def test_invalid_magic() -> None:
    """Неверная магическая сигнатура должна привести к ContainerFormatError."""
    header_bytes = bytearray(_build_sample_header())
    # подпортили magic
    header_bytes[0:6] = b"BADMAG"

    with pytest.raises(ContainerFormatError):
        parse_header(bytes(header_bytes))


def test_unsupported_key_mode() -> None:
    """Неподдерживаемый режим ключа должен приводить к UnsupportedFeatureError."""
    header_bytes = bytearray(_build_sample_header())

    # Принудительно выставляем другой key_mode (например, PQ hybrid)
    header_bytes[7] = 1

    with pytest.raises(UnsupportedFeatureError):
        parse_header(bytes(header_bytes))


def test_header_flags_not_supported() -> None:
    """Любые выставленные флаги считаем неподдерживаемой функцией."""
    header_bytes = bytearray(_build_sample_header())

    # header_flags — двухбайтовое поле сразу после key_mode
    header_bytes[8:10] = (1).to_bytes(2, "little")

    with pytest.raises(UnsupportedFeatureError):
        parse_header(bytes(header_bytes))


def test_reserved_bytes_not_zero() -> None:
    """Незаполненные нулями резервные байты считаем неподдерживаемыми."""
    header_bytes = bytearray(_build_sample_header())
    header_bytes[-1] = 1

    with pytest.raises(UnsupportedFeatureError):
        parse_header(bytes(header_bytes))
