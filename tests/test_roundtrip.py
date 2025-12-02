import os
from pathlib import Path

import pytest

from zilant_encrypt.container.api import STREAM_CHUNK_SIZE, decrypt_file, encrypt_file
from zilant_encrypt.container.format import VERSION_V3, read_header_from_stream
from zilant_encrypt.crypto.kdf import Argon2Params
from zilant_encrypt.errors import UnsupportedFeatureError

PAYLOAD_SIZE = 1024


def test_roundtrip(tmp_path: Path) -> None:
    """Полный круг: зашифровать файл и успешно расшифровать его обратно."""
    # Генерируем случайное содержимое
    data = os.urandom(PAYLOAD_SIZE)
    source = tmp_path / "source.bin"
    source.write_bytes(data)

    container = tmp_path / "data.zil"
    output = tmp_path / "output.bin"

    # Шифруем и расшифровываем с одним и тем же паролем
    encrypt_file(
        source,
        container,
        password="password123",
        overwrite=False,
    )
    with container.open("rb") as f:
        header, _descriptors, _header_bytes = read_header_from_stream(f)
    assert header.version == VERSION_V3
    decrypt_file(
        container,
        output,
        password="password123",
        overwrite=False,
    )

    # Данные после расшифровки должны совпасть с исходными
    assert output.read_bytes() == data


def test_large_file_streaming(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    size = STREAM_CHUNK_SIZE * 3 + 123
    source = tmp_path / "big.bin"
    payload = os.urandom(size)
    source.write_bytes(payload)

    container = tmp_path / "big.zil"
    output = tmp_path / "restored.bin"

    read_sizes: list[int] = []
    real_open = Path.open

    def spy_open(self: Path, mode: str = "r", *args, **kwargs):  # type: ignore[override]
        handle = real_open(self, mode, *args, **kwargs)
        if "rb" in mode and self == source:
            original_read = handle.read

            def _read(n: int = -1):
                read_sizes.append(n)
                return original_read(n)

            handle.read = _read  # type: ignore[assignment]
        return handle

    monkeypatch.setattr(Path, "open", spy_open)

    encrypt_file(source, container, "pw")
    assert len(read_sizes) > 1
    assert max(read_sizes) <= STREAM_CHUNK_SIZE

    decrypt_sizes: list[int] = []

    def decrypt_spy_open(self: Path, mode: str = "r", *args, **kwargs):  # type: ignore[override]
        handle = real_open(self, mode, *args, **kwargs)
        if "rb" in mode and self == container:
            original_read = handle.read

            def _read(n: int = -1):
                decrypt_sizes.append(n)
                return original_read(n)

            handle.read = _read  # type: ignore[assignment]
        return handle

    monkeypatch.setattr(Path, "open", decrypt_spy_open)

    decrypt_file(container, output, "pw")
    assert output.read_bytes() == payload
    assert max(decrypt_sizes) <= STREAM_CHUNK_SIZE
    assert len(decrypt_sizes) > 1


def test_api_honors_custom_argon_params(tmp_path: Path) -> None:
    source = tmp_path / "argon.bin"
    source.write_bytes(b"payload")
    container = tmp_path / "argon.zil"
    params = Argon2Params(mem_cost_kib=128 * 1024, time_cost=4, parallelism=2)

    encrypt_file(source, container, password="pw", argon_params=params)

    _header, descriptors, _bytes = read_header_from_stream(container.open("rb"))
    desc = descriptors[0]
    assert desc.argon_mem_cost == params.mem_cost_kib
    assert desc.argon_time_cost == params.time_cost
    assert desc.argon_parallelism == params.parallelism


def test_api_rejects_unsafe_argon_params(tmp_path: Path) -> None:
    source = tmp_path / "argon_bad.bin"
    source.write_bytes(b"payload")
    container = tmp_path / "argon_bad.zil"
    params = Argon2Params(mem_cost_kib=1024, time_cost=0, parallelism=0)

    with pytest.raises(UnsupportedFeatureError):
        encrypt_file(source, container, password="pw", argon_params=params)
