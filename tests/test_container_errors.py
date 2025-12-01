import os
from pathlib import Path

import pytest

from zilant_encrypt.container.api import decrypt_file, encrypt_file
from zilant_encrypt.container.format import HEADER_LEN
from zilant_encrypt.errors import ContainerFormatError


def test_decrypt_truncated_container(tmp_path: Path) -> None:
    """Повреждённый контейнер должен приводить к ContainerFormatError."""

    data = os.urandom(64)
    source = tmp_path / "source.bin"
    source.write_bytes(data)

    container = tmp_path / "data.zil"
    encrypt_file(source, container, password="pw")

    truncated = tmp_path / "truncated.zil"
    truncated.write_bytes(container.read_bytes()[: HEADER_LEN + 4])

    with pytest.raises(ContainerFormatError):
        decrypt_file(truncated, tmp_path / "out.bin", password="pw")


def test_encrypt_does_not_overwrite_without_flag(tmp_path: Path) -> None:
    """Не перезаписывать существующий файл, если overwrite не указан."""

    source = tmp_path / "source.bin"
    source.write_bytes(b"content")

    container = tmp_path / "data.zil"
    container.write_bytes(b"existing")

    with pytest.raises(FileExistsError):
        encrypt_file(source, container, password="pw", overwrite=False)

    assert container.read_bytes() == b"existing"


def test_decrypt_does_not_overwrite_without_flag(tmp_path: Path) -> None:
    """Расшифровка не должна затирать существующий файл без overwrite=True."""

    data = os.urandom(32)
    source = tmp_path / "source.bin"
    source.write_bytes(data)

    container = tmp_path / "data.zil"
    encrypt_file(source, container, password="pw")

    output = tmp_path / "output.bin"
    output.write_bytes(b"keep")

    with pytest.raises(FileExistsError):
        decrypt_file(container, output, password="pw", overwrite=False)

    assert output.read_bytes() == b"keep"
