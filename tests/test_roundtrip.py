import os
from pathlib import Path

from zilant_encrypt.container.api import decrypt_file, encrypt_file


def test_roundtrip(tmp_path: Path) -> None:
    data = os.urandom(1024)
    source = tmp_path / "source.bin"
    source.write_bytes(data)

    container = tmp_path / "data.zil"
    output = tmp_path / "output.bin"

    encrypt_file(source, container, "password123", overwrite=False)
    decrypt_file(container, output, "password123", overwrite=False)

    assert output.read_bytes() == data
