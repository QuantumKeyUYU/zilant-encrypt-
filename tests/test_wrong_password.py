import os
from pathlib import Path

import pytest

from zilant_encrypt.container.api import decrypt_file, encrypt_file
from zilant_encrypt.errors import InvalidPassword


def test_wrong_password(tmp_path: Path) -> None:
    data = os.urandom(512)
    source = tmp_path / "source.bin"
    source.write_bytes(data)

    container = tmp_path / "data.zil"
    encrypt_file(source, container, "correcthorsebatterystaple", overwrite=False)

    with pytest.raises(InvalidPassword):
        decrypt_file(container, tmp_path / "out.bin", "wrongpassword", overwrite=False)
