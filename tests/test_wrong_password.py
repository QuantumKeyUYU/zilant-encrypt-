import os
from pathlib import Path

import pytest

from zilant_encrypt.container.api import decrypt_file, encrypt_file
from zilant_encrypt.errors import InvalidPassword

PAYLOAD_SIZE = 512


def test_wrong_password(tmp_path: Path) -> None:
    """Decrypting с неправильным паролем должно выбрасывать InvalidPassword."""
    # Подготовка исходных данных
    data = os.urandom(PAYLOAD_SIZE)
    source = tmp_path / "source.bin"
    source.write_bytes(data)

    # Шифруем с корректным паролем
    container = tmp_path / "data.zil"
    encrypt_file(
        source,
        container,
        password="correcthorsebatterystaple",
        overwrite=False,
    )

    # При попытке расшифровать с неверным паролем должно быть исключение
    with pytest.raises(InvalidPassword):
        decrypt_file(
            container,
            tmp_path / "out.bin",
            password="wrongpassword",
            overwrite=False,
        )
