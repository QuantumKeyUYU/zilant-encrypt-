import os
from pathlib import Path

from zilant_encrypt.container.api import decrypt_file, encrypt_file

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
    decrypt_file(
        container,
        output,
        password="password123",
        overwrite=False,
    )

    # Данные после расшифровки должны совпасть с исходными
    assert output.read_bytes() == data
