import os
import os
from pathlib import Path

import pytest

pytest.importorskip("oqs")

from zilant_encrypt.container.api import decrypt_file, encrypt_file  # noqa: E402
from zilant_encrypt.container.format import KEY_MODE_PQ_HYBRID, read_header_from_stream  # noqa: E402


def test_pq_hybrid_roundtrip(tmp_path: Path) -> None:
    payload = os.urandom(256)
    source = tmp_path / "payload.bin"
    source.write_bytes(payload)

    container = tmp_path / "container.zil"
    output = tmp_path / "restored.bin"

    encrypt_file(source, container, "secret", mode="pq-hybrid")
    decrypt_file(container, output, "secret", mode="pq-hybrid")

    assert output.read_bytes() == payload


def test_pq_hybrid_wrong_password(tmp_path: Path) -> None:
    payload = b"data"
    source = tmp_path / "payload.txt"
    source.write_bytes(payload)

    container = tmp_path / "container.zil"
    output = tmp_path / "restored.txt"

    encrypt_file(source, container, "secret", mode="pq-hybrid")
    with pytest.raises(Exception):
        decrypt_file(container, output, "wrong", mode="pq-hybrid")


def test_pq_header_fields(tmp_path: Path) -> None:
    payload = b"check"
    source = tmp_path / "payload.bin"
    source.write_bytes(payload)

    container = tmp_path / "container.zil"
    encrypt_file(source, container, "secret", mode="pq-hybrid")

    with container.open("rb") as f:
        header, _descriptors, _header_bytes = read_header_from_stream(f)
    assert header.key_mode == KEY_MODE_PQ_HYBRID
    assert header.argon_mem_cost > 0
    assert header.pq_ciphertext is not None
