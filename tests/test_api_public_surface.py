from __future__ import annotations

from pathlib import Path

import pytest

from zilant_encrypt.container import (
    decrypt_auto_volume,
    decrypt_file,
    encrypt_file,
    encrypt_with_decoy,
)
from zilant_encrypt.crypto import pq


def test_public_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "secret.txt"
    source.write_text("top secret", encoding="utf-8")
    container = tmp_path / "secret.zil"
    output = tmp_path / "secret.out"

    encrypt_file(source, container, "pw")
    decrypt_file(container, output, "pw")

    assert output.read_text(encoding="utf-8") == "top secret"


def test_public_decoy_volume(tmp_path: Path) -> None:
    main = tmp_path / "main.txt"
    main.write_text("main payload", encoding="utf-8")
    decoy = tmp_path / "decoy.txt"
    decoy.write_text("decoy payload", encoding="utf-8")

    container = tmp_path / "combo.zil"
    encrypt_with_decoy(main, decoy, container, password="pw", decoy_password="decoy")

    main_out = tmp_path / "main.out"
    decrypt_file(container, main_out, "pw", volume_selector="main")
    decoy_out = tmp_path / "decoy.out"
    decrypt_file(container, decoy_out, "decoy", volume_selector="decoy")

    assert main_out.read_text(encoding="utf-8") == "main payload"
    assert decoy_out.read_text(encoding="utf-8") == "decoy payload"


@pytest.mark.skipif(not pq.available(), reason="pq support not available")
def test_public_pq_hybrid_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "pq.txt"
    source.write_text("quantum ready", encoding="utf-8")
    container = tmp_path / "pq.zil"
    output = tmp_path / "pq.out"

    encrypt_file(source, container, "pw", mode="pq-hybrid")
    decrypt_file(container, output, "pw", mode="pq-hybrid")

    assert output.read_text(encoding="utf-8") == "quantum ready"


@pytest.mark.skipif(not pq.available(), reason="pq support not available")
def test_public_auto_volume_finds_decoy(tmp_path: Path) -> None:
    main = tmp_path / "main.txt"
    main.write_text("main payload", encoding="utf-8")
    decoy = tmp_path / "decoy.txt"
    decoy.write_text("decoy payload", encoding="utf-8")

    container = tmp_path / "auto.zil"
    encrypt_with_decoy(main, decoy, container, password="pw", decoy_password="decoy")

    # Ensure decoy password alone discovers decoy volume
    volume_index, volume_name = decrypt_auto_volume(container, tmp_path / "auto-out", password="decoy")
    assert volume_index == 1
    assert volume_name == "decoy"
