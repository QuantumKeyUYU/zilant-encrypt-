from pathlib import Path

import pytest

from zilant_encrypt.container import api
from zilant_encrypt.errors import ContainerFormatError, InvalidPassword, UnsupportedFeatureError


def test_main_and_decoy_roundtrip_password_only(tmp_path: Path) -> None:
    main_data = tmp_path / "main.txt"
    main_data.write_text("MAIN")

    decoy_data = tmp_path / "decoy.txt"
    decoy_data.write_text("DECOY")

    container = tmp_path / "vault.zil"

    api.encrypt_file(main_data, container, "pass-main", volume="main")
    api.encrypt_file(decoy_data, container, "pass-decoy", volume="decoy")

    main_out = tmp_path / "main_out.txt"
    decoy_out = tmp_path / "decoy_out.txt"

    api.decrypt_file(container, main_out, "pass-main", volume="main")
    api.decrypt_file(container, decoy_out, "pass-decoy", volume="decoy")

    assert main_out.read_text() == "MAIN"
    assert decoy_out.read_text() == "DECOY"
    assert main_out.read_text() != decoy_out.read_text()

    with pytest.raises(InvalidPassword):
        api.decrypt_file(container, tmp_path / "wrong_main.txt", "pass-decoy", volume="main")
    with pytest.raises(InvalidPassword):
        api.decrypt_file(container, tmp_path / "wrong_decoy.txt", "pass-main", volume="decoy")


def test_decoy_requires_existing_v3_container(tmp_path: Path) -> None:
    payload = tmp_path / "data.txt"
    payload.write_text("data")
    out_path = tmp_path / "new.zil"

    with pytest.raises(UnsupportedFeatureError):
        api.encrypt_file(payload, out_path, "pw", volume="decoy")

    api.encrypt_file(payload, out_path, "pw", volume="main")

    api.encrypt_file(payload, out_path, "pw2", volume="decoy")

    with pytest.raises(UnsupportedFeatureError):
        api.decrypt_file(out_path, tmp_path / "missing.txt", "pw2", volume="decoy", mode="pq-hybrid")
