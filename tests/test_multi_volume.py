from pathlib import Path

import pytest

from zilant_encrypt.container import api
from zilant_encrypt.container.format import (
    KEY_MODE_PASSWORD_ONLY,
    KEY_MODE_PQ_HYBRID,
    read_header_from_stream,
)
from zilant_encrypt.errors import ContainerFormatError, InvalidPassword, UnsupportedFeatureError
from zilant_encrypt.crypto import pq


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


def test_decoy_must_match_main_key_mode(tmp_path: Path) -> None:
    payload = tmp_path / "data.txt"
    payload.write_text("hello")
    container = tmp_path / "vault.zil"

    api.encrypt_file(payload, container, "pw", volume="main", mode="password")
    with pytest.raises(UnsupportedFeatureError):
        api.encrypt_file(payload, container, "pw", volume="decoy", mode="pq-hybrid")

    if not pq.available():
        pytest.skip("oqs not available")

    pq_container = tmp_path / "pq.zil"
    api.encrypt_file(payload, pq_container, "pw", volume="main", mode="pq-hybrid")
    with pytest.raises(UnsupportedFeatureError):
        api.encrypt_file(payload, pq_container, "pw", volume="decoy", mode="password")


def test_encrypt_decrypt_pq_main_and_decoy(tmp_path: Path) -> None:
    if not pq.available():
        pytest.skip("oqs not available")

    main_data = tmp_path / "main.txt"
    decoy_data = tmp_path / "decoy.txt"
    main_data.write_text("MAIN")
    decoy_data.write_text("DECOY")

    container = tmp_path / "pq_multi.zil"

    api.encrypt_file(main_data, container, "pw-main", volume="main", mode="pq-hybrid")
    api.encrypt_file(decoy_data, container, "pw-decoy", volume="decoy", mode="pq-hybrid")

    main_out = tmp_path / "main_out.txt"
    decoy_out = tmp_path / "decoy_out.txt"

    api.decrypt_file(container, main_out, "pw-main", volume="main")
    api.decrypt_file(container, decoy_out, "pw-decoy", volume="decoy")

    assert main_out.read_text() == "MAIN"
    assert decoy_out.read_text() == "DECOY"


def test_encrypt_with_decoy_helper_roundtrip(tmp_path: Path) -> None:
    main_data = tmp_path / "main.txt"
    decoy_data = tmp_path / "decoy.txt"
    main_data.write_text("MAIN")
    decoy_data.write_text("DECOY")

    container = tmp_path / "helper.zil"

    api.encrypt_with_decoy(
        main_data,
        container,
        main_password="main-pass",
        decoy_password="decoy-pass",
        input_path_decoy=decoy_data,
        mode="password",
    )

    main_out = tmp_path / "main_out.txt"
    decoy_out = tmp_path / "decoy_out.txt"
    api.decrypt_file(container, main_out, "main-pass", volume="main")
    api.decrypt_file(container, decoy_out, "decoy-pass", volume="decoy")

    assert main_out.read_text() == "MAIN"
    assert decoy_out.read_text() == "DECOY"

    with container.open("rb") as f:
        _header, descriptors, _hb = read_header_from_stream(f)

    assert len(descriptors) >= 2
    assert all(d.key_mode == descriptors[0].key_mode for d in descriptors)
    assert descriptors[0].key_mode == KEY_MODE_PASSWORD_ONLY


def test_encrypt_with_decoy_helper_roundtrip_pq(tmp_path: Path) -> None:
    if not pq.available():
        pytest.skip("oqs not available")

    main_data = tmp_path / "main.txt"
    decoy_data = tmp_path / "decoy.txt"
    main_data.write_text("MAIN")
    decoy_data.write_text("DECOY")

    container = tmp_path / "helper_pq.zil"

    api.encrypt_with_decoy(
        main_data,
        container,
        main_password="main-pass",
        decoy_password="decoy-pass",
        input_path_decoy=decoy_data,
        mode="pq_hybrid",
    )

    main_out = tmp_path / "main_out.txt"
    decoy_out = tmp_path / "decoy_out.txt"
    api.decrypt_file(container, main_out, "main-pass", volume="main")
    api.decrypt_file(container, decoy_out, "decoy-pass", volume="decoy")

    assert main_out.read_text() == "MAIN"
    assert decoy_out.read_text() == "DECOY"

    with container.open("rb") as f:
        _header, descriptors, _hb = read_header_from_stream(f)

    assert len(descriptors) >= 2
    assert all(d.key_mode == descriptors[0].key_mode for d in descriptors)
    assert descriptors[0].key_mode == KEY_MODE_PQ_HYBRID
