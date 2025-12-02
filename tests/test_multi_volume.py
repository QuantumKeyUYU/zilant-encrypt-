from pathlib import Path

import pytest

from zilant_encrypt.container import api
import zilant_encrypt.container.format as fmt
from zilant_encrypt.container.format import (
    KEY_MODE_PASSWORD_ONLY,
    KEY_MODE_PQ_HYBRID,
    VolumeDescriptor,
    build_header,
    read_header_from_stream,
)
from zilant_encrypt.crypto import pq
from zilant_encrypt.crypto.kdf import recommended_params
from zilant_encrypt.errors import ContainerFormatError, IntegrityError, InvalidPassword, UnsupportedFeatureError


def test_main_and_decoy_roundtrip_password_only(tmp_path: Path) -> None:
    main_data = tmp_path / "main.txt"
    main_data.write_text("MAIN")

    decoy_data = tmp_path / "decoy.txt"
    decoy_data.write_text("DECOY")

    container = tmp_path / "vault.zil"

    api.encrypt_with_decoy(
        main_data,
        container,
        main_password="pass-main",
        decoy_password="pass-decoy",
        input_path_decoy=decoy_data,
        mode="password",
        overwrite=True,
    )

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


def test_decoy_requires_rebuild(tmp_path: Path) -> None:
    payload = tmp_path / "data.txt"
    payload.write_text("data")
    out_path = tmp_path / "new.zil"

    with pytest.raises(UnsupportedFeatureError):
        api.encrypt_file(payload, out_path, "pw", volume="decoy")

    api.encrypt_file(payload, out_path, "pw", volume="main")

    with pytest.raises(UnsupportedFeatureError):
        api.encrypt_file(payload, out_path, "pw2", volume="decoy")


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

    api.encrypt_with_decoy(
        main_data,
        container,
        main_password="pw-main",
        decoy_password="pw-decoy",
        input_path_decoy=decoy_data,
        mode="pq-hybrid",
        overwrite=True,
    )

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
        overwrite=True,
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
        overwrite=True,
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


def test_v3_metadata_layout_uniform_with_decoy(tmp_path: Path) -> None:
    main_data = tmp_path / "main.txt"
    decoy_data = tmp_path / "decoy.txt"
    main_data.write_text("MAIN")
    decoy_data.write_text("DECOY")

    container = tmp_path / "layout.zil"

    api.encrypt_with_decoy(
        main_data,
        container,
        main_password="main-pass",
        decoy_password="decoy-pass",
        input_path_decoy=decoy_data,
        mode="password",
        overwrite=True,
    )

    with container.open("rb") as f:
        _header, descriptors, header_bytes = read_header_from_stream(f)

    assert len(descriptors) == 2
    prefix = fmt._HEADER_STRUCT_V3_PREFIX.size
    meta0 = fmt._VOLUME_DESCRIPTOR_STRUCT.unpack(
        header_bytes[prefix : prefix + fmt._VOLUME_DESCRIPTOR_STRUCT.size]
    )[-1]
    meta1 = fmt._VOLUME_DESCRIPTOR_STRUCT.unpack(
        header_bytes[prefix + fmt._VOLUME_DESCRIPTOR_STRUCT.size : prefix + 2 * fmt._VOLUME_DESCRIPTOR_STRUCT.size]
    )[-1]
    assert meta0 == meta1

    assert descriptors[0].pq_ciphertext is not None and descriptors[1].pq_ciphertext is not None
    assert len(descriptors[0].pq_ciphertext) == len(descriptors[1].pq_ciphertext) > 0
    assert descriptors[0].pq_wrapped_secret is not None and descriptors[1].pq_wrapped_secret is not None
    assert len(descriptors[0].pq_wrapped_secret) == len(descriptors[1].pq_wrapped_secret) > 0

    if pq.available():
        pq_container = tmp_path / "layout_pq.zil"
        api.encrypt_with_decoy(
            main_data,
            pq_container,
            main_password="main-pass",
            decoy_password="decoy-pass",
            input_path_decoy=decoy_data,
            mode="pq-hybrid",
            overwrite=True,
        )
        with pq_container.open("rb") as f:
            _pq_header, pq_descriptors, pq_header_bytes = read_header_from_stream(f)

        pq_prefix = fmt._HEADER_STRUCT_V3_PREFIX.size
        pq_meta0 = fmt._VOLUME_DESCRIPTOR_STRUCT.unpack(
            pq_header_bytes[pq_prefix : pq_prefix + fmt._VOLUME_DESCRIPTOR_STRUCT.size]
        )[-1]
        pq_meta1 = fmt._VOLUME_DESCRIPTOR_STRUCT.unpack(
            pq_header_bytes[
                pq_prefix + fmt._VOLUME_DESCRIPTOR_STRUCT.size : pq_prefix + 2 * fmt._VOLUME_DESCRIPTOR_STRUCT.size
            ]
        )[-1]
        assert pq_meta0 == pq_meta1
        assert len(pq_descriptors[0].pq_ciphertext or b"") == len(pq_descriptors[1].pq_ciphertext or b"")
        assert len(pq_descriptors[0].pq_wrapped_secret or b"") == len(pq_descriptors[1].pq_wrapped_secret or b"")


def test_check_container_validates_each_volume(tmp_path: Path) -> None:
    main_data = tmp_path / "main.txt"
    decoy_data = tmp_path / "decoy.txt"
    main_data.write_text("MAIN")
    decoy_data.write_text("DECOY")

    container = tmp_path / "checked.zil"
    api.encrypt_with_decoy(
        main_data,
        container,
        main_password="main-pass",
        decoy_password="decoy-pass",
        input_path_decoy=decoy_data,
        mode="password",
        overwrite=True,
    )

    overview, validated_main = api.check_container(container, password="main-pass", mode="password", volume="main")
    assert overview.descriptors
    assert validated_main == [0]

    _overview2, validated_decoy = api.check_container(
        container, password="decoy-pass", mode="password", volume="decoy"
    )
    assert validated_decoy == [1]


def test_corrupted_header_bytes_fail_integrity(tmp_path: Path) -> None:
    payload = tmp_path / "data.txt"
    payload.write_text("secret")
    container = tmp_path / "vault.zil"
    api.encrypt_file(payload, container, "pw", volume="main")

    with container.open("rb") as f:
        _header, descriptors, header_bytes = read_header_from_stream(f)

    corrupted = tmp_path / "vault_corrupt.zil"
    data = bytearray(container.read_bytes())
    nonce = descriptors[0].nonce_aes_gcm
    nonce_offset = header_bytes.find(nonce)
    assert nonce_offset != -1
    data[nonce_offset] ^= 0x01
    corrupted.write_bytes(data)

    with pytest.raises(IntegrityError):
        api.decrypt_file(corrupted, tmp_path / "out.txt", "pw")


def test_container_rejects_excess_volumes(tmp_path: Path) -> None:
    params = recommended_params()
    salt = b"s" * 16
    nonce = b"n" * 12
    descriptor = VolumeDescriptor(
        volume_id=0,
        key_mode=KEY_MODE_PASSWORD_ONLY,
        flags=0,
        payload_offset=128,
        payload_length=32,
        salt_argon2=salt,
        argon_mem_cost=params.mem_cost_kib,
        argon_time_cost=params.time_cost,
        argon_parallelism=params.parallelism,
        nonce_aes_gcm=nonce,
        wrapped_key=b"k" * 16,
        wrapped_key_tag=b"t" * 16,
        reserved=bytes(28),
    )

    with pytest.raises(ContainerFormatError):
        build_header(
            key_mode=descriptor.key_mode,
            header_flags=descriptor.flags,
            salt_argon2=descriptor.salt_argon2,
            argon_mem_cost=descriptor.argon_mem_cost,
            argon_time_cost=descriptor.argon_time_cost,
            argon_parallelism=descriptor.argon_parallelism,
            nonce_aes_gcm=descriptor.nonce_aes_gcm,
            wrapped_key=descriptor.wrapped_key,
            wrapped_key_tag=descriptor.wrapped_key_tag,
            reserved=descriptor.reserved,
            version=3,
            volume_descriptors=[descriptor, descriptor, descriptor],
            common_meta={},
        )


def test_container_rejects_overlapping_volumes(tmp_path: Path) -> None:
    params = recommended_params()
    salt = b"s" * 16
    nonce = b"n" * 12
    base_descriptor = VolumeDescriptor(
        volume_id=0,
        key_mode=KEY_MODE_PASSWORD_ONLY,
        flags=0,
        payload_offset=256,
        payload_length=64,
        salt_argon2=salt,
        argon_mem_cost=params.mem_cost_kib,
        argon_time_cost=params.time_cost,
        argon_parallelism=params.parallelism,
        nonce_aes_gcm=nonce,
        wrapped_key=b"k" * 16,
        wrapped_key_tag=b"t" * 16,
        reserved=bytes(28),
    )

    overlap_descriptor = VolumeDescriptor(
        volume_id=1,
        key_mode=KEY_MODE_PASSWORD_ONLY,
        flags=0,
        payload_offset=base_descriptor.payload_offset + 10,
        payload_length=64,
        salt_argon2=salt,
        argon_mem_cost=params.mem_cost_kib,
        argon_time_cost=params.time_cost,
        argon_parallelism=params.parallelism,
        nonce_aes_gcm=nonce,
        wrapped_key=b"k" * 16,
        wrapped_key_tag=b"t" * 16,
        reserved=bytes(28),
    )

    with pytest.raises(ContainerFormatError):
        build_header(
            key_mode=base_descriptor.key_mode,
            header_flags=base_descriptor.flags,
            salt_argon2=base_descriptor.salt_argon2,
            argon_mem_cost=base_descriptor.argon_mem_cost,
            argon_time_cost=base_descriptor.argon_time_cost,
            argon_parallelism=base_descriptor.argon_parallelism,
            nonce_aes_gcm=base_descriptor.nonce_aes_gcm,
            wrapped_key=base_descriptor.wrapped_key,
            wrapped_key_tag=base_descriptor.wrapped_key_tag,
            reserved=base_descriptor.reserved,
            version=3,
            volume_descriptors=[base_descriptor, overlap_descriptor],
            common_meta={},
        )
