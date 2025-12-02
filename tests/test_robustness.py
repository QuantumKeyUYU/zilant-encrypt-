from pathlib import Path

import pytest

import zilant_encrypt.container.format as fmt
from zilant_encrypt.container import api
from zilant_encrypt.crypto import pq
from zilant_encrypt.crypto.aead import TAG_LEN
from zilant_encrypt.errors import ContainerFormatError, IntegrityError, PqSupportError


def _flip_header_byte(container: Path, offset: int) -> Path:
    data = bytearray(container.read_bytes())
    data[offset] ^= 0x01
    corrupted = container.with_name(container.name + ".flip")
    corrupted.write_bytes(data)
    return corrupted


def _truncate_bytes(container: Path, keep: int) -> Path:
    truncated = container.with_name(container.name + ".trunc")
    truncated.write_bytes(container.read_bytes()[:keep])
    return truncated


def _mutate_descriptor(
    container: Path, *, payload_offset: int | None = None, payload_length: int | None = None
) -> Path:
    header, _descriptors, header_bytes = fmt.read_header_from_stream(container.open("rb"))
    descriptor_table_offset = fmt._HEADER_STRUCT_V3_PREFIX.size
    entry_size = fmt._VOLUME_DESCRIPTOR_STRUCT.size
    entry = bytearray(header_bytes[descriptor_table_offset : descriptor_table_offset + entry_size])
    (volume_id, key_mode, flags, old_offset, old_length, meta_len) = fmt._VOLUME_DESCRIPTOR_STRUCT.unpack(entry)
    new_entry = fmt._VOLUME_DESCRIPTOR_STRUCT.pack(
        volume_id,
        key_mode,
        flags,
        payload_offset if payload_offset is not None else old_offset,
        payload_length if payload_length is not None else old_length,
        meta_len,
    )
    mutated_header = bytearray(header_bytes)
    mutated_header[descriptor_table_offset : descriptor_table_offset + entry_size] = new_entry
    mutated = container.with_name(container.name + ".mut")
    mutated.write_bytes(bytes(mutated_header) + container.read_bytes()[len(header_bytes) :])
    return mutated


def test_api_rejects_tampered_header_aad(tmp_path: Path) -> None:
    source = tmp_path / "data.bin"
    source.write_bytes(b"A" * 1024)
    container = tmp_path / "container.zil"
    api.encrypt_file(source, container, "pw")

    header, _descriptors, header_bytes = fmt.read_header_from_stream(container.open("rb"))
    flip_offset = header.header_len - 8

    # Flip a byte in the header (but keep a valid header structure).
    corrupted = _flip_header_byte(container, flip_offset)

    with pytest.raises(IntegrityError):
        api.decrypt_file(corrupted, tmp_path / "out.bin", "pw")


def test_api_rejects_missing_tag_and_payload_truncation(tmp_path: Path) -> None:
    source = tmp_path / "data.bin"
    source.write_bytes(b"B" * 2048)
    container = tmp_path / "container.zil"
    api.encrypt_file(source, container, "pw")

    missing_tag = _truncate_bytes(container, container.stat().st_size - 1)
    with pytest.raises(ContainerFormatError):
        api.decrypt_file(missing_tag, tmp_path / "out.bin", "pw")

    # Remove some ciphertext but leave the final tag in place.
    truncated_payload = _truncate_bytes(container, container.stat().st_size - (TAG_LEN + 32))
    truncated_payload.write_bytes(truncated_payload.read_bytes() + container.read_bytes()[-TAG_LEN:])

    with pytest.raises(ContainerFormatError):
        api.decrypt_file(truncated_payload, tmp_path / "out2.bin", "pw")


def test_invalid_descriptor_offsets_fail_fast(tmp_path: Path) -> None:
    source = tmp_path / "data.bin"
    source.write_bytes(b"C" * 512)
    container = tmp_path / "container.zil"
    api.encrypt_file(source, container, "pw")

    broken = _mutate_descriptor(container, payload_offset=0)

    with pytest.raises(ContainerFormatError):
        fmt.read_header_from_stream(broken.open("rb"))
    with pytest.raises(ContainerFormatError):
        api.check_container(broken, password=None)
    with pytest.raises(ContainerFormatError):
        api.decrypt_file(broken, tmp_path / "out.bin", "pw")


def test_overlapping_layouts_detected_even_with_decoy(tmp_path: Path) -> None:
    main = tmp_path / "main.bin"
    decoy = tmp_path / "decoy.bin"
    main.write_bytes(b"M" * 256)
    decoy.write_bytes(b"D" * 256)
    container = tmp_path / "double.zil"
    api.encrypt_with_decoy(main, container, main_password="pw-main", decoy_password="pw-decoy")

    header, _desc, _header_bytes = fmt.read_header_from_stream(container.open("rb"))
    first_len = _desc[0].payload_length
    overlapping = _mutate_descriptor(
        container,
        payload_offset=header.header_len + first_len // 2,
    )

    with pytest.raises(ContainerFormatError):
        api.check_container(overlapping, password=None)
    with pytest.raises(ContainerFormatError):
        api.decrypt_auto_volume(overlapping, tmp_path / "out.bin", password="pw-main")


@pytest.mark.skipif(not pq.available(), reason="oqs not available")
def test_pq_metadata_corruption_detection(tmp_path: Path) -> None:
    source = tmp_path / "data.bin"
    source.write_bytes(b"PQ" * 512)
    container = tmp_path / "pq.zil"
    api.encrypt_file(source, container, "pw", mode="pq-hybrid")

    header, descriptors, header_bytes = fmt.read_header_from_stream(container.open("rb"))
    assert descriptors

    descriptor_table_offset = fmt._HEADER_STRUCT_V3_PREFIX.size
    entry_size = fmt._VOLUME_DESCRIPTOR_STRUCT.size
    first_entry = bytearray(header_bytes[descriptor_table_offset : descriptor_table_offset + entry_size])

    # Shrink the metadata length to truncate the pq_wrapped_secret_tag.
    (volume_id, key_mode, flags, payload_offset, payload_length, meta_len) = fmt._VOLUME_DESCRIPTOR_STRUCT.unpack(first_entry)
    bad_meta_len = max(0, meta_len - 4)
    first_entry = fmt._VOLUME_DESCRIPTOR_STRUCT.pack(volume_id, key_mode, flags, payload_offset, payload_length, bad_meta_len)

    corrupted_header = bytearray(header_bytes)
    corrupted_header[descriptor_table_offset : descriptor_table_offset + entry_size] = first_entry
    corrupted = container.with_name(container.name + ".pqbad")
    corrupted.write_bytes(bytes(corrupted_header) + container.read_bytes()[len(header_bytes) :])

    with pytest.raises(ContainerFormatError):
        api.decrypt_file(corrupted, tmp_path / "out.bin", "pw", mode="pq-hybrid")

    # Tamper with reserved bytes in the PQ metadata blob.
    # meta_start = descriptor_table_offset + entry_size  <-- Removed unused variable
    meta_end = header.header_len
    tampered_header = bytearray(header_bytes)
    tampered_header[meta_end - 1] ^= 0xFF
    tampered = container.with_name(container.name + ".pqtamper")
    tampered.write_bytes(bytes(tampered_header) + container.read_bytes()[len(header_bytes) :])

    with pytest.raises(ContainerFormatError):
        fmt.read_header_from_stream(tampered.open("rb"))


def test_pq_container_without_support_reports_missing_engine(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = tmp_path / "data.bin"
    source.write_bytes(b"PQ" * 10)
    container = tmp_path / "pq_missing.zil"

    monkeypatch.setattr("zilant_encrypt.crypto.pq.available", lambda: False)
    with pytest.raises(PqSupportError):
        api.encrypt_file(source, container, "pw", mode="pq-hybrid")

    # Build a password-only container and then mark the descriptor as PQ to trigger the support error on decrypt.
    api.encrypt_file(source, container, "pw")
    _header, _descriptors, header_bytes = fmt.read_header_from_stream(container.open("rb"))
    descriptor_table_offset = fmt._HEADER_STRUCT_V3_PREFIX.size
    first_entry = bytearray(header_bytes[descriptor_table_offset : descriptor_table_offset + fmt._VOLUME_DESCRIPTOR_STRUCT.size])
    (volume_id, _key_mode, flags, payload_offset, payload_length, meta_len) = fmt._VOLUME_DESCRIPTOR_STRUCT.unpack(first_entry)
    pq_entry = fmt._VOLUME_DESCRIPTOR_STRUCT.pack(
        volume_id,
        fmt.KEY_MODE_PQ_HYBRID,
        flags,
        payload_offset,
        payload_length,
        meta_len,
    )
    mutated_header = bytearray(header_bytes)
    mutated_header[descriptor_table_offset : descriptor_table_offset + fmt._VOLUME_DESCRIPTOR_STRUCT.size] = pq_entry
    with container.open("wb") as f:
        f.write(bytes(mutated_header) + container.read_bytes()[len(header_bytes) :])

    with pytest.raises(PqSupportError):
        api.decrypt_auto_volume(container, tmp_path / "out.bin", password="pw", mode="pq-hybrid")
