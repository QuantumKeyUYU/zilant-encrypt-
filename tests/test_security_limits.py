import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from zilant_encrypt.container import api, format as fmt
from zilant_encrypt.errors import ContainerFormatError


def test_read_header_rejects_oversized_len() -> None:
    header_len = fmt.MAX_HEADER_LEN + 1
    prefix = fmt._HEADER_STRUCT_V3_PREFIX.pack(fmt.MAGIC, fmt.VERSION_V3, 1, header_len)
    stream = BytesIO(prefix)

    with pytest.raises(ContainerFormatError):
        fmt.read_header_from_stream(stream)


def test_payload_metadata_len_limit(tmp_path: Path) -> None:
    out_path = tmp_path / "file.bin"
    writer = api._PayloadWriter(out_path)

    oversized = api.MAX_PAYLOAD_META_LEN + 1
    payload_header = (
        api.PAYLOAD_MAGIC
        + bytes([api.PAYLOAD_VERSION])
        + oversized.to_bytes(api.PAYLOAD_META_LEN_SIZE, "little")
    )

    with pytest.raises(ContainerFormatError):
        writer.feed(payload_header)


def test_directory_payload_blocks_zip_slip(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    writer = api._PayloadWriter(out_dir)

    header = api._build_payload_header(api.PayloadMeta(kind="directory", name="dir"))
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        archive.writestr("../../evil.txt", "bad")

    writer.feed(header + zip_buffer.getvalue())

    with pytest.raises(ContainerFormatError):
        writer.finalize()

    assert not (out_dir / "evil.txt").exists()
