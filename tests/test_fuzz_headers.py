"""Property-based fuzz tests for container headers and payload metadata."""

from __future__ import annotations

import io

import pytest
from hypothesis import given, strategies as st

from zilant_encrypt.container.format import (
    MAGIC,
    MAX_HEADER_LEN,
    PAYLOAD_TAG_LEN,
    VERSION_V3,
    KEY_MODE_PASSWORD_ONLY,
    _HEADER_STRUCT_V3_PREFIX,
    _VOLUME_DESCRIPTOR_STRUCT,
    _VOLUME_META_V3_PASSWORD_STRUCT,
    SALT_LEN,
    NONCE_LEN,
    WRAPPED_KEY_MAX_LEN,
    WRAPPED_KEY_TAG_LEN,
    RESERVED_LEN,
    parse_header,
    read_header_from_stream,
)
from zilant_encrypt.errors import ContainerFormatError


@st.composite
def _v3_prefix_with_short_header(draw: st.DrawFn) -> bytes:
    volume_count = draw(st.integers(min_value=1, max_value=3))
    min_len = _HEADER_STRUCT_V3_PREFIX.size
    descriptor_table_len = _VOLUME_DESCRIPTOR_STRUCT.size * volume_count
    # Make header_len too short to contain the descriptor table fully.
    header_len = draw(st.integers(min_value=min_len, max_value=min_len + descriptor_table_len - 1))
    prefix = _HEADER_STRUCT_V3_PREFIX.pack(MAGIC, VERSION_V3, volume_count, header_len)
    # Provide exactly header_len bytes so parse_header reads a truncated descriptor table.
    filler_len = max(0, header_len - len(prefix))
    filler = draw(st.binary(min_size=filler_len, max_size=filler_len))
    return prefix + filler


@given(data=_v3_prefix_with_short_header())
def test_parse_header_rejects_truncated_v3_descriptor_table(data: bytes) -> None:
    """Any v3 header shorter than its descriptor table must raise a format error."""
    with pytest.raises(ContainerFormatError):
        parse_header(data)


@st.composite
def _v3_header_with_incomplete_metadata(draw: st.DrawFn) -> bytes:
    salt = draw(st.binary(min_size=SALT_LEN, max_size=SALT_LEN))
    nonce = draw(st.binary(min_size=NONCE_LEN, max_size=NONCE_LEN))
    wrapped_len = draw(st.integers(min_value=1, max_value=WRAPPED_KEY_MAX_LEN))
    wrapped_key = draw(st.binary(min_size=wrapped_len, max_size=wrapped_len))
    wrapped_padded = wrapped_key.ljust(WRAPPED_KEY_MAX_LEN, b"\x00")
    wrapped_tag = draw(st.binary(min_size=WRAPPED_KEY_TAG_LEN, max_size=WRAPPED_KEY_TAG_LEN))
    reserved = bytes(RESERVED_LEN)

    meta_blob = _VOLUME_META_V3_PASSWORD_STRUCT.pack(
        0,
        salt,
        1024,
        2,
        1,
        nonce,
        wrapped_len,
        wrapped_padded,
        wrapped_tag,
        reserved,
    )

    meta_len = len(meta_blob) + draw(st.integers(min_value=1, max_value=8))
    descriptor = _VOLUME_DESCRIPTOR_STRUCT.pack(
        0,
        KEY_MODE_PASSWORD_ONLY,
        0,
        _HEADER_STRUCT_V3_PREFIX.size + _VOLUME_DESCRIPTOR_STRUCT.size + meta_len,
        0,
        meta_len,
    )

    header_len = len(meta_blob) + len(descriptor) + _HEADER_STRUCT_V3_PREFIX.size
    prefix = _HEADER_STRUCT_V3_PREFIX.pack(MAGIC, VERSION_V3, 1, header_len)
    # Deliberately supply less metadata than the descriptor advertises.
    return b"".join([prefix, descriptor, meta_blob])


@given(data=_v3_header_with_incomplete_metadata())
def test_parse_header_rejects_mismatched_metadata_lengths(data: bytes) -> None:
    """Incorrect meta_len values must trigger ContainerFormatError during parsing."""
    with pytest.raises(ContainerFormatError):
        parse_header(data)


@st.composite
def _v3_header_with_overlapping_payloads(draw: st.DrawFn) -> bytes:
    def password_meta(volume_index: int) -> bytes:
        salt = draw(st.binary(min_size=SALT_LEN, max_size=SALT_LEN))
        nonce = draw(st.binary(min_size=NONCE_LEN, max_size=NONCE_LEN))
        wrapped_key = draw(st.binary(min_size=WRAPPED_KEY_MAX_LEN, max_size=WRAPPED_KEY_MAX_LEN))
        wrapped_tag = draw(st.binary(min_size=WRAPPED_KEY_TAG_LEN, max_size=WRAPPED_KEY_TAG_LEN))
        reserved = bytes(RESERVED_LEN)
        return _VOLUME_META_V3_PASSWORD_STRUCT.pack(
            0,
            salt,
            1024,
            2,
            1,
            nonce,
            WRAPPED_KEY_MAX_LEN,
            wrapped_key,
            wrapped_tag,
            reserved,
        )

    meta_first = password_meta(0)
    meta_second = password_meta(1)

    payload_start = _HEADER_STRUCT_V3_PREFIX.size + 2 * _VOLUME_DESCRIPTOR_STRUCT.size + len(meta_first) + len(meta_second)
    overlap_gap = draw(st.integers(min_value=1, max_value=PAYLOAD_TAG_LEN))

    first_descriptor = _VOLUME_DESCRIPTOR_STRUCT.pack(
        0,
        KEY_MODE_PASSWORD_ONLY,
        0,
        payload_start,
        draw(st.integers(min_value=0, max_value=32)),
        len(meta_first),
    )
    second_descriptor = _VOLUME_DESCRIPTOR_STRUCT.pack(
        1,
        KEY_MODE_PASSWORD_ONLY,
        0,
        payload_start + overlap_gap,
        draw(st.integers(min_value=0, max_value=32)),
        len(meta_second),
    )

    header_len = payload_start
    prefix = _HEADER_STRUCT_V3_PREFIX.pack(MAGIC, VERSION_V3, 2, header_len)
    return b"".join([prefix, first_descriptor, second_descriptor, meta_first, meta_second])


@given(data=_v3_header_with_overlapping_payloads())
def test_parse_header_rejects_overlapping_payloads(data: bytes) -> None:
    """Volume payload ranges that overlap must fail validation."""
    with pytest.raises(ContainerFormatError):
        parse_header(data)


@given(header_len=st.integers(min_value=MAX_HEADER_LEN + 1, max_value=MAX_HEADER_LEN * 2))
def test_read_header_from_stream_enforces_max_length(header_len: int) -> None:
    """read_header_from_stream should reject headers larger than MAX_HEADER_LEN."""
    prefix = _HEADER_STRUCT_V3_PREFIX.pack(MAGIC, VERSION_V3, 1, header_len)
    stream = io.BytesIO(prefix)

    with pytest.raises(ContainerFormatError):
        read_header_from_stream(stream)
