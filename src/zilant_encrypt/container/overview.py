"""Container overview helpers (layouts, descriptor selection)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from zilant_encrypt.container.format import (
    HEADER_V1_LEN,
    MAX_VOLUMES,
    ContainerHeader,
    VolumeDescriptor,
    read_header_from_stream,
)
from zilant_encrypt.crypto import pq
from zilant_encrypt.crypto.aead import TAG_LEN
from zilant_encrypt.errors import ContainerFormatError


@dataclass(frozen=True)
class VolumeLayout:
    descriptor: VolumeDescriptor
    ciphertext_len: int


@dataclass(frozen=True)
class ContainerOverview:
    header: ContainerHeader
    descriptors: list[VolumeDescriptor]
    header_bytes: bytes
    layouts: list[VolumeLayout]
    file_size: int
    pq_available: bool


def _ciphertext_length_for_descriptor(
    descriptor: VolumeDescriptor,
    all_descriptors: list[VolumeDescriptor],
    file_size: int,
) -> int:
    if descriptor.payload_offset <= 0 or descriptor.payload_length < 0:
        raise ContainerFormatError("invalid descriptor layout")

    if descriptor.payload_length:
        return descriptor.payload_length

    ordered = sorted(all_descriptors, key=lambda d: d.payload_offset)
    for idx, desc in enumerate(ordered):
        if desc.volume_index == descriptor.volume_index:
            next_offset = ordered[idx + 1].payload_offset if idx + 1 < len(ordered) else file_size
            length = next_offset - desc.payload_offset - TAG_LEN
            if length < 0:
                raise ContainerFormatError("invalid descriptor layout")
            return length

    raise ContainerFormatError("invalid descriptor layout")


def _compute_volume_layouts(
    descriptors: list[VolumeDescriptor], header_len: int, file_size: int
) -> list[VolumeLayout]:
    if len(descriptors) > MAX_VOLUMES:
        raise ContainerFormatError(f"Container has too many volumes (max {MAX_VOLUMES})")

    ordered = sorted(descriptors, key=lambda d: d.payload_offset)
    layouts: list[VolumeLayout] = []
    previous_end = header_len

    for idx, desc in enumerate(ordered):
        if desc.payload_offset < header_len:
            raise ContainerFormatError("Payload offset overlaps header")

        next_offset = ordered[idx + 1].payload_offset if idx + 1 < len(ordered) else file_size
        length = desc.payload_length or (next_offset - desc.payload_offset - TAG_LEN)
        if length < 0:
            raise ContainerFormatError("Invalid payload length")

        end = desc.payload_offset + length + TAG_LEN
        if end > file_size:
            raise ContainerFormatError("Payload exceeds container size")
        if desc.payload_offset < previous_end:
            raise ContainerFormatError("Volume payload ranges overlap")

        layouts.append(VolumeLayout(descriptor=desc, ciphertext_len=length))
        previous_end = end

    return layouts


def _load_overview(container_path: Path) -> ContainerOverview:
    container = Path(container_path)
    if not container.exists():
        raise FileNotFoundError(container)

    file_size = container.stat().st_size
    if file_size < HEADER_V1_LEN + TAG_LEN:
        raise ContainerFormatError("Container too small")

    with container.open("rb") as f:
        header, descriptors, header_bytes = read_header_from_stream(f)

    layouts = _compute_volume_layouts(descriptors, header.header_len, file_size)
    return ContainerOverview(
        header=header,
        descriptors=descriptors,
        header_bytes=header_bytes,
        layouts=layouts,
        file_size=file_size,
        pq_available=pq.available(),
    )


def _select_descriptors(descriptors: list[VolumeDescriptor], volume_selector: str) -> list[VolumeDescriptor]:
    if volume_selector == "all":
        return descriptors

    target_index = 0 if volume_selector == "main" else 1
    selected = [desc for desc in descriptors if desc.volume_index == target_index]
    if not selected:
        raise ContainerFormatError(f"Requested volume '{volume_selector}' is not present in the container")
    return selected


__all__ = [
    "ContainerOverview",
    "VolumeLayout",
    "_ciphertext_length_for_descriptor",
    "_compute_volume_layouts",
    "_load_overview",
    "_select_descriptors",
]
