import os

from zilant_encrypt.container.format import (
    KEY_MODE_PASSWORD_ONLY,
    RESERVED_LEN,
    VERSION_V3,
    VolumeDescriptor,
    build_header_v3,
    parse_header,
)


def test_build_and_parse_v3_header() -> None:
    main_descriptor = VolumeDescriptor(
        volume_id=0,
        key_mode=KEY_MODE_PASSWORD_ONLY,
        flags=0,
        payload_offset=0,
        payload_length=0,
        salt_argon2=os.urandom(16),
        argon_mem_cost=1024,
        argon_time_cost=2,
        argon_parallelism=1,
        nonce_aes_gcm=os.urandom(12),
        wrapped_key=os.urandom(32),
        wrapped_key_tag=os.urandom(16),
        reserved=bytes(RESERVED_LEN),
    )
    extra_descriptor = VolumeDescriptor(
        volume_id=1,
        key_mode=KEY_MODE_PASSWORD_ONLY,
        flags=0,
        payload_offset=4096,
        payload_length=0,
        salt_argon2=os.urandom(16),
        argon_mem_cost=2048,
        argon_time_cost=3,
        argon_parallelism=2,
        nonce_aes_gcm=os.urandom(12),
        wrapped_key=os.urandom(16),
        wrapped_key_tag=os.urandom(16),
        reserved=bytes(RESERVED_LEN),
    )

    header_bytes = build_header_v3([main_descriptor, extra_descriptor], {})

    header, descriptors = parse_header(header_bytes)

    assert header.version == VERSION_V3
    assert len(descriptors) == 2
    assert descriptors[0].volume_id == 0
    assert descriptors[0].payload_offset == len(header_bytes)
    assert descriptors[1].volume_id == 1
    assert descriptors[1].payload_offset == 4096
    assert descriptors[1].argon_mem_cost == 2048
