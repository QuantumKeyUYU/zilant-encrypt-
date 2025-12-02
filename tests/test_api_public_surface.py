from pathlib import Path

import pytest

from zilant_encrypt import __version__
from zilant_encrypt.container import (
    ARGON_MEM_MAX_KIB,
    ARGON_MEM_MIN_KIB,
    ARGON_PARALLELISM_MAX,
    ARGON_PARALLELISM_MIN,
    ARGON_TIME_MAX,
    ARGON_TIME_MIN,
    Argon2Params,
    check_container,
    decrypt_auto_volume,
    encrypt_file,
    normalize_mode,
    resolve_argon_params,
)


def test_public_constants_and_normalization() -> None:
    assert __version__
    assert ARGON_MEM_MIN_KIB < ARGON_MEM_MAX_KIB
    assert ARGON_TIME_MIN <= ARGON_TIME_MAX
    assert ARGON_PARALLELISM_MIN <= ARGON_PARALLELISM_MAX
    assert normalize_mode("password") == "password"
    assert normalize_mode("pq_hybrid") == "pq-hybrid"

    params = resolve_argon_params(
        base=Argon2Params(mem_cost_kib=ARGON_MEM_MIN_KIB, time_cost=ARGON_TIME_MIN, parallelism=ARGON_PARALLELISM_MIN)
    )
    assert params.mem_cost_kib >= ARGON_MEM_MIN_KIB


def test_round_trip_public_api(tmp_path: Path) -> None:
    source = tmp_path / "input.txt"
    source.write_text("secret message")
    container = tmp_path / "container.zil"
    output = tmp_path / "output.txt"

    encrypt_file(source, container, "pw")

    overview, validated = check_container(container, password="pw", volume_selector="main")
    assert overview.descriptors[0].volume_index == 0
    assert validated == [0]

    volume_index, label = decrypt_auto_volume(container, output, password="pw")
    assert volume_index == 0
    assert label == "main"
    assert output.read_text() == "secret message"
