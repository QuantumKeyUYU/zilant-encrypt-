from pathlib import Path

from zilant_encrypt.container.api import encrypt_file
from zilant_encrypt.container.format import read_header_from_stream
from zilant_encrypt.crypto.kdf import RecommendedArgon2Params


def test_recommended_argon2_params_in_header(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    container = tmp_path / "sample.zil"
    encrypt_file(sample, container, password="pw")

    with container.open("rb") as f:
        header, _descriptors, _header_bytes = read_header_from_stream(f)
    assert header.argon_mem_cost == RecommendedArgon2Params.mem_cost_kib
    assert header.argon_time_cost == RecommendedArgon2Params.time_cost
    assert header.argon_parallelism == RecommendedArgon2Params.parallelism
