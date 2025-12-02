from pathlib import Path

import pytest
from click.testing import CliRunner

from zilant_encrypt.cli import (
    EXIT_CORRUPT,
    EXIT_CRYPTO,
    EXIT_FS,
    EXIT_PQ_UNSUPPORTED,
    EXIT_SUCCESS,
    EXIT_USAGE,
    cli,
)
from zilant_encrypt.container import api
import zilant_encrypt.container.format as fmt
from zilant_encrypt.crypto import pq
from zilant_encrypt.crypto.aead import TAG_LEN
from zilant_encrypt.crypto.kdf import Argon2Params, recommended_params


def test_cli_encrypt_decrypt_file(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "source.txt"
    source.write_text("hello")

    container = tmp_path / "data.zil"
    output = tmp_path / "restored.txt"

    result = runner.invoke(cli, ["encrypt", str(source), str(container), "--password", "pw"])
    assert result.exit_code == EXIT_SUCCESS

    result = runner.invoke(cli, ["decrypt", str(container), str(output), "--password", "pw"])
    assert result.exit_code == EXIT_SUCCESS
    assert output.read_text() == "hello"


def test_cli_encrypt_decrypt_directory(tmp_path: Path) -> None:
    runner = CliRunner()
    folder = tmp_path / "папка"
    folder.mkdir()
    (folder / "файл.txt").write_text("content")

    container = tmp_path / "folder.zil"
    restored = tmp_path / "restored"

    result = runner.invoke(cli, ["encrypt", str(folder), str(container), "--password", "pw"])
    assert result.exit_code == EXIT_SUCCESS

    result = runner.invoke(
        cli,
        ["decrypt", str(container), str(restored), "--password", "pw", "--overwrite"],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert (restored / "файл.txt").read_text() == "content"


def test_cli_encrypt_accepts_argon_overrides(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "argon.bin"
    source.write_bytes(b"A" * 64)
    container = tmp_path / "argon.zil"

    mem_kib = 96 * 1024
    result = runner.invoke(
        cli,
        [
            "encrypt",
            str(source),
            str(container),
            "--password",
            "pw",
            "--argon-mem-kib",
            str(mem_kib),
            "--argon-time",
            "2",
            "--argon-parallelism",
            "2",
        ],
    )
    assert result.exit_code == EXIT_SUCCESS

    _header, descriptors, _bytes = fmt.read_header_from_stream(container.open("rb"))
    assert descriptors[0].argon_mem_cost == mem_kib
    assert descriptors[0].argon_time_cost == 2
    assert descriptors[0].argon_parallelism == 2


def test_cli_rejects_invalid_argon_overrides(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "argon.bin"
    source.write_bytes(b"A" * 64)
    container = tmp_path / "argon_bad.zil"

    result = runner.invoke(
        cli,
        [
            "encrypt",
            str(source),
            str(container),
            "--password",
            "pw",
            "--argon-mem-kib",
            "1024",
        ],
    )
    assert result.exit_code == EXIT_USAGE


def test_cli_missing_input(tmp_path: Path) -> None:
    runner = CliRunner()
    missing = tmp_path / "nope.bin"
    container = tmp_path / "out.zil"

    result = runner.invoke(cli, ["encrypt", str(missing), str(container), "--password", "pw"])
    assert result.exit_code == EXIT_FS


def test_cli_decrypt_random_file(tmp_path: Path) -> None:
    runner = CliRunner()
    random_file = tmp_path / "random.bin"
    random_file.write_text("not a container")

    output = tmp_path / "out.bin"
    result = runner.invoke(cli, ["decrypt", str(random_file), str(output), "--password", "pw"])
    assert result.exit_code == EXIT_CORRUPT


def test_cli_encrypt_decrypt_decoy(tmp_path: Path) -> None:
    runner = CliRunner()
    main_src = tmp_path / "main.txt"
    decoy_src = tmp_path / "decoy.txt"
    main_src.write_text("MAIN")
    decoy_src.write_text("DECOY")

    container = tmp_path / "double.zil"

    result = runner.invoke(
        cli,
        [
            "encrypt",
            str(main_src),
            str(container),
            "--password",
            "pw-main",
            "--decoy-password",
            "pw-decoy",
            "--decoy-input",
            str(decoy_src),
        ],
    )
    assert result.exit_code == EXIT_SUCCESS

    main_out = tmp_path / "main_out.txt"
    decoy_out = tmp_path / "decoy_out.txt"

    result = runner.invoke(
        cli,
        ["decrypt", str(container), str(main_out), "--password", "pw-main", "--volume", "main"],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert main_out.read_text() == "MAIN"

    result = runner.invoke(
        cli,
        ["decrypt", str(container), str(decoy_out), "--password", "pw-decoy", "--volume", "decoy"],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert decoy_out.read_text() == "DECOY"


def test_cli_encrypt_with_decoy_and_auto_decrypt_main(tmp_path: Path) -> None:
    runner = CliRunner()
    main_src = tmp_path / "main.txt"
    decoy_src = tmp_path / "decoy.txt"
    main_src.write_text("MAIN")
    decoy_src.write_text("DECOY")

    container = tmp_path / "combo.zil"
    result = runner.invoke(
        cli,
        [
            "encrypt",
            str(main_src),
            str(container),
            "--password",
            "pw-main",
            "--decoy-password",
            "pw-decoy",
            "--decoy-input",
            str(decoy_src),
        ],
    )
    assert result.exit_code == EXIT_SUCCESS

    main_out = tmp_path / "main_out.txt"
    result = runner.invoke(
        cli,
        ["decrypt", str(container), str(main_out), "--password", "pw-main"],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert main_out.read_text() == "MAIN"


def test_cli_encrypt_with_decoy_and_auto_decrypt_decoy(tmp_path: Path) -> None:
    runner = CliRunner()
    main_src = tmp_path / "main.txt"
    decoy_src = tmp_path / "decoy.txt"
    main_src.write_text("MAIN")
    decoy_src.write_text("DECOY")

    container = tmp_path / "combo2.zil"
    assert (
        runner.invoke(
            cli,
            [
                "encrypt",
                str(main_src),
                str(container),
                "--password",
                "pw-main",
                "--decoy-password",
                "pw-decoy",
                "--decoy-input",
                str(decoy_src),
            ],
        ).exit_code
        == EXIT_SUCCESS
    )

    decoy_out = tmp_path / "decoy_out.txt"
    result = runner.invoke(
        cli,
        ["decrypt", str(container), str(decoy_out), "--password", "pw-decoy"],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert decoy_out.read_text() == "DECOY"
    assert "decoy volume" not in result.output.lower()


def test_cli_auto_decrypt_invalid_password(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "src.txt"
    decoy_src = tmp_path / "decoy.txt"
    source.write_text("MAIN")
    decoy_src.write_text("DECOY")
    container = tmp_path / "invalid_combo.zil"

    assert (
        runner.invoke(
            cli,
            [
                "encrypt",
                str(source),
                str(container),
                "--password",
                "pw-main",
                "--decoy-password",
                "pw-decoy",
                "--decoy-input",
                str(decoy_src),
            ],
        ).exit_code
        == EXIT_SUCCESS
    )

    result = runner.invoke(cli, ["decrypt", str(container), "--password", "wrong"])
    assert result.exit_code == EXIT_CRYPTO
    assert "Invalid password or key" in result.output


def test_cli_pq_mode_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "source.txt"
    source.write_text("hello")

    monkeypatch.setattr("zilant_encrypt.crypto.pq.available", lambda: False)
    result = runner.invoke(
        cli,
        ["encrypt", str(source), str(tmp_path / "out.zil"), "--password", "pw", "--mode", "pq-hybrid"],
    )
    assert result.exit_code == EXIT_PQ_UNSUPPORTED


def test_cli_prevents_mode_mismatch(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "src.txt"
    source.write_text("hello")
    container = tmp_path / "out.zil"

    result = runner.invoke(cli, ["encrypt", str(source), str(container), "--password", "pw"])
    assert result.exit_code == EXIT_SUCCESS

    result = runner.invoke(
        cli,
        [
            "encrypt",
            str(source),
            str(container),
            "--password",
            "pw",
            "--mode",
            "pq-hybrid",
            "--volume",
            "decoy",
        ],
    )
    assert result.exit_code != EXIT_SUCCESS


def test_cli_encrypt_decrypt_pq_with_volumes(tmp_path: Path) -> None:
    if not pq.available():
        pytest.skip("oqs not available")

    runner = CliRunner()
    main_src = tmp_path / "main.txt"
    decoy_src = tmp_path / "decoy.txt"
    main_src.write_text("MAIN")
    decoy_src.write_text("DECOY")
    container = tmp_path / "pq_cli.zil"

    result = runner.invoke(
        cli,
        [
            "encrypt",
            str(main_src),
            str(container),
            "--password",
            "pw-main",
            "--mode",
            "pq-hybrid",
            "--volume",
            "main",
        ],
    )
    assert result.exit_code == EXIT_SUCCESS

    result = runner.invoke(
        cli,
        [
            "encrypt",
            str(decoy_src),
            str(container),
            "--password",
            "pw-decoy",
            "--mode",
            "pq-hybrid",
            "--volume",
            "decoy",
        ],
    )
    assert result.exit_code == EXIT_SUCCESS

    main_out = tmp_path / "main_out.txt"
    decoy_out = tmp_path / "decoy_out.txt"

    result = runner.invoke(
        cli,
        [
            "decrypt",
            str(container),
            str(main_out),
            "--password",
            "pw-main",
            "--mode",
            "pq-hybrid",
            "--volume",
            "main",
        ],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert main_out.read_text() == "MAIN"

    result = runner.invoke(
        cli,
        [
            "decrypt",
            str(container),
            str(decoy_out),
            "--password",
            "pw-decoy",
            "--mode",
            "pq-hybrid",
            "--volume",
            "decoy",
        ],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert decoy_out.read_text() == "DECOY"


def test_cli_encrypt_with_decoy_pq_auto_decrypt_main(tmp_path: Path) -> None:
    if not pq.available():
        pytest.skip("oqs not available")

    runner = CliRunner()
    main_src = tmp_path / "main.txt"
    decoy_src = tmp_path / "decoy.txt"
    main_src.write_text("MAIN")
    decoy_src.write_text("DECOY")

    container = tmp_path / "pq_combo.zil"
    assert (
        runner.invoke(
            cli,
            [
                "encrypt",
                str(main_src),
                str(container),
                "--password",
                "pw-main",
                "--decoy-password",
                "pw-decoy",
                "--decoy-input",
                str(decoy_src),
                "--mode",
                "pq-hybrid",
            ],
        ).exit_code
        == EXIT_SUCCESS
    )

    main_out = tmp_path / "main_out.txt"
    result = runner.invoke(
        cli,
        ["decrypt", str(container), str(main_out), "--password", "pw-main", "--mode", "pq-hybrid"],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert main_out.read_text() == "MAIN"


def test_cli_encrypt_with_decoy_pq_auto_decrypt_decoy(tmp_path: Path) -> None:
    if not pq.available():
        pytest.skip("oqs not available")

    runner = CliRunner()
    main_src = tmp_path / "main.txt"
    decoy_src = tmp_path / "decoy.txt"
    main_src.write_text("MAIN")
    decoy_src.write_text("DECOY")

    container = tmp_path / "pq_combo2.zil"
    assert (
        runner.invoke(
            cli,
            [
                "encrypt",
                str(main_src),
                str(container),
                "--password",
                "pw-main",
                "--decoy-password",
                "pw-decoy",
                "--decoy-input",
                str(decoy_src),
                "--mode",
                "pq-hybrid",
            ],
        ).exit_code
        == EXIT_SUCCESS
    )

    decoy_out = tmp_path / "decoy_out.txt"
    result = runner.invoke(
        cli,
        ["decrypt", str(container), str(decoy_out), "--password", "pw-decoy", "--mode", "pq-hybrid"],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert decoy_out.read_text() == "DECOY"


def test_cli_info_outputs_modes(tmp_path: Path) -> None:
    runner = CliRunner()
    main_src = tmp_path / "main.txt"
    decoy_src = tmp_path / "decoy.txt"
    main_src.write_text("MAIN")
    decoy_src.write_text("DECOY")
    container = tmp_path / "info.zil"

    assert (
        runner.invoke(
            cli,
            [
                "encrypt",
                str(main_src),
                str(container),
                "--password",
                "pw-main",
                "--decoy-password",
                "pw-decoy",
                "--decoy-input",
                str(decoy_src),
            ],
        ).exit_code
        == EXIT_SUCCESS
    )

    result = runner.invoke(cli, ["info", str(container)])
    assert result.exit_code == EXIT_SUCCESS
    assert "password-only" in result.output
    assert "decoy" not in result.output.lower()

    verbose = runner.invoke(cli, ["info", str(container), "--volumes"])
    assert verbose.exit_code == EXIT_SUCCESS
    assert "volume main" in verbose.output
    assert "additional volumes may be present" in verbose.output


def test_cli_info_outputs_pq_mode(tmp_path: Path) -> None:
    if not pq.available():
        pytest.skip("oqs not available")

    runner = CliRunner()
    source = tmp_path / "source.txt"
    source.write_text("hello")
    container = tmp_path / "pq_info.zil"

    assert (
        runner.invoke(
            cli,
            [
                "encrypt",
                str(source),
                str(container),
                "--password",
                "pw",
                "--mode",
                "pq-hybrid",
            ],
        ).exit_code
        == EXIT_SUCCESS
    )

    result = runner.invoke(cli, ["info", str(container)])
    assert "pq-hybrid" in result.output


def test_cli_info_summarizes_standard_container(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "info.txt"
    source.write_text("hello")
    container = tmp_path / "info.zil"

    assert runner.invoke(cli, ["encrypt", str(source), str(container), "--password", "pw"]).exit_code == EXIT_SUCCESS

    result = runner.invoke(cli, ["info", str(container)])
    assert result.exit_code == EXIT_SUCCESS
    assert "1 (outer only)" in result.output


def test_cli_info_handles_decoy_passwords(tmp_path: Path) -> None:
    runner = CliRunner()
    main_src = tmp_path / "main.txt"
    decoy_src = tmp_path / "decoy.txt"
    main_src.write_text("MAIN")
    decoy_src.write_text("DECOY")
    container = tmp_path / "decoy_info.zil"

    assert (
        runner.invoke(
            cli,
            [
                "encrypt",
                str(main_src),
                str(container),
                "--password",
                "pw-main",
                "--decoy-password",
                "pw-decoy",
                "--decoy-input",
                str(decoy_src),
            ],
        ).exit_code
        == EXIT_SUCCESS
    )

    neutral = runner.invoke(cli, ["info", str(container)])
    assert neutral.exit_code == EXIT_SUCCESS
    assert "additional volumes may be present" in neutral.output

    main_view = runner.invoke(cli, ["info", str(container), "--password", "pw-main", "--volumes"])
    assert main_view.exit_code == EXIT_SUCCESS
    assert "password matched: main" in main_view.output
    assert "volume decoy (locked)" in main_view.output

    decoy_view = runner.invoke(cli, ["info", str(container), "--password", "pw-decoy", "--volumes"])
    assert decoy_view.exit_code == EXIT_SUCCESS
    assert "password matched: decoy" in decoy_view.output
    assert "volume decoy (authenticated)" in decoy_view.output


def test_cli_info_reports_corruption(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "data.txt"
    source.write_text("hello")
    container = tmp_path / "corrupt_info.zil"

    assert runner.invoke(cli, ["encrypt", str(source), str(container), "--password", "pw"]).exit_code == EXIT_SUCCESS

    corrupted = bytearray(container.read_bytes())
    corrupted[5] ^= 0xFF
    broken = tmp_path / "broken.zil"
    broken.write_bytes(bytes(corrupted))

    result = runner.invoke(cli, ["info", str(broken)])
    assert result.exit_code == EXIT_CORRUPT
    assert "corrupted or not supported" in result.output


def _build_forced_header(
    monkeypatch: pytest.MonkeyPatch, descriptors: list[fmt.VolumeDescriptor]
) -> bytes:
    monkeypatch.setattr(fmt, "_validate_volume_layout", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(fmt, "MAX_VOLUMES", max(len(descriptors), fmt.MAX_VOLUMES))
    first = descriptors[0]
    return fmt.build_header(
        key_mode=first.key_mode,
        header_flags=first.flags,
        salt_argon2=first.salt_argon2,
        argon_mem_cost=first.argon_mem_cost,
        argon_time_cost=first.argon_time_cost,
        argon_parallelism=first.argon_parallelism,
        nonce_aes_gcm=first.nonce_aes_gcm,
        wrapped_key=first.wrapped_key,
        wrapped_key_tag=first.wrapped_key_tag,
        reserved=first.reserved,
        version=3,
        volume_descriptors=descriptors,
        common_meta={},
    )


def _descriptor(volume_id: int, offset: int, payload_length: int) -> fmt.VolumeDescriptor:
    params = recommended_params()
    salt = bytes([volume_id + 1]) * 16
    nonce = bytes([volume_id + 2]) * 12
    return fmt.VolumeDescriptor(
        volume_id=volume_id,
        key_mode=fmt.KEY_MODE_PASSWORD_ONLY,
        flags=0,
        payload_offset=offset,
        payload_length=payload_length,
        salt_argon2=salt,
        argon_mem_cost=params.mem_cost_kib,
        argon_time_cost=params.time_cost,
        argon_parallelism=params.parallelism,
        nonce_aes_gcm=nonce,
        wrapped_key=b"k" * 16,
        wrapped_key_tag=b"t" * 16,
        reserved=bytes(28),
    )


def test_cli_check_single_volume_success(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "source.txt"
    source.write_text("hello")
    container = tmp_path / "data.zil"
    assert runner.invoke(cli, ["encrypt", str(source), str(container), "--password", "pw"]).exit_code == EXIT_SUCCESS

    result = runner.invoke(
        cli,
        ["check", str(container), "--password", "pw", "--mode", "password", "--volume", "main"],
    )
    assert result.exit_code == EXIT_SUCCESS
    assert "Integrity verified" in result.output


def test_cli_check_skips_crypto_when_password_missing(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "src.txt"
    source.write_text("hello")
    container = tmp_path / "struct_only.zil"
    assert runner.invoke(cli, ["encrypt", str(source), str(container), "--password", "pw"]).exit_code == EXIT_SUCCESS

    result = runner.invoke(cli, ["check", str(container)])
    assert result.exit_code == EXIT_SUCCESS
    assert "Cryptographic tag verification skipped" in result.output


def test_cli_check_detects_corrupted_payload(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "src.txt"
    source.write_text("hello")
    container = tmp_path / "corrupt.zil"
    assert runner.invoke(cli, ["encrypt", str(source), str(container), "--password", "pw"]).exit_code == EXIT_SUCCESS

    corrupted = tmp_path / "corrupt_copy.zil"
    data = bytearray(container.read_bytes())
    data[-1] ^= 0x01
    corrupted.write_bytes(data)

    result = runner.invoke(cli, ["check", str(corrupted), "--password", "pw", "--mode", "password"])
    assert result.exit_code == EXIT_CORRUPT
    assert "corrupted or not supported" in result.output

    structural = runner.invoke(cli, ["check", str(corrupted)])
    assert structural.exit_code == EXIT_SUCCESS
    assert "Cryptographic tag verification skipped" in structural.output


def test_cli_check_truncated_structural_fails(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "src2.txt"
    source.write_text("hello")
    container = tmp_path / "trunc_struct.zil"

    assert runner.invoke(cli, ["encrypt", str(source), str(container), "--password", "pw"]).exit_code == EXIT_SUCCESS

    truncated = tmp_path / "trunc_struct_copy.zil"
    truncated.write_bytes(container.read_bytes()[:-1])

    result = runner.invoke(cli, ["check", str(truncated)])
    assert result.exit_code == EXIT_CORRUPT
    assert "corrupted" in result.output.lower()


def test_cli_check_rejects_excess_volumes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    descriptors = [
        _descriptor(0, 2048, 32),
        _descriptor(1, 2144, 32),
        _descriptor(2, 2240, 32),
    ]
    header = _build_forced_header(monkeypatch, descriptors)
    payload_size = max(d.payload_offset + d.payload_length + TAG_LEN for d in descriptors)
    forged = tmp_path / "too_many.zil"
    forged.write_bytes(header.ljust(payload_size, b"\x00"))

    runner = CliRunner()
    result = runner.invoke(cli, ["check", str(forged)])
    assert result.exit_code == EXIT_CORRUPT
    assert "container is corrupted" in result.output


def test_cli_check_detects_overlapping_payloads(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    descriptors = [
        _descriptor(0, 2048, 64),
        _descriptor(1, 2100, 64),
    ]
    header = _build_forced_header(monkeypatch, descriptors)
    payload_size = max(d.payload_offset + d.payload_length + TAG_LEN for d in descriptors)
    forged = tmp_path / "overlap.zil"
    forged.write_bytes(header.ljust(payload_size, b"\x00"))

    runner = CliRunner()
    result = runner.invoke(cli, ["check", str(forged)])
    assert result.exit_code == EXIT_CORRUPT
    assert "container is corrupted" in result.output


def test_cli_check_pq_hybrid_main_and_decoy(tmp_path: Path) -> None:
    if not pq.available():
        pytest.skip("oqs not available")

    runner = CliRunner()
    main_src = tmp_path / "main.txt"
    decoy_src = tmp_path / "decoy.txt"
    main_src.write_text("MAIN")
    decoy_src.write_text("DECOY")
    container = tmp_path / "pq_check.zil"

    api.encrypt_with_decoy(
        main_src,
        container,
        main_password="pw-main",
        decoy_password="pw-decoy",
        input_path_decoy=decoy_src,
        mode="pq-hybrid",
        overwrite=True,
    )

    main_check = runner.invoke(
        cli,
        ["check", str(container), "--password", "pw-main", "--mode", "pq-hybrid", "--volume", "main"],
    )
    assert main_check.exit_code == EXIT_SUCCESS
    assert "Integrity verified" in main_check.output

    decoy_check = runner.invoke(
        cli,
        ["check", str(container), "--password", "pw-decoy", "--mode", "pq-hybrid", "--volume", "decoy"],
    )
    assert decoy_check.exit_code == EXIT_SUCCESS
    assert "Integrity verified" in decoy_check.output


def test_cli_info_default_hides_additional_volumes(tmp_path: Path) -> None:
    runner = CliRunner()
    main_src = tmp_path / "main.txt"
    decoy_src = tmp_path / "decoy.txt"
    main_src.write_text("MAIN")
    decoy_src.write_text("DECOY")
    container = tmp_path / "hidden_info.zil"

    assert (
        runner.invoke(
            cli,
            [
                "encrypt",
                str(main_src),
                str(container),
                "--password",
                "pw-main",
                "--decoy-password",
                "pw-decoy",
                "--decoy-input",
                str(decoy_src),
            ],
        ).exit_code
        == EXIT_SUCCESS
    )

    default_info = runner.invoke(cli, ["info", str(container)])
    assert default_info.exit_code == EXIT_SUCCESS
    assert "volume decoy" not in default_info.output.lower()
    verbose = runner.invoke(cli, ["info", str(container), "--volumes"])
    assert verbose.exit_code == EXIT_SUCCESS
    assert "additional volumes may be present" in verbose.output.lower()


def test_cli_reports_corrupted_container(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "data.txt"
    source.write_text("hello")
    container = tmp_path / "corrupt.zil"

    assert runner.invoke(cli, ["encrypt", str(source), str(container), "--password", "pw"]).exit_code == EXIT_SUCCESS

    data = bytearray(container.read_bytes())
    data[10] ^= 0x01
    corrupted = tmp_path / "corrupt_copy.zil"
    corrupted.write_bytes(data)

    result = runner.invoke(cli, ["decrypt", str(corrupted), str(tmp_path / "out.txt"), "--password", "pw"])
    assert result.exit_code == EXIT_CORRUPT
    assert "container is corrupted or not supported" in result.output


def test_cli_check_flags_corrupted_header(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "data.txt"
    source.write_text("hello")
    container = tmp_path / "corrupt_check.zil"

    assert runner.invoke(cli, ["encrypt", str(source), str(container), "--password", "pw"]).exit_code == EXIT_SUCCESS

    data = bytearray(container.read_bytes())
    data[fmt.MAGIC_LEN + 6] ^= 0xFF
    corrupted = tmp_path / "corrupt_check_copy.zil"
    corrupted.write_bytes(data)

    result = runner.invoke(cli, ["check", str(corrupted), "--password", "pw"])
    assert result.exit_code == EXIT_CORRUPT
    assert "corrupted" in result.output.lower()


def test_cli_check_handles_truncated_payload(tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "data.txt"
    source.write_text("hello world")
    container = tmp_path / "trunc.zil"

    assert runner.invoke(cli, ["encrypt", str(source), str(container), "--password", "pw"]).exit_code == EXIT_SUCCESS

    truncated = tmp_path / "trunc_copy.zil"
    truncated.write_bytes(container.read_bytes()[:-TAG_LEN // 2])

    result = runner.invoke(cli, ["check", str(truncated), "--password", "pw"])
    assert result.exit_code == EXIT_CORRUPT
    assert "corrupted" in result.output.lower()


def test_cli_pq_container_without_support(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    if not pq.available():
        pytest.skip("oqs not available")

    runner = CliRunner()
    source = tmp_path / "pq.txt"
    source.write_text("pq")
    container = tmp_path / "pq_only.zil"

    assert (
        runner.invoke(
            cli,
            ["encrypt", str(source), str(container), "--password", "pw", "--mode", "pq-hybrid"],
        ).exit_code
        == EXIT_SUCCESS
    )

    monkeypatch.setattr("zilant_encrypt.crypto.pq.available", lambda: False)
    result = runner.invoke(
        cli,
        ["decrypt", str(container), str(tmp_path / "pq_out.txt"), "--password", "pw", "--mode", "pq-hybrid"],
    )
    assert result.exit_code == EXIT_PQ_UNSUPPORTED
    assert "requires PQ support" in result.output


def test_cli_auto_mode_reports_missing_pq_support(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "pq_auto.txt"
    source.write_text("pq")
    container = tmp_path / "pq_auto.zil"

    # Build a password container, then mark the descriptor as PQ to trigger the support check when pq is unavailable.
    assert runner.invoke(cli, ["encrypt", str(source), str(container), "--password", "pw"]).exit_code == EXIT_SUCCESS

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
    mutated = tmp_path / "pq_auto_mutated.zil"
    mutated.write_bytes(bytes(mutated_header) + container.read_bytes()[len(header_bytes) :])

    monkeypatch.setattr("zilant_encrypt.crypto.pq.available", lambda: False)
    result = runner.invoke(cli, ["decrypt", str(mutated), str(tmp_path / "out.txt"), "--password", "pw"])
    assert result.exit_code == EXIT_PQ_UNSUPPORTED
    assert "requires PQ support" in result.output
