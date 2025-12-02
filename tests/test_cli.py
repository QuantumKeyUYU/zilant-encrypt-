from pathlib import Path

import pytest
from click.testing import CliRunner

from zilant_encrypt.cli import EXIT_CRYPTO, EXIT_FS, EXIT_SUCCESS, EXIT_USAGE, cli
from zilant_encrypt.crypto import pq


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
    assert result.exit_code == EXIT_CRYPTO


def test_cli_encrypt_decrypt_decoy(tmp_path: Path) -> None:
    runner = CliRunner()
    main_src = tmp_path / "main.txt"
    decoy_src = tmp_path / "decoy.txt"
    main_src.write_text("MAIN")
    decoy_src.write_text("DECOY")

    container = tmp_path / "double.zil"

    result = runner.invoke(cli, ["encrypt", str(main_src), str(container), "--password", "pw-main"])
    assert result.exit_code == EXIT_SUCCESS

    result = runner.invoke(
        cli,
        [
            "encrypt",
            str(decoy_src),
            str(container),
            "--password",
            "pw-decoy",
            "--volume",
            "decoy",
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
    assert "Неверный пароль" in result.output


def test_cli_pq_mode_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runner = CliRunner()
    source = tmp_path / "source.txt"
    source.write_text("hello")

    monkeypatch.setattr("zilant_encrypt.crypto.pq.available", lambda: False)
    result = runner.invoke(
        cli,
        ["encrypt", str(source), str(tmp_path / "out.zil"), "--password", "pw", "--mode", "pq-hybrid"],
    )
    assert result.exit_code == EXIT_USAGE


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
    assert "main" in verbose.output
    assert "decoy" in verbose.output


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
