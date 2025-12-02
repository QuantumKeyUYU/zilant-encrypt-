from pathlib import Path

import pytest
from click.testing import CliRunner

from zilant_encrypt.cli import EXIT_CRYPTO, EXIT_FS, EXIT_SUCCESS, EXIT_USAGE, cli


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
