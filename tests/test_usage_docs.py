from pathlib import Path

from click.testing import CliRunner

from zilant_encrypt.cli import cli


def test_help_commands_run() -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["--help"]).exit_code == 0
    assert runner.invoke(cli, ["encrypt", "--help"]).exit_code == 0


def test_docs_reference_pq_and_check_commands() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    readme = (repo_root / "README.md").read_text()
    usage = (repo_root / "docs" / "USAGE_V3.md").read_text()

    assert "PQ-hybrid" in readme or "post-quantum hybrid" in readme
    assert "zilenc check" in readme

    assert "PQ-hybrid" in usage or "post-quantum" in usage
    assert "zilenc check" in usage
