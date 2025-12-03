from click.testing import CliRunner


def test_version_attribute() -> None:
    import zilant_encrypt

    assert isinstance(zilant_encrypt.__version__, str)
    assert zilant_encrypt.__version__


def test_cli_reports_version() -> None:
    from zilant_encrypt import __version__
    from zilant_encrypt.cli import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])

    assert result.exit_code == 0
    assert "Zilant Encrypt" in result.output
    assert __version__ in result.output

    command_result = runner.invoke(cli, ["version"])

    assert command_result.exit_code == 0
    assert "Zilant Encrypt" in command_result.output
    assert __version__ in command_result.output
