"""Command line interface for Zilant Encrypt."""

from __future__ import annotations

import getpass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Callable

import click
from rich.console import Console
from rich.table import Table

from zilant_encrypt import __version__
from zilant_encrypt.container import api
from zilant_encrypt.container.format import HEADER_LEN, parse_header
from zilant_encrypt.errors import (
    ContainerFormatError,
    IntegrityError,
    InvalidPassword,
    UnsupportedFeatureError,
)

EXIT_SUCCESS = 0
EXIT_USAGE = 1
EXIT_CRYPTO = 2
EXIT_FS = 3

console = Console()


def _package_version() -> str:
    try:
        return version("zilant-encrypt")
    except PackageNotFoundError:
        return __version__


def _prompt_password(password_opt: str | None) -> str:
    if password_opt is not None:
        return password_opt
    return getpass.getpass("Password: ")


def _human_size(num: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{num} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


def _handle_action(action: Callable[[], None]) -> int:
    try:
        action()
    except InvalidPassword:
        console.print("[red]Invalid password.[/red]")
        return EXIT_CRYPTO
    except IntegrityError:
        console.print("[red]Container is corrupted or password is incorrect.[/red]")
        return EXIT_CRYPTO
    except (ContainerFormatError, UnsupportedFeatureError) as exc:
        console.print(f"[red]Unsupported or invalid container:[/red] {exc}")
        return EXIT_CRYPTO
    except FileExistsError as exc:
        console.print(f"[red]{exc}. Use --overwrite to replace.[/red]")
        return EXIT_FS
    except FileNotFoundError as exc:
        console.print(f"[red]File not found:[/red] {exc}")
        return EXIT_FS
    except PermissionError as exc:
        console.print(f"[red]Permission denied:[/red] {exc}")
        return EXIT_FS
    except OSError as exc:  # noqa: BLE001
        console.print(f"[red]Filesystem error:[/red] {exc}")
        return EXIT_FS
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Unexpected error:[/red] {exc}")
        return EXIT_USAGE
    return EXIT_SUCCESS


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=False,
)
@click.version_option(version=_package_version(), prog_name="Zilant Encrypt")
def cli() -> None:
    """Secure file and directory encryption using .zil containers."""


@cli.command(
    help="Encrypt a file or directory into a .zil container.",
    epilog="Examples:\n  zilenc encrypt secret.txt secret.zil\n  zilenc encrypt ./folder ./folder.zil\n  zilenc encrypt ./folder  # output defaults to ./folder.zil",
)
@click.argument("input_path", type=click.Path(path_type=Path))
@click.argument("output_path", required=False, type=click.Path(path_type=Path))
@click.option("--password", "password_opt", help="Encryption password (will prompt if omitted).")
@click.option(
    "--overwrite/--no-overwrite",
    default=False,
    help="Overwrite output if it already exists.",
)
@click.pass_context
def encrypt(
    ctx: click.Context,
    input_path: Path,
    output_path: Path | None,
    password_opt: str | None,
    overwrite: bool,
) -> None:
    password = _prompt_password(password_opt)
    target = output_path or input_path.with_suffix(f"{input_path.suffix}.zil")

    code = _handle_action(lambda: api.encrypt_file(input_path, target, password, overwrite=overwrite))
    if code == EXIT_SUCCESS:
        size = target.stat().st_size if target.exists() else 0
        console.print(f"[green]Encrypted to[/green] {target} (~{_human_size(size)}).")
    ctx.exit(code)


@cli.command(
    help="Decrypt a .zil container into a file or directory.",
    epilog="Examples:\n  zilenc decrypt secret.zil\n  zilenc decrypt archive.zil ./restored\n  zilenc decrypt secret.zil message.txt --overwrite",
)
@click.argument("container", type=click.Path(path_type=Path))
@click.argument("output_path", required=False, type=click.Path(path_type=Path))
@click.option("--password", "password_opt", help="Decryption password (will prompt if omitted).")
@click.option(
    "--overwrite/--no-overwrite",
    default=False,
    help="Overwrite existing files/directories at the destination.",
)
@click.pass_context
def decrypt(
    ctx: click.Context,
    container: Path,
    output_path: Path | None,
    password_opt: str | None,
    overwrite: bool,
) -> None:
    password = _prompt_password(password_opt)
    out_path = output_path or container.with_suffix(container.suffix + ".out")

    code = _handle_action(lambda: api.decrypt_file(container, out_path, password, overwrite=overwrite))
    if code == EXIT_SUCCESS:
        console.print(f"[green]Decrypted to[/green] {out_path}.")
    ctx.exit(code)


@cli.command(
    help="Display container header information without decrypting payload.",
    epilog="Example:\n  zilenc info secret.zil",
)
@click.argument("container", type=click.Path(path_type=Path))
@click.pass_context
def info(ctx: click.Context, container: Path) -> None:
    try:
        data = container.read_bytes()
    except OSError as exc:  # noqa: BLE001
        console.print(f"[red]Unable to read container:[/red] {exc}")
        ctx.exit(EXIT_FS)
        return

    header_bytes = data[:HEADER_LEN]
    try:
        header = parse_header(header_bytes)
    except (ContainerFormatError, UnsupportedFeatureError) as exc:
        console.print(f"[red]Unsupported or invalid container:[/red] {exc}")
        ctx.exit(EXIT_CRYPTO)
        return

    payload_size = max(len(data) - HEADER_LEN, 0)
    table = Table(show_header=False, box=None)
    table.add_row("Magic/Version", "ZILENC / 1")
    table.add_row("Key mode", str(header.key_mode))
    table.add_row(
        "Argon2id",
        f"mem={header.argon_mem_cost} KiB, time={header.argon_time_cost}, p={header.argon_parallelism}",
    )
    table.add_row("Payload size", f"~{_human_size(payload_size)}")

    console.print("[bold]Zilant container[/bold]")
    console.print(table)
    ctx.exit(EXIT_SUCCESS)


def main(argv: list[str] | None = None) -> int:
    try:
        return cli.main(args=argv, prog_name="zilenc", standalone_mode=False)
    except SystemExit as exc:  # noqa: TRY003
        code = exc.code if isinstance(exc.code, int) else EXIT_USAGE
        return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
