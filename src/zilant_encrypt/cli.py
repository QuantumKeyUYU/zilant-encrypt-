"""Command line interface for Zilant Encrypt."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from zilant_encrypt.container import api
from zilant_encrypt.container.format import HEADER_LEN, parse_header
from zilant_encrypt.errors import (
    ContainerFormatError,
    IntegrityError,
    InvalidPassword,
    UnsupportedFeatureError,
)

console = Console()


def _prompt_password() -> str:
    return click.prompt("Password", hide_input=True, confirmation_prompt=True)


@click.group()
def main() -> None:
    """Zilant Encrypt CLI."""


@main.command()
@click.argument("input_path", type=click.Path(exists=True, path_type=Path))
@click.argument("output_path", type=click.Path(path_type=Path))
@click.option("--password", "password_opt", help="Encryption password")
@click.option("--overwrite/--no-overwrite", default=False, help="Overwrite output if exists")
def encrypt(input_path: Path, output_path: Path, password_opt: str | None, overwrite: bool) -> None:
    """Encrypt INPUT into OUTPUT container."""

    password = password_opt or _prompt_password()

    try:
        api.encrypt_file(input_path, output_path, password, overwrite=overwrite)
    except FileExistsError as exc:
        console.print(f"[red]Error:[/red] {exc}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Failed to encrypt:[/red] {exc}")


@main.command()
@click.argument("container", type=click.Path(exists=True, path_type=Path))
@click.argument("output_path", required=False, type=click.Path(path_type=Path))
@click.option("--password", "password_opt", help="Decryption password")
@click.option("--overwrite/--no-overwrite", default=False, help="Overwrite output if exists")
def decrypt(container: Path, output_path: Path | None, password_opt: str | None, overwrite: bool) -> None:
    """Decrypt CONTAINER into OUTPUT (defaults to <container>.out)."""

    password = password_opt or _prompt_password()
    out_path = output_path or container.with_suffix(container.suffix + ".out")

    try:
        api.decrypt_file(container, out_path, password, overwrite=overwrite)
    except InvalidPassword:
        console.print("[red]Неверный пароль[/red]")
    except IntegrityError:
        console.print("[red]Контейнер повреждён[/red]")
    except FileExistsError as exc:
        console.print(f"[red]Error:[/red] {exc}")
    except UnsupportedFeatureError as exc:
        console.print(f"[red]Неподдерживаемая функция:[/red] {exc}")
    except ContainerFormatError as exc:
        console.print(f"[red]Ошибка формата контейнера:[/red] {exc}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Failed to decrypt:[/red] {exc}")


@main.command()
@click.argument("container", type=click.Path(exists=True, path_type=Path))
def info(container: Path) -> None:
    """Show container header information."""

    data = container.read_bytes()
    header_bytes = data[:HEADER_LEN]

    try:
        header = parse_header(header_bytes)
    except (ContainerFormatError, UnsupportedFeatureError) as exc:
        console.print(f"[red]Ошибка формата контейнера:[/red] {exc}")
        return

    console.print("[bold]Zilant container[/bold]")
    console.print("Version: 1")
    console.print(f"Key mode: {header.key_mode}")
    console.print(
        f"Argon2id: mem={header.argon_mem_cost} KiB, " f"time={header.argon_time_cost}, p={header.argon_parallelism}",
    )
    payload_size = max(len(data) - HEADER_LEN, 0)
    console.print(f"Encrypted payload size: ~{payload_size} bytes")


if __name__ == "__main__":
    main()
