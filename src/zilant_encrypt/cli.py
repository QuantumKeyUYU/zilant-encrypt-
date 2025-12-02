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
from zilant_encrypt.container.format import (
    HEADER_V1_LEN,
    KEY_MODE_PASSWORD_ONLY,
    KEY_MODE_PQ_HYBRID,
    read_header_from_stream,
)
from zilant_encrypt.crypto.aead import TAG_LEN
from zilant_encrypt.crypto import pq
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


def _handle_action(
    action: Callable[[], None],
    *,
    invalid_password_message: str | None = None,
    integrity_error_message: str | None = None,
) -> int:
    try:
        action()
    except InvalidPassword:
        message = invalid_password_message or "[red]Invalid password.[/red]"
        console.print(message)
        return EXIT_CRYPTO
    except IntegrityError:
        message = integrity_error_message or "[red]Error: container is damaged or not supported.[/red]"
        console.print(message)
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
    "--decoy-password",
    "decoy_password_opt",
    help="Optional decoy volume password to create main+decoy in one step.",
)
@click.option(
    "--decoy-input",
    "decoy_input",
    type=click.Path(path_type=Path),
    help="Path for the decoy payload (defaults to the main input).",
)
@click.option(
    "--mode",
    type=click.Choice(["password", "pq-hybrid"], case_sensitive=False),
    default="password",
    show_default=True,
    help="Key protection mode.",
)
@click.option(
    "--volume",
    type=click.Choice(["main", "decoy"], case_sensitive=False),
    default="main",
    show_default=True,
    help="Target volume (main or decoy).",
)
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
    decoy_password_opt: str | None,
    decoy_input: Path | None,
    overwrite: bool,
    mode: str,
    volume: str,
) -> None:
    password = _prompt_password(password_opt)
    target = output_path or input_path.with_suffix(f"{input_path.suffix}.zil")

    if mode == "pq-hybrid" and not pq.available():
        console.print("[red]PQ-hybrid режим недоступен (oqs не установлен).[/red]")
        ctx.exit(EXIT_USAGE)
        return

    if decoy_password_opt:
        if volume != "main":
            console.print("[red]When using --decoy-password, --volume must remain 'main'.[/red]")
            ctx.exit(EXIT_USAGE)
            return

        decoy_payload = decoy_input or input_path
        code = _handle_action(
            lambda: api.encrypt_with_decoy(
                input_path,
                target,
                main_password=password,
                decoy_password=decoy_password_opt,
                input_path_decoy=decoy_payload,
                mode=mode,
                overwrite=overwrite,
            ),
        )
    else:
        if volume == "decoy" and not target.exists():
            console.print("[red]decoy volume can only be added to an existing v3 container[/red]")
            ctx.exit(EXIT_USAGE)
            return
        if volume == "decoy" and target.exists():
            try:
                with target.open("rb") as f:
                    header, _descriptors, _header_bytes = read_header_from_stream(f)
                if header.version != 3:
                    raise ContainerFormatError("decoy volume requires v3 container header")
            except Exception as exc:  # noqa: BLE001
                console.print(
                    f"[red]decoy volume can only be added to an existing v3 container:[/red] {exc}"
                )
                ctx.exit(EXIT_USAGE)
                return

        code = _handle_action(
            lambda: api.encrypt_file(
                input_path, target, password, overwrite=overwrite, mode=mode, volume=volume
            ),
        )
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
@click.option(
    "--mode",
    type=click.Choice(["password", "pq-hybrid"], case_sensitive=False),
    default=None,
    help="Force a key mode (normally auto-detected).",
)
@click.option(
    "--volume",
    type=click.Choice(["main", "decoy"], case_sensitive=False),
    default=None,
    show_default=False,
    help="Which volume to decrypt (auto-detect if omitted).",
)
@click.pass_context
def decrypt(
    ctx: click.Context,
    container: Path,
    output_path: Path | None,
    password_opt: str | None,
    overwrite: bool,
    mode: str | None,
    volume: str | None,
) -> None:
    password = _prompt_password(password_opt)
    out_path = output_path or container.with_suffix(container.suffix + ".out")

    if mode == "pq-hybrid" and not pq.available():
        console.print("[red]PQ-hybrid mode requires the 'oqs' library; install it or use password-only mode.[/red]")
        ctx.exit(EXIT_USAGE)
        return

    if volume is None:
        volume_result: dict[str, tuple[int, str]] = {}
        code = _handle_action(
            lambda: volume_result.setdefault(
                "value",
                api.decrypt_auto_volume(
                    container,
                    out_path,
                    password=password,
                    overwrite=overwrite,
                    mode=mode,
                ),
            ),
            invalid_password_message="[red]Неверный пароль или контейнер повреждён[/red]",
            integrity_error_message="[red]Неверный пароль или контейнер повреждён[/red]",
        )
    else:
        code = _handle_action(
            lambda: api.decrypt_file(
                container, out_path, password, overwrite=overwrite, mode=mode, volume=volume
            ),
        )
    if code == EXIT_SUCCESS:
        console.print(f"[green]Decrypted to[/green] {out_path}.")
    ctx.exit(code)


@cli.command(
    help="Display container header information without decrypting payload.",
    epilog="Example:\n  zilenc info secret.zil",
)
@click.argument("container", type=click.Path(path_type=Path))
@click.option(
    "--volumes/--no-volumes",
    "show_volumes",
    default=False,
    help="Show per-volume details (main/decoy).",
)
@click.pass_context
def info(ctx: click.Context, container: Path, show_volumes: bool) -> None:
    try:
        data = container.read_bytes()
    except OSError as exc:  # noqa: BLE001
        console.print(f"[red]Unable to read container:[/red] {exc}")
        ctx.exit(EXIT_FS)
        return

    header_bytes = data[:HEADER_V1_LEN]
    try:
        with container.open("rb") as f:
            header, descriptors, header_bytes = read_header_from_stream(f)
    except (ContainerFormatError, UnsupportedFeatureError) as exc:
        console.print(f"[red]Unsupported or invalid container:[/red] {exc}")
        ctx.exit(EXIT_CRYPTO)
        return

    payload_size = max(len(data) - header.header_len, 0)
    table = Table(show_header=False, box=None)
    table.add_row("Magic/Version", f"ZILENC / {header.version}")
    table.add_row("Volumes", str(len(descriptors)))
    if header.key_mode == KEY_MODE_PQ_HYBRID:
        mode_label = "pq-hybrid (Kyber768 + AES-GCM)"
    elif header.key_mode == KEY_MODE_PASSWORD_ONLY:
        mode_label = "password-only"
    else:
        mode_label = f"unknown ({header.key_mode})"
    table.add_row("Key mode", mode_label)
    table.add_row(
        "Argon2id",
        f"mem={header.argon_mem_cost} KiB, time={header.argon_time_cost}, p={header.argon_parallelism}",
    )
    table.add_row("Payload size", f"~{_human_size(payload_size)}")

    console.print("[bold]Zilant container[/bold]")
    console.print(table)

    if show_volumes:
        console.print("Volumes:")
        ordered = sorted(descriptors, key=lambda d: d.volume_id)
        for desc in ordered:
            name = "main" if desc.volume_id == 0 else "decoy" if desc.volume_id == 1 else f"id={desc.volume_id}"
            size = desc.payload_length if desc.payload_length else max(len(data) - desc.payload_offset - TAG_LEN, 0)
            if desc.key_mode == KEY_MODE_PQ_HYBRID:
                mode_label = "pq-hybrid (Kyber768 + AES-GCM)"
            elif desc.key_mode == KEY_MODE_PASSWORD_ONLY:
                mode_label = "password-only"
            else:
                mode_label = f"unknown ({desc.key_mode})"
            console.print(
                "  - "
                + name
                + f" (id={desc.volume_id}, key_mode={mode_label}, size≈{_human_size(size)}, "
                + f"argon2: mem={desc.argon_mem_cost} KiB, time={desc.argon_time_cost}, p={desc.argon_parallelism})",
            )
    ctx.exit(EXIT_SUCCESS)


def main(argv: list[str] | None = None) -> int:
    try:
        return cli.main(args=argv, prog_name="zilenc", standalone_mode=False)
    except SystemExit as exc:  # noqa: TRY003
        code = exc.code if isinstance(exc.code, int) else EXIT_USAGE
        return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
