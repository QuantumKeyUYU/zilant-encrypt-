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
    KEY_MODE_PASSWORD_ONLY,
    KEY_MODE_PQ_HYBRID,
    read_header_from_stream,
)
from zilant_encrypt.crypto import pq
from zilant_encrypt.errors import (
    ContainerFormatError,
    IntegrityError,
    InvalidPassword,
    PqSupportError,
    UnsupportedFeatureError,
)

EXIT_SUCCESS = 0
EXIT_USAGE = 1
EXIT_CRYPTO = 2
EXIT_FS = 3
EXIT_CORRUPT = 4
EXIT_PQ_UNSUPPORTED = 5

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


def _volume_label(volume_id: int) -> str:
    if volume_id == 0:
        return "main"
    if volume_id == 1:
        return "decoy"
    return f"id={volume_id}"


def _mode_label(key_mode: int, pq_available: bool) -> str:
    pq_status = "pq available" if pq_available else "pq unavailable"
    if key_mode == KEY_MODE_PQ_HYBRID:
        return f"pq-hybrid (Kyber768 + AES-GCM, {pq_status})"
    if key_mode == KEY_MODE_PASSWORD_ONLY:
        return "password-only"
    return f"unknown ({key_mode})"


def _handle_action(
    action: Callable[[], None],
    *,
    invalid_password_message: str | None = None,
    integrity_error_message: str | None = None,
) -> int:
    try:
        action()
    except InvalidPassword:
        message = invalid_password_message or "[red]Invalid password or key[/red]"
        console.print(message)
        return EXIT_CRYPTO
    except (IntegrityError, ContainerFormatError):
        message = integrity_error_message or "[red]Error: container is corrupted or not supported[/red]"
        console.print(message)
        return EXIT_CORRUPT
    except PqSupportError:
        console.print("[red]Error: container requires PQ support that is not available[/red]")
        return EXIT_PQ_UNSUPPORTED
    except UnsupportedFeatureError as exc:
        console.print(f"[red]Unsupported or invalid container:[/red] {exc}")
        return EXIT_USAGE
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
    """Encrypt files and folders into v3 .zil containers with password or PQ-hybrid protection."""


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
    help="Key protection mode (password or pq-hybrid when liboqs/oqs is available).",
)
@click.option(
    "--volume",
    type=click.Choice(["main", "decoy"], case_sensitive=False),
    default="main",
    show_default=True,
    help="Target volume (main or decoy). For decoy, the container must already exist (v3).",
)
@click.option(
    "--overwrite/--no-overwrite",
    default=False,
    help="Overwrite output if it already exists.",
)
@click.option(
    "-M",
    "--argon-mem-kib",
    type=int,
    default=None,
    help="Override Argon2 memory cost in KiB (advanced).",
)
@click.option(
    "-T",
    "--argon-time",
    type=int,
    default=None,
    help="Override Argon2 time cost (iterations, advanced).",
)
@click.option(
    "-P",
    "--argon-parallelism",
    type=int,
    default=None,
    help="Override Argon2 parallelism (advanced).",
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
    argon_mem_kib: int | None,
    argon_time: int | None,
    argon_parallelism: int | None,
) -> None:
    password = _prompt_password(password_opt)
    target = output_path or input_path.with_suffix(f"{input_path.suffix}.zil")

    try:
        argon_params = api.resolve_argon_params(
            mem_kib=argon_mem_kib,
            time_cost=argon_time,
            parallelism=argon_parallelism,
        )
    except UnsupportedFeatureError as exc:
        console.print(f"[red]{exc}[/red]")
        ctx.exit(EXIT_USAGE)
        return

    if mode == "pq-hybrid" and not pq.available():
        console.print("[red]Error: container requires PQ support that is not available[/red]")
        ctx.exit(EXIT_PQ_UNSUPPORTED)
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
                argon_params=argon_params,
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
                input_path,
                target,
                password,
                overwrite=overwrite,
                mode=mode,
                volume=volume,
                argon_params=argon_params,
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
    help="Which volume to decrypt (auto-detect if omitted; password decides main vs decoy).",
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
        console.print("[red]Error: container requires PQ support that is not available[/red]")
        ctx.exit(EXIT_PQ_UNSUPPORTED)
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
            invalid_password_message="[red]Invalid password or key[/red]",
            integrity_error_message="[red]Error: container is corrupted or not supported[/red]",
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
@click.option("--password", "password_opt", help="Password to authenticate a volume (optional).")
@click.option(
    "--volumes/--no-volumes",
    "show_volumes",
    default=False,
    help="Show verbose per-volume details.",
)
@click.pass_context
def info(ctx: click.Context, container: Path, password_opt: str | None, show_volumes: bool) -> None:
    password = _prompt_password(password_opt) if password_opt is not None else None

    try:
        overview, _ = api.check_container(container, password=None)
    except (ContainerFormatError, UnsupportedFeatureError):
        console.print("[red]Error: container is corrupted or not supported[/red]")
        ctx.exit(EXIT_CORRUPT)
        return
    except FileNotFoundError as exc:
        console.print(f"[red]File not found:[/red] {exc}")
        ctx.exit(EXIT_FS)
        return

    validated: set[int] = set()
    if password is not None:
        for candidate in overview.descriptors:
            label = "main" if candidate.volume_id == 0 else "decoy" if candidate.volume_id == 1 else "all"
            try:
                _checked, ids = api.check_container(
                    container, password=password, volume=label if label in {"main", "decoy"} else "all"
                )
                validated.update(ids)
            except InvalidPassword:
                continue
            except PqSupportError:
                console.print("[red]Error: container requires PQ support that is not available[/red]")
                ctx.exit(EXIT_PQ_UNSUPPORTED)
                return
            except ContainerFormatError:
                console.print("[red]Error: container is corrupted or not supported[/red]")
                ctx.exit(EXIT_CORRUPT)
                return
        if not validated:
            console.print("[red]Invalid password or key[/red]")
            ctx.exit(EXIT_CRYPTO)
            return

    ordered_layouts = sorted(overview.layouts, key=lambda l: l.descriptor.volume_id)
    primary_layout = ordered_layouts[0]
    selected = primary_layout.descriptor

    if validated:
        matched_labels = ", ".join(_volume_label(v) for v in sorted(validated))
        volume_summary = f"{len(overview.descriptors)} (password matched: {matched_labels})"
    elif len(overview.descriptors) == 1:
        volume_summary = "1 (outer only)"
    else:
        volume_summary = "1 (outer; additional volumes may be present)"

    table = Table(show_header=False, box=None)
    table.add_row("Magic/Version", f"ZILENC / {overview.header.version}")
    table.add_row("Container size", _human_size(overview.file_size))
    table.add_row("Volumes", volume_summary)
    table.add_row("Key mode", _mode_label(selected.key_mode, overview.pq_available))
    table.add_row(
        "Argon2id",
        f"mem={selected.argon_mem_cost} KiB, time={selected.argon_time_cost}, p={selected.argon_parallelism}",
    )
    table.add_row("Primary payload", f"~{_human_size(primary_layout.ciphertext_len)}")
    table.add_row("PQ support", "available" if overview.pq_available else "unavailable")

    console.print("[bold]Zilant container[/bold]")
    console.print(table)

    if show_volumes:
        console.print("Volumes (verbose):")
        if validated:
            for layout in ordered_layouts:
                desc = layout.descriptor
                pq_info = ""
                if desc.pq_ciphertext is not None and desc.pq_wrapped_secret is not None:
                    pq_info = f", pq-fields: ct={len(desc.pq_ciphertext)}B, sk={len(desc.pq_wrapped_secret)}B"
                status = "authenticated" if desc.volume_id in validated else "locked"
                console.print(
                    "  - "
                    + f"volume {_volume_label(desc.volume_id)} ({status})"
                    + f" (key_mode={_mode_label(desc.key_mode, overview.pq_available)}, size≈{_human_size(layout.ciphertext_len)}, "
                    + f"argon2: mem={desc.argon_mem_cost} KiB, time={desc.argon_time_cost}, p={desc.argon_parallelism}{pq_info})",
                )
        else:
            primary_label = _volume_label(primary_layout.descriptor.volume_id)
            console.print(
                "  - "
                + f"volume {primary_label} (locked)"
                + f" (key_mode={_mode_label(primary_layout.descriptor.key_mode, overview.pq_available)}, size≈{_human_size(primary_layout.ciphertext_len)}, "
                + f"argon2: mem={primary_layout.descriptor.argon_mem_cost} KiB, time={primary_layout.descriptor.argon_time_cost}, p={primary_layout.descriptor.argon_parallelism})",
            )
            if len(overview.descriptors) > 1:
                console.print("  - additional volumes may be present (not listed without a password)")
    ctx.exit(EXIT_SUCCESS)


@cli.command(
    help="Validate container structure and optional integrity without writing files.",
    epilog="Example:\n  zilenc check secret.zil --password pw --volume main",
)
@click.argument("container", type=click.Path(path_type=Path))
@click.option("--password", "password_opt", help="Password for integrity verification (prompts if omitted).")
@click.option(
    "--mode",
    type=click.Choice(["password", "pq-hybrid"], case_sensitive=False),
    default=None,
    show_default=False,
    help="Force a key mode for authentication (auto by default).",
)
@click.option(
    "--volume",
    type=click.Choice(["main", "decoy", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Which volume(s) to validate.",
)
@click.option(
    "--verbose/--quiet",
    "verbose",
    default=False,
    help="Show detailed per-volume information.",
)
@click.pass_context
def check(
    ctx: click.Context,
    container: Path,
    password_opt: str | None,
    mode: str | None,
    volume: str,
    verbose: bool,
) -> None:
    perform_auth = password_opt is not None or mode is not None or volume != "all"
    password = _prompt_password(password_opt) if perform_auth else None

    def _run() -> None:
        overview, validated = api.check_container(container, password=password, mode=mode, volume=volume)
        ordered_layouts = sorted(overview.layouts, key=lambda l: l.descriptor.volume_id)
        primary = ordered_layouts[0]
        table = Table(show_header=False, box=None)
        table.add_row("Magic/Version", f"ZILENC / {overview.header.version}")
        table.add_row("Volumes", str(len(overview.descriptors)))
        table.add_row("Key mode", _mode_label(primary.descriptor.key_mode, overview.pq_available))
        table.add_row(
            "Argon2id",
            f"mem={primary.descriptor.argon_mem_cost} KiB, time={primary.descriptor.argon_time_cost}, p={primary.descriptor.argon_parallelism}",
        )
        table.add_row("Payload size", f"~{_human_size(primary.ciphertext_len)}")
        table.add_row("PQ support", "available" if overview.pq_available else "unavailable")
        table.add_row("Validated", ", ".join(_volume_label(v) for v in validated) if validated else "(structural only)")

        console.print("[bold]Container check[/bold]")
        console.print(table)
        if verbose:
            console.print("Volumes (verbose):")
            for layout in ordered_layouts:
                desc = layout.descriptor
                pq_info = ""
                if desc.pq_ciphertext is not None and desc.pq_wrapped_secret is not None:
                    pq_info = f", pq-fields: ct={len(desc.pq_ciphertext)}B, sk={len(desc.pq_wrapped_secret)}B"
                console.print(
                    "  - "
                    + f"volume {_volume_label(desc.volume_id)}"
                    + f" (key_mode={_mode_label(desc.key_mode, overview.pq_available)}, size≈{_human_size(layout.ciphertext_len)}, "
                    + f"argon2: mem={desc.argon_mem_cost} KiB, time={desc.argon_time_cost}, p={desc.argon_parallelism}{pq_info})",
                )

        if not validated:
            console.print("[yellow]Cryptographic tag verification skipped (no password supplied).[/yellow]")
        else:
            console.print(
                "[green]Integrity verified for volume(s): "
                + ", ".join(_volume_label(v) for v in validated)
                + ".[/green]"
            )
        console.print("[green]All requested checks passed.[/green]")

    code = _handle_action(
        _run,
        invalid_password_message="[red]Invalid password or key[/red]",
        integrity_error_message="[red]Error: container is corrupted or not supported[/red]",
    )
    ctx.exit(code)


def main(argv: list[str] | None = None) -> int:
    try:
        return cli.main(args=argv, prog_name="zilenc", standalone_mode=False)
    except SystemExit as exc:  # noqa: TRY003
        code = exc.code if isinstance(exc.code, int) else EXIT_USAGE
        return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
