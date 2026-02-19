"""Command line interface for Zilant Encrypt."""

from __future__ import annotations

import getpass
from pathlib import Path
from typing import Callable, Literal, cast

import click
from rich.console import Console
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TransferSpeedColumn
from rich.table import Table

from zilant_encrypt import __version__
from zilant_encrypt.container import (
    KEY_MODE_PASSWORD_ONLY,
    KEY_MODE_PQ_HYBRID,
    ModeLiteral,
    check_container,
    decrypt_auto_volume,
    decrypt_file,
    encrypt_file,
    encrypt_with_decoy,
    normalize_mode,
    read_header_from_stream,
    resolve_argon_params,
)
from zilant_encrypt.crypto import pq
from zilant_encrypt.crypto.keyfile import derive_keyfile_material
from zilant_encrypt.errors import (
    ContainerFormatError,
    IntegrityError,
    InvalidPassword,
    PqSupportError,
    UnsupportedFeatureError,
)
from zilant_encrypt.password_strength import evaluate_password

EXIT_SUCCESS = 0
EXIT_USAGE = 1
EXIT_CRYPTO = 2
EXIT_FS = 3
EXIT_CORRUPT = 4
EXIT_PQ_UNSUPPORTED = 5

PQ_ERROR_MESSAGE = "Error: container requires PQ support (oqs) which is not available on this system."

console = Console()


def _prompt_password(password_opt: str | None, *, confirm: bool = False, warn_cmdline: bool = False) -> str:
    if password_opt is not None:
        if warn_cmdline:
            # Passwords passed on the command line are visible in process lists
            # (ps, /proc/*/cmdline) and shell history – warn the user.
            console.print(
                "[yellow]Security notice: password supplied on command line is visible "
                "in process lists and shell history. Prefer interactive prompt.[/yellow]"
            )
        return password_opt
    password = getpass.getpass("Password: ")
    if confirm:
        password2 = getpass.getpass("Confirm password: ")
        if password != password2:
            raise click.ClickException("Passwords do not match")
    return password


def _check_password_strength(password: str, *, is_encrypt: bool = False) -> None:
    """Show password strength feedback during encryption.

    Warns but does NOT abort for weak passwords – the user may have a valid
    reason (e.g. testing, scripted environments).  The original behaviour of
    silently accepting passwords when ``--password`` was given is preserved so
    that existing scripts continue to work.
    """
    if not is_encrypt:
        return
    # evaluate_password never raises; it just scores.
    strength = evaluate_password(password)
    entropy_note = f", ~{strength.entropy_bits:.0f} bits entropy"
    if strength.level == "weak":
        console.print(
            f"[yellow]Warning: weak password ({strength.score}/100{entropy_note})[/yellow]"
        )
        for tip in strength.feedback:
            console.print(f"[yellow]  - {tip}[/yellow]")
    elif strength.level == "fair":
        console.print(
            f"[yellow]Password strength: fair ({strength.score}/100{entropy_note})[/yellow]"
        )
    elif strength.level == "good":
        console.print(
            f"[green]Password strength: good ({strength.score}/100{entropy_note})[/green]"
        )


class _cli_progress:
    """Context manager that yields a progress callback for streaming operations."""

    def __init__(self, description: str, total: int) -> None:
        self._description = description
        self._total = total
        self._progress: Progress | None = None
        self._task_id: int | None = None

    def __enter__(self) -> Callable[[int], None]:
        if self._total > 0:
            self._progress = Progress(
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                console=console,
            )
            self._progress.start()
            self._task_id = self._progress.add_task(self._description, total=self._total)
        return self._advance

    def _advance(self, n: int) -> None:
        if self._progress is not None and self._task_id is not None:
            self._progress.update(self._task_id, advance=n)

    def __exit__(self, *args: object) -> None:
        if self._progress is not None:
            self._progress.stop()


def _human_size(num_bytes: int) -> str:
    num = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024.0 or unit == "TB":
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"


def _pq_error() -> int:
    console.print(PQ_ERROR_MESSAGE, soft_wrap=True)
    return EXIT_PQ_UNSUPPORTED


def _normalized_mode(mode_opt: str | None, *, default_to_password: bool = False) -> ModeLiteral | None:
    if mode_opt is None:
        return "password" if default_to_password else None
    return normalize_mode(mode_opt)


def _volume_selector(volume_index: int) -> Literal["main", "decoy", "all"]:
    if volume_index == 0:
        return "main"
    if volume_index == 1:
        return "decoy"
    return "all"


def _password_match_summary(validated: set[int]) -> str:
    if not validated:
        return "no volumes"
    labels = sorted(validated)
    if labels == [0]:
        return "main volume"
    if labels == [1]:
        return "decoy volume"
    if labels == [0, 1]:
        return "main and decoy volumes"
    return ", ".join(_volume_label(v) for v in labels)


def _volume_label(volume_index: int) -> str:
    if volume_index == 0:
        return "main"
    if volume_index == 1:
        return "decoy"
    return f"id={volume_index}"


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
        return _pq_error()
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
@click.version_option(
    __version__,
    "-V",
    "--version",
    prog_name="Zilant Encrypt",
    message="%(prog)s v%(version)s",
)
def cli() -> None:
    """Manage v3 .zil containers (encrypt, decrypt, inspect, check).

    Examples:
      zilenc encrypt secret.txt secret.zil --password pw
      zilenc encrypt secret.txt secret.zil --decoy-password decoy
      zilenc info secret.zil --password pw

    PQ-hybrid commands require oqs; without it you will see:
      Error: container requires PQ support (oqs) which is not available on this system.
    """


@cli.command(help="Show the installed version.")
def version() -> None:
    click.echo(f"Zilant Encrypt v{__version__}")


@cli.command(help="Generate shell completion script.")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell: str) -> None:
    """Output shell completion script for the given shell."""
    import os

    env_var = "_ZILENC_COMPLETE"
    shell_map = {"bash": "bash_source", "zsh": "zsh_source", "fish": "fish_source"}
    os.environ[env_var] = shell_map[shell]
    try:
        from click.shell_completion import get_completion_class

        comp_cls = get_completion_class(shell)
        if comp_cls is not None:
            comp = comp_cls(cli, {}, "zilenc", env_var)
            click.echo(comp.source())
    finally:
        del os.environ[env_var]


@cli.command(
    help=(
        "Encrypt a file or directory into a .zil container. Supports optional "
        "decoy volumes and PQ-hybrid mode when oqs is installed."
    ),
    epilog=(
        "Examples:\n  zilenc encrypt secret.txt secret.zil --password pw"
        "\n  zilenc encrypt ./folder ./folder.zil --decoy-password decoy"
        "\n  zilenc encrypt ./folder --mode pq-hybrid"
    ),
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
    type=click.Choice(["password", "pq-hybrid", "pq_hybrid"], case_sensitive=False),
    default="password",
    show_default=True,
    help=(
        "Key protection mode. Use 'password' for standard encryption or 'pq-hybrid'"
        " ('pq_hybrid') to add Kyber768 when oqs is available."
    ),
)
@click.option(
    "--volume",
    type=click.Choice(["main", "decoy"], case_sensitive=False),
    default="main",
    show_default=True,
    help=(
        "Target volume. Use 'decoy' only to add a decoy volume to an existing v3 container."
    ),
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
    help=(
        "Override Argon2 memory cost in KiB (advanced). Higher values slow down key derivation."
    ),
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
@click.option(
    "--keyfile",
    "keyfile_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to a keyfile for additional key material (combined with password).",
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
    keyfile_path: Path | None,
) -> None:
    password = _prompt_password(password_opt, confirm=password_opt is None, warn_cmdline=password_opt is not None)
    _check_password_strength(password, is_encrypt=True)
    kf_material = derive_keyfile_material(keyfile_path) if keyfile_path else None
    target = output_path or input_path.with_suffix(f"{input_path.suffix}.zil")
    normalized_mode = cast(ModeLiteral, _normalized_mode(mode, default_to_password=True))

    try:
        argon_params = resolve_argon_params(
            mem_kib=argon_mem_kib,
            time_cost=argon_time,
            parallelism=argon_parallelism,
        )
    except UnsupportedFeatureError as exc:
        console.print(f"[red]{exc}[/red]")
        ctx.exit(EXIT_USAGE)
        return

    if normalized_mode == "pq-hybrid" and not pq.available():
        ctx.exit(_pq_error())
        return

    total_size = input_path.stat().st_size if input_path.exists() else 0

    if decoy_password_opt:
        if volume != "main":
            console.print("[red]When using --decoy-password, --volume must remain 'main'.[/red]")
            ctx.exit(EXIT_USAGE)
            return

        decoy_payload = decoy_input or input_path

        code = _handle_action(
            lambda: encrypt_with_decoy(
                main_input=input_path,
                out_path=target,
                main_password=password,
                decoy_password=decoy_password_opt,
                input_path_decoy=decoy_payload,
                mode=normalized_mode,
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

        def _do_encrypt() -> None:
            with _cli_progress("Encrypting", total_size) as callback:
                encrypt_file(
                    input_path,
                    target,
                    password,
                    overwrite=overwrite,
                    mode=normalized_mode,
                    volume_selector=cast(Literal["main", "decoy"], volume),
                    argon_params=argon_params,
                    progress_callback=callback,
                    keyfile_material=kf_material,
                )

        code = _handle_action(_do_encrypt)

    if code == EXIT_SUCCESS:
        size = target.stat().st_size if target.exists() else 0
        console.print(f"[green]Encrypted to[/green] {target} (~{_human_size(size)}).")
    ctx.exit(code)


@cli.command(
    help=(
        "Decrypt a .zil container into a file or directory. Auto-detects main vs "
        "decoy volumes unless explicitly specified."
    ),
    epilog=(
        "Examples:\n  zilenc decrypt secret.zil --password pw"
        "\n  zilenc decrypt archive.zil ./restored --overwrite"
        "\n  zilenc decrypt pq.zil --mode pq-hybrid"
    ),
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
    type=click.Choice(["password", "pq-hybrid", "pq_hybrid"], case_sensitive=False),
    default=None,
    help=(
        "Force a key mode (normally auto-detected). Use pq-hybrid only when oqs "
        "is installed; otherwise the command exits with a PQ support error."
    ),
)
@click.option(
    "--volume",
    type=click.Choice(["main", "decoy"], case_sensitive=False),
    default=None,
    show_default=False,
    help="Which volume to decrypt (auto-detect if omitted; password decides main vs decoy).",
)
@click.option(
    "--keyfile",
    "keyfile_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to a keyfile (must match the one used during encryption).",
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
    keyfile_path: Path | None,
) -> None:
    password = _prompt_password(password_opt, warn_cmdline=password_opt is not None)
    kf_material = derive_keyfile_material(keyfile_path) if keyfile_path else None
    out_path = output_path or container.with_suffix(container.suffix + ".out")

    normalized_mode = _normalized_mode(mode)

    if normalized_mode == "pq-hybrid" and not pq.available():
        ctx.exit(_pq_error())
        return

    dec_mode = normalized_mode

    container_size = container.stat().st_size if container.exists() else 0

    if volume is None:
        volume_result: dict[str, tuple[int, str]] = {}

        def _run_auto() -> None:
            volume_result["value"] = decrypt_auto_volume(
                container,
                out_path,
                password=password,
                overwrite=overwrite,
                mode=dec_mode,
            )

        code = _handle_action(
            _run_auto,
            invalid_password_message="[red]Invalid password or key[/red]",
            integrity_error_message="[red]Error: container is corrupted or not supported[/red]",
        )
    else:
        dec_volume = cast(Literal["main", "decoy"], volume)

        def _do_decrypt() -> None:
            with _cli_progress("Decrypting", container_size) as callback:
                decrypt_file(
                    container,
                    out_path,
                    password,
                    overwrite=overwrite,
                    mode=dec_mode,
                    volume_selector=dec_volume,
                    progress_callback=callback,
                    keyfile_material=kf_material,
                )

        code = _handle_action(
            _do_decrypt,
        )
    if code == EXIT_SUCCESS:
        console.print(f"[green]Decrypted to[/green] {out_path}.")
    ctx.exit(code)


@cli.command(
    help=(
        "Display container header information without decrypting payload. Supply "
        "--password to verify which volume(s) the password unlocks."
    ),
    epilog="Example:\n  zilenc info secret.zil --password pw",
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
        overview, _ = check_container(container, password=None)
    except (ContainerFormatError, UnsupportedFeatureError):
        console.print("[red]Error: container is corrupted or not supported[/red]")
        ctx.exit(EXIT_CORRUPT)
        return
    except FileNotFoundError as exc:
        console.print(f"[red]File not found:[/red] {exc}")
        ctx.exit(EXIT_FS)
        return

    validated: set[int] = set()
    password_summary: str | None = None
    if password is not None:
        for candidate in overview.descriptors:
            check_vol = _volume_selector(candidate.volume_index)
            try:
                _checked, ids = check_container(container, password=password, volume_selector=check_vol)
                validated.update(ids)
            except InvalidPassword:
                continue
            except PqSupportError:
                ctx.exit(_pq_error())
                return
            except ContainerFormatError:
                console.print("[red]Error: container is corrupted or not supported[/red]")
                ctx.exit(EXIT_CORRUPT)
                return
        if not validated:
            console.print("[red]Invalid password or key[/red]")
            ctx.exit(EXIT_CRYPTO)
            return
        password_summary = _password_match_summary(validated)

    # Use 'layout' instead of 'l'
    ordered_layouts = sorted(overview.layouts, key=lambda layout: layout.descriptor.volume_index)
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
    if password_summary is not None:
        table.add_row("Password matches", password_summary)

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
                status = "authenticated" if desc.volume_index in validated else "locked"
                console.print(
                    "  - "
                    + f"volume {_volume_label(desc.volume_index)} ({status})"
                    + f" (key_mode={_mode_label(desc.key_mode, overview.pq_available)}, size≈{_human_size(layout.ciphertext_len)}, "
                    + f"argon2: mem={desc.argon_mem_cost} KiB, time={desc.argon_time_cost}, p={desc.argon_parallelism}{pq_info})",
                )
        else:
            primary_label = _volume_label(primary_layout.descriptor.volume_index)
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
    help=(
        "Validate container structure and optional integrity without writing files. "
        "Authentication is performed when a password or mode/volume is provided."
    ),
    epilog="Example:\n  zilenc check secret.zil --password pw --volume main",
)
@click.argument("container", type=click.Path(path_type=Path))
@click.option("--password", "password_opt", help="Password for integrity verification (prompts if omitted).")
@click.option(
    "--mode",
    type=click.Choice(["password", "pq-hybrid", "pq_hybrid"], case_sensitive=False),
    default=None,
    show_default=False,
    help=(
        "Force a key mode for authentication (auto by default). Use pq-hybrid only "
        "when oqs is installed; otherwise a PQ support error is reported."
    ),
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

    check_mode = _normalized_mode(mode)
    check_volume = cast(Literal["main", "decoy", "all"], volume)

    def _run() -> None:
        overview, validated = check_container(
            container, password=password, mode=check_mode, volume_selector=check_volume
        )
        # Use 'layout' instead of 'l'
        ordered_layouts = sorted(overview.layouts, key=lambda layout: layout.descriptor.volume_index)
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
                    + f"volume {_volume_label(desc.volume_index)}"
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
        return cli.main(args=argv, prog_name="zilenc", standalone_mode=False)  # type: ignore[no-any-return]
    except SystemExit as exc:  # noqa: TRY003
        code = exc.code if isinstance(exc.code, int) else EXIT_USAGE
        return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
