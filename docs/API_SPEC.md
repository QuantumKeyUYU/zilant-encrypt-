# Zilant Encrypt v0.2 Public API Specification

This document defines the supported public surface for the v0.2 release. It
covers both the Python library and the `zilenc` CLI. Anything not covered here
is considered internal and may change without notice.

## Architecture overview

Zilant Encrypt implements authenticated containers with optional decoy volumes
and PQ-hybrid key wrapping. The stack is split into layers:

- **Core orchestration (`zilant_encrypt.container.core`)** – volume creation,
  encryption/decryption flows, mode normalization, Argon2 parameter handling.
- **Key management (`zilant_encrypt.container.keymgmt`)** – password-based key
  derivation and wrapping helpers, Argon2 validation, PQ availability checks.
- **Payload streaming (`zilant_encrypt.container.payload`)** – streaming AES-GCM
  encryption/decryption over files or directories, payload metadata handling.
- **Container overview/layout (`zilant_encrypt.container.overview`)** – parsing
  container headers, computing ciphertext lengths, summarizing layout.
- **Wire format (`zilant_encrypt.container.format`)** – header constants and
  serialization helpers, plus basic header inspection for info/check commands.
- **CLI (`zilant_encrypt.cli`)** – user-facing commands (`encrypt`, `decrypt`,
  `info`, `check`) layered on top of the public container API.

All layers live under the `zilant_encrypt.container` namespace. Public
re-exports are exposed via `zilant_encrypt.container` and are listed below.

## Public Python API

Import the supported surface from `zilant_encrypt.container`:

```python
from zilant_encrypt.container import (
    ARGON_MEM_MAX_KIB, ARGON_MEM_MIN_KIB,
    ARGON_PARALLELISM_MAX, ARGON_PARALLELISM_MIN,
    ARGON_TIME_MAX, ARGON_TIME_MIN,
    Argon2Params,
    ContainerOverview,
    KEY_MODE_PASSWORD_ONLY, KEY_MODE_PQ_HYBRID,
    MAX_PAYLOAD_META_LEN, PAYLOAD_MAGIC, PAYLOAD_META_LEN_SIZE, PAYLOAD_VERSION,
    ModeLiteral,
    PasswordKeyProvider, PayloadMeta,
    STREAM_CHUNK_SIZE,
    VolumeLayout, WrappedKey, WRAP_NONCE,
    build_volume_descriptor,
    check_container,
    decrypt_auto_volume,
    decrypt_file,
    encrypt_file,
    encrypt_with_decoy,
    normalize_mode,
    read_header_from_stream,
    resolve_argon_params,
)
```

### High-level operations

- `encrypt_file(in_path: Path, out_path: Path, password: str, *, overwrite=False,
  mode: ModeLiteral | None = None, volume_selector="main", argon_params: Argon2Params | None = None) -> None`
  - Encrypts a file or directory into a `.zil` container. Creates the main
    volume; `volume_selector="decoy"` is rejected (use `encrypt_with_decoy`).
  - `mode` defaults to password-only unless explicitly set to `"pq-hybrid"`.
  - `overwrite=True` replaces an existing target (file or directory).
- `encrypt_with_decoy(main_input: Path, decoy_or_out: Path | None = None,
  out_path: Path | None = None, *, main_password: str | None = None,
  password: str | None = None, decoy_password: str,
  input_path_decoy: Path | None = None, decoy_input: Path | None = None,
  mode: ModeLiteral | None = None, overwrite: bool = False,
  argon_params: Argon2Params | None = None) -> None`
  - Builds a container with both main (index 0) and decoy (index 1) volumes in
    one pass. `main_password` or `password` is required for the main volume; a
    distinct `decoy_password` is required for the decoy volume.
  - Optional `decoy_input`/`input_path_decoy` selects a separate decoy payload.
- `decrypt_file(container_path: os.PathLike | str, out_path: os.PathLike | str,
  password: str, *, overwrite: bool = False, mode: ModeLiteral | None = None,
  volume_selector: Literal["main", "decoy"] = "main") -> None`
  - Decrypts a specific volume (main or decoy) into `out_path`.
- `decrypt_auto_volume(container_path: os.PathLike | str, out_path: os.PathLike | str,
  *, password: str, mode: ModeLiteral | None = None, overwrite: bool = False)
  -> tuple[int, str]`
  - Attempts to decrypt any volume that matches the supplied password, returning
    `(volume_index, volume_label)` on success. Fails with `InvalidPassword` if no
    volume accepts the password.
- `check_container(container_path: os.PathLike | str, *, password: str | None = None,
  mode: ModeLiteral | None = None, volume_selector: Literal["main", "decoy", "all"] = "all")
  -> tuple[ContainerOverview, list[int]]`
  - Validates structural integrity and (when a password is provided) verifies
    authentication tags for the selected volumes. Returns an overview and the
    list of validated volume indices.

### Supporting types and helpers

- `Argon2Params(mem_cost_kib: int, time_cost: int, parallelism: int)` – dataclass
  configuring Argon2id. Use `resolve_argon_params(base: Argon2Params | None = None)`
  to merge user input with safe defaults while enforcing limits
  (`ARGON_MEM_MIN_KIB..ARGON_MEM_MAX_KIB`, `ARGON_TIME_MIN..ARGON_TIME_MAX`,
  `ARGON_PARALLELISM_MIN..ARGON_PARALLELISM_MAX`).
- `ModeLiteral` – "password" or "pq-hybrid". Normalize user input via
  `normalize_mode(mode: str | None)`.
- `PasswordKeyProvider(password: str, salt: bytes, params: Argon2Params)` –
  utility for deriving and wrapping file keys with Argon2id + AES-GCM.
- `WrappedKey(data: bytes, tag: bytes)` and `WRAP_NONCE` – low-level key wrap
  helpers for advanced integrations.
- `ContainerOverview` and `VolumeLayout` – parsed header/volume metadata from
  `_load_overview`, exposed through `check_container` for inspection purposes.
- `PayloadMeta`, `MAX_PAYLOAD_META_LEN`, `PAYLOAD_MAGIC`, `PAYLOAD_META_LEN_SIZE`,
  `PAYLOAD_VERSION`, `STREAM_CHUNK_SIZE` – constants describing payload framing.
- `build_volume_descriptor(...) -> VolumeDescriptor` – advanced helper for
  constructing descriptors when integrating custom pipelines (supported but
  intended for power users).
- `read_header_from_stream(io.BufferedReader) -> tuple[Header, list[VolumeDescriptor], bytes]`
  - Light-weight parser to inspect headers without processing payloads.

### Exceptions

All exceptions live in `zilant_encrypt.errors`:

- `ZilantEncryptError` – base class for all library errors.
- `ContainerFormatError` – malformed header or container layout issues.
- `InvalidPassword` – password cannot unwrap the key for the requested volume.
- `IntegrityError` – authentication tag mismatch during decryption.
- `UnsupportedFeatureError` – caller requested an unsupported feature or mode
  (e.g., conflicting key modes across volumes).
- `PqSupportError` – PQ-hybrid requested/required but `oqs` is unavailable.

Library calls raise standard filesystem errors (`FileNotFoundError`,
`FileExistsError`, `PermissionError`, `OSError`) when IO fails.

### Error model & compatibility guarantees

- **Usage errors**: `UnsupportedFeatureError`, `InvalidPassword` when mismatched
  volume/mode is selected.
- **Crypto errors**: `IntegrityError`, `InvalidPassword` for unwrap failures.
- **Filesystem errors**: propagated `OSError` subclasses when reading/writing
  inputs or outputs.
- **PQ unsupported**: `PqSupportError` when PQ-hybrid is requested or required
  but `oqs` is absent.
- **Corrupt containers**: `ContainerFormatError` on malformed headers/payload
  sizing.

Within the v0.x line:
- Patch releases keep signatures and semantics stable.
- Minor releases may add new optional parameters or constants but do not break
  existing behavior without deprecation notes.
- Anything outside the surface listed in this section is internal and may change
  between releases.

## CLI specification (`zilenc`)

### Commands and options

- `encrypt <input_path> [output_path] [--password TEXT] [--decoy-password TEXT]
  [--decoy-input PATH] [--mode {password,pq-hybrid}] [--argon-mem-kib INT]
  [--argon-time INT] [--argon-parallelism INT] [--volume {main,decoy}] [--overwrite]`
  - Creates a container from a file or directory. When both `--password` and
    `--decoy-password` are supplied, `encrypt` produces a main+decoy layout in
    one pass (decoy payload defaults to the main input unless `--decoy-input`
    overrides it).
  - `--volume decoy` adds a decoy volume to an existing container built with the
    same mode; header integrity must be preserved.
- `decrypt <container> [output_path] --password TEXT [--mode {password,pq-hybrid}]
  [--volume {auto,main,decoy}] [--overwrite]`
  - Defaults to auto-volume selection; with `--volume main|decoy` it targets a
    specific volume. `output_path` defaults to `<container>.out`.
- `info <container> [--password TEXT] [--volumes] [--verbose]`
  - Prints header metadata; with `--password` it authenticates a matching volume
    without writing files.
- `check <container> [--password TEXT] [--mode {password,pq-hybrid}] [--volume {main,decoy,all}] [--verbose]`
  - Validates structure and, when a password is provided, verifies tags for the
    chosen volumes without decrypting payloads.

### Exit codes

- `0` (`EXIT_SUCCESS`) – command completed successfully.
- `1` (`EXIT_USAGE`) – invalid arguments or unsupported feature/mode.
- `2` (`EXIT_CRYPTO`) – bad password or unwrap failure.
- `3` (`EXIT_FS`) – filesystem error (missing file, permissions, IO failure).
- `4` (`EXIT_CORRUPT`) – container corrupted or failed integrity check.
- `5` (`EXIT_PQ_UNSUPPORTED`) – PQ-hybrid requested or required but `oqs`
  bindings are unavailable.

### PQ-hybrid mode

- When `--mode pq-hybrid` is selected (or when decrypting a PQ-hybrid volume),
  the CLI requires `oqs` and Kyber768 support. If unavailable, it prints a
  PQ-specific error and exits with code 5.
- Hybrid derivation combines the Argon2id password key with the Kyber shared
  secret through HKDF; both secrets must be present to unwrap the payload key.

### Security and validation invariants

- **Argon2id bounds**: memory cost enforced between
  `ARGON_MEM_MIN_KIB`..`ARGON_MEM_MAX_KIB`; time cost between
  `ARGON_TIME_MIN`..`ARGON_TIME_MAX`; parallelism between
  `ARGON_PARALLELISM_MIN`..`ARGON_PARALLELISM_MAX`.
- **PQ availability**: decrypt/encrypt paths that need PQ-hybrid always verify
  `oqs` availability before proceeding.
- **Container parsing**: header offsets and ciphertext lengths are checked to
  prevent zip-slip style path traversal, oversized metadata, or invalid payload
  lengths.
- **Streaming**: payload encryption/decryption is streaming with fixed chunk
  sizing (`STREAM_CHUNK_SIZE`) to limit memory usage; authentication tags are
  validated before any decrypted data is released to callers.

## Versioning & compatibility

- Public API is the surface listed in this document plus the `__version__`
  attribute at `zilant_encrypt.__version__`.
- CLI commands/options, exit codes, and mode semantics are stable for v0.2. New
  options may be added in future minor releases but existing behavior will not be
  broken without prior notice.
- Internal modules not explicitly documented (e.g., `container.api`, private
  helpers prefixed with `_`, and most symbols outside `zilant_encrypt.container`
  `__all__`) are unstable.

## Example flows

### Python round-trip

```python
from pathlib import Path
from zilant_encrypt.container import encrypt_file, decrypt_auto_volume

src = Path("./secret.txt")
container = Path("./secret.zil")
output = Path("./restored")

encrypt_file(src, container, "password123")
volume_index, label = decrypt_auto_volume(container, output, password="password123")
assert label == "main"
```

### CLI quick start

```bash
zilenc encrypt notes.txt notes.zil --password "pw"
zilenc decrypt notes.zil ./notes --password "pw"  # auto-volume
zilenc info notes.zil --volumes
zilenc check notes.zil --password "pw" --volume all
```
