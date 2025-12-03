# Zilant Encrypt v0.2 Usage Guide

This guide shows how to use Zilant Encrypt as an end user. For a formal contract
of the public API, see [API_SPEC.md](./API_SPEC.md).

## Installation

```
pip install zilant-encrypt
```

PQ-hybrid mode requires `liboqs` and the `oqs` Python binding. See
`docs/INSTALL_PQ_DESKTOP.md` for platform notes.

## Desktop GUI

Install the optional GUI extras and launch the desktop shell:

```
pip install "zilant-encrypt[gui]"
zilenc-gui
```

The GUI mirrors the CLI feature set:

- **Encrypt / Decrypt** tab: grouped blocks for mode selection, source/destination, password &
  security mode, decoy configuration, and advanced decrypt options (auto/main/decoy, assume
  PQ-hybrid). The action button flips between Encrypt/Decrypt, and an “Open output folder” shortcut
  appears after success.
- **Decoy volume** support: enable the decoy toggle, set a decoy password, and choose a decoy input
  (or reuse the main input by leaving it blank).
- **Inspect / Check** tab: choose a container, optionally enable “Run full integrity check” with a
  password, then click **Inspect container** to view a read-only report (version, volumes, PQ
  availability, and validation status) without decrypting payloads.
- Version is displayed in the window title and in the About dialog for quick verification.

## CLI quickstart

The CLI entry point is `zilenc`.

### Encrypt a single file

```bash
zilenc encrypt secrets.txt secrets.zil --password "s3cret"
```

### Encrypt a directory to `.zil`

```bash
zilenc encrypt ./folder  # output defaults to ./folder.zil
```

### Create main + decoy in one step

```bash
zilenc encrypt docs/ vault.zil \
  --password "real-pass" \
  --decoy-password "cover-pass" \
  --decoy-input decoy_notes/
```

### Decrypt

- Auto-volume (default):

  ```bash
  zilenc decrypt vault.zil ./restored --password "real-pass"
  ```

- Force a specific volume:

  ```bash
  zilenc decrypt vault.zil ./cover --password "cover-pass" --volume decoy
  ```

- PQ-hybrid: add `--mode pq-hybrid` when the container was created in hybrid
  mode and `oqs` is available.

### Inspect without decrypting

- Header summary:

  ```bash
  zilenc info vault.zil --volumes
  ```

- Integrity check (structure + optional tag validation):

  ```bash
  zilenc check vault.zil
  zilenc check vault.zil --password "real-pass" --volume all
  ```

### Argon2 tuning

Defaults: 64 MiB memory, time cost 3, parallelism 1. Override within supported
ranges:

```bash
zilenc encrypt secrets/ vault.zil --password "pw" \
  --argon-mem-kib 131072 --argon-time 4 --argon-parallelism 2
```

## Python examples

```python
from pathlib import Path
from zilant_encrypt.container import (
    encrypt_file, decrypt_auto_volume, check_container,
)

src = Path("./demo.txt")
container = Path("./demo.zil")
output = Path("./restored.txt")
password = "demo-pass"

# Create the container
encrypt_file(src, container, password)

# Check structure and authenticate the main volume
overview, validated = check_container(container, password=password, volume_selector="main")
print("validated", validated)

# Decrypt using auto-volume selection
volume_index, label = decrypt_auto_volume(container, output, password=password)
print(volume_index, label)
```

## Common CLI exit codes

- `0` – success
- `1` – usage error or unsupported feature/mode
- `2` – invalid password / unwrap failure
- `3` – filesystem error (missing file, permissions, IO failure)
- `4` – container corrupted or integrity check failed
- `5` – PQ-hybrid requested/required but `oqs` is unavailable

## Additional references

- [API_SPEC.md](./API_SPEC.md) – formal public API definition and compatibility
  guarantees.
- [TECHNICAL_SPEC_V3.md](./TECHNICAL_SPEC_V3.md) – implementation details for the
  container format.
