# Zilant Encrypt

Zilant Encrypt is a modern `.zil` container format and CLI focused on strong
password-based encryption with an optional post-quantum hybrid mode. v3 adds
main + decoy volumes, richer inspection commands, and hardened metadata so the
tool is usable without reading the source.

## Features

* **Post-quantum hybrid encryption** (Argon2id + Kyber768 via `oqs`) with
  automatic fallback to password-only when PQ support is unavailable.
* **Decoy/hidden volumes** for plausible deniability; decoy metadata remains
  undisclosed unless you request verbose volume listings or authenticate it.
* **Auto-volume detection** on decrypt: the password selects the matching volume
  (main or decoy) without extra flags.
* **Structured checks**: `zilenc info` for summaries and `zilenc check` for
  integrity/structure validation without writing files.

## Documentation

* [Usage guide (v3)](docs/USAGE_V3.md) – quickstarts for password-only and
  PQ-hybrid modes, decoy volumes, auto-mode behavior, and common errors.
* [Desktop PQ installation](docs/INSTALL_PQ_DESKTOP.md) – how to install
  `liboqs` and the Python `oqs` bindings on Linux, macOS, and Windows, plus
  fallback behavior when PQ is missing.
* [Technical specification](docs/TECHNICAL_SPEC_V3.md) – full container and
  cryptographic details.

## Installation

```bash
python -m pip install .
# or with dev tools
python -m pip install .[dev]
# desktop GUI extras
python -m pip install .[gui]
```

Launch the desktop shell (requires the `gui` extra):

```bash
python -m zilant_encrypt.gui_app
```

## Quick start

Encrypt a single file (password-only by default):

```bash
zilenc encrypt secrets.txt secrets.zil --password "s3cret"
```

Encrypt a directory (Unicode file names are supported) and let the output
default to `<folder>.zil`:

```bash
zilenc encrypt ./project
```

Enable PQ-hybrid when `oqs` is installed:

```bash
zilenc encrypt report.pdf report.zil --password "pw" --mode pq-hybrid
```

Create main + decoy in one pass:

```bash
zilenc encrypt docs/ vault.zil \
  --password "real-pass" \
  --decoy-password "cover-pass" \
  --decoy-input decoy_notes/
```

Decrypt and let auto-mode pick the right volume for the provided password:

```bash
zilenc decrypt secrets.zil ./restored --password "s3cret"
```

Inspect and verify containers without decrypting payloads:

```bash
zilenc info secrets.zil --volumes
zilenc check secrets.zil --password "s3cret"
```

Use `info` for a high-level overview (format, Argon2 profile, PQ availability);
use `check` as the authoritative integrity tool—it validates layout by default
and authenticates tags when a password is provided.

Advanced Argon2 tuning (optional, defaults remain 64 MiB / 3 / 1):

```bash
zilenc encrypt data.bin data.zil --password "pw" \
  --argon-mem-kib 131072 --argon-time 4 --argon-parallelism 2
```

## v3 container format (brief)

* AES-256-GCM encrypts payloads and authenticates the plaintext header as AAD;
  tampering the header invalidates the GCM tag.
* Per-volume Argon2id parameters (memory, time, parallelism) are stored in the
  header and reproduced during decryption; defaults are 64 MiB, 3 iterations,
  parallelism 1.
* PQ-hybrid metadata adds Kyber768 ciphertext + wrapped secrets. When PQ support
  is missing at runtime, containers created with password-only remain usable;
  PQ-only volumes require `oqs` and fail with exit code `5` otherwise.
* Up to two volumes (main and optional decoy). Decoy headers mirror the main
  structure; `zilenc info` reports a neutral summary by default and only lists
  volumes when `--volumes` is provided or the matching password is supplied.

## Security notes

* AES-256-GCM with Argon2id password derivation by default; PQ-hybrid mixes the
  Argon2id output with the Kyber shared secret before wrapping keys.
* The CLI avoids logging sensitive inputs. Invalid passwords, corrupted
  containers, and missing PQ support surface distinct errors to aid triage.

## Running tests

```bash
PYTHONPATH=src pytest -q
```
