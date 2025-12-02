# Zilant Encrypt

Zilant Encrypt is a password-based container format (`.zil`) and CLI that uses AES-256-GCM
and Argon2id. This 0.1 release focuses on a production-ready password-only mode while
keeping space for future PQ/hybrid features.

## Installation

```bash
python -m pip install .
# or with dev tools
python -m pip install .[dev]
```

## Quick start

Encrypt a single file:

```bash
zilenc encrypt secrets.txt secrets.zil --password "s3cret"
```

Encrypt a directory (unicode file names are supported) and let the output default to
`<folder>.zil`:

```bash
zilenc encrypt ./project
```

Decrypt a container. If `--password` is omitted you will be prompted securely:

```bash
zilenc decrypt secrets.zil restored.txt
zilenc decrypt project.zil ./restored-project
```

Inspect container metadata without decrypting payload:

```bash
zilenc info secrets.zil
```

Key flags:

* `--overwrite/--no-overwrite` – allow replacing existing outputs (files or directories).
* `--password` – pass the password non-interactively; otherwise a TTY prompt is used.
* `--version` – show the CLI version.

## How the container is structured

* A fixed 128-byte header containing magic/version, Argon2id parameters, nonce, and the
  wrapped file key.
* Payload is encrypted with AES-256-GCM using a random file key; the file key is wrapped
  with a password-derived key (Argon2id).
* Directory inputs are archived into a ZIP before encryption; on decrypt they are
  unpacked into the provided output path.

## Security notes

* Password-only mode with AES-256-GCM and Argon2id.
* Default Argon2id profile: 64 MiB memory, time_cost=3, parallelism=1 – a balanced
  setting for interactive use while resisting brute force.
* No post-quantum/hybrid keying or hidden volumes yet; these are planned for future
  releases.

## Limitations in 0.1

* Only password-based containers are supported.
* No GUI and no PQ/hybrid wrapping yet.

## Running tests

```bash
PYTHONPATH=src pytest -q
```
