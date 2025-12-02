# Zilant Encrypt v3 usage guide

This guide shows how to use the v3 CLI (`zilenc`) without reading the source
code. Commands work in password-only mode by default and switch to
post-quantum (PQ) hybrid encryption when `liboqs` and the `oqs` Python binding
are available.

## Quickstart

### Password-only mode

Encrypt a file or directory with a password (Argon2id, AES-256-GCM):

```bash
zilenc encrypt secrets.txt secrets.zil --password "s3cret"
zilenc encrypt ./folder  # output defaults to ./folder.zil
```

Decrypt and let `zilenc` auto-detect the correct volume based on the password:

```bash
zilenc decrypt secrets.zil ./restored --password "s3cret"
```

### PQ-hybrid mode

When `oqs` is installed and the Kyber768 KEM is available, enable hybrid key
wrapping. The master key mixes the Argon2id password key with the Kyber shared
secret.

```bash
zilenc encrypt data.bin data.zil --password "p@ss" --mode pq-hybrid
zilenc decrypt data.zil ./out --password "p@ss" --mode pq-hybrid
```

If PQ support is missing, the CLI returns exit code `5` with the message
"container requires PQ support that is not available".

### Main + decoy in one pass

Create a primary volume and a decoy volume together. The decoy payload defaults
to the main input if `--decoy-input` is omitted.

```bash
zilenc encrypt docs/ vault.zil \
  --password "real-pass" \
  --decoy-password "cover-pass" \
  --decoy-input decoy_notes/
```

To decrypt, supply the matching password. Auto-mode will select the volume that
matches the password, or you can force a target volume:

```bash
zilenc decrypt vault.zil ./real --password "real-pass"       # main
zilenc decrypt vault.zil ./cover --password "cover-pass"     # decoy
zilenc decrypt vault.zil ./cover --password "cover-pass" --volume decoy
```

### Adding a decoy volume to an existing container

For v3 containers, you can add a decoy volume later:

```bash
zilenc encrypt payload.bin vault.zil --password "main-pass"
zilenc encrypt decoy.bin vault.zil --password "decoy-pass" --volume decoy
```

### Auto-volume and auto-mode

* `zilenc decrypt <container>` defaults to `<container>.out` when no output is
  provided.
* When no `--volume` is supplied, `zilenc` attempts to open whichever volume
  matches the password (main or decoy) and reports which one succeeded.
* `--mode` is normally auto-detected. Force `--mode pq-hybrid` only when you
  know the container was created with PQ and the local `oqs` dependency is
  installed.

### Advanced Argon2 tuning

Defaults remain 64 MiB memory, 3 iterations, parallelism 1. Override them when
you need a stronger KDF profile and accept longer runtime:

```bash
zilenc encrypt secrets/ vault.zil --password "pw" \
  --argon-mem-kib 131072 --argon-time 4 --argon-parallelism 2
```

Supported ranges: memory between 32 MiB and 2 GiB, time cost 1–10, parallelism
1–8. Values outside these ranges are rejected.

## Inspecting containers

Show header metadata without decrypting payloads:

```bash
zilenc info vault.zil            # concise summary
zilenc info vault.zil --volumes  # per-volume details
```

Validate structure (and optionally authentication tags) without writing files:

```bash
zilenc check vault.zil                       # structural check only
zilenc check vault.zil --password "pw"      # also verify tags
zilenc check vault.zil --volume decoy --verbose
```

`info` lists algorithms (AES-256-GCM, Kyber768 when present), Argon2 parameters,
and whether PQ support is available locally. The default summary is neutral for
decoy-aware layouts (e.g. `1 (outer; additional volumes may be present)`); add
`--password` to authenticate a volume and `--volumes` to reveal per-volume
details.

`check` is the preferred integrity tool: it validates container layout even
without a password and authenticates tags when credentials are supplied.

## Exit codes and common errors

* `0` – success
* `1` – usage error (bad arguments, unsupported feature)
* `2` – invalid password or key
* `3` – filesystem error (permissions, missing files when reading/writing)
* `4` – container is corrupted or not supported
* `5` – PQ support required but not available

Typical messages:

* `Invalid password or key` – the supplied password does not unlock any volume.
* `Error: container is corrupted or not supported` – header or payload failed
  integrity checks, or the file is not a valid `.zil` container.
* `Error: container requires PQ support that is not available` – the container
  needs Kyber768 via `oqs` but the dependency is missing.

On decryption, if PQ is unavailable but the container has a password-only
fallback, `zilenc` will continue in password mode; otherwise it stops with exit
code `5`.

## Notes on the v3 format

* AES-GCM authenticates the plaintext header as AAD; any tampering is detected
  when tags are verified.
* Argon2id parameters (memory, time, parallelism) are stored per volume in the
  header and reproduced on decrypt.
* Containers support a main volume and an optional decoy. Decoy metadata is
  indistinguishable from the primary volume; `info` hides decoy entries unless
  `--volumes` is provided or the decoy password is validated.
