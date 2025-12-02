# Installing PQ support on desktop

Zilant Encrypt v3 ships with a PQ-hybrid mode that wraps the file key using
Argon2id (password) plus the CRYSTALS-Kyber768 KEM via the `oqs` library. The
CLI works in password-only mode even when PQ is missing. PQ is activated when
both the `liboqs` shared library and the Python `oqs` bindings are present.

## Linux

1. Install the shared library. Examples:
   * Debian/Ubuntu: `sudo apt install liboqs-dev` (or build from source if the
     package is unavailable).
   * Fedora: `sudo dnf install liboqs-devel`.
   * From source: clone `https://github.com/open-quantum-safe/liboqs` and run
     `cmake -S . -B build -DBUILD_SHARED_LIBS=ON && cmake --build build --target install`.
2. Install the Python binding: `python -m pip install oqs`.
3. Ensure your linker can find `liboqs.so` (e.g., `/usr/lib`, `/usr/local/lib`,
   or update `LD_LIBRARY_PATH`).

## macOS

1. Install the Homebrew formula: `brew install open-quantum-safe/liboqs/liboqs`.
2. Install the Python binding: `python -m pip install oqs`.
3. If `liboqs.dylib` lives in a non-standard path, export
   `DYLD_LIBRARY_PATH=/opt/homebrew/lib` (or similar) before running `zilenc`.

## Windows

1. Install the Microsoft Visual C++ Build Tools (for compiling dependencies).
2. Build `liboqs` from source or install via vcpkg:
   * vcpkg: `vcpkg install oqs` and ensure the resulting DLL is on your `%PATH%`.
   * Manual build: clone `liboqs`, run `cmake -S . -B build -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=ON`, then
     `cmake --build build --config Release`.
3. Install the Python binding in the same environment: `python -m pip install oqs`.
4. Make sure `oqs.dll` is discoverable (e.g., add the build output directory to
   `%PATH%`).

## Behavior when PQ is missing

* Encryption defaults to password-only. If you request `--mode pq-hybrid`
  without a working `oqs` installation, `zilenc` exits with code `5` and prints
  `Error: container requires PQ support that is not available`.
* Decryption auto-detects the container. If PQ metadata is present but `oqs`
  cannot load, `zilenc` stops with exit code `5`. Containers that include a
  password-only fallback can still open in classic mode; otherwise, PQ is
  required.
* The rest of the CLI (info/check) remains usable and will report that PQ is
  unavailable locally.
