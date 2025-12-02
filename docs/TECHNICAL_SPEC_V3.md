# Zilant Encrypt v3 Technical Specification

This document defines the scope, architecture, and behavioral requirements for the
v3 release of Zilant Encrypt. It covers hybrid post-quantum support, container
format hardening, CLI/UX improvements, testing, and documentation targets.

## 1. Desktop PQ-hybrid encryption

### 1.1 PQ engine and algorithm
- Primary post-quantum KEM: **CRYSTALS-Kyber768** via the vetted liboqs
  implementation and its Python bindings (`oqs`). No home-grown PQ crypto is
  permitted.
- Hybrid key derivation: combine the Argon2id-derived key with the Kyber shared
  secret to form a master key (e.g., HKDF or key concatenation followed by a
  KDF) for wrapping the file key and for AES-GCM payload encryption.

### 1.2 Platform compatibility
- Supported desktop OSes: Linux, Windows, macOS (x86_64 and ARM64).
- The Python codebase must stay portable; external deps (liboqs shared library
  and Python bindings) need install guidance per OS.
- Provide installation instructions for liboqs (package manager or source
  build) and the `oqs` Python package for every supported platform.

### 1.3 Engine probing and fallback
- On startup, attempt to load the PQ engine (e.g., import `oqs`, load the shared
  library).
- If unavailable or initialization fails, automatically fall back to
  password-only mode and emit a clear warning such as: "PQ engine not found –
  using password-only encryption." The application must remain fully usable in
  this mode.

## 2. Mobile PQ support and compatibility mode

### 2.1 Feasibility analysis
- Assess PQ-hybrid viability on **Android** and **iOS**: availability of liboqs
  builds, performance of Kyber768, quality of random sources, and safe key
  storage.
- Android path: build liboqs with NDK, bundle into the app, and bridge via
  JNI/Python (e.g., Chaquopy/Kivy). Secrets should leverage Android KeyStore or
  protected memory.
- iOS path: compile liboqs for iOS and wrap via Swift/Obj-C, or run Python via
  Kivy-iOS/Pyodide. Key material should use the iOS Keychain; consider WASM
  limitations when using Pyodide.

### 2.2 Fallback behavior on mobile
- If PQ support is not reliable on mobile, disable PQ-hybrid there and operate
  in password-only mode.
- Containers created with PQ on desktop must offer a compatibility path: if a
  mobile device lacks PQ, it can decrypt only when a password-only fallback was
  embedded. The app must state that PQ encryption is unsupported when a PQ-only
  container is opened.

## 3. Container format hardening

### 3.1 AEAD for header integrity
- Use AES-GCM with the container header supplied as **AAD**; the header stays
  in plaintext but is authenticated by the GCM tag. Any tampering must cause
  authentication failure.

### 3.2 Configurable Argon2 parameters
- Support user- or policy-configurable Argon2 settings: memory, time
  (iterations), and parallelism. Default profile: Argon2id, 64 MiB, 3
  iterations, parallelism 1.
- Persist the actual Argon2 parameters in the container metadata so decryption
  can reproduce the derivation.

### 3.3 Volume limits and layout
- Limit the number of volumes per container (recommend **max two**: primary and
  hidden/decoy).
- Forbid overlapping data regions between volumes. If a hidden volume design
  requires reuse of free space, document and guard it carefully; otherwise avoid
  overlap entirely.

### 3.4 Decoy hygiene and metadata unification
- `--info` (or equivalent) must list only volumes proved by the supplied
  credential; decoy volumes remain undisclosed by default to preserve plausible
  deniability.
- PQ-related metadata must not leak which volumes are real or decoy. All volume
  headers must share the same structure and lengths; PQ fields must exist (with
  random fillers when unused) so that hidden volumes are indistinguishable by
  size or layout.

## 4. CLI and UX improvements

### 4.1 Error messaging
- Differentiate common failure cases:
  - Wrong password/key: "Invalid password or key."
  - Corrupted/unsupported container: "Error: container is damaged or not
    supported."
  - Missing PQ support when required: "Error: container requires PQ support
    that is not available."
  - Unsupported/expired format version: "Container version is not supported by
    this program."
- Offer remediation hints where possible (update software, install PQ engine,
  retry password, etc.).

### 4.2 `check` command
- Add `zilenc check <container>` (or similar) to validate container structure
  without mounting:
  - Verify header structure, field sizes, AAD tag correctness, and offsets.
  - Detect truncated files, bad tags, invalid counts, or unsupported versions.
  - Report "Check passed" on success or list detected issues (e.g., "AAD tag
    mismatch; file may be corrupted").

### 4.3 Expanded `--info`
- Include algorithms (AES-256-GCM, Kyber768 when applicable), KDF profile and
  parameters, per-volume sizes and total size, PQ status, number of volumes, and
  decoy posture. If only the outer volume is opened, indicate potential hidden
  volumes without confirming their presence.

## 5. Testing and security auditing

### 5.1 Negative and robustness tests
- Cover malformed inputs: truncated headers, extra bytes, damaged PQ fields,
  tampered GCM tags or AAD, invalid volume counts/overlaps.
- Ensure the program surfaces clear, distinct errors rather than generic
  failures or crashes.

### 5.2 Large-file handling
- Exercise encryption/decryption of very large containers (tens of GiB) and
  monitor memory/time usage, especially with high Argon2 settings. Optimize for
  streaming where needed.

### 5.3 Auto-mode coverage
- Test auto-detection: PQ containers decrypt with PQ when available; if PQ is
  missing and a password fallback exists, decryption continues in password mode.
- Verify correct volume selection: outer vs hidden passwords open only their
  respective volumes; wrong passwords mount nothing.
- Mixed PQ/non-PQ volumes must route through the appropriate decryption path
  without cross-applying PQ to classic volumes or vice versa.

### 5.4 Static analysis and side-channel hygiene
- Run Bandit/linters; avoid insecure primitives and accidental logging of
  secrets.
- Use constant-time comparisons (e.g., `hmac.compare_digest`) for authenticity
  checks and other secret data comparisons.
- Keep release builds free of debug logs that could leak cryptographic state.

## 6. Documentation and examples (v3)

- Document the v3 container format, including new PQ fields, AAD usage, volume
  limits, and metadata layout.
- Describe UX changes: `check` command, richer `info`, and error messaging with
  usage examples.
- Explain auto-decrypt decision flow with scenarios (PQ available vs absent,
  outer vs hidden volume passwords).
- Define decoy/hidden volume behavior and operational guidance for plausible
  deniability.
- Provide diagrams for encryption, decryption/auto-detection, and the v3
  container layout.
- Publish platform-specific build/run guides:
  - **With PQ**: installing liboqs and Python bindings on Linux/macOS/Windows;
    enabling PQ mode or autodetecting it.
  - **Without PQ**: how to install/run in password-only mode, including any
    build-time switches if applicable.
  - **Mobile (if offered)**: Android/iOS build steps, SDK/NDK/Xcode requirements,
    and key storage constraints.
- Add usage examples: creating PQ-enabled containers, opening hidden vs outer
  volumes, running `check`, and interpreting outputs for healthy vs corrupted
  containers.

