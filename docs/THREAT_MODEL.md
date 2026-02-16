# Zilant Encrypt — Threat Model

## 1. What Zilant Encrypt Protects Against

### 1.1 At-Rest Data Theft
**Threat:** An attacker gains access to encrypted `.zil` files (stolen laptop, cloud breach, USB loss).

**Protection:** AES-256-GCM provides authenticated encryption with 256-bit security. File keys are wrapped with Argon2id-derived keys (64 MiB memory, 3 iterations default), making offline brute-force impractical for passwords with ≥60 bits of entropy.

### 1.2 Password Brute-Force
**Threat:** An attacker attempts to crack the password offline.

**Protection:** Argon2id (winner of the Password Hashing Competition) with configurable memory-hard parameters. Default: 64 MiB RAM, 3 iterations, parallelism 1. Each derivation takes ~0.5-1s on modern hardware. At $0.01/hash on cloud GPU, a 12-character mixed-case+digit+symbol password (~78 bits) would cost ~$10^14 to crack.

### 1.3 Quantum Computing (Future Threat)
**Threat:** A sufficiently powerful quantum computer breaks classical key exchange.

**Protection:** Optional PQ-hybrid mode combines Kyber768 (ML-KEM) with Argon2id via HKDF-SHA256. Even if Kyber768 is broken, the password-derived key remains as a fallback. Even if the password is weak, Kyber768 provides protection.

### 1.4 Coercion / Plausible Deniability
**Threat:** An adversary forces the user to reveal their password.

**Protection:** Decoy volumes allow two independent encrypted payloads in one container. The user can reveal the decoy password while keeping the main volume secret. Key properties:
- Password-only and PQ-hybrid containers are structurally identical (PQ placeholder fields filled with random data)
- Both volumes use identical `meta_len` values
- No header field reveals the number of volumes or which mode is in use
- Auto-volume detection tries all volumes for every password (timing-equalized)

### 1.5 Header Tampering
**Threat:** An attacker modifies the container header to downgrade security parameters or redirect decryption.

**Protection:** The entire header is used as Additional Authenticated Data (AAD) for AES-GCM payload encryption. Any modification to any header byte causes the GCM authentication tag to fail during decryption.

### 1.6 Key Material Leakage
**Threat:** Key material persists in memory after use (cold boot attack, memory dump).

**Protection:**
- File keys and derived keys use mutable `bytearray` with explicit zeroing in `finally` blocks
- Read-back barrier after zeroing to prevent compiler optimization
- Optional `mlock` support (`SecureBuffer`) to prevent key material from being swapped to disk
- HKDF-derived wrap nonces per container (no fixed nonce reuse)

---

## 2. What Zilant Encrypt Does NOT Protect Against

### 2.1 Evil Maid / Pre-Boot Attacks
If an attacker has physical access to the device BEFORE the user decrypts, they can install keyloggers or modify the `zilenc` binary. Zilant Encrypt does not verify its own integrity.

**Mitigation:** Use full-disk encryption (LUKS, BitLocker, FileVault) and Secure Boot.

### 2.2 Rubber Hose Cryptanalysis
If an adversary uses physical coercion, the decoy volume feature provides limited plausible deniability. However, if the adversary knows Zilant Encrypt supports decoy volumes, they may demand both passwords.

**Mitigation:** The structural indistinguishability of single-volume and dual-volume containers helps, but this is not a guarantee against a determined adversary.

### 2.3 Compromised System (Malware)
If the operating system is compromised, malware can intercept passwords during input, read decrypted files, or exfiltrate key material from memory.

**Mitigation:** Use a trusted, up-to-date operating system. Consider air-gapped encryption for highest-sensitivity data.

### 2.4 Side-Channel Attacks
Python's runtime does not guarantee constant-time operations. The `cryptography` library uses OpenSSL which provides constant-time primitives, but Python-level operations (password comparison, key XOR) may leak timing information.

**Mitigation:** Critical cryptographic operations are delegated to C-level libraries (OpenSSL, argon2-cffi). Auto-volume detection performs key derivation for all volumes to equalize timing.

### 2.5 Traffic Analysis / Metadata
Zilant Encrypt does not hide:
- File sizes (container size ≈ plaintext size + header)
- Access timestamps (filesystem-level)
- The fact that encryption is being used (the `.zil` extension and `ZILENC` magic bytes are identifiable)

**Mitigation:** Use in combination with steganography or encrypted filesystems for metadata privacy.

### 2.6 Implementation Bugs
Zilant Encrypt has not undergone a formal third-party security audit. While the cryptographic primitives (AES-GCM, Argon2id, Kyber768, HKDF-SHA256) are well-vetted, the integration layer may contain bugs.

**Mitigation:** The project maintains >80% test coverage, property-based fuzzing of header parsing, and robustness tests for tampered/truncated containers. A formal audit is recommended before use in high-stakes scenarios.

---

## 3. Security Architecture Summary

```
Password + Salt ──→ Argon2id ──→ password_key ──┐
                                                  ├──(XOR)──→ combined_key
Keyfile (optional) ──→ SHA-256 ──→ keyfile_mat ──┘
                                                       │
                    ┌──────────────────────────────────┘
                    │
                    ▼
           ┌─── password-only mode ───┐     ┌─── pq-hybrid mode ──────────────┐
           │                          │     │                                   │
           │  AES-GCM-Wrap(           │     │  KEM = Kyber768.Encap(pk)        │
           │    key=combined_key,     │     │  HKDF(shared_secret ‖ password_  │
           │    nonce=HKDF(salt),     │     │        key, salt, "zilant-pq")   │
           │    plaintext=file_key    │     │        → master_key              │
           │  ) → wrapped_key         │     │  AES-GCM-Wrap(master_key,        │
           │                          │     │    file_key) → wrapped_key       │
           └──────────────────────────┘     └──────────────────────────────────┘
                    │
                    ▼
           AES-256-GCM(
             key=file_key,
             nonce=random_12,
             aad=header_bytes,
             plaintext=payload
           ) → ciphertext ‖ tag
```

---

## 4. Cryptographic Primitive Justification

| Primitive | Choice | Rationale |
|-----------|--------|-----------|
| Symmetric cipher | AES-256-GCM | NIST standard, hardware-accelerated (AES-NI), provides both confidentiality and authenticity |
| KDF | Argon2id v1.9 | PHC winner, memory-hard, resistant to GPU/ASIC attacks, recommended by OWASP |
| PQ-KEM | Kyber768 (ML-KEM) | NIST FIPS 203, IND-CCA2 secure, 192-bit post-quantum security level |
| Key combination | HKDF-SHA256 | NIST SP 800-56C compliant, standard for combining multiple key materials |
| Key wrapping | AES-256-GCM with HKDF-derived nonce | Each container has a unique wrap nonce derived from its unique salt |
| Keyfile hashing | SHA-256 | Standard, collision-resistant, combined via XOR with password key |

---

## 5. Recommended Usage

1. **Use strong passwords** (12+ characters, mixed case/digits/symbols, ≥60 bits entropy)
2. **Enable keyfile** for high-value data (`--keyfile`)
3. **Use PQ-hybrid mode** when protecting data with >10 year sensitivity horizon
4. **Use decoy volumes** only when plausible deniability is needed (adds complexity)
5. **Keep backups** of keyfiles in a separate secure location
6. **Verify containers** periodically with `zilenc check --password`
