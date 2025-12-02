"""Optional post-quantum KEM helpers (experimental)."""

from __future__ import annotations

try:  # pragma: no cover - optional dependency
    import oqs

    _OQS_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    _OQS_AVAILABLE = False


def available() -> bool:
    """Return True if the oqs library is importable."""

    return _OQS_AVAILABLE


def _ensure_available() -> None:
    if not _OQS_AVAILABLE:
        raise RuntimeError("PQ KEM support is not available (oqs not installed)")


def generate_kem_keypair() -> tuple[bytes, bytes]:
    """Generate a Kyber768 KEM keypair."""

    _ensure_available()
    with oqs.KeyEncapsulation("Kyber768") as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    return public_key, secret_key


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret for the provided public key."""

    _ensure_available()
    with oqs.KeyEncapsulation("Kyber768") as kem:
        kem.import_public_key(public_key)
        ciphertext, shared_secret = kem.encap_secret()
    return ciphertext, shared_secret


def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Recover the shared secret using the provided KEM secret key."""

    _ensure_available()
    with oqs.KeyEncapsulation("Kyber768") as kem:
        kem.import_secret_key(secret_key)
        return kem.decap_secret(ciphertext)
