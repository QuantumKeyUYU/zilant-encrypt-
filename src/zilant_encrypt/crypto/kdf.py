"""Key derivation helpers using only the standard library."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

DEFAULT_MEM_COST_KIB = 64 * 1024  # placeholder for compatibility
DEFAULT_TIME_COST = 3
DEFAULT_PARALLELISM = 1
DERIVED_KEY_LEN = 32
SALT_LEN = 16


@dataclass(frozen=True)
class Argon2Params:
    mem_cost_kib: int = DEFAULT_MEM_COST_KIB
    time_cost: int = DEFAULT_TIME_COST
    parallelism: int = DEFAULT_PARALLELISM


def derive_key_from_password(
    password: str,
    salt: bytes,
    *,
    mem_cost: int,
    time_cost: int,
    parallelism: int,
) -> bytes:
    """Derive a 256-bit key from password using PBKDF2-HMAC-SHA256.

    The parameters mirror the previous Argon2-based implementation
    so the rest of the code can stay unchanged for the tests.
    """

    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be {SALT_LEN} bytes long, got {len(salt)}")

    password_bytes = password.encode("utf-8")
    iterations = max(time_cost, 1) * 10_000
    return hashlib.pbkdf2_hmac(
        "sha256", password_bytes, salt, iterations, dklen=DERIVED_KEY_LEN
    )


def recommended_params() -> Argon2Params:
    """Return recommended default parameters."""

    return Argon2Params()
