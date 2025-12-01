"""Password-based key derivation helpers using only stdlib."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

DEFAULT_MEM_COST_KIB = 64 * 1024  # placeholder values kept for compatibility
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

    The parameters are accepted for API compatibility; only ``time_cost`` is
    used to set the iteration count, while ``mem_cost`` and ``parallelism`` are
    ignored.
    """

    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be {SALT_LEN} bytes long, got {len(salt)}")

    iterations = max(time_cost, 1) * 1000
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=DERIVED_KEY_LEN)


def recommended_params() -> Argon2Params:
    """Return default parameters (kept for compatibility with Argon2 API)."""

    return Argon2Params()
