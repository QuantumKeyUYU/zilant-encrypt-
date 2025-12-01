"""Key derivation helpers using a PBKDF2 fallback.

The original implementation relied on ``argon2-cffi`` which is unavailable in the
execution environment. For the purposes of the kata we use ``hashlib.pbkdf2_hmac``
to derive a 256-bit key. The exposed API remains the same so the rest of the code
continues to work unchanged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

DEFAULT_MEM_COST_KIB = 64 * 1024  # 64 MiB
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
    """Derive a 256-bit key from password using PBKDF2-HMAC-SHA256."""

    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be {SALT_LEN} bytes long, got {len(salt)}")

    password_bytes = password.encode("utf-8")
    iterations = max(1, time_cost) * 1000
    return hashlib.pbkdf2_hmac(
        "sha256",
        password_bytes,
        salt,
        iterations,
        dklen=DERIVED_KEY_LEN,
    )


def recommended_params() -> Argon2Params:
    """Return recommended default Argon2id parameters."""

    return Argon2Params()
