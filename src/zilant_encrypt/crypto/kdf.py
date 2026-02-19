"""Key derivation helpers using Argon2id."""

from __future__ import annotations

from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

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
    """Derive a 256-bit key from password using Argon2id."""

    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be {SALT_LEN} bytes long, got {len(salt)}")

    password_bytes = password.encode("utf-8")
    return hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=time_cost,
        memory_cost=mem_cost,
        parallelism=parallelism,
        hash_len=DERIVED_KEY_LEN,
        type=Type.ID,
        version=19,
    )


def recommended_params() -> Argon2Params:
    """Return recommended default Argon2id parameters."""

    return Argon2Params()


# Named profile for the current release. Can be extended in the future
# (e.g. "interactive", "moderate", "strong"), but keeping one fixed profile
# for 0.1 simplifies compatibility.
RecommendedArgon2Params = Argon2Params()
