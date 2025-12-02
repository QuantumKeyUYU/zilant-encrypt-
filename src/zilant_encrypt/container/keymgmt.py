"""Key management utilities for container operations."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

from cryptography.exceptions import InvalidTag

from zilant_encrypt.crypto.aead import AesGcmEncryptor
from zilant_encrypt.crypto.kdf import Argon2Params, derive_key_from_password, recommended_params
from zilant_encrypt.errors import ContainerFormatError, InvalidPassword, PqSupportError, UnsupportedFeatureError
from zilant_encrypt.crypto import pq

WRAP_NONCE = b"\x00" * 12
ARGON_MEM_MIN_KIB = 32 * 1024
ARGON_MEM_MAX_KIB = 2 * 1024 * 1024
ARGON_TIME_MIN = 1
ARGON_TIME_MAX = 10
ARGON_PARALLELISM_MIN = 1
ARGON_PARALLELISM_MAX = 8


@dataclass(frozen=True)
class WrappedKey:
    data: bytes
    tag: bytes


class PasswordKeyProvider:
    """Password-based key provider using Argon2id."""

    def __init__(self, password: str, salt: bytes, params: Argon2Params) -> None:
        self.password = password
        self.salt = salt
        self.params = params
        self._password_key: bytearray | None = None

    def _ensure_key(self) -> bytes:
        if self._password_key is None:
            self._password_key = bytearray(
                derive_key_from_password(
                    self.password,
                    self.salt,
                    mem_cost=self.params.mem_cost_kib,
                    time_cost=self.params.time_cost,
                    parallelism=self.params.parallelism,
                )
            )
        return self._password_key

    def _clear_key(self) -> None:
        _zeroize(self._password_key)
        self._password_key = None

    def wrap_file_key(self, file_key: bytes) -> WrappedKey:
        key = self._ensure_key()
        try:
            ciphertext, tag = AesGcmEncryptor.encrypt(key, WRAP_NONCE, file_key, b"")
            return WrappedKey(data=ciphertext, tag=tag)
        finally:
            self._clear_key()

    def unwrap_file_key(self, wrapped: WrappedKey) -> bytes:
        key = self._ensure_key()
        try:
            return AesGcmEncryptor.decrypt(key, WRAP_NONCE, wrapped.data, wrapped.tag, b"")
        except InvalidTag as exc:
            raise InvalidPassword("Unable to unwrap file key") from exc
        finally:
            self._clear_key()


def _validate_argon_params(params: Argon2Params) -> Argon2Params:
    if not (ARGON_MEM_MIN_KIB <= params.mem_cost_kib <= ARGON_MEM_MAX_KIB):
        raise UnsupportedFeatureError(
            f"Argon2 memory must be between {ARGON_MEM_MIN_KIB} and {ARGON_MEM_MAX_KIB} KiB",
        )
    if not (ARGON_TIME_MIN <= params.time_cost <= ARGON_TIME_MAX):
        raise UnsupportedFeatureError(
            f"Argon2 time cost must be between {ARGON_TIME_MIN} and {ARGON_TIME_MAX}",
        )
    if not (ARGON_PARALLELISM_MIN <= params.parallelism <= ARGON_PARALLELISM_MAX):
        raise UnsupportedFeatureError(
            "Argon2 parallelism must be between "
            f"{ARGON_PARALLELISM_MIN} and {ARGON_PARALLELISM_MAX}",
        )
    return params


def _validate_decrypt_argon_params(params: Argon2Params) -> Argon2Params:
    try:
        return _validate_argon_params(params)
    except UnsupportedFeatureError as exc:  # pragma: no cover - thin wrapper
        raise ContainerFormatError("Container has invalid Argon2 parameters") from exc


def _zeroize(buffer: bytearray | None) -> None:
    if buffer is None:
        return
    for idx in range(len(buffer)):
        buffer[idx] = 0


def resolve_argon_params(
    *,
    mem_kib: int | None = None,
    time_cost: int | None = None,
    parallelism: int | None = None,
    base: Argon2Params | None = None,
) -> Argon2Params:
    """Build validated Argon2 parameters using overrides when provided."""
    defaults = base or recommended_params()
    candidate = Argon2Params(
        mem_cost_kib=mem_kib if mem_kib is not None else defaults.mem_cost_kib,
        time_cost=time_cost if time_cost is not None else defaults.time_cost,
        parallelism=parallelism if parallelism is not None else defaults.parallelism,
    )
    return _validate_argon_params(candidate)


def _validate_pq_available(resolved_mode: Literal["password", "pq-hybrid"] | None) -> None:
    if resolved_mode == "pq-hybrid" and not pq.available():
        raise PqSupportError("PQ-hybrid mode is not available (oqs not installed)")


__all__ = [
    "ARGON_MEM_MAX_KIB",
    "ARGON_MEM_MIN_KIB",
    "ARGON_PARALLELISM_MAX",
    "ARGON_PARALLELISM_MIN",
    "ARGON_TIME_MAX",
    "ARGON_TIME_MIN",
    "PasswordKeyProvider",
    "WrappedKey",
    "WRAP_NONCE",
    "_validate_argon_params",
    "_validate_decrypt_argon_params",
    "_validate_pq_available",
    "_zeroize",
    "resolve_argon_params",
]
