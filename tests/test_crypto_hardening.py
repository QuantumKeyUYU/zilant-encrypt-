import os

import pytest

from zilant_encrypt.container import api
from zilant_encrypt.container.format import (
    KEY_MODE_PASSWORD_ONLY,
    VolumeDescriptor,
    read_header_from_stream,
)
from zilant_encrypt.crypto.kdf import Argon2Params
from zilant_encrypt.errors import ContainerFormatError, InvalidPassword


def test_invalid_argon_params_rejected_on_derive() -> None:
    salt = os.urandom(16)
    params = Argon2Params()
    provider = api.PasswordKeyProvider("pw", salt, params)
    key_ref = provider._ensure_key()
    wrap_nonce = api.derive_wrap_nonce(bytes(key_ref), salt, context="password")
    wrapped = api.WrappedKey(*api.AesGcmEncryptor.encrypt(key_ref, wrap_nonce, b"k" * 32, b""))

    descriptor = VolumeDescriptor(
        volume_index=0,
        key_mode=KEY_MODE_PASSWORD_ONLY,
        flags=0,
        payload_offset=0,
        payload_length=0,
        salt_argon2=salt,
        argon_mem_cost=api.ARGON_MEM_MAX_KIB + 1,
        argon_time_cost=params.time_cost,
        argon_parallelism=params.parallelism,
        nonce_aes_gcm=os.urandom(12),
        wrapped_key=wrapped.data,
        wrapped_key_tag=wrapped.tag,
        reserved=bytes(api.RESERVED_LEN),
    )

    with pytest.raises(ContainerFormatError):
        api._derive_file_key(descriptor, "pw", None)


def test_password_key_zeroized_after_unwrap() -> None:
    salt = os.urandom(16)
    params = Argon2Params()
    provider = api.PasswordKeyProvider("pw", salt, params)
    key_ref = provider._ensure_key()
    wrap_nonce = api.derive_wrap_nonce(bytes(key_ref), salt, context="password")
    wrapped = api.WrappedKey(*api.AesGcmEncryptor.encrypt(key_ref, wrap_nonce, b"f" * 32, b""))

    unwrapped = provider.unwrap_file_key(wrapped)

    assert unwrapped == b"f" * 32
    assert provider._password_key is None
    assert all(b == 0 for b in key_ref)


def test_pq_hkdf_uses_salt(monkeypatch: pytest.MonkeyPatch, tmp_path: os.PathLike[str]) -> None:
    pytest.importorskip("oqs")

    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as RealHKDF

    salts: list[bytes | None] = []

    class HKDFWithCheck:
        def __init__(self, *args, **kwargs):
            salts.append(kwargs.get("salt"))
            self._inner = RealHKDF(*args, **kwargs)

        def derive(self, material: bytes) -> bytes:
            return self._inner.derive(material)

    monkeypatch.setattr(api, "HKDF", HKDFWithCheck)

    source = tmp_path / "payload.bin"
    source.write_bytes(b"data")
    container = tmp_path / "container.zil"

    api.encrypt_file(source, container, "secret", mode="pq-hybrid")

    with container.open("rb") as f:
        header, _descriptors, _header_bytes = read_header_from_stream(f)

    assert salts, "HKDF was not invoked"
    assert salts[0] == header.salt_argon2


def test_legacy_pq_container_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: os.PathLike[str]) -> None:
    pytest.importorskip("oqs")

    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as RealHKDF

    class LegacyHKDF:
        def __init__(self, *args, **kwargs):
            kwargs["salt"] = None
            self._inner = RealHKDF(*args, **kwargs)

        def derive(self, material: bytes) -> bytes:
            return self._inner.derive(material)

    monkeypatch.setattr(api, "HKDF", LegacyHKDF)

    source = tmp_path / "payload.bin"
    source.write_bytes(b"data")
    container = tmp_path / "container.zil"
    output = tmp_path / "restored.bin"

    api.encrypt_file(source, container, "secret", mode="pq-hybrid")

    monkeypatch.setattr(api, "HKDF", RealHKDF)

    with pytest.raises(InvalidPassword):
        api.decrypt_file(container, output, "secret", mode="pq-hybrid")


def test_password_provider_accepts_legacy_zero_nonce_ciphertext() -> None:
    salt = os.urandom(16)
    params = Argon2Params()
    provider = api.PasswordKeyProvider("pw", salt, params)
    key_ref = provider._ensure_key()
    legacy_wrapped = api.WrappedKey(*api.AesGcmEncryptor.encrypt(key_ref, api.WRAP_NONCE, b"z" * 32, b""))
    provider._clear_key()

    assert provider.unwrap_file_key(legacy_wrapped) == b"z" * 32
