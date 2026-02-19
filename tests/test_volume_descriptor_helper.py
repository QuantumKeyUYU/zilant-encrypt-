import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zilant_encrypt.container.api import PasswordKeyProvider, build_volume_descriptor
from zilant_encrypt.container.format import (
    KEY_MODE_PASSWORD_ONLY,
    KEY_MODE_PQ_HYBRID,
    PQ_PLACEHOLDER_CIPHERTEXT_LEN,
    PQ_PLACEHOLDER_SECRET_LEN,
    RESERVED_LEN,
    WRAPPED_KEY_TAG_LEN,
    VolumeDescriptor,
)
from zilant_encrypt.container.keymgmt import derive_wrap_nonce
from zilant_encrypt.crypto import pq
from zilant_encrypt.crypto.aead import AesGcmEncryptor
from zilant_encrypt.crypto.kdf import Argon2Params, derive_key_from_password


def test_build_volume_descriptor_password_regression(monkeypatch) -> None:
    placeholders = [
        b"a" * PQ_PLACEHOLDER_CIPHERTEXT_LEN,
        b"b" * PQ_PLACEHOLDER_SECRET_LEN,
        b"c" * WRAPPED_KEY_TAG_LEN,
    ]

    placeholder_iter = iter(placeholders)

    def fake_urandom(length: int) -> bytes:
        value = next(placeholder_iter)
        assert len(value) == length
        return value

    monkeypatch.setattr(os, "urandom", fake_urandom)

    password = "secret-password"
    salt = b"s" * 16
    nonce = b"n" * 12
    file_key = b"f" * 32
    params = Argon2Params(mem_cost_kib=64 * 1024, time_cost=3, parallelism=2)

    descriptor = build_volume_descriptor(
        mode="password",
        volume_index=0,
        password=password,
        salt=salt,
        argon_params=params,
        file_key=file_key,
        nonce=nonce,
    )

    wrapped = PasswordKeyProvider(password, salt, params).wrap_file_key(file_key)

    expected = VolumeDescriptor(
        volume_index=0,
        key_mode=KEY_MODE_PASSWORD_ONLY,
        flags=0,
        payload_offset=0,
        payload_length=0,
        salt_argon2=salt,
        argon_mem_cost=params.mem_cost_kib,
        argon_time_cost=params.time_cost,
        argon_parallelism=params.parallelism,
        nonce_aes_gcm=nonce,
        wrapped_key=wrapped.data,
        wrapped_key_tag=wrapped.tag,
        reserved=bytes(RESERVED_LEN),
        pq_ciphertext=placeholders[0],
        pq_wrapped_secret=placeholders[1],
        pq_wrapped_secret_tag=placeholders[2],
    )

    assert descriptor == expected


def test_build_volume_descriptor_pq_hybrid_regression(monkeypatch) -> None:
    monkeypatch.setattr(pq, "available", lambda: True)

    public_key = b"public-key"
    secret_key = b"secret-key-material"
    kem_ciphertext = b"kem-ciphertext"
    shared_secret = b"shared-secret-material"

    monkeypatch.setattr(pq, "generate_kem_keypair", lambda: (public_key, secret_key))
    monkeypatch.setattr(pq, "encapsulate", lambda _pk: (kem_ciphertext, shared_secret))

    password = "hybrid-password"
    salt = b"p" * 16
    nonce = b"q" * 12
    file_key = b"k" * 32
    params = Argon2Params(mem_cost_kib=64 * 1024, time_cost=3, parallelism=2)

    descriptor = build_volume_descriptor(
        mode="pq-hybrid",
        volume_index=1,
        password=password,
        salt=salt,
        argon_params=params,
        file_key=file_key,
        nonce=nonce,
        pq_artifacts=(public_key, secret_key, kem_ciphertext, shared_secret),
    )

    password_key = derive_key_from_password(
        password,
        salt,
        mem_cost=params.mem_cost_kib,
        time_cost=params.time_cost,
        parallelism=params.parallelism,
    )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"zilant-pq-hybrid",
    )
    master_key = hkdf.derive(shared_secret + password_key)

    wrapped_key_data, wrapped_key_tag = AesGcmEncryptor.encrypt(
        master_key, derive_wrap_nonce(master_key, salt, context="filekey"), file_key, b""
    )
    wrapped_secret, wrapped_secret_tag = AesGcmEncryptor.encrypt(
        password_key, derive_wrap_nonce(password_key, salt, context="pq-secret"), secret_key, b""
    )

    expected = VolumeDescriptor(
        volume_index=1,
        key_mode=KEY_MODE_PQ_HYBRID,
        flags=0,
        payload_offset=0,
        payload_length=0,
        salt_argon2=salt,
        argon_mem_cost=params.mem_cost_kib,
        argon_time_cost=params.time_cost,
        argon_parallelism=params.parallelism,
        nonce_aes_gcm=nonce,
        wrapped_key=wrapped_key_data,
        wrapped_key_tag=wrapped_key_tag,
        reserved=bytes(RESERVED_LEN),
        pq_ciphertext=kem_ciphertext,
        pq_wrapped_secret=wrapped_secret,
        pq_wrapped_secret_tag=wrapped_secret_tag,
    )

    assert descriptor == expected
