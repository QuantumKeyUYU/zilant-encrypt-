import pytest

from zilant_encrypt.container.api import _decrypt_volume, build_volume_descriptor
from zilant_encrypt.container.format import KEY_MODE_PQ_HYBRID
from zilant_encrypt.crypto import pq
from zilant_encrypt.crypto.kdf import Argon2Params
from zilant_encrypt.errors import UnsupportedFeatureError


def test_decrypt_volume_password(monkeypatch) -> None:
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

    result = _decrypt_volume(descriptor, password, resolved_mode="password")

    assert result == file_key


@pytest.mark.skipif(not pq.available(), reason="PQ support not available")
def test_decrypt_volume_pq_hybrid(monkeypatch) -> None:
    monkeypatch.setattr(pq, "available", lambda: True)

    public_key = b"public-key"
    secret_key = b"secret-key-material"
    kem_ciphertext = b"kem-ciphertext"
    shared_secret = b"shared-secret-material"

    monkeypatch.setattr(pq, "generate_kem_keypair", lambda: (public_key, secret_key))
    monkeypatch.setattr(pq, "encapsulate", lambda _pk: (kem_ciphertext, shared_secret))
    monkeypatch.setattr(
        pq,
        "decapsulate",
        lambda ciphertext, kem_secret: (
            shared_secret
            if ciphertext == kem_ciphertext and kem_secret == secret_key
            else b"unexpected"
        ),
    )

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

    result = _decrypt_volume(descriptor, password, enforce_mode="pq-hybrid")

    assert descriptor.key_mode == KEY_MODE_PQ_HYBRID
    assert result == file_key


def test_decrypt_volume_mode_mismatch(monkeypatch) -> None:
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

    with pytest.raises(UnsupportedFeatureError) as excinfo:
        _decrypt_volume(descriptor, password, resolved_mode="pq-hybrid")

    assert "requested decrypt mode does not match volume key_mode" in str(excinfo.value)
