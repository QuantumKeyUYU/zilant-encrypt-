"""Core high-level operations for container encryption/decryption."""
from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zilant_encrypt.container.format import (
    HEADER_V1_LEN,
    KEY_MODE_PASSWORD_ONLY,
    KEY_MODE_PQ_HYBRID,
    PQ_PLACEHOLDER_CIPHERTEXT_LEN,
    PQ_PLACEHOLDER_SECRET_LEN,
    RESERVED_LEN,
    VERSION_V3,
    WRAPPED_KEY_TAG_LEN,
    VolumeDescriptor,
    build_header,
    read_header_from_stream,
)
from zilant_encrypt.container.keymgmt import (
    ARGON_MEM_MAX_KIB,
    ARGON_MEM_MIN_KIB,
    ARGON_PARALLELISM_MAX,
    ARGON_PARALLELISM_MIN,
    ARGON_TIME_MAX,
    ARGON_TIME_MIN,
    WRAP_NONCE,
    PasswordKeyProvider,
    WrappedKey,
    _validate_decrypt_argon_params,
    _validate_pq_available,
    _zeroize,
    resolve_argon_params,
)
from zilant_encrypt.container.overview import (
    ContainerOverview,
    VolumeLayout,
    _ciphertext_length_for_descriptor,
    _load_overview,
    _select_descriptors,
)
from zilant_encrypt.container.payload import (
    PayloadMeta,
    _build_payload_header,
    _decrypt_stream,
    _encrypt_stream,
    _NullWriter,
    _PayloadSource,
    _PayloadWriter,
)
from zilant_encrypt.crypto import pq
from zilant_encrypt.crypto.aead import TAG_LEN, AesGcmEncryptor
from zilant_encrypt.crypto.kdf import Argon2Params, derive_key_from_password
from zilant_encrypt.errors import (
    ContainerFormatError,
    IntegrityError,
    InvalidPassword,
    PqSupportError,
    UnsupportedFeatureError,
)

ModeLiteral = Literal["password", "pq-hybrid"]

__all__ = [
    "ARGON_MEM_MAX_KIB",
    "ARGON_MEM_MIN_KIB",
    "ARGON_PARALLELISM_MAX",
    "ARGON_PARALLELISM_MIN",
    "ARGON_TIME_MAX",
    "ARGON_TIME_MIN",
    "ContainerOverview",
    "ModeLiteral",
    "PayloadMeta",
    "VolumeLayout",
    "_decrypt_volume",
    "_ensure_output",
    "build_volume_descriptor",
    "check_container",
    "decrypt_auto_volume",
    "decrypt_file",
    "encrypt_file",
    "encrypt_with_decoy",
    "normalize_mode",
    "resolve_argon_params",
]


class _PasswordOnlyProviderFactory:
    def __init__(self, password: str, params: Argon2Params, salt: bytes) -> None:
        self.password = password
        self.params = params
        self.salt = salt

    def build(self) -> PasswordKeyProvider:
        return PasswordKeyProvider(self.password, self.salt, self.params)


def _decrypt_volume(
    descriptor: VolumeDescriptor,
    password: str,
    resolved_mode: ModeLiteral | None = None,
) -> bytes:
    decrypt_params = _validate_decrypt_argon_params(
        Argon2Params(
            mem_cost_kib=descriptor.argon_mem_cost,
            time_cost=descriptor.argon_time_cost,
            parallelism=descriptor.argon_parallelism,
        )
    )

    expected_mode: ModeLiteral = (
        "pq-hybrid" if descriptor.key_mode == KEY_MODE_PQ_HYBRID else "password"
    )
    if resolved_mode is not None and resolved_mode != expected_mode:
        raise UnsupportedFeatureError("requested decrypt mode does not match volume key_mode")

    if descriptor.key_mode == KEY_MODE_PASSWORD_ONLY:
        provider = PasswordKeyProvider(password, descriptor.salt_argon2, decrypt_params)
        try:
            return provider.unwrap_file_key(
                WrappedKey(data=descriptor.wrapped_key, tag=descriptor.wrapped_key_tag),
            )
        finally:
            del provider

    if descriptor.key_mode == KEY_MODE_PQ_HYBRID:
        if not pq.available():
            raise PqSupportError("PQ-hybrid containers require oqs support")
        if (
            descriptor.pq_wrapped_secret is None
            or descriptor.pq_ciphertext is None
            or descriptor.pq_wrapped_secret_tag is None
        ):
            raise ContainerFormatError("PQ header missing required fields")

        # Derive password key as mutable bytearray for zeroization
        password_key = bytearray(
            derive_key_from_password(
                password,
                descriptor.salt_argon2,
                mem_cost=decrypt_params.mem_cost_kib,
                time_cost=decrypt_params.time_cost,
                parallelism=decrypt_params.parallelism,
            )
        )
        try:
            kem_secret = AesGcmEncryptor.decrypt(
                bytes(password_key),  # cast to bytes for library call
                WRAP_NONCE,
                descriptor.pq_wrapped_secret,
                descriptor.pq_wrapped_secret_tag,
                b"",
            )
        except InvalidTag as exc:
            _zeroize(password_key)
            raise InvalidPassword("Unable to unwrap KEM secret key") from exc

        shared_secret = pq.decapsulate(descriptor.pq_ciphertext, kem_secret)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=descriptor.salt_argon2,
            info=b"zilant-pq-hybrid",
        )

        # Convert derived master key to mutable bytearray immediately for zeroization
        master_key = bytearray(hkdf.derive(shared_secret + password_key))

        try:
            return AesGcmEncryptor.decrypt(
                bytes(master_key),  # cast to bytes for library call
                WRAP_NONCE,
                descriptor.wrapped_key,
                descriptor.wrapped_key_tag,
                b"",
            )
        except InvalidTag as exc:
            raise InvalidPassword("Unable to unwrap file key") from exc
        finally:
            _zeroize(password_key)
            _zeroize(master_key)

    raise UnsupportedFeatureError("Unsupported key mode")


def build_volume_descriptor(
    *,
    mode: ModeLiteral,
    volume_index: int,
    password: str,
    salt: bytes,
    argon_params: Argon2Params,
    file_key: bytes,
    nonce: bytes,
    pq_artifacts: tuple[bytes, bytes, bytes, bytes] | None = None,
) -> VolumeDescriptor:
    """Construct a :class:`VolumeDescriptor` for the given parameters."""

    resolved_mode = normalize_mode(mode)
    reserved_bytes = bytes(RESERVED_LEN)

    if resolved_mode == "password":
        provider = _PasswordOnlyProviderFactory(password, argon_params, salt).build()
        wrapped_key = provider.wrap_file_key(file_key)
        placeholder_ciphertext = os.urandom(PQ_PLACEHOLDER_CIPHERTEXT_LEN)
        placeholder_secret = os.urandom(PQ_PLACEHOLDER_SECRET_LEN)
        placeholder_secret_tag = os.urandom(WRAPPED_KEY_TAG_LEN)

        return VolumeDescriptor(
            volume_index=volume_index,
            key_mode=KEY_MODE_PASSWORD_ONLY,
            flags=0,
            payload_offset=0,
            payload_length=0,
            salt_argon2=salt,
            argon_mem_cost=argon_params.mem_cost_kib,
            argon_time_cost=argon_params.time_cost,
            argon_parallelism=argon_params.parallelism,
            nonce_aes_gcm=nonce,
            wrapped_key=wrapped_key.data,
            wrapped_key_tag=wrapped_key.tag,
            reserved=reserved_bytes,
            pq_ciphertext=placeholder_ciphertext,
            pq_wrapped_secret=placeholder_secret,
            pq_wrapped_secret_tag=placeholder_secret_tag,
        )

    if resolved_mode == "pq-hybrid":
        if not pq.available():
            raise PqSupportError("PQ-hybrid mode is not available (oqs not installed)")

        if pq_artifacts is None:
            public_key, secret_key = pq.generate_kem_keypair()
            kem_ciphertext, shared_secret = pq.encapsulate(public_key)
        else:
            public_key, secret_key, kem_ciphertext, shared_secret = pq_artifacts
            del public_key

        password_key = bytearray(
            derive_key_from_password(
                password,
                salt,
                mem_cost=argon_params.mem_cost_kib,
                time_cost=argon_params.time_cost,
                parallelism=argon_params.parallelism,
            )
        )

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"zilant-pq-hybrid",
        )

        # Store as mutable bytearray for subsequent zeroization
        master_key = bytearray(hkdf.derive(shared_secret + password_key))

        try:
            wrapped_key_data, wrapped_key_tag = AesGcmEncryptor.encrypt(
                bytes(master_key),  # cast to bytes
                WRAP_NONCE,
                file_key,
                b""
            )
            wrapped_secret, wrapped_secret_tag = AesGcmEncryptor.encrypt(
                bytes(password_key),  # cast to bytes
                WRAP_NONCE,
                secret_key,
                b""
            )
        finally:
            _zeroize(password_key)
            _zeroize(master_key)

        return VolumeDescriptor(
            volume_index=volume_index,
            key_mode=KEY_MODE_PQ_HYBRID,
            flags=0,
            payload_offset=0,
            payload_length=0,
            salt_argon2=salt,
            argon_mem_cost=argon_params.mem_cost_kib,
            argon_time_cost=argon_params.time_cost,
            argon_parallelism=argon_params.parallelism,
            nonce_aes_gcm=nonce,
            wrapped_key=wrapped_key_data,
            wrapped_key_tag=wrapped_key_tag,
            reserved=reserved_bytes,
            pq_ciphertext=kem_ciphertext,
            pq_wrapped_secret=wrapped_secret,
            pq_wrapped_secret_tag=wrapped_secret_tag,
        )

    raise UnsupportedFeatureError(f"Unknown encryption mode: {mode}")


def _ensure_output(path: Path, overwrite: bool) -> None:
    if path.exists():
        if not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing file: {path}")
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)


def _derive_file_key(descriptor: VolumeDescriptor, password: str, resolved_mode: ModeLiteral | None) -> bytes:
    return _decrypt_volume(descriptor, password, resolved_mode)


def check_container(
    container_path: os.PathLike[str] | str,
    *,
    password: str | None = None,
    mode: ModeLiteral | None = None,
    volume_selector: Literal["main", "decoy", "all"] = "all",
) -> tuple[ContainerOverview, list[int]]:
    """Validate container structure and optionally verify tags for selected volumes."""
    overview = _load_overview(Path(container_path))
    resolved_mode = None if mode is None else normalize_mode(mode)

    if password is None:
        return overview, []

    selected = _select_descriptors(overview.descriptors, volume_selector)
    validated: list[int] = []

    with Path(container_path).open("rb") as f:
        for desc in selected:
            file_key = _derive_file_key(desc, password, resolved_mode)
            layout = next(
                (layout for layout in overview.layouts if layout.descriptor.volume_index == desc.volume_index),
                None,
            )
            if layout is None:
                raise ContainerFormatError("Missing layout information for volume")
            f.seek(desc.payload_offset)
            _decrypt_stream(
                f,
                _NullWriter(),
                file_key,
                desc.nonce_aes_gcm,
                overview.header_bytes,
                layout.ciphertext_len,
            )
            validated.append(desc.volume_index)

    return overview, validated


def encrypt_file(
    in_path: Path,
    out_path: Path,
    password: str,
    *,
    overwrite: bool = False,
    mode: ModeLiteral | None = None,
    volume_selector: Literal["main", "decoy"] = "main",
    argon_params: Argon2Params | None = None,
) -> None:
    """Encrypt input file or directory into a .zil container."""
    if not in_path.exists():
        raise FileNotFoundError(in_path)
    is_new = not out_path.exists()

    if is_new or volume_selector == "main":
        _ensure_output(out_path, overwrite)

    argon_params = resolve_argon_params(base=argon_params)

    resolved_mode = None if mode is None else normalize_mode(mode)
    if resolved_mode is None and not (volume_selector == "decoy" and not is_new):
        resolved_mode = "password"

    _validate_pq_available(resolved_mode)

    if volume_selector == "decoy":
        raise UnsupportedFeatureError(
            "Adding a decoy volume requires rebuilding the container with encrypt_with_decoy to preserve header integrity",
        )

    salt = os.urandom(16)
    nonce = os.urandom(12)
    file_key = os.urandom(32)

    resolved_mode = resolved_mode or "password"

    descriptor = build_volume_descriptor(
        mode=resolved_mode,
        volume_index=0,
        password=password,
        salt=salt,
        argon_params=argon_params,
        file_key=file_key,
        nonce=nonce,
    )

    with _PayloadSource(in_path) as payload_source:
        payload_header = _build_payload_header(payload_source.meta)
        plaintext_len = len(payload_header) + payload_source.path.stat().st_size

        descriptor = replace(
            descriptor,
            payload_length=plaintext_len,
        )

        temp_header = build_header(
            key_mode=descriptor.key_mode,
            header_flags=descriptor.flags,
            salt_argon2=descriptor.salt_argon2,
            argon_mem_cost=descriptor.argon_mem_cost,
            argon_time_cost=descriptor.argon_time_cost,
            argon_parallelism=descriptor.argon_parallelism,
            nonce_aes_gcm=descriptor.nonce_aes_gcm,
            wrapped_key=descriptor.wrapped_key,
            wrapped_key_tag=descriptor.wrapped_key_tag,
            reserved=descriptor.reserved,
            version=VERSION_V3,
            pq_ciphertext=descriptor.pq_ciphertext,
            pq_wrapped_secret=descriptor.pq_wrapped_secret,
            pq_wrapped_secret_tag=descriptor.pq_wrapped_secret_tag,
            volume_descriptors=[descriptor],
            common_meta={},
        )

        descriptor = replace(descriptor, payload_offset=len(temp_header))

        header_bytes = build_header(
            key_mode=descriptor.key_mode,
            header_flags=descriptor.flags,
            salt_argon2=descriptor.salt_argon2,
            argon_mem_cost=descriptor.argon_mem_cost,
            argon_time_cost=descriptor.argon_time_cost,
            argon_parallelism=descriptor.argon_parallelism,
            nonce_aes_gcm=descriptor.nonce_aes_gcm,
            wrapped_key=descriptor.wrapped_key,
            wrapped_key_tag=descriptor.wrapped_key_tag,
            reserved=descriptor.reserved,
            version=VERSION_V3,
            pq_ciphertext=descriptor.pq_ciphertext,
            pq_wrapped_secret=descriptor.pq_wrapped_secret,
            pq_wrapped_secret_tag=descriptor.pq_wrapped_secret_tag,
            volume_descriptors=[descriptor],
            common_meta={},
        )

        aad = header_bytes
        with out_path.open("xb") as dest:
            dest.write(header_bytes)
            with payload_source.path.open("rb") as payload_file:
                tag = _encrypt_stream(payload_file, dest, file_key, nonce, aad, initial=payload_header)
                dest.write(tag)


def encrypt_with_decoy(
    main_input: Path,
    decoy_or_out: Path | None = None,
    out_path: Path | None = None,
    *,
    main_password: str | None = None,
    password: str | None = None,
    decoy_password: str,
    input_path_decoy: Path | None = None,
    decoy_input: Path | None = None,
    mode: ModeLiteral | None = None,
    overwrite: bool = False,
    argon_params: Argon2Params | None = None,
) -> None:
    resolved_main_password = main_password or password
    if resolved_main_password is None:
        raise TypeError("main_password is required")

    if out_path is None:
        if decoy_or_out is None:
            raise TypeError("out_path is required")
        out_path = decoy_or_out
        decoy_source = decoy_input or input_path_decoy or main_input
    else:
        decoy_source = decoy_input or input_path_decoy or decoy_or_out or main_input

    if not main_input.exists():
        raise FileNotFoundError(main_input)
    if not decoy_source.exists():
        raise FileNotFoundError(decoy_source)

    _ensure_output(out_path, overwrite)
    argon_params = resolve_argon_params(base=argon_params)

    resolved_mode = None if mode is None else normalize_mode(mode)
    if resolved_mode is None:
        resolved_mode = "password"

    _validate_pq_available(resolved_mode)

    main_salt, main_nonce, main_file_key = os.urandom(16), os.urandom(12), os.urandom(32)
    decoy_salt, decoy_nonce, decoy_file_key = os.urandom(16), os.urandom(12), os.urandom(32)

    descriptors = [
        build_volume_descriptor(
            mode=resolved_mode,
            volume_index=0,
            password=resolved_main_password,
            salt=main_salt,
            argon_params=argon_params,
            file_key=main_file_key,
            nonce=main_nonce,
        ),
        build_volume_descriptor(
            mode=resolved_mode,
            volume_index=1,
            password=decoy_password,
            salt=decoy_salt,
            argon_params=argon_params,
            file_key=decoy_file_key,
            nonce=decoy_nonce,
        ),
    ]

    with _PayloadSource(main_input) as main_payload, _PayloadSource(decoy_source) as decoy_payload:
        main_header = _build_payload_header(main_payload.meta)
        decoy_header = _build_payload_header(decoy_payload.meta)

        main_plaintext_len = len(main_header) + main_payload.path.stat().st_size
        decoy_plaintext_len = len(decoy_header) + decoy_payload.path.stat().st_size

        descriptors = [
            replace(descriptors[0], payload_offset=0, payload_length=main_plaintext_len),
            replace(descriptors[1], payload_offset=0, payload_length=decoy_plaintext_len),
        ]

        header = build_header(
            key_mode=descriptors[0].key_mode,
            header_flags=descriptors[0].flags,
            salt_argon2=descriptors[0].salt_argon2,
            argon_mem_cost=descriptors[0].argon_mem_cost,
            argon_time_cost=descriptors[0].argon_time_cost,
            argon_parallelism=descriptors[0].argon_parallelism,
            nonce_aes_gcm=descriptors[0].nonce_aes_gcm,
            wrapped_key=descriptors[0].wrapped_key,
            wrapped_key_tag=descriptors[0].wrapped_key_tag,
            reserved=descriptors[0].reserved,
            version=VERSION_V3,
            pq_ciphertext=descriptors[0].pq_ciphertext,
            pq_wrapped_secret=descriptors[0].pq_wrapped_secret,
            pq_wrapped_secret_tag=descriptors[0].pq_wrapped_secret_tag,
            volume_descriptors=descriptors,
            common_meta={},
        )

        header_len = len(header)
        descriptors = [
            replace(descriptors[0], payload_offset=header_len),
            replace(descriptors[1], payload_offset=header_len + main_plaintext_len + TAG_LEN),
        ]

        header_bytes = build_header(
            key_mode=descriptors[0].key_mode,
            header_flags=descriptors[0].flags,
            salt_argon2=descriptors[0].salt_argon2,
            argon_mem_cost=descriptors[0].argon_mem_cost,
            argon_time_cost=descriptors[0].argon_time_cost,
            argon_parallelism=descriptors[0].argon_parallelism,
            nonce_aes_gcm=descriptors[0].nonce_aes_gcm,
            wrapped_key=descriptors[0].wrapped_key,
            wrapped_key_tag=descriptors[0].wrapped_key_tag,
            reserved=descriptors[0].reserved,
            version=VERSION_V3,
            pq_ciphertext=descriptors[0].pq_ciphertext,
            pq_wrapped_secret=descriptors[0].pq_wrapped_secret,
            pq_wrapped_secret_tag=descriptors[0].pq_wrapped_secret_tag,
            volume_descriptors=descriptors,
            common_meta={},
        )

        aad = header_bytes
        with out_path.open("xb") as dest:
            dest.write(header_bytes)
            with main_payload.path.open("rb") as payload_file:
                tag = _encrypt_stream(
                    payload_file,
                    dest,
                    main_file_key,
                    descriptors[0].nonce_aes_gcm,
                    aad,
                    initial=main_header,
                )
                dest.write(tag)

            with decoy_payload.path.open("rb") as payload_file:
                tag = _encrypt_stream(
                    payload_file,
                    dest,
                    decoy_file_key,
                    descriptors[1].nonce_aes_gcm,
                    aad,
                    initial=decoy_header,
                )
                dest.write(tag)


def decrypt_file(
    container_path: Path,
    out_path: Path,
    password: str,
    *,
    overwrite: bool = False,
    mode: ModeLiteral | None = None,
    volume_selector: Literal["main", "decoy"] = "main",
) -> None:
    """Decrypt a container to an output file."""
    if not container_path.exists():
        raise FileNotFoundError(container_path)

    file_size = container_path.stat().st_size
    if file_size < HEADER_V1_LEN + TAG_LEN:
        raise ContainerFormatError("Container too small")

    _ensure_output(out_path, overwrite)

    with container_path.open("rb") as f:
        header, descriptors, header_bytes = read_header_from_stream(f)
        aad = header_bytes

        target_volume = 0 if volume_selector == "main" else 1
        descriptor = next((d for d in descriptors if d.volume_index == target_volume), None)
        if descriptor is None:
            raise ContainerFormatError(f"Volume id {target_volume} not found")

        main_descriptor = next((d for d in descriptors if d.volume_index == 0), None)
        if main_descriptor is not None and any(d.key_mode != main_descriptor.key_mode for d in descriptors):
            raise UnsupportedFeatureError("all volumes in a container must share the same key_mode")

        resolved_mode = None if mode is None else normalize_mode(mode)
        ciphertext_len = _ciphertext_length_for_descriptor(descriptor, descriptors, file_size)
        if ciphertext_len < 0:
            raise ContainerFormatError("Invalid payload length")

        file_key = _decrypt_volume(descriptor, password, resolved_mode=resolved_mode)

        writer = _PayloadWriter(out_path)
        f.seek(descriptor.payload_offset)
        _decrypt_stream(
            f,
            writer,
            file_key,
            descriptor.nonce_aes_gcm,
            aad,
            ciphertext_len,
        )


def decrypt_auto_volume(
    container_path: os.PathLike[str] | str,
    out_path: os.PathLike[str] | str,
    *,
    password: str,
    mode: ModeLiteral | None = None,
    overwrite: bool = False,
) -> tuple[int, str]:
    """Attempt to decrypt any volume that matches the provided password."""
    container = Path(container_path)
    output = Path(out_path)

    if not container.exists():
        raise FileNotFoundError(container)

    file_size = container.stat().st_size
    if file_size < HEADER_V1_LEN + TAG_LEN:
        raise ContainerFormatError("Container too small")

    resolved_mode = None if mode is None else normalize_mode(mode)

    with container.open("rb") as f:
        header, descriptors, header_bytes = read_header_from_stream(f)
        aad = header_bytes

        main_descriptor = next((d for d in descriptors if d.volume_index == 0), None)
        if main_descriptor is not None and any(d.key_mode != main_descriptor.key_mode for d in descriptors):
            raise UnsupportedFeatureError("all volumes in a container must share the same key_mode")

        ordered = sorted(descriptors, key=lambda d: d.volume_index)
        successful: tuple[int, str] | None = None

        for descriptor in ordered:
            expected_mode = "pq-hybrid" if descriptor.key_mode == KEY_MODE_PQ_HYBRID else "password"
            if resolved_mode is not None and resolved_mode != expected_mode:
                continue

            ciphertext_len = _ciphertext_length_for_descriptor(descriptor, descriptors, file_size)
            if ciphertext_len < 0:
                raise ContainerFormatError("Invalid payload length")

            try:
                file_key = _decrypt_volume(descriptor, password, resolved_mode=resolved_mode)

                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_out = Path(temp_dir) / "payload"
                    writer = _PayloadWriter(temp_out)
                    f.seek(descriptor.payload_offset)
                    _decrypt_stream(
                        f,
                        writer,
                        file_key,
                        descriptor.nonce_aes_gcm,
                        aad,
                        ciphertext_len,
                    )

                    _ensure_output(output, overwrite)
                    if temp_out.is_dir():
                        shutil.move(str(temp_out), output)
                    else:
                        output.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(temp_out), output)

                volume_name = "main" if descriptor.volume_index == 0 else "decoy" if descriptor.volume_index == 1 else f"id={descriptor.volume_index}"
                successful = (descriptor.volume_index, volume_name)
                break

            except (InvalidPassword, IntegrityError):
                continue

        if successful is None:
            raise InvalidPassword("Unable to decrypt any volume with the provided password")

        return successful


def normalize_mode(mode: str | None) -> ModeLiteral:
    """Normalize user-provided mode strings."""

    if mode is None or mode.lower() == "password":
        return "password"

    normalized = mode.lower().replace("_", "-")
    if normalized == "pq-hybrid":
        return "pq-hybrid"

    raise UnsupportedFeatureError(f"Unknown encryption mode: {mode}")
