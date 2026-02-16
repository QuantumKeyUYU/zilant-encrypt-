"""Tests for password strength validation."""
from __future__ import annotations

import pytest

from zilant_encrypt.password_strength import (
    WeakPasswordError,
    evaluate_password,
    validate_password,
)


def test_empty_password_rejected() -> None:
    with pytest.raises(WeakPasswordError, match="cannot be empty"):
        validate_password("")


def test_short_password_rejected() -> None:
    with pytest.raises(WeakPasswordError):
        validate_password("abc")


def test_short_password_allowed_when_weak_ok() -> None:
    strength = validate_password("abc", allow_weak=True)
    assert strength.level == "weak"


def test_strong_password() -> None:
    strength = evaluate_password("MyS3cur3P@ssw0rd!")
    assert strength.level in ("good", "strong")
    assert strength.score >= 55


def test_repeated_char_feedback() -> None:
    strength = evaluate_password("aaaaaaaaaaa")
    assert any("repeated" in f.lower() for f in strength.feedback)


def test_good_password_passes_validation() -> None:
    strength = validate_password("Tr0ub4dor&3!")
    assert strength.level in ("good", "strong")
    assert strength.score > 50
