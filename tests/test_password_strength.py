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


def test_common_password_scored_low() -> None:
    """Well-known breached passwords must receive a very low score."""
    strength = evaluate_password("password")
    assert strength.score <= 15
    assert any("common" in f.lower() or "easily" in f.lower() for f in strength.feedback)


def test_common_password_case_insensitive() -> None:
    """Common password check is case-insensitive."""
    strength = evaluate_password("PASSWORD")
    assert strength.score <= 15


def test_sequential_chars_feedback() -> None:
    """Passwords containing obvious sequences get a feedback note."""
    strength = evaluate_password("abcdefgh")
    assert any("sequential" in f.lower() for f in strength.feedback)


def test_entropy_exposed_in_result() -> None:
    """PasswordStrength.entropy_bits must be a positive finite number."""
    strength = evaluate_password("MyS3cur3P@ss!")
    assert strength.entropy_bits > 0
