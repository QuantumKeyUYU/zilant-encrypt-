"""Password strength validation and scoring."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Literal

MIN_PASSWORD_LENGTH = 8
RECOMMENDED_PASSWORD_LENGTH = 12

StrengthLevel = Literal["weak", "fair", "good", "strong"]

# Top-100 most breached passwords (NIST SP 800-63B guidance).
# Checked case-insensitively so "Password1" also matches "password1".
_COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password", "password1", "password123", "123456", "12345678", "123456789",
        "1234567890", "qwerty", "qwerty123", "qwertyuiop", "abc123", "iloveyou",
        "admin", "letmein", "welcome", "monkey", "dragon", "master", "sunshine",
        "princess", "shadow", "superman", "michael", "football", "baseball",
        "soccer", "hockey", "batman", "trustno1", "hello", "passw0rd", "pass",
        "test", "root", "login", "access", "azerty", "111111", "1111111",
        "000000", "696969", "654321", "121212", "666666", "555555", "123123",
        "112233", "11111111", "1234567", "12345", "1234", "123", "1q2w3e4r",
        "1q2w3e", "zxcvbnm", "qazwsx", "q1w2e3r4", "asdfgh", "asdfghjkl",
        "hunter2", "starwars", "whatever", "charlie", "donald", "password2",
        "matrix", "computer", "internet", "flower", "cheese", "lovely",
        "jessica", "michelle", "daniel", "george", "jordan", "harley",
        "ranger", "dakota", "robert", "thomas", "andrea", "maggie", "summer",
        "taylor", "andrew", "jessica", "hunter", "joshua", "pepper", "austin",
        "ginger", "buster", "cookie", "biteme", "snoopy", "tigger", "oliver",
        "thomas", "william", "jennifer", "asshole", "fuckyou", "fucku",
        "sexy", "mustang", "maverick", "thunder",
    }
)


@dataclass(frozen=True)
class PasswordStrength:
    score: int  # 0-100
    level: StrengthLevel
    feedback: list[str]
    entropy_bits: float


class WeakPasswordError(ValueError):
    """Raised when a password does not meet minimum requirements."""

    def __init__(self, feedback: list[str]) -> None:
        self.feedback = feedback
        super().__init__("; ".join(feedback))


def estimate_entropy(password: str) -> float:
    """Estimate password entropy in bits based on character-set size."""
    if not password:
        return 0.0

    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset_size += 32

    if charset_size == 0:
        return 0.0

    return len(password) * math.log2(charset_size)


def _is_common_password(password: str) -> bool:
    """Return True if the password appears in the known-breached list."""
    return password.lower() in _COMMON_PASSWORDS


def evaluate_password(password: str) -> PasswordStrength:
    """Evaluate password strength and return detailed feedback."""
    feedback: list[str] = []

    if len(password) < MIN_PASSWORD_LENGTH:
        feedback.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    char_classes = sum([has_lower, has_upper, has_digit, has_special])
    if char_classes < 2:
        feedback.append("Use a mix of uppercase, lowercase, digits, and symbols")

    # Check for trivially crackable patterns
    if re.match(r"^(.)\1+$", password):
        feedback.append("Password must not be a single repeated character")

    if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|xyz)", password.lower()):
        feedback.append("Avoid sequential characters (e.g. 123, abc)")

    # Check against known breached passwords
    is_common = _is_common_password(password)
    if is_common:
        feedback.append("This password is extremely common and easily guessed – choose a unique one")

    entropy = estimate_entropy(password)

    # Score calculation (0-100)
    score = 0
    score += min(30, len(password) * 3)   # length: up to 10 chars gets full points
    score += min(20, char_classes * 6)    # diversity: 4 classes = 24 pts, capped at 20
    score += min(20, int(entropy / 4))    # raw entropy contribution
    if len(password) >= RECOMMENDED_PASSWORD_LENGTH:
        score += 10
    if len(password) >= 16:
        score += 10
    if len(password) >= 20:
        score += 10

    # Severe penalties
    if is_common:
        score = min(score, 15)
    if re.match(r"^(.)\1+$", password):
        score = min(score, 5)

    score = min(100, max(0, score))

    if score < 30:
        level: StrengthLevel = "weak"
    elif score < 55:
        level = "fair"
    elif score < 80:
        level = "good"
    else:
        level = "strong"

    return PasswordStrength(
        score=score,
        level=level,
        feedback=feedback,
        entropy_bits=entropy,
    )


def validate_password(password: str, *, allow_weak: bool = False) -> PasswordStrength:
    """Validate password meets minimum requirements.

    Raises :exc:`WeakPasswordError` if the password is too short and
    *allow_weak* is ``False``.
    """
    if not password:
        raise WeakPasswordError(["Password cannot be empty"])

    strength = evaluate_password(password)

    if not allow_weak and len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            strength.feedback or [f"Password must be at least {MIN_PASSWORD_LENGTH} characters"]
        )

    return strength
