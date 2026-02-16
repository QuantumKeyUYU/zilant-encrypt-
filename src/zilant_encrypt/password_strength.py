"""Password strength validation and scoring."""
from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass
from typing import Literal

MIN_PASSWORD_LENGTH = 8
RECOMMENDED_PASSWORD_LENGTH = 12

StrengthLevel = Literal["weak", "fair", "good", "strong"]


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
    """Estimate password entropy in bits."""
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

    # Check for common patterns
    if re.match(r"^(.)\1+$", password):
        feedback.append("Password must not be a repeated character")

    if re.match(r"^(012|123|234|345|456|567|678|789|abc|bcd|cde|def|xyz)", password.lower()):
        feedback.append("Avoid sequential characters")

    entropy = estimate_entropy(password)

    # Score calculation
    score = 0
    score += min(30, len(password) * 3)  # length contribution
    score += min(25, char_classes * 8)  # diversity contribution
    score += min(25, entropy / 3)  # entropy contribution
    if len(password) >= RECOMMENDED_PASSWORD_LENGTH:
        score += 10
    if len(password) >= 16:
        score += 10
    score = min(100, max(0, int(score)))

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

    Raises WeakPasswordError if the password is too weak and allow_weak is False.
    """
    if not password:
        raise WeakPasswordError(["Password cannot be empty"])

    strength = evaluate_password(password)

    if not allow_weak and len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(strength.feedback or [f"Password must be at least {MIN_PASSWORD_LENGTH} characters"])

    return strength
