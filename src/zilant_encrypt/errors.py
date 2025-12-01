"""Custom exceptions for Zilant Encrypt."""

class ZilantEncryptError(Exception):
    """Base exception for Zilant Encrypt."""


class ContainerFormatError(ZilantEncryptError):
    """Container does not match expected format."""


class InvalidPassword(ZilantEncryptError):
    """Password is invalid or cannot unwrap keys."""


class IntegrityError(ZilantEncryptError):
    """Container data integrity check failed."""


class UnsupportedFeatureError(ZilantEncryptError):
    """Feature is reserved for future versions."""
