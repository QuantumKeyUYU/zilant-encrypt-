"""Zilant Encrypt package."""

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:
    __version__ = version("zilant-encrypt")
except PackageNotFoundError:  # pragma: no cover - happens only from source checkout
    __version__ = "0.0.0-dev"
