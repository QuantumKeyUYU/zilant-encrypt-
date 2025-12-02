from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable


@dataclass
class _Strategy:
    generator: Callable[[], object]

    def example(self):
        return self.generator()


def integers(min_value: int | None = None, max_value: int | None = None) -> _Strategy:
    def _gen() -> int:
        if min_value is None and max_value is None:
            return 0
        if min_value is None:
            return max_value or 0
        return min_value

    return _Strategy(_gen)


def binary(min_size: int = 0, max_size: int | None = None) -> _Strategy:
    def _gen() -> bytes:
        size = min_size if max_size is None else min_size
        return os.urandom(size)

    return _Strategy(_gen)


def composite(func: Callable[[Callable[[_Strategy], object]], object]):
    def wrapper(*args, **kwargs):
        def draw(strategy: _Strategy):
            return strategy.example()

        def _generator():
            return func(draw, *args, **kwargs)

        return _Strategy(_generator)

    return wrapper


def data():  # pragma: no cover - compatibility stub
    return _Strategy(lambda: None)


__all__ = ["binary", "composite", "data", "integers"]
