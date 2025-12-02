from __future__ import annotations

from hypothesis import strategies as strategies  # type: ignore


def given(*strategies_args, **strategies_kwargs):
    def decorator(fn):
        def wrapper(*args, **kwargs):
            positional = [s.example() for s in strategies_args]
            keyword = {key: strat.example() for key, strat in strategies_kwargs.items()}
            merged_kwargs = {**kwargs, **keyword}
            return fn(*args, *positional, **merged_kwargs)

        return wrapper

    return decorator


def settings(**_kwargs):  # pragma: no cover - compatibility stub
    def decorator(fn):
        return fn

    return decorator

__all__ = ["given", "settings", "strategies"]
