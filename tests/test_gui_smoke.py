import importlib
import sys

import pytest


@pytest.mark.skipif(
    "PySide6" not in sys.modules and importlib.util.find_spec("PySide6") is None,
    reason="GUI extra not installed",
)
def test_gui_main_importable() -> None:
    from zilant_encrypt import gui_app

    assert hasattr(gui_app, "main")
    assert hasattr(gui_app, "create_app")
