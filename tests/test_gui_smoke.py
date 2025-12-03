import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def test_gui_module_importable() -> None:
    from zilant_encrypt import gui_app

    assert hasattr(gui_app, "main")
    assert hasattr(gui_app, "create_app")


def test_gui_entrypoints_or_warning() -> None:
    from zilant_encrypt import gui_app

    qt_installed = importlib.util.find_spec("PySide6") is not None or "PySide6" in sys.modules
    if qt_installed:
        assert hasattr(gui_app, "ZilantWindow")
    else:
        with pytest.raises(ImportError):
            gui_app.create_app()


def test_format_overview_report() -> None:
    from zilant_encrypt import gui_app

    overview = SimpleNamespace(
        header=SimpleNamespace(version=3),
        descriptors=[
            SimpleNamespace(volume_index=0, key_mode=0x01),
            SimpleNamespace(volume_index=1, key_mode=gui_app.KEY_MODE_PQ_HYBRID),
        ],
        pq_available=True,
    )

    report = gui_app._format_overview_report(Path("sample.zil"), overview, [0], True)

    assert "sample.zil" in report
    assert "main" in report
    assert "decoy" in report
