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
    from zilant_encrypt.gui_i18n import get_strings

    overview = SimpleNamespace(
        header=SimpleNamespace(version=3),
        descriptors=[
            SimpleNamespace(volume_index=0, key_mode=0x01),
            SimpleNamespace(volume_index=1, key_mode=gui_app.KEY_MODE_PQ_HYBRID),
        ],
        pq_available=True,
    )

    strings = get_strings("en")
    report = gui_app._format_overview_report(
        Path("sample.zil"), overview, [0], True, strings
    )

    assert "sample.zil" in report
    assert "main" in report
    assert "decoy" in report


def test_window_title_includes_version() -> None:
    import zilant_encrypt
    from zilant_encrypt import gui_app

    if not gui_app.QT_AVAILABLE:
        pytest.skip("PySide6 is not installed")

    app = gui_app.QtWidgets.QApplication.instance()
    created_app = False
    if app is None:
        app = gui_app.QtWidgets.QApplication([])
        created_app = True

    window = gui_app.ZilantWindow()
    title = window.windowTitle()

    assert window.tr.app_title in title
    assert zilant_encrypt.__version__ in title

    window.close()
    if created_app:
        app.quit()


def test_lang_switch_updates_title_and_status() -> None:
    import zilant_encrypt
    from zilant_encrypt import gui_app

    if not gui_app.QT_AVAILABLE:
        pytest.skip("PySide6 is not installed")

    app = gui_app.QtWidgets.QApplication.instance()
    created_app = False
    if app is None:
        app = gui_app.QtWidgets.QApplication([])
        created_app = True

    window = gui_app.ZilantWindow()

    assert hasattr(window, "lang_combo")
    assert window.status_lbl.text() == window.tr.status_ready

    initial_title = window.windowTitle()
    next_index = 1 if window.lang_combo.currentIndex() == 0 else 0
    window.lang_combo.setCurrentIndex(next_index)
    gui_app.QtWidgets.QApplication.processEvents()
    updated_title = window.windowTitle()

    assert initial_title != updated_title
    assert window.tr.app_title in updated_title
    assert zilant_encrypt.__version__ in updated_title

    window.close()
    if created_app:
        app.quit()
