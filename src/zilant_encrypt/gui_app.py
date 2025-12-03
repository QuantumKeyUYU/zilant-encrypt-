"""Desktop GUI for Zilant Encrypt."""
from __future__ import annotations

import importlib.util
import inspect
import locale
import sys
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Literal, cast

from zilant_encrypt import __version__
from zilant_encrypt.container import (
    ContainerOverview,
    check_container,
    decrypt_auto_volume,
    decrypt_file,
    encrypt_file,
    encrypt_with_decoy,
    normalize_mode,
)
from zilant_encrypt.container.format import KEY_MODE_PQ_HYBRID
from zilant_encrypt.errors import (
    ContainerFormatError,
    IntegrityError,
    InvalidPassword,
    PqSupportError,
)
from zilant_encrypt.gui_i18n import Lang, Strings, get_strings

QT_AVAILABLE = importlib.util.find_spec("PySide6") is not None

if QT_AVAILABLE:
    from PySide6 import QtCore, QtGui, QtWidgets  # type: ignore[import-not-found]
elif TYPE_CHECKING:  # pragma: no cover
    from PySide6 import QtCore, QtGui, QtWidgets
else:  # pragma: no cover
    QtCore = QtGui = QtWidgets = cast(Any, None)

# ---- API feature detection -------------------------------------------------

try:
    # Support both decrypt_auto_volume(password, mode)
    # and decrypt_auto_volume(password, mode, overwrite=...)
    _DECRYPT_AUTO_SUPPORTS_OVERWRITE = (
        "overwrite" in inspect.signature(decrypt_auto_volume).parameters
    )
except Exception:
    _DECRYPT_AUTO_SUPPORTS_OVERWRITE = False

# --- Styles & Constants -----------------------------------------------------

ACCENT_COLOR = "#3B8ED0"  # Modern calm blue
BG_COLOR = "#1E1E1E"
SURFACE_COLOR = "#252526"
TEXT_COLOR = "#E0E0E0"
ERROR_COLOR = "#FF6B6B"
SUCCESS_COLOR = "#51CF66"

STYLESHEET = f"""
QMainWindow {{
    background-color: {BG_COLOR};
    color: {TEXT_COLOR};
}}
QWidget {{
    color: {TEXT_COLOR};
    font-family: "Segoe UI", "Roboto", sans-serif;
    font-size: 14px;
}}
QTabWidget::pane {{
    border: 1px solid #3E3E42;
    background: {SURFACE_COLOR};
    border-radius: 6px;
    margin-top: -1px;
}}
QTabBar::tab {{
    background: {BG_COLOR};
    border: 1px solid #3E3E42;
    padding: 8px 20px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    color: #A0A0A0;
    margin-right: 4px;
}}
QTabBar::tab:selected {{
    background: {SURFACE_COLOR};
    color: {ACCENT_COLOR};
    border-bottom: 1px solid {SURFACE_COLOR};
    font-weight: bold;
}}
QGroupBox {{
    background-color: {SURFACE_COLOR};
    border: 1px solid #3E3E42;
    border-radius: 6px;
    margin-top: 24px;
    padding-top: 16px;
    font-weight: bold;
    color: {ACCENT_COLOR};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 10px;
    left: 10px;
    background-color: {SURFACE_COLOR};
}}
QLineEdit {{
    background-color: #1E1E1E;
    border: 1px solid #3E3E42;
    border-radius: 4px;
    padding: 8px;
    color: white;
    selection-background-color: {ACCENT_COLOR};
}}
QLineEdit:focus {{
    border: 1px solid {ACCENT_COLOR};
}}
QPushButton {{
    background-color: #3E3E42;
    border: none;
    border-radius: 4px;
    padding: 8px 16px;
    color: white;
}}
QPushButton:hover {{
    background-color: #4E4E52;
}}
QPushButton:pressed {{
    background-color: #2D2D30;
}}
QPushButton[class="primary"] {{
    background-color: {ACCENT_COLOR};
    font-weight: bold;
    font-size: 15px;
}}
QPushButton[class="primary"]:hover {{
    background-color: #3682BE;
}}
QCheckBox {{
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 3px;
    border: 1px solid #555;
    background: #1E1E1E;
}}
QCheckBox::indicator:checked {{
    background: {ACCENT_COLOR};
    border-color: {ACCENT_COLOR};
}}
QRadioButton {{
    spacing: 8px;
}}
QRadioButton::indicator {{
    width: 18px;
    height: 18px;
}}
QTextEdit, QPlainTextEdit {{
    background-color: #1E1E1E;
    border: 1px solid #3E3E42;
    border-radius: 4px;
    font-family: "Consolas", "Monospace";
    font-size: 13px;
}}
QProgressBar {{
    border: none;
    background-color: #3E3E42;
    border-radius: 2px;
    height: 4px;
    text-align: center;
}}
QProgressBar::chunk {{
    background-color: {ACCENT_COLOR};
}}
"""


def _detect_lang() -> Lang:
    code, _ = locale.getdefaultlocale()
    if code and code.lower().startswith("ru"):
        return "ru"
    return "en"


def _format_overview_report(
    path: Path,
    overview: ContainerOverview,
    validated: list[int],
    pq_available: bool,
    strings: Strings,
) -> str:
    """Return a human-readable overview of a container."""
    version = overview.header.version
    lines: list[str] = [
        strings.overview_file.format(path=path),
        strings.overview_version.format(version=version),
        strings.overview_volumes,
    ]

    password_used = bool(validated)

    for desc in overview.descriptors:
        if desc.volume_index == 0:
            label = strings.overview_label_main
        elif desc.volume_index == 1:
            label = strings.overview_label_decoy
        else:
            label = str(desc.volume_index)

        mode = (
            strings.overview_mode_pq
            if desc.key_mode == KEY_MODE_PQ_HYBRID
            else strings.overview_mode_pw
        )

        if password_used:
            status = (
                strings.overview_status_ok
                if desc.volume_index in validated
                else strings.overview_status_not_checked
            )
        else:
            status = strings.overview_status_skipped

        lines.append(
            f"  [{desc.volume_index}] {label:<5} mode={mode:<10} status={status}"
        )

    pq_line = (
        strings.overview_pq_available
        if pq_available
        else strings.overview_pq_missing
    )
    lines.append(pq_line)

    return "\n".join(lines)


if QT_AVAILABLE:

    # --- Worker Thread for Async Crypto -------------------------------------

    class TaskWorker(QtCore.QThread):  # type: ignore[misc]
        """Background thread to prevent GUI freezing during crypto ops."""

        finished_success = QtCore.Signal(str)  # Message
        finished_error = QtCore.Signal(str)  # Error message

        def __init__(self, func: Callable[[], Any], strings: Strings) -> None:
            super().__init__()
            self._func = func
            self._strings = strings

        def run(self) -> None:
            try:
                self._func()
                self.finished_success.emit(self._strings.processing_success)
            except InvalidPassword:
                self.finished_error.emit(self._strings.processing_invalid_password)
            except PqSupportError:
                self.finished_error.emit(self._strings.processing_requires_pq)
            except (ContainerFormatError, IntegrityError) as e:
                self.finished_error.emit(
                    self._strings.processing_integrity_error.format(error=e)
                )
            except Exception as e:  # pragma: no cover - debug path
                traceback.print_exc()
                self.finished_error.emit(
                    self._strings.processing_unexpected_error.format(error=e)
                )

    # --- Main Window --------------------------------------------------------

    class ZilantWindow(QtWidgets.QMainWindow):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__()
            self._lang: Lang = _detect_lang()
            self.tr = get_strings(self._lang)

            self.setWindowTitle(f"{self.tr.app_title} v{__version__}")
            self.resize(1100, 750)
            self.setMinimumSize(900, 600)

            # State
            self._output_path: Path | None = None
            self._worker: TaskWorker | None = None
            self._temp_report: str | None = None
            self._status_state: Literal["ready", "processing", "error"] = "ready"

            # Setup UI
            self.setStyleSheet(STYLESHEET)

            central = QtWidgets.QWidget(self)
            self.setCentralWidget(central)

            self.main_layout = QtWidgets.QVBoxLayout(central)
            self.main_layout.setContentsMargins(24, 24, 24, 24)
            self.main_layout.setSpacing(24)

            self._build_header()
            self.tabs = QtWidgets.QTabWidget()
            self.main_layout.addWidget(self.tabs)

            self._build_encrypt_decrypt_tab()
            self._build_inspect_tab()
            self._build_footer()
            self._update_defaults()
            self._retranslate_ui()

        # --- UI Construction -------------------------------------------------

        def _build_header(self) -> None:
            header_widget = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout(header_widget)
            layout.setContentsMargins(0, 0, 0, 0)

            titles_layout = QtWidgets.QVBoxLayout()
            self.title_lbl = QtWidgets.QLabel(self.tr.app_title)
            self.title_lbl.setStyleSheet(
                f"font-size: 24px; font-weight: bold; color: {TEXT_COLOR};"
            )

            self.subtitle_lbl = QtWidgets.QLabel(self.tr.subtitle)
            self.subtitle_lbl.setStyleSheet("font-size: 13px; color: #888;")

            titles_layout.addWidget(self.title_lbl)
            titles_layout.addWidget(self.subtitle_lbl)

            layout.addLayout(titles_layout)
            layout.addStretch()

            self.lang_combo = QtWidgets.QComboBox()
            self.lang_combo.addItem("English", "en")
            self.lang_combo.addItem("Русский", "ru")
            idx = 0 if self._lang == "en" else 1
            self.lang_combo.setCurrentIndex(idx)
            self.lang_combo.currentIndexChanged.connect(self._on_lang_changed)
            layout.addWidget(self.lang_combo)

            self.about_btn = QtWidgets.QPushButton(self.tr.about)
            self.about_btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.about_btn.clicked.connect(self._show_about_dialog)
            layout.addWidget(self.about_btn)

            self.main_layout.addWidget(header_widget)

        def _build_encrypt_decrypt_tab(self) -> None:
            tab = QtWidgets.QWidget()
            self.workflow_layout = QtWidgets.QVBoxLayout(tab)
            self.workflow_layout.setSpacing(16)
            self.workflow_layout.setContentsMargins(16, 24, 16, 16)

            # 1. Mode Selection
            mode_frame = QtWidgets.QFrame()
            mode_layout = QtWidgets.QHBoxLayout(mode_frame)
            mode_layout.setContentsMargins(0, 0, 0, 0)

            self.mode_label = QtWidgets.QLabel(self.tr.action_label)
            self.mode_label.setStyleSheet("font-weight: bold;")
            self.encrypt_radio = QtWidgets.QRadioButton(self.tr.encrypt)
            self.decrypt_radio = QtWidgets.QRadioButton(self.tr.decrypt)
            self.encrypt_radio.setChecked(True)
            self.encrypt_radio.toggled.connect(self._on_op_mode_changed)

            mode_layout.addWidget(self.mode_label)
            mode_layout.addWidget(self.encrypt_radio)
            mode_layout.addWidget(self.decrypt_radio)
            mode_layout.addStretch()
            self.workflow_layout.addWidget(mode_frame)

            # 2. IO Card
            self.io_group = QtWidgets.QGroupBox(self.tr.input_output_group)
            io_layout = QtWidgets.QVBoxLayout()

            type_layout = QtWidgets.QHBoxLayout()
            self.type_label = QtWidgets.QLabel(self.tr.source_type)
            self.type_label.setStyleSheet("color: #888;")
            self.file_radio = QtWidgets.QRadioButton(self.tr.single_file)
            self.dir_radio = QtWidgets.QRadioButton(self.tr.directory_zip)
            self.file_radio.setChecked(True)
            self.file_radio.toggled.connect(self._on_input_type_changed)

            type_layout.addWidget(self.type_label)
            type_layout.addWidget(self.file_radio)
            type_layout.addWidget(self.dir_radio)
            type_layout.addStretch()
            io_layout.addLayout(type_layout)

            self.input_edit = self._create_path_picker(
                self.tr.select_input_ph, self._browse_input
            )
            self.output_edit = self._create_path_picker(
                self.tr.select_output_ph, self._browse_output
            )

            self.input_label = QtWidgets.QLabel(self.tr.input_path)
            io_layout.addWidget(self.input_label)
            io_layout.addLayout(self.input_edit["layout"])
            self.output_label = QtWidgets.QLabel(self.tr.output_path)
            io_layout.addWidget(self.output_label)
            io_layout.addLayout(self.output_edit["layout"])

            self.overwrite_checkbox = QtWidgets.QCheckBox(self.tr.overwrite_checkbox)
            self.overwrite_checkbox.setToolTip(self.tr.overwrite_tooltip)
            io_layout.addWidget(self.overwrite_checkbox)

            self.io_group.setLayout(io_layout)
            self.workflow_layout.addWidget(self.io_group)

            # 3. Security / Password
            self.sec_group = QtWidgets.QGroupBox(self.tr.security_group)
            sec_layout = QtWidgets.QVBoxLayout()

            algo_layout = QtWidgets.QHBoxLayout()
            self.mode_password_radio = QtWidgets.QRadioButton(self.tr.mode_standard)
            self.mode_pq_radio = QtWidgets.QRadioButton(self.tr.mode_pq)
            self.mode_password_radio.setChecked(True)
            self.mode_password_radio.setToolTip(self.tr.mode_standard_tt)
            self.mode_pq_radio.setToolTip(self.tr.mode_pq_tt)

            algo_layout.addWidget(self.mode_password_radio)
            algo_layout.addWidget(self.mode_pq_radio)
            algo_layout.addStretch()
            sec_layout.addLayout(algo_layout)

            self.password_edit = QtWidgets.QLineEdit()
            self.password_edit.setPlaceholderText(self.tr.password_ph)
            self.password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

            self.show_pass_check = QtWidgets.QCheckBox(self.tr.show_password)
            self.show_pass_check.stateChanged.connect(self._toggle_password_visibility)

            sec_layout.addWidget(self.password_edit)
            sec_layout.addWidget(self.show_pass_check)
            self.sec_group.setLayout(sec_layout)
            self.workflow_layout.addWidget(self.sec_group)

            # 4. Decoy
            self.decoy_group = QtWidgets.QGroupBox(self.tr.decoy_group)
            self.decoy_group.setCheckable(True)
            self.decoy_group.setChecked(False)
            self.decoy_group.toggled.connect(self._update_ui_state)
            self.decoy_group.setToolTip(self.tr.decoy_tooltip)

            decoy_layout = QtWidgets.QVBoxLayout()
            self.decoy_info_lbl = QtWidgets.QLabel(
                self.tr.decoy_subtitle
            )
            self.decoy_info_lbl.setStyleSheet("color: #888; font-style: italic;")
            self.decoy_password_edit = QtWidgets.QLineEdit()
            self.decoy_password_edit.setPlaceholderText(self.tr.decoy_password)
            self.decoy_password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

            self.decoy_input_picker = self._create_path_picker(
                self.tr.decoy_select_ph, self._browse_decoy_input
            )

            decoy_layout.addWidget(self.decoy_info_lbl)
            decoy_layout.addWidget(self.decoy_password_edit)
            decoy_layout.addLayout(self.decoy_input_picker["layout"])
            self.decoy_group.setLayout(decoy_layout)
            self.workflow_layout.addWidget(self.decoy_group)

            # 5. Decrypt Options
            self.decrypt_opts_frame = QtWidgets.QFrame()
            d_layout = QtWidgets.QHBoxLayout(self.decrypt_opts_frame)
            d_layout.setContentsMargins(0, 0, 0, 0)

            self.auto_vol_radio = QtWidgets.QRadioButton(self.tr.auto_volume)
            self.auto_vol_radio.setChecked(True)
            self.force_main_radio = QtWidgets.QRadioButton(self.tr.force_main)
            self.force_decoy_radio = QtWidgets.QRadioButton(self.tr.force_decoy)

            self.decrypt_target_lbl = QtWidgets.QLabel(self.tr.decrypt_target_label)
            d_layout.addWidget(self.decrypt_target_lbl)
            d_layout.addWidget(self.auto_vol_radio)
            d_layout.addWidget(self.force_main_radio)
            d_layout.addWidget(self.force_decoy_radio)
            d_layout.addStretch()
            self.workflow_layout.addWidget(self.decrypt_opts_frame)

            # 6. Action Button
            self.action_button = QtWidgets.QPushButton(self.tr.start_encrypt)
            self.action_button.setProperty("class", "primary")
            self.action_button.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.action_button.setMinimumHeight(50)
            self.action_button.clicked.connect(self._on_action_clicked)

            self.workflow_layout.addStretch()
            self.workflow_layout.addWidget(self.action_button)

            self.tabs.addTab(tab, self.tr.tab_encrypt)

        def _build_inspect_tab(self) -> None:
            tab = QtWidgets.QWidget()
            layout = QtWidgets.QVBoxLayout(tab)
            layout.setSpacing(16)
            layout.setContentsMargins(16, 24, 16, 16)

            self.insp_group = QtWidgets.QGroupBox(self.tr.inspect_group)
            insp_layout = QtWidgets.QVBoxLayout()
            self.inspect_picker = self._create_path_picker(
                self.tr.inspect_select_ph, self._browse_inspect_input
            )
            insp_layout.addLayout(self.inspect_picker["layout"])

            opt_layout = QtWidgets.QHBoxLayout()
            self.inspect_auth_check = QtWidgets.QCheckBox(
                self.tr.inspect_verify
            )
            self.inspect_auth_check.stateChanged.connect(self._toggle_inspect_password)
            self.inspect_pass_edit = QtWidgets.QLineEdit()
            self.inspect_pass_edit.setPlaceholderText(self.tr.inspect_password_ph)
            self.inspect_pass_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.inspect_pass_edit.setEnabled(False)

            opt_layout.addWidget(self.inspect_auth_check)
            opt_layout.addWidget(self.inspect_pass_edit)
            insp_layout.addLayout(opt_layout)
            self.insp_group.setLayout(insp_layout)
            layout.addWidget(self.insp_group)

            self.inspect_btn = QtWidgets.QPushButton(self.tr.inspect_button)
            self.inspect_btn.setProperty("class", "primary")
            self.inspect_btn.clicked.connect(self._handle_inspect)
            layout.addWidget(self.inspect_btn)

            self.inspect_output = QtWidgets.QPlainTextEdit()
            self.inspect_output.setReadOnly(True)
            self.inspect_output.setStyleSheet("font-size: 12px; line-height: 1.4;")
            layout.addWidget(self.inspect_output, 1)

            self.tabs.addTab(tab, self.tr.tab_inspect)

        def _build_footer(self) -> None:
            footer_widget = QtWidgets.QWidget()
            footer_widget.setStyleSheet(
                f"background-color: {SURFACE_COLOR}; border-top: 1px solid #3E3E42;"
            )
            layout = QtWidgets.QVBoxLayout(footer_widget)
            layout.setContentsMargins(16, 8, 16, 8)

            self.progress_bar = QtWidgets.QProgressBar()
            self.progress_bar.setVisible(False)
            layout.addWidget(self.progress_bar)

            status_layout = QtWidgets.QHBoxLayout()
            self.status_icon = QtWidgets.QLabel("●")
            self.status_icon.setStyleSheet(
                f"color: {SUCCESS_COLOR}; font-size: 10px;"
            )
            self.status_lbl = QtWidgets.QLabel(self.tr.status_ready)
            self.status_lbl.setStyleSheet("font-weight: bold;")

            self.open_folder_btn = QtWidgets.QPushButton(self.tr.open_folder)
            self.open_folder_btn.setStyleSheet(
                "background: transparent; color: #888; "
                "border: 1px solid #444; padding: 2px 8px;"
            )
            self.open_folder_btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.open_folder_btn.clicked.connect(self._open_output_folder)

            status_layout.addWidget(self.status_icon)
            status_layout.addWidget(self.status_lbl)
            status_layout.addStretch()
            status_layout.addWidget(self.open_folder_btn)

            layout.addLayout(status_layout)
            self.main_layout.addWidget(footer_widget)

        # --- Helpers / events ------------------------------------------------

        def _create_path_picker(
            self, placeholder: str, slot: Callable[[], None]
        ) -> dict[str, Any]:
            layout = QtWidgets.QHBoxLayout()
            edit = QtWidgets.QLineEdit()
            edit.setPlaceholderText(placeholder)
            edit.textChanged.connect(self._on_input_changed)

            btn = QtWidgets.QPushButton(self.tr.browse)
            btn.setFixedWidth(80)
            btn.clicked.connect(slot)

            layout.addWidget(edit)
            layout.addWidget(btn)
            return {"layout": layout, "edit": edit, "btn": btn}

        def _on_lang_changed(self, index: int) -> None:
            lang_value = self.lang_combo.itemData(index) or "en"
            self._lang = cast(Lang, lang_value)
            self.tr = get_strings(self._lang)
            self._retranslate_ui()

        def _retranslate_ui(self) -> None:
            self.setWindowTitle(f"{self.tr.app_title} v{__version__}")
            self.title_lbl.setText(self.tr.app_title)
            self.subtitle_lbl.setText(self.tr.subtitle)
            self.about_btn.setText(self.tr.about)

            self.tabs.setTabText(0, self.tr.tab_encrypt)
            self.tabs.setTabText(1, self.tr.tab_inspect)

            self.mode_label.setText(self.tr.action_label)
            self.encrypt_radio.setText(self.tr.encrypt)
            self.decrypt_radio.setText(self.tr.decrypt)

            self.io_group.setTitle(self.tr.input_output_group)
            self.type_label.setText(self.tr.source_type)
            self.file_radio.setText(self.tr.single_file)
            self.dir_radio.setText(self.tr.directory_zip)
            self.input_label.setText(self.tr.input_path)
            self.output_label.setText(self.tr.output_path)
            self.input_edit["edit"].setPlaceholderText(self.tr.select_input_ph)
            self.output_edit["edit"].setPlaceholderText(self.tr.select_output_ph)
            self.input_edit["btn"].setText(self.tr.browse)
            self.output_edit["btn"].setText(self.tr.browse)
            self.overwrite_checkbox.setText(self.tr.overwrite_checkbox)
            self.overwrite_checkbox.setToolTip(self.tr.overwrite_tooltip)

            self.sec_group.setTitle(self.tr.security_group)
            self.mode_password_radio.setText(self.tr.mode_standard)
            self.mode_pq_radio.setText(self.tr.mode_pq)
            self.mode_password_radio.setToolTip(self.tr.mode_standard_tt)
            self.mode_pq_radio.setToolTip(self.tr.mode_pq_tt)
            self.password_edit.setPlaceholderText(self.tr.password_ph)
            self.show_pass_check.setText(self.tr.show_password)

            self.decoy_group.setTitle(self.tr.decoy_group)
            self.decoy_group.setToolTip(self.tr.decoy_tooltip)
            self.decoy_info_lbl.setText(self.tr.decoy_subtitle)
            self.decoy_password_edit.setPlaceholderText(self.tr.decoy_password)
            self.decoy_input_picker["edit"].setPlaceholderText(self.tr.decoy_select_ph)
            self.decoy_input_picker["btn"].setText(self.tr.browse)

            self.decrypt_target_lbl.setText(self.tr.decrypt_target_label)
            self.auto_vol_radio.setText(self.tr.auto_volume)
            self.force_main_radio.setText(self.tr.force_main)
            self.force_decoy_radio.setText(self.tr.force_decoy)

            is_encrypt = self.encrypt_radio.isChecked()
            self.action_button.setText(
                self.tr.start_encrypt if is_encrypt else self.tr.start_decrypt
            )

            self.insp_group.setTitle(self.tr.inspect_group)
            self.inspect_picker["edit"].setPlaceholderText(self.tr.inspect_select_ph)
            self.inspect_picker["btn"].setText(self.tr.browse)
            self.inspect_auth_check.setText(self.tr.inspect_verify)
            self.inspect_pass_edit.setPlaceholderText(self.tr.inspect_password_ph)
            self.inspect_btn.setText(self.tr.inspect_button)

            self.open_folder_btn.setText(self.tr.open_folder)

            if self._status_state == "processing":
                self.status_lbl.setText(self.tr.status_processing)
            elif self._status_state == "error":
                self.status_lbl.setText(self.tr.status_error)
            else:
                self.status_lbl.setText(self.tr.status_ready)

        def _on_op_mode_changed(self) -> None:
            is_encrypt = self.encrypt_radio.isChecked()
            self.action_button.setText(
                self.tr.start_encrypt if is_encrypt else self.tr.start_decrypt
            )

            self.decoy_group.setVisible(is_encrypt)
            self.decrypt_opts_frame.setVisible(not is_encrypt)

            if not is_encrypt:
                self.file_radio.setChecked(True)
                self.dir_radio.setEnabled(False)
            else:
                self.dir_radio.setEnabled(True)

            self._update_defaults()

        def _on_input_type_changed(self) -> None:
            self._update_defaults()

        def _update_ui_state(self) -> None:
            has_decoy = self.decoy_group.isChecked()
            self.decoy_password_edit.setEnabled(has_decoy)
            self.decoy_input_picker["edit"].setEnabled(has_decoy)
            self.decoy_input_picker["btn"].setEnabled(has_decoy)

        def _toggle_password_visibility(self, state: int) -> None:
            checked = state == QtCore.Qt.CheckState.Checked.value
            mode = (
                QtWidgets.QLineEdit.EchoMode.Normal
                if checked
                else QtWidgets.QLineEdit.EchoMode.Password
            )
            self.password_edit.setEchoMode(mode)

        def _toggle_inspect_password(self, state: int) -> None:
            checked = state == QtCore.Qt.CheckState.Checked.value
            self.inspect_pass_edit.setEnabled(checked)
            if not checked:
                self.inspect_pass_edit.clear()

        # File browsing -------------------------------------------------------

        def _browse_input(self) -> None:
            if self.encrypt_radio.isChecked() and self.dir_radio.isChecked():
                path = QtWidgets.QFileDialog.getExistingDirectory(
                    self, self.tr.dialog_select_folder_encrypt
                )
            else:
                path, _ = QtWidgets.QFileDialog.getOpenFileName(
                    self, self.tr.dialog_select_file
                )

            if path:
                self.input_edit["edit"].setText(path)

        def _browse_output(self) -> None:
            if self.encrypt_radio.isChecked():
                path, _ = QtWidgets.QFileDialog.getSaveFileName(
                    self,
                    self.tr.dialog_save_container,
                    filter="Zilant Container (*.zil)",
                )
            else:
                path = QtWidgets.QFileDialog.getExistingDirectory(
                    self, self.tr.dialog_select_output_dir
                )

            if path:
                self.output_edit["edit"].setText(path)

        def _browse_decoy_input(self) -> None:
            if self.dir_radio.isChecked():
                path = QtWidgets.QFileDialog.getExistingDirectory(
                    self, self.tr.dialog_select_decoy_folder
                )
            else:
                path, _ = QtWidgets.QFileDialog.getOpenFileName(
                    self, self.tr.dialog_select_decoy_file
                )

            if path:
                self.decoy_input_picker["edit"].setText(path)

        def _browse_inspect_input(self) -> None:
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self,
                self.tr.dialog_select_container,
                filter="Zilant Container (*.zil)",
            )
            if path:
                self.inspect_picker["edit"].setText(path)

        def _on_input_changed(self) -> None:
            self._update_defaults()

        def _update_defaults(self) -> None:
            inp = self.input_edit["edit"].text().strip()
            if not inp:
                return

            path = Path(inp)
            is_encrypt = self.encrypt_radio.isChecked()
            current_out = self.output_edit["edit"].text().strip()

            if not current_out:
                if is_encrypt:
                    suggestion = (
                        path.with_suffix(path.suffix + ".zil")
                        if path.is_file()
                        else path.with_name(path.name + ".zil")
                    )
                else:
                    suggestion = path.with_suffix("")
                self.output_edit["edit"].setPlaceholderText(str(suggestion))

        # --- Main actions ----------------------------------------------------

        def _on_action_clicked(self) -> None:
            is_encrypt = self.encrypt_radio.isChecked()
            in_path_str = self.input_edit["edit"].text().strip()
            out_path_str = (
                self.output_edit["edit"].text().strip()
                or self.output_edit["edit"].placeholderText()
            )
            password = self.password_edit.text()

            if not in_path_str or not Path(in_path_str).exists():
                self._show_error(self.tr.input_missing)
                return
            if not password:
                self._show_error(self.tr.password_required)
                return

            in_path = Path(in_path_str)
            out_path = Path(out_path_str)

            overwrite_mode = self.overwrite_checkbox.isChecked()
            if out_path.exists() and not overwrite_mode:
                res = QtWidgets.QMessageBox.question(
                    self,
                    self.tr.overwrite_prompt_title,
                    self.tr.overwrite_prompt_body.format(path=out_path),
                )
                if res != QtWidgets.QMessageBox.StandardButton.Yes:
                    return
                overwrite_mode = True

            mode = (
                normalize_mode("pq-hybrid")
                if self.mode_pq_radio.isChecked()
                else normalize_mode("password")
            )

            self._set_busy(True)

            def encryption_task() -> None:
                decoy_active = self.decoy_group.isChecked()
                if decoy_active:
                    d_pass = self.decoy_password_edit.text()
                    if not d_pass:
                        raise InvalidPassword(self.tr.decoy_password_required)
                    d_in = self.decoy_input_picker["edit"].text().strip()
                    d_path = Path(d_in) if d_in else None
                    encrypt_with_decoy(
                        in_path,
                        d_path,
                        out_path,
                        main_password=password,
                        decoy_password=d_pass,
                        mode=mode,
                        overwrite=overwrite_mode,
                    )
                else:
                    encrypt_file(
                        in_path,
                        out_path,
                        password,
                        mode=mode,
                        overwrite=overwrite_mode,
                    )

            def decryption_task() -> None:
                vol: Literal["main", "decoy"] | None = None
                if self.force_main_radio.isChecked():
                    vol = "main"
                elif self.force_decoy_radio.isChecked():
                    vol = "decoy"

                if vol:
                    decrypt_file(
                        in_path,
                        out_path,
                        password,
                        volume_selector=vol,
                        mode=mode,
                        overwrite=overwrite_mode,
                    )
                else:
                    kwargs: dict[str, Any] = {
                        "password": password,
                        "mode": mode,
                    }
                    if _DECRYPT_AUTO_SUPPORTS_OVERWRITE:
                        kwargs["overwrite"] = overwrite_mode
                    decrypt_auto_volume(in_path, out_path, **kwargs)

            target_func = encryption_task if is_encrypt else decryption_task
            self._start_worker(target_func, out_path)

        def _handle_inspect(self) -> None:
            path_str = self.inspect_picker["edit"].text().strip()
            if not path_str or not Path(path_str).exists():
                self._show_error(self.tr.container_not_found)
                return

            path = Path(path_str)
            pwd = (
                self.inspect_pass_edit.text()
                if self.inspect_auth_check.isChecked()
                else None
            )

            self._set_busy(True)
            self._worker = TaskWorker(
                lambda: self._run_inspect_logic(path, pwd), self.tr
            )
            self._worker.finished_success.connect(
                lambda msg: self._on_worker_finished(True, msg)
            )
            self._worker.finished_error.connect(
                lambda msg: self._on_worker_finished(False, msg)
            )
            self._worker.start()

        def _run_inspect_logic(self, path: Path, pwd: str | None) -> None:
            overview, validated = check_container(
                path,
                password=pwd,
                volume_selector="all",
            )
            report = _format_overview_report(
                path, overview, validated, overview.pq_available, self.tr
            )
            self._temp_report = report

        # --- Worker plumbing -------------------------------------------------

        def _start_worker(
            self, func: Callable[[], None], output_target: Path | None
        ) -> None:
            self.progress_bar.setRange(0, 0)
            self.progress_bar.setVisible(True)
            self.status_lbl.setText(self.tr.status_processing)
            self.status_icon.setStyleSheet(f"color: {ACCENT_COLOR};")
            self._status_state = "processing"

            self._output_path = output_target
            self._worker = TaskWorker(func, self.tr)
            self._worker.finished_success.connect(
                lambda msg: self._on_worker_finished(True, msg)
            )
            self._worker.finished_error.connect(
                lambda msg: self._on_worker_finished(False, msg)
            )
            self._worker.start()

        def _on_worker_finished(self, success: bool, message: str) -> None:
            self._set_busy(False)
            self.progress_bar.setVisible(False)

            if success:
                self.status_lbl.setText(self.tr.status_ready)
                self.status_icon.setStyleSheet(f"color: {SUCCESS_COLOR};")
                self._status_state = "ready"

                if self._temp_report is not None:
                    self.inspect_output.setPlainText(self._temp_report)
                    self._temp_report = None
                    self.inspect_pass_edit.clear()
                else:
                    self.password_edit.clear()
                    self.decoy_password_edit.clear()
                    self._show_info(self.tr.success_title, message)
            else:
                self.status_lbl.setText(self.tr.status_error)
                self.status_icon.setStyleSheet(f"color: {ERROR_COLOR};")
                self._status_state = "error"
                self.password_edit.clear()
                self.decoy_password_edit.clear()
                self._show_error(message)

        # --- Misc helpers ----------------------------------------------------

        def _set_busy(self, busy: bool) -> None:
            self.tabs.setEnabled(not busy)
            if busy:
                self.setCursor(QtCore.Qt.CursorShape.BusyCursor)
            else:
                self.unsetCursor()

        def _open_output_folder(self) -> None:
            if self._output_path and self._output_path.exists():
                target = (
                    self._output_path
                    if self._output_path.is_dir()
                    else self._output_path.parent
                )
                QtGui.QDesktopServices.openUrl(
                    QtCore.QUrl.fromLocalFile(str(target))
                )

        def _show_error(self, msg: str) -> None:
            QtWidgets.QMessageBox.critical(self, self.tr.error_title, msg)

        def _show_info(self, title: str, msg: str) -> None:
            QtWidgets.QMessageBox.information(self, title, msg)

        def _show_about_dialog(self) -> None:
            QtWidgets.QMessageBox.about(
                self,
                self.tr.about_title,
                self.tr.about_body.format(version=__version__),
            )


    def create_app() -> QtWidgets.QApplication:
        app = QtWidgets.QApplication(sys.argv)
        font = QtGui.QFont("Segoe UI", 10)
        app.setFont(font)

        window = ZilantWindow()
        window.show()

        # Keep reference so it isn't GC'ed
        app._zilant_window = window
        return app

else:

    def create_app() -> Any:
        raise ImportError("PySide6 not installed.")


def main() -> None:
    if not QT_AVAILABLE:
        print("Error: PySide6 library is missing.")
        print("Run: pip install PySide6")
        sys.exit(1)

    app = create_app()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
