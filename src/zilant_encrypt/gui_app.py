"""Desktop GUI for Zilant Encrypt with Modern Zinc theme and Robust Path Logic."""
from __future__ import annotations

import importlib.util
import inspect
import locale
import platform
import subprocess
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
    from PySide6 import QtCore, QtGui, QtWidgets
elif TYPE_CHECKING:
    from PySide6 import QtCore, QtGui, QtWidgets
else:
    QtCore = QtGui = QtWidgets = cast(Any, None)

try:
    _DECRYPT_AUTO_SUPPORTS_OVERWRITE = (
        "overwrite" in inspect.signature(decrypt_auto_volume).parameters
    )
except Exception:
    _DECRYPT_AUTO_SUPPORTS_OVERWRITE = False

# --- Design Tokens ---
BG_MAIN = "#18181B"
BG_SURFACE = "#27272A"
BG_INPUT = "#3F3F46"
ACCENT = "#3B82F6"
ACCENT_HOVER = "#60A5FA"
TEXT_PRIMARY = "#F4F4F5"
TEXT_SECONDARY = "#A1A1AA"
BORDER = "#52525B"
SUCCESS_COLOR = "#22C55E"
ERROR_COLOR = "#EF4444"

FONT_FAMILY = "Segoe UI, Inter, Roboto, sans-serif"

STYLESHEET = f"""
* {{
    font-family: "{FONT_FAMILY}";
    outline: none;
}}

QMainWindow, QWidget#ContentWidget {{
    background-color: {BG_MAIN};
    color: {TEXT_PRIMARY};
}}

QGroupBox {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 10px;
    margin-top: 18px;
    padding: 18px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: {ACCENT};
    font-weight: 700;
}}

QLabel {{ color: {TEXT_PRIMARY}; }}
QLabel#H1 {{ font-size: 20px; font-weight: 800; }}
QLabel#Subtitle {{ color: {TEXT_SECONDARY}; font-size: 13px; }}
QLabel#H2 {{ font-size: 14px; font-weight: 700; margin-bottom: 6px; }}
QLabel#StatusIcon {{ font-size: 16px; }}

QLineEdit {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 12px 14px;
    color: {TEXT_PRIMARY};
    font-size: 14px;
}}
QLineEdit:focus {{
    border: 1px solid {ACCENT};
    background-color: #45454a;
}}
QLineEdit:disabled {{
    color: {TEXT_SECONDARY};
    background-color: #2D2D30;
    border-color: #444;
}}

QPushButton {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 10px 14px;
    color: {TEXT_PRIMARY};
    font-weight: 600;
}}
QPushButton:hover {{
    background-color: #52525B;
    border-color: #666;
}}
QPushButton:pressed {{
    background-color: #2d2d30;
}}

QPushButton#PrimaryButton {{
    background-color: {ACCENT};
    border: 1px solid {ACCENT};
    color: white;
    font-weight: 800;
    padding: 12px 20px;
}}
QPushButton#PrimaryButton:hover {{
    background-color: {ACCENT_HOVER};
    border-color: {ACCENT_HOVER};
}}

QPushButton#GhostButton {{
    background: transparent;
    border: none;
    color: {ACCENT};
    font-weight: 700;
}}
QPushButton#GhostButton:hover {{
    text-decoration: underline;
    color: {ACCENT_HOVER};
}}

QCheckBox, QRadioButton {{
    color: {TEXT_PRIMARY};
    spacing: 8px;
    font-size: 14px;
}}

QProgressBar {{
    background-color: {BG_INPUT};
    border: none;
    border-radius: 3px;
    height: 6px;
}}
QProgressBar::chunk {{
    background-color: {ACCENT};
}}

QComboBox {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 8px 12px;
    color: {TEXT_PRIMARY};
}}
QComboBox::drop-down {{ border: none; width: 24px; }}
"""


def _detect_lang() -> Lang:
    try:
        code, _ = locale.getdefaultlocale()
        if code and code.lower().startswith("ru"):
            return "ru"
    except Exception:
        pass
    return "en"


def _format_overview_report(
    path: Path,
    overview: ContainerOverview,
    validated: list[int],
    pq_available: bool,
    strings: Strings,
) -> str:
    version = overview.header.version
    lines: list[str] = [
        strings.overview_file.format(path=path),
        strings.overview_version.format(version=version),
        "-" * 40,
        strings.overview_volumes,
    ]

    password_used = bool(validated)

    for desc in overview.descriptors:
        if desc.volume_index == 0:
            label = strings.overview_label_main.upper()
        elif desc.volume_index == 1:
            label = strings.overview_label_decoy.upper()
        else:
            label = f"VOL #{desc.volume_index}"

        mode = "PQ-HYBRID" if desc.key_mode == KEY_MODE_PQ_HYBRID else "STANDARD"

        if password_used:
            status = "[ OK ]" if desc.volume_index in validated else "[ -- ]"
        else:
            status = "[ ?? ]"

        lines.append(f"{status} {label:<8} | {mode}")

    lines.append("-" * 40)
    pq_status = "YES" if pq_available else "NO"
    lines.append(f"System PQ Support: {pq_status}")
    return "\n".join(lines)


if QT_AVAILABLE:

    class TaskWorker(QtCore.QThread):
        finished_success = QtCore.Signal(str)
        finished_error = QtCore.Signal(str)

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
            except Exception as e:
                traceback.print_exc()
                self.finished_error.emit(
                    self._strings.processing_unexpected_error.format(error=e)
                )

    class ZilantWindow(QtWidgets.QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self._lang: Lang = _detect_lang()
            self.ui_strings: Strings = get_strings(self._lang)

            self.setWindowTitle(f"{self.ui_strings.app_title} v{__version__}")
            self.resize(1040, 840)
            self.setMinimumSize(900, 700)

            self._worker: TaskWorker | None = None
            self._output_path: Path | None = None
            self._temp_report: str | None = None
            self._status_state: Literal["ready", "processing", "error"] = "ready"

            self.setStyleSheet(STYLESHEET)

            content = QtWidgets.QWidget()
            content.setObjectName("ContentWidget")
            self.setCentralWidget(content)

            layout = QtWidgets.QVBoxLayout(content)
            layout.setContentsMargins(28, 26, 28, 20)
            layout.setSpacing(18)

            self._build_header(layout)
            self.tabs = QtWidgets.QTabWidget()
            layout.addWidget(self.tabs)

            self._build_encrypt_tab()
            self._build_inspect_tab()
            self._build_footer(layout)

            self._retranslate_ui()
            self._update_defaults()

        def _build_header(self, parent_layout: QtWidgets.QVBoxLayout) -> None:
            header = QtWidgets.QWidget()
            h_layout = QtWidgets.QHBoxLayout(header)
            h_layout.setContentsMargins(0, 0, 0, 0)

            title_block = QtWidgets.QVBoxLayout()
            self.title_lbl = QtWidgets.QLabel(self.ui_strings.app_title)
            self.title_lbl.setObjectName("H1")
            self.subtitle_lbl = QtWidgets.QLabel(self.ui_strings.subtitle)
            self.subtitle_lbl.setObjectName("Subtitle")
            title_block.addWidget(self.title_lbl)
            title_block.addWidget(self.subtitle_lbl)

            h_layout.addLayout(title_block)
            h_layout.addStretch()

            self.lang_combo = QtWidgets.QComboBox()
            self.lang_combo.addItems(["English", "Русский"])
            self.lang_combo.setItemData(0, "en")
            self.lang_combo.setItemData(1, "ru")
            self.lang_combo.setCurrentIndex(0 if self._lang == "en" else 1)
            self.lang_combo.currentIndexChanged.connect(self._on_lang_changed)

            self.about_btn = QtWidgets.QPushButton(self.ui_strings.about)
            self.about_btn.clicked.connect(self._show_about_dialog)

            h_layout.addWidget(self.lang_combo)
            h_layout.addWidget(self.about_btn)

            parent_layout.addWidget(header)

        def _build_encrypt_tab(self) -> None:
            tab = QtWidgets.QWidget()
            tab.setObjectName("ContentWidget")
            self.tabs.addTab(tab, "")

            vbox = QtWidgets.QVBoxLayout(tab)
            vbox.setContentsMargins(6, 12, 6, 12)
            vbox.setSpacing(16)

            mode_group = QtWidgets.QGroupBox()
            mode_group.setTitle(self.ui_strings.action_label)
            mode_layout = QtWidgets.QHBoxLayout(mode_group)
            mode_layout.setSpacing(14)

            self.encrypt_radio = QtWidgets.QRadioButton(self.ui_strings.encrypt)
            self.decrypt_radio = QtWidgets.QRadioButton(self.ui_strings.decrypt)
            self.encrypt_radio.setChecked(True)
            self.encrypt_radio.toggled.connect(self._on_op_mode_changed)

            mode_layout.addWidget(self.encrypt_radio)
            mode_layout.addWidget(self.decrypt_radio)
            mode_layout.addStretch()
            vbox.addWidget(mode_group)

            io_group = QtWidgets.QGroupBox()
            io_group.setTitle(self.ui_strings.input_output_group)
            io_layout = QtWidgets.QVBoxLayout(io_group)
            io_layout.setSpacing(14)

            type_row = QtWidgets.QHBoxLayout()
            self.type_label = QtWidgets.QLabel(self.ui_strings.source_type)
            self.file_radio = QtWidgets.QRadioButton(self.ui_strings.single_file)
            self.dir_radio = QtWidgets.QRadioButton(self.ui_strings.directory_zip)
            self.file_radio.setChecked(True)
            self.file_radio.toggled.connect(self._on_input_type_changed)
            type_row.addWidget(self.type_label)
            type_row.addSpacing(10)
            type_row.addWidget(self.file_radio)
            type_row.addWidget(self.dir_radio)
            type_row.addStretch()
            io_layout.addLayout(type_row)

            self.input_label = QtWidgets.QLabel()
            self.input_label.setObjectName("H2")
            self.input_picker = self._create_path_picker(self._browse_input)
            io_layout.addWidget(self.input_label)
            io_layout.addLayout(self.input_picker["layout"])

            self.output_label = QtWidgets.QLabel()
            self.output_label.setObjectName("H2")
            self.output_picker = self._create_path_picker(self._browse_output)
            io_layout.addWidget(self.output_label)
            io_layout.addLayout(self.output_picker["layout"])

            self.overwrite_checkbox = QtWidgets.QCheckBox(
                self.ui_strings.overwrite_checkbox
            )
            io_layout.addWidget(self.overwrite_checkbox)

            vbox.addWidget(io_group)

            security_group = QtWidgets.QGroupBox()
            security_group.setTitle(self.ui_strings.security_group)
            sec_layout = QtWidgets.QVBoxLayout(security_group)
            sec_layout.setSpacing(12)

            self.mode_password_radio = QtWidgets.QRadioButton(
                self.ui_strings.mode_standard
            )
            self.mode_pq_radio = QtWidgets.QRadioButton(self.ui_strings.mode_pq)
            self.mode_password_radio.setChecked(True)
            sec_layout.addWidget(self.mode_password_radio)
            sec_layout.addWidget(self.mode_pq_radio)

            pass_row = QtWidgets.QVBoxLayout()
            self.pass_label = QtWidgets.QLabel()
            self.pass_label.setObjectName("H2")
            pass_row.addWidget(self.pass_label)

            pass_field = QtWidgets.QHBoxLayout()
            self.password_edit = QtWidgets.QLineEdit()
            self.password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.password_edit.setMinimumHeight(44)
            self.show_pass_check = QtWidgets.QCheckBox()
            self.show_pass_check.stateChanged.connect(self._toggle_password_visibility)
            pass_field.addWidget(self.password_edit)
            pass_field.addWidget(self.show_pass_check)
            pass_row.addLayout(pass_field)
            sec_layout.addLayout(pass_row)

            self.decoy_group = QtWidgets.QGroupBox()
            self.decoy_group.setTitle(self.ui_strings.decoy_group)
            self.decoy_group.setCheckable(True)
            self.decoy_group.setChecked(False)
            self.decoy_group.toggled.connect(self._update_ui_state)

            decoy_layout = QtWidgets.QVBoxLayout(self.decoy_group)
            self.decoy_info_lbl = QtWidgets.QLabel(self.ui_strings.decoy_subtitle)
            self.decoy_info_lbl.setWordWrap(True)
            decoy_layout.addWidget(self.decoy_info_lbl)

            self.decoy_password_edit = QtWidgets.QLineEdit()
            self.decoy_password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.decoy_password_edit.setPlaceholderText(self.ui_strings.decoy_password)
            self.decoy_password_edit.setMinimumHeight(44)
            decoy_layout.addWidget(self.decoy_password_edit)

            self.decoy_picker_label = QtWidgets.QLabel(self.ui_strings.input_path)
            self.decoy_picker_label.setObjectName("H2")
            self.decoy_picker = self._create_path_picker(self._browse_decoy_input)
            decoy_layout.addWidget(self.decoy_picker_label)
            decoy_layout.addLayout(self.decoy_picker["layout"])

            sec_layout.addWidget(self.decoy_group)
            vbox.addWidget(security_group)

            self.decrypt_opts_frame = QtWidgets.QGroupBox()
            self.decrypt_opts_frame.setTitle(self.ui_strings.decrypt_target_label)
            dec_layout = QtWidgets.QHBoxLayout(self.decrypt_opts_frame)
            self.auto_vol_radio = QtWidgets.QRadioButton(self.ui_strings.auto_volume)
            self.force_main_radio = QtWidgets.QRadioButton(self.ui_strings.force_main)
            self.force_decoy_radio = QtWidgets.QRadioButton(self.ui_strings.force_decoy)
            self.auto_vol_radio.setChecked(True)
            dec_layout.addWidget(self.auto_vol_radio)
            dec_layout.addWidget(self.force_main_radio)
            dec_layout.addWidget(self.force_decoy_radio)
            dec_layout.addStretch()
            self.decrypt_opts_frame.setVisible(False)
            vbox.addWidget(self.decrypt_opts_frame)

            self.action_button = QtWidgets.QPushButton()
            self.action_button.setObjectName("PrimaryButton")
            self.action_button.clicked.connect(self._on_action_clicked)
            vbox.addWidget(
                self.action_button, alignment=QtCore.Qt.AlignmentFlag.AlignRight
            )

        def _build_inspect_tab(self) -> None:
            tab = QtWidgets.QWidget()
            tab.setObjectName("ContentWidget")
            self.tabs.addTab(tab, "")

            vbox = QtWidgets.QVBoxLayout(tab)
            vbox.setContentsMargins(6, 12, 6, 12)
            vbox.setSpacing(14)

            insp_group = QtWidgets.QGroupBox()
            insp_group.setTitle(self.ui_strings.inspect_group)
            insp_layout = QtWidgets.QVBoxLayout(insp_group)
            insp_layout.setSpacing(10)

            self.inspect_picker = self._create_path_picker(self._browse_inspect_input)
            insp_layout.addWidget(
                QtWidgets.QLabel("📄 " + self.ui_strings.inspect_select_ph)
            )
            insp_layout.addLayout(self.inspect_picker["layout"])

            self.inspect_auth_check = QtWidgets.QCheckBox(self.ui_strings.inspect_verify)
            self.inspect_auth_check.stateChanged.connect(self._toggle_inspect_password)
            insp_layout.addWidget(self.inspect_auth_check)

            self.inspect_pass_edit = QtWidgets.QLineEdit()
            self.inspect_pass_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.inspect_pass_edit.setEnabled(False)
            self.inspect_pass_edit.setPlaceholderText(
                self.ui_strings.inspect_password_ph
            )
            self.inspect_pass_edit.setMinimumHeight(44)
            insp_layout.addWidget(self.inspect_pass_edit)

            self.inspect_btn = QtWidgets.QPushButton(self.ui_strings.inspect_button)
            self.inspect_btn.clicked.connect(self._handle_inspect)
            insp_layout.addWidget(
                self.inspect_btn, alignment=QtCore.Qt.AlignmentFlag.AlignRight
            )

            self.inspect_output = QtWidgets.QPlainTextEdit()
            self.inspect_output.setReadOnly(True)
            self.inspect_output.setMinimumHeight(200)
            insp_layout.addWidget(self.inspect_output)

            vbox.addWidget(insp_group)

        def _build_footer(self, parent_layout: QtWidgets.QVBoxLayout) -> None:
            footer = QtWidgets.QWidget()
            f_layout = QtWidgets.QVBoxLayout(footer)
            f_layout.setContentsMargins(0, 6, 0, 0)
            f_layout.setSpacing(8)

            self.progress_bar = QtWidgets.QProgressBar()
            self.progress_bar.setVisible(False)
            f_layout.addWidget(self.progress_bar)

            status_row = QtWidgets.QHBoxLayout()
            self.status_icon = QtWidgets.QLabel("●")
            self.status_icon.setObjectName("StatusIcon")
            self.status_lbl = QtWidgets.QLabel(self.ui_strings.status_ready)
            self.open_folder_btn = QtWidgets.QPushButton(self.ui_strings.open_folder)
            self.open_folder_btn.setObjectName("GhostButton")
            self.open_folder_btn.clicked.connect(self._open_output_folder)
            self.open_folder_btn.setVisible(False)

            status_row.addWidget(self.status_icon)
            status_row.addSpacing(6)
            status_row.addWidget(self.status_lbl)
            status_row.addStretch()
            status_row.addWidget(self.open_folder_btn)
            f_layout.addLayout(status_row)

            parent_layout.addWidget(footer)

        def _create_path_picker(self, slot: Callable[[], None]) -> dict[str, Any]:
            layout = QtWidgets.QHBoxLayout()
            layout.setSpacing(6)

            edit = QtWidgets.QLineEdit()
            edit.setMinimumHeight(44)
            edit.textChanged.connect(self._on_input_changed)

            btn = QtWidgets.QPushButton(self.ui_strings.browse)
            btn.setMinimumHeight(44)
            btn.setFixedWidth(96)
            btn.clicked.connect(slot)

            layout.addWidget(edit)
            layout.addWidget(btn)
            return {"layout": layout, "edit": edit, "btn": btn}

        def _on_lang_changed(self, index: int) -> None:
            lang_value = self.lang_combo.itemData(index) or "en"
            self._lang = cast(Lang, lang_value)
            self.ui_strings = get_strings(self._lang)
            self._retranslate_ui()
            self._update_defaults()

        def _retranslate_ui(self) -> None:
            self.setWindowTitle(f"{self.ui_strings.app_title} v{__version__}")
            self.title_lbl.setText(self.ui_strings.app_title)
            self.subtitle_lbl.setText(self.ui_strings.subtitle)
            self.about_btn.setText(self.ui_strings.about)
            self.tabs.setTabText(0, self.ui_strings.tab_encrypt)
            self.tabs.setTabText(1, self.ui_strings.tab_inspect)

            self.encrypt_radio.setText(self.ui_strings.encrypt)
            self.decrypt_radio.setText(self.ui_strings.decrypt)
            self.type_label.setText("📄 " + self.ui_strings.source_type)
            self.file_radio.setText(self.ui_strings.single_file)
            self.dir_radio.setText("📂 " + self.ui_strings.directory_zip)

            self.input_label.setText("📄 " + self.ui_strings.input_path)
            self.output_label.setText("💾 " + self.ui_strings.output_path)
            self.overwrite_checkbox.setText(self.ui_strings.overwrite_checkbox)

            self.mode_password_radio.setText(self.ui_strings.mode_standard)
            self.mode_pq_radio.setText(self.ui_strings.mode_pq)
            self.pass_label.setText("🔒 " + self.ui_strings.password_ph)
            self.show_pass_check.setText("👁️ " + self.ui_strings.show_password)

            self.decoy_group.setTitle(self.ui_strings.decoy_group)
            self.decoy_info_lbl.setText(self.ui_strings.decoy_subtitle)
            self.decoy_password_edit.setPlaceholderText(self.ui_strings.decoy_password)
            self.decoy_picker_label.setText("📄 " + self.ui_strings.input_path)
            self.decoy_picker["btn"].setText(self.ui_strings.browse)

            self.decrypt_opts_frame.setTitle(self.ui_strings.decrypt_target_label)
            self.auto_vol_radio.setText(self.ui_strings.auto_volume)
            self.force_main_radio.setText(self.ui_strings.force_main)
            self.force_decoy_radio.setText(self.ui_strings.force_decoy)

            self.action_button.setText(
                self.ui_strings.start_encrypt
                if self.encrypt_radio.isChecked()
                else self.ui_strings.start_decrypt
            )

            self.inspect_btn.setText(self.ui_strings.inspect_button)
            self.inspect_auth_check.setText(self.ui_strings.inspect_verify)
            self.inspect_pass_edit.setPlaceholderText(
                self.ui_strings.inspect_password_ph
            )
            self.inspect_picker["btn"].setText(self.ui_strings.browse)

            self.open_folder_btn.setText(self.ui_strings.open_folder)
            self._update_status_text()

        def _update_status_text(self) -> None:
            if self._status_state == "processing":
                self.status_lbl.setText(self.ui_strings.status_processing)
                self.status_icon.setStyleSheet(f"color: {ACCENT};")
            elif self._status_state == "error":
                self.status_lbl.setText(self.ui_strings.status_error)
                self.status_icon.setStyleSheet(f"color: {ERROR_COLOR};")
            else:
                self.status_lbl.setText(self.ui_strings.status_ready)
                self.status_icon.setStyleSheet(f"color: {SUCCESS_COLOR};")

        def _on_op_mode_changed(self) -> None:
            is_encrypt = self.encrypt_radio.isChecked()
            self.action_button.setText(
                self.ui_strings.start_encrypt
                if is_encrypt
                else self.ui_strings.start_decrypt
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
            self.decoy_picker["edit"].setEnabled(has_decoy)
            self.decoy_picker["btn"].setEnabled(has_decoy)

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

        def _browse_input(self) -> None:
            if self.encrypt_radio.isChecked() and self.dir_radio.isChecked():
                path = QtWidgets.QFileDialog.getExistingDirectory(
                    self, self.ui_strings.dialog_select_folder_encrypt
                )
            else:
                path, _ = QtWidgets.QFileDialog.getOpenFileName(
                    self, self.ui_strings.dialog_select_file
                )
            if path:
                self.input_picker["edit"].setText(path)

        def _browse_output(self) -> None:
            if self.encrypt_radio.isChecked():
                path, _ = QtWidgets.QFileDialog.getSaveFileName(
                    self,
                    self.ui_strings.dialog_save_container,
                    filter="Zilant Container (*.zil)",
                )
            else:
                path = QtWidgets.QFileDialog.getExistingDirectory(
                    self, self.ui_strings.dialog_select_output_dir
                )
            if path:
                self.output_picker["edit"].setText(path)

        def _browse_decoy_input(self) -> None:
            if self.dir_radio.isChecked():
                path = QtWidgets.QFileDialog.getExistingDirectory(
                    self, self.ui_strings.dialog_select_decoy_folder
                )
            else:
                path, _ = QtWidgets.QFileDialog.getOpenFileName(
                    self, self.ui_strings.dialog_select_decoy_file
                )
            if path:
                self.decoy_picker["edit"].setText(path)

        def _browse_inspect_input(self) -> None:
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self,
                self.ui_strings.dialog_select_container,
                filter="Zilant Container (*.zil)",
            )
            if path:
                self.inspect_picker["edit"].setText(path)

        def _on_input_changed(self) -> None:
            self._update_defaults()

        def _suggest_output_name(self, input_path: Path, is_encrypt: bool) -> str:
            if is_encrypt:
                return input_path.name + ".zil"

            # Smart decryption naming
            if input_path.name.endswith(".zil"):
                candidate = input_path.name[: -len(".zil")]
                # If result has no extension (e.g. 'kek1'), append .decrypted to avoid confusion
                if "." not in candidate:
                    return candidate + ".decrypted"
                return candidate

            return input_path.name + ".decrypted"

        def _suggest_output_path(self, input_path: Path, is_encrypt: bool) -> Path:
            return input_path.with_name(
                self._suggest_output_name(input_path, is_encrypt)
            )

        def _resolve_output_path(
            self, input_path: Path, out_text: str | None, is_encrypt: bool
        ) -> Path:
            base_name = self._suggest_output_name(input_path, is_encrypt)
            if out_text:
                candidate = Path(out_text)
                # If it exists as a dir, or looks like a dir path (ends in slash)
                if (candidate.exists() and candidate.is_dir()) or (
                    not candidate.suffix and str(out_text).endswith(("/", "\\"))
                ):
                    return candidate / base_name
                # If parent exists and it's not a dir, assume it's a full file path
                return candidate
            return self._suggest_output_path(input_path, is_encrypt)

        def _update_defaults(self) -> None:
            raw_input = self.input_picker["edit"].text().strip()
            if not raw_input:
                return
            in_path = Path(raw_input)
            target = self._suggest_output_path(
                in_path, self.encrypt_radio.isChecked()
            )
            if not self.output_picker["edit"].text().strip():
                self.output_picker["edit"].setPlaceholderText(str(target))

        def _on_action_clicked(self) -> None:
            is_encrypt = self.encrypt_radio.isChecked()
            in_path_str = self.input_picker["edit"].text().strip()
            out_raw = self.output_picker["edit"].text().strip()
            out_placeholder = self.output_picker["edit"].placeholderText().strip()
            password = self.password_edit.text()

            if not in_path_str or not Path(in_path_str).exists():
                self._show_error(self.ui_strings.input_missing)
                return
            if not password:
                self._show_error(self.ui_strings.password_required)
                return

            resolved_out = self._resolve_output_path(
                Path(in_path_str), out_raw or out_placeholder, is_encrypt
            )
            self.output_picker["edit"].setText(str(resolved_out))

            overwrite = self.overwrite_checkbox.isChecked()
            if resolved_out.exists() and resolved_out.is_file() and not overwrite:
                res = QtWidgets.QMessageBox.question(
                    self,
                    self.ui_strings.overwrite_prompt_title,
                    self.ui_strings.overwrite_prompt_body.format(path=resolved_out),
                )
                if res != QtWidgets.QMessageBox.StandardButton.Yes:
                    return
                overwrite = True

            mode = (
                normalize_mode("pq-hybrid")
                if self.mode_pq_radio.isChecked()
                else normalize_mode("password")
            )
            self._set_busy(True)

            def enc_task() -> None:
                if self.decoy_group.isChecked():
                    d_pass = self.decoy_password_edit.text()
                    if not d_pass:
                        raise InvalidPassword(self.ui_strings.decoy_password_required)
                    d_in = self.decoy_picker["edit"].text().strip()
                    encrypt_with_decoy(
                        Path(in_path_str),
                        Path(d_in) if d_in else None,
                        resolved_out,
                        main_password=password,
                        decoy_password=d_pass,
                        mode=mode,
                        overwrite=overwrite,
                    )
                else:
                    encrypt_file(
                        Path(in_path_str),
                        resolved_out,
                        password,
                        mode=mode,
                        overwrite=overwrite,
                    )

            def dec_task() -> None:
                vol: Literal["main", "decoy"] | None = None
                if self.force_main_radio.isChecked():
                    vol = "main"
                elif self.force_decoy_radio.isChecked():
                    vol = "decoy"

                if vol:
                    decrypt_file(
                        Path(in_path_str),
                        resolved_out,
                        password,
                        volume_selector=vol,
                        mode=mode,
                        overwrite=overwrite,
                    )
                else:
                    if _DECRYPT_AUTO_SUPPORTS_OVERWRITE:
                        decrypt_auto_volume(
                            Path(in_path_str),
                            resolved_out,
                            password=password,
                            mode=mode,
                            overwrite=overwrite,
                        )
                    else:
                        decrypt_auto_volume(
                            Path(in_path_str),
                            Path(resolved_out),
                            password=password,
                            mode=mode,
                        )

            self._start_worker(enc_task if is_encrypt else dec_task, resolved_out)

        def _handle_inspect(self) -> None:
            p_str = self.inspect_picker["edit"].text().strip()
            if not p_str or not Path(p_str).exists():
                self._show_error(self.ui_strings.container_not_found)
                return

            pwd = (
                self.inspect_pass_edit.text()
                if self.inspect_auth_check.isChecked()
                else None
            )
            self._set_busy(True)

            def logic() -> None:
                overview, validated = check_container(
                    Path(p_str), password=pwd, volume_selector="all"
                )
                self._temp_report = _format_overview_report(
                    Path(p_str),
                    overview,
                    validated,
                    overview.pq_available,
                    self.ui_strings,
                )

            self._start_worker(logic, None)

        def _start_worker(self, func: Callable[[], None], target: Path | None) -> None:
            self.progress_bar.setRange(0, 0)
            self.progress_bar.setVisible(True)
            self._status_state = "processing"
            self._update_status_text()
            self.open_folder_btn.setVisible(False)
            self._output_path = target

            self._worker = TaskWorker(func, self.ui_strings)
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
                self._status_state = "ready"
                if self._output_path:
                    self.open_folder_btn.setVisible(True)
                if self._temp_report:
                    self.inspect_output.setPlainText(self._temp_report)
                    self._temp_report = None
                else:
                    self.password_edit.clear()
                    self.decoy_password_edit.clear()
                    self._show_info(self.ui_strings.success_title, message)
            else:
                self._status_state = "error"
                self.password_edit.clear()
                self.decoy_password_edit.clear()
                self._show_error(message)

            self._update_status_text()

        def _set_busy(self, busy: bool) -> None:
            self.tabs.setEnabled(not busy)
            if busy:
                self.setCursor(QtCore.Qt.CursorShape.BusyCursor)
            else:
                self.unsetCursor()

        def _open_output_folder(self) -> None:
            if self._output_path and self._output_path.exists():
                self._reveal_in_file_manager(self._output_path)

        def _reveal_in_file_manager(self, path: Path) -> None:
            """Open file manager and select the file."""
            if not path.exists():
                return

            path_str = str(path.resolve())
            system_name = platform.system()

            try:
                if system_name == "Windows":
                    subprocess.run(["explorer", "/select,", path_str])
                elif system_name == "Darwin":  # macOS
                    subprocess.run(["open", "-R", path_str])
                else:  # Linux and others
                    # Try dbus/freedesktop standard first
                    try:
                        subprocess.run(["xdg-open", str(path.parent)])
                    except Exception:
                        pass
            except Exception:
                # Fallback just open the parent folder
                QtGui.QDesktopServices.openUrl(
                    QtCore.QUrl.fromLocalFile(str(path.parent))
                )

        def _show_error(self, msg: str) -> None:
            QtWidgets.QMessageBox.critical(self, self.ui_strings.error_title, msg)

        def _show_info(self, title: str, msg: str) -> None:
            QtWidgets.QMessageBox.information(self, title, msg)

        def _show_about_dialog(self) -> None:
            QtWidgets.QMessageBox.about(
                self,
                self.ui_strings.about_title,
                self.ui_strings.about_body.format(version=__version__),
            )


def create_app() -> Any:
    if not QT_AVAILABLE:
        raise ImportError("PySide6 not installed.")
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    window = ZilantWindow()
    window.show()
    app._zilant_window = window  # type: ignore[attr-defined]
    return app


def main() -> None:
    if not QT_AVAILABLE:
        print("Error: PySide6 library is missing.")
        sys.exit(1)
    app = create_app()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
