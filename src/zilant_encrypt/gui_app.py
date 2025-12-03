"""Desktop GUI for Zilant Encrypt (Refined UI)."""
from __future__ import annotations

import importlib.util
import inspect
import locale
import sys
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Literal, cast

# --- Imports from your package ---
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

# ---- API feature detection -------------------------------------------------

try:
    _DECRYPT_AUTO_SUPPORTS_OVERWRITE = (
        "overwrite" in inspect.signature(decrypt_auto_volume).parameters
    )
except Exception:
    _DECRYPT_AUTO_SUPPORTS_OVERWRITE = False

# --- Styles & Constants (Modern "Zinc" Dark Theme) -----------------------

# Palette
BG_MAIN = "#18181B"        # Main Window Background
BG_SURFACE = "#27272A"     # Cards / Groups
BG_INPUT = "#3F3F46"       # Inputs
ACCENT = "#3B82F6"         # Primary Blue
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

/* --- Scroll Area --- */
QScrollArea {{
    background: transparent;
    border: none;
}}

/* --- Tabs --- */
QTabWidget::pane {{
    border: none;
    background: {BG_MAIN};
    border-top: 1px solid {BORDER};
}}
QTabWidget::tab-bar {{
    alignment: left;
}}
QTabBar::tab {{
    background: transparent;
    color: {TEXT_SECONDARY};
    padding: 12px 20px;
    font-size: 14px;
    font-weight: 600;
    border-bottom: 3px solid transparent;
    margin-right: 4px;
}}
QTabBar::tab:selected {{
    color: {TEXT_PRIMARY};
    border-bottom: 3px solid {ACCENT};
}}
QTabBar::tab:hover {{
    color: {TEXT_PRIMARY};
    background-color: rgba(255, 255, 255, 0.05);
}}

/* --- Group Box (Cards) --- */
QGroupBox {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
    margin-top: 24px;
    padding-top: 24px;
    padding-bottom: 16px;
    padding-left: 16px;
    padding-right: 16px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 5px;
    left: 10px;
    color: {ACCENT};
    font-weight: bold;
    font-size: 13px;
    background-color: transparent;
}}

/* --- Inputs --- */
QLineEdit {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 8px 12px;
    color: {TEXT_PRIMARY};
    font-size: 14px;
    selection-background-color: {ACCENT};
}}
QLineEdit:focus {{
    border: 1px solid {ACCENT};
    background-color: #45454A;
}}
QLineEdit:disabled {{
    background-color: #2A2A2D;
    color: {TEXT_SECONDARY};
    border: 1px solid #333;
}}

/* --- Buttons --- */
QPushButton {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 8px 16px;
    color: {TEXT_PRIMARY};
    font-weight: 500;
    font-size: 13px;
}}
QPushButton:hover {{
    background-color: #52525B;
    border-color: #666;
}}
QPushButton:pressed {{
    background-color: #27272A;
}}

/* Primary Action Button */
QPushButton#PrimaryButton {{
    background-color: {ACCENT};
    border: 1px solid {ACCENT};
    color: white;
    font-size: 15px;
    font-weight: 700;
    padding: 12px;
}}
QPushButton#PrimaryButton:hover {{
    background-color: {ACCENT_HOVER};
    border-color: {ACCENT_HOVER};
}}

/* Ghost/Link Button (for Open Folder) */
QPushButton#GhostButton {{
    background-color: transparent;
    border: none;
    color: {ACCENT};
    text-align: right;
}}
QPushButton#GhostButton:hover {{
    text-decoration: underline;
    color: {ACCENT_HOVER};
}}

/* --- Radio Buttons & Checkboxes --- */
QRadioButton, QCheckBox {{
    spacing: 8px;
    color: {TEXT_PRIMARY};
    font-size: 14px;
}}
QRadioButton::indicator, QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 9px;
    border: 1px solid {BORDER};
    background: {BG_INPUT};
}}
QCheckBox::indicator {{
    border-radius: 4px;
}}
QRadioButton::indicator:checked, QCheckBox::indicator:checked {{
    background-color: {ACCENT};
    border-color: {ACCENT};
    image: none;
}}
/* Simple dot for radio checked */
QRadioButton::indicator:checked {{
    border: 4px solid {BG_SURFACE};
    background-color: {ACCENT};
}}

/* --- Labels --- */
QLabel {{ color: {TEXT_PRIMARY}; }}
QLabel#H1 {{ font-size: 18px; font-weight: bold; }}
QLabel#Subtitle {{ color: {TEXT_SECONDARY}; font-size: 13px; }}
QLabel#H2 {{ font-size: 14px; font-weight: bold; margin-bottom: 4px; }}
QLabel#StatusIcon {{ font-size: 16px; }}

/* --- Progress Bar --- */
QProgressBar {{
    border: none;
    background-color: {BG_INPUT};
    border-radius: 2px;
    height: 4px;
    text-align: center;
}}
QProgressBar::chunk {{
    background-color: {ACCENT};
}}

/* --- ComboBox --- */
QComboBox {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 5px 10px;
    color: {TEXT_PRIMARY};
}}
QComboBox::drop-down {{
    border: none;
    width: 20px;
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

        mode = (
            "PQ-HYBRID"
            if desc.key_mode == KEY_MODE_PQ_HYBRID
            else "STANDARD"
        )

        if password_used:
            status = (
                "[ OK ]"
                if desc.volume_index in validated
                else "[ -- ]"
            )
        else:
            status = "[ ?? ]"

        lines.append(f"{status} {label:<8} | {mode}")

    lines.append("-" * 40)
    pq_status = "YES" if pq_available else "NO"
    lines.append(f"System PQ Support: {pq_status}")

    return "\n".join(lines)


if QT_AVAILABLE:

    # --- Worker Thread ------------------------------------------------------

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

    # --- Main Window --------------------------------------------------------

    class ZilantWindow(QtWidgets.QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self._lang: Lang = _detect_lang()
            self.ui_strings: Strings = get_strings(self._lang)

            self.setWindowTitle(f"{self.ui_strings.app_title} v{__version__}")
            self.resize(1000, 800)
            self.setMinimumSize(900, 650)

            self._output_path: Path | None = None
            self._worker: TaskWorker | None = None
            self._temp_report: str | None = None
            self._status_state: Literal["ready", "processing", "error"] = "ready"

            self.setStyleSheet(STYLESHEET)

            central = QtWidgets.QWidget(self)
            central.setObjectName("ContentWidget")
            self.setCentralWidget(central)

            self.main_layout = QtWidgets.QVBoxLayout(central)
            self.main_layout.setContentsMargins(30, 30, 30, 10)
            self.main_layout.setSpacing(15)

            self._build_header()

            self.tabs = QtWidgets.QTabWidget()
            self.main_layout.addWidget(self.tabs)

            self._build_encrypt_tab()
            self._build_inspect_tab()

            self._build_footer()

            self._update_defaults()
            self._retranslate_ui()

        def _build_header(self) -> None:
            header = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout(header)
            layout.setContentsMargins(0, 0, 0, 10)

            titles = QtWidgets.QVBoxLayout()
            titles.setSpacing(2)

            self.title_lbl = QtWidgets.QLabel(self.ui_strings.app_title)
            self.title_lbl.setObjectName("H1")

            self.subtitle_lbl = QtWidgets.QLabel(self.ui_strings.subtitle)
            self.subtitle_lbl.setObjectName("Subtitle")

            titles.addWidget(self.title_lbl)
            titles.addWidget(self.subtitle_lbl)

            layout.addLayout(titles)
            layout.addStretch()

            # Top Right Controls
            controls = QtWidgets.QHBoxLayout()
            controls.setSpacing(10)

            self.lang_combo = QtWidgets.QComboBox()
            self.lang_combo.addItems(["English", "Русский"])
            self.lang_combo.setItemData(0, "en")
            self.lang_combo.setItemData(1, "ru")
            self.lang_combo.setFixedWidth(100)
            self.lang_combo.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.lang_combo.setCurrentIndex(0 if self._lang == "en" else 1)
            self.lang_combo.currentIndexChanged.connect(self._on_lang_changed)

            self.about_btn = QtWidgets.QPushButton(self.ui_strings.about)
            self.about_btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.about_btn.clicked.connect(self._show_about_dialog)

            controls.addWidget(self.lang_combo)
            controls.addWidget(self.about_btn)
            layout.addLayout(controls)

            self.main_layout.addWidget(header)

        def _build_encrypt_tab(self) -> None:
            content_widget = QtWidgets.QWidget()
            content_widget.setObjectName("ContentWidget")
            self.workflow_layout = QtWidgets.QVBoxLayout(content_widget)
            self.workflow_layout.setSpacing(20)
            self.workflow_layout.setContentsMargins(10, 20, 10, 20)

            # 1. Action Selection
            mode_group = QtWidgets.QGroupBox(self.ui_strings.action_label)
            mode_layout = QtWidgets.QHBoxLayout()
            mode_layout.setSpacing(20)

            self.encrypt_radio = QtWidgets.QRadioButton(self.ui_strings.encrypt)
            self.decrypt_radio = QtWidgets.QRadioButton(self.ui_strings.decrypt)
            self.encrypt_radio.setChecked(True)
            self.encrypt_radio.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.decrypt_radio.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)

            # Make them look bigger
            self.encrypt_radio.setStyleSheet("font-weight: bold; font-size: 15px;")
            self.decrypt_radio.setStyleSheet("font-weight: bold; font-size: 15px;")

            self.encrypt_radio.toggled.connect(self._on_op_mode_changed)

            mode_layout.addWidget(self.encrypt_radio)
            mode_layout.addWidget(self.decrypt_radio)
            mode_layout.addStretch()
            mode_group.setLayout(mode_layout)
            self.workflow_layout.addWidget(mode_group)

            # 2. Main Grid
            grid = QtWidgets.QGridLayout()
            grid.setSpacing(20)
            grid.setColumnStretch(0, 1)
            grid.setColumnStretch(1, 1)

            # === LEFT: IO ===
            self.io_group = QtWidgets.QGroupBox(self.ui_strings.input_output_group)
            io_vbox = QtWidgets.QVBoxLayout(self.io_group)
            io_vbox.setSpacing(15)

            # Source Type
            type_layout = QtWidgets.QHBoxLayout()
            self.type_label = QtWidgets.QLabel(self.ui_strings.source_type)
            self.file_radio = QtWidgets.QRadioButton(self.ui_strings.single_file)
            self.dir_radio = QtWidgets.QRadioButton(self.ui_strings.directory_zip)
            self.file_radio.setChecked(True)
            self.file_radio.toggled.connect(self._on_input_type_changed)

            type_layout.addWidget(self.type_label)
            type_layout.addSpacing(10)
            type_layout.addWidget(self.file_radio)
            type_layout.addWidget(self.dir_radio)
            type_layout.addStretch()
            io_vbox.addLayout(type_layout)

            # Paths
            self.input_label = QtWidgets.QLabel(self.ui_strings.input_path)
            self.input_label.setObjectName("H2")
            self.input_edit = self._create_path_picker(
                self.ui_strings.select_input_ph, self._browse_input
            )

            self.output_label = QtWidgets.QLabel(self.ui_strings.output_path)
            self.output_label.setObjectName("H2")
            self.output_edit = self._create_path_picker(
                self.ui_strings.select_output_ph, self._browse_output
            )

            io_vbox.addWidget(self.input_label)
            io_vbox.addLayout(self.input_edit["layout"])
            io_vbox.addWidget(self.output_label)
            io_vbox.addLayout(self.output_edit["layout"])

            self.overwrite_checkbox = QtWidgets.QCheckBox(self.ui_strings.overwrite_checkbox)
            io_vbox.addSpacing(5)
            io_vbox.addWidget(self.overwrite_checkbox)

            grid.addWidget(self.io_group, 0, 0)

            # === RIGHT: Security ===
            right_container = QtWidgets.QWidget()
            right_layout = QtWidgets.QVBoxLayout(right_container)
            right_layout.setContentsMargins(0, 0, 0, 0)
            right_layout.setSpacing(20)

            self.sec_group = QtWidgets.QGroupBox(self.ui_strings.security_group)
            sec_vbox = QtWidgets.QVBoxLayout(self.sec_group)
            sec_vbox.setSpacing(12)

            self.mode_password_radio = QtWidgets.QRadioButton(self.ui_strings.mode_standard)
            self.mode_pq_radio = QtWidgets.QRadioButton(self.ui_strings.mode_pq)
            self.mode_password_radio.setChecked(True)

            sec_vbox.addWidget(self.mode_password_radio)
            sec_vbox.addWidget(self.mode_pq_radio)
            sec_vbox.addSpacing(8)

            self.pass_label = QtWidgets.QLabel(self.ui_strings.password_ph)
            self.pass_label.setObjectName("H2")
            sec_vbox.addWidget(self.pass_label)

            pass_row = QtWidgets.QHBoxLayout()
            self.password_edit = QtWidgets.QLineEdit()
            self.password_edit.setPlaceholderText("••••••••")
            self.password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.password_edit.setMinimumHeight(38)

            self.show_pass_check = QtWidgets.QCheckBox(self.ui_strings.show_password)
            self.show_pass_check.stateChanged.connect(self._toggle_password_visibility)

            pass_row.addWidget(self.password_edit, 1)
            sec_vbox.addLayout(pass_row)
            sec_vbox.addWidget(self.show_pass_check)

            right_layout.addWidget(self.sec_group)

            # Decoy / Decrypt Options
            self.decoy_group = QtWidgets.QGroupBox(self.ui_strings.decoy_group)
            self.decoy_group.setCheckable(True)
            self.decoy_group.setChecked(False)
            self.decoy_group.toggled.connect(self._update_ui_state)

            decoy_vbox = QtWidgets.QVBoxLayout(self.decoy_group)
            decoy_vbox.setSpacing(10)

            self.decoy_info_lbl = QtWidgets.QLabel(self.ui_strings.decoy_subtitle)
            self.decoy_info_lbl.setStyleSheet(f"color: {TEXT_SECONDARY}; margin-bottom: 5px;")
            self.decoy_info_lbl.setWordWrap(True)

            self.decoy_password_edit = QtWidgets.QLineEdit()
            self.decoy_password_edit.setPlaceholderText(self.ui_strings.decoy_password)
            self.decoy_password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.decoy_password_edit.setMinimumHeight(38)

            self.decoy_input_picker = self._create_path_picker(
                self.ui_strings.decoy_select_ph, self._browse_decoy_input
            )

            decoy_vbox.addWidget(self.decoy_info_lbl)
            decoy_vbox.addWidget(self.decoy_password_edit)
            decoy_vbox.addLayout(self.decoy_input_picker["layout"])

            right_layout.addWidget(self.decoy_group)

            # Decrypt specific
            self.decrypt_opts_frame = QtWidgets.QGroupBox(self.ui_strings.decrypt_target_label)
            d_layout = QtWidgets.QVBoxLayout(self.decrypt_opts_frame)
            d_layout.setSpacing(8)

            self.auto_vol_radio = QtWidgets.QRadioButton(self.ui_strings.auto_volume)
            self.force_main_radio = QtWidgets.QRadioButton(self.ui_strings.force_main)
            self.force_decoy_radio = QtWidgets.QRadioButton(self.ui_strings.force_decoy)
            self.auto_vol_radio.setChecked(True)

            d_layout.addWidget(self.auto_vol_radio)
            d_layout.addWidget(self.force_main_radio)
            d_layout.addWidget(self.force_decoy_radio)

            right_layout.addWidget(self.decrypt_opts_frame)
            right_layout.addStretch()

            grid.addWidget(right_container, 0, 1)
            self.workflow_layout.addLayout(grid)
            self.workflow_layout.addStretch()

            # Start Button
            self.action_button = QtWidgets.QPushButton(self.ui_strings.start_encrypt)
            self.action_button.setObjectName("PrimaryButton")
            self.action_button.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.action_button.setMinimumHeight(50)
            self.action_button.clicked.connect(self._on_action_clicked)
            self.workflow_layout.addWidget(self.action_button)

            scroll_area = QtWidgets.QScrollArea()
            scroll_area.setWidgetResizable(True)
            scroll_area.setWidget(content_widget)
            self.tabs.addTab(scroll_area, self.ui_strings.tab_encrypt)

        def _build_inspect_tab(self) -> None:
            container = QtWidgets.QWidget()
            container.setObjectName("ContentWidget")
            layout = QtWidgets.QVBoxLayout(container)
            layout.setContentsMargins(30, 30, 30, 30)
            layout.setSpacing(20)

            self.insp_group = QtWidgets.QGroupBox(self.ui_strings.inspect_group)
            insp_layout = QtWidgets.QVBoxLayout(self.insp_group)
            insp_layout.setSpacing(15)

            self.inspect_picker = self._create_path_picker(
                self.ui_strings.inspect_select_ph, self._browse_inspect_input
            )
            insp_layout.addLayout(self.inspect_picker["layout"])

            self.inspect_auth_check = QtWidgets.QCheckBox(self.ui_strings.inspect_verify)
            self.inspect_auth_check.stateChanged.connect(self._toggle_inspect_password)

            self.inspect_pass_edit = QtWidgets.QLineEdit()
            self.inspect_pass_edit.setPlaceholderText(self.ui_strings.inspect_password_ph)
            self.inspect_pass_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.inspect_pass_edit.setEnabled(False)
            self.inspect_pass_edit.setMinimumHeight(38)

            insp_layout.addWidget(self.inspect_auth_check)
            insp_layout.addWidget(self.inspect_pass_edit)

            self.inspect_btn = QtWidgets.QPushButton(self.ui_strings.inspect_button)
            self.inspect_btn.setObjectName("PrimaryButton")
            self.inspect_btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.inspect_btn.clicked.connect(self._handle_inspect)

            insp_layout.addSpacing(10)
            insp_layout.addWidget(self.inspect_btn)

            layout.addWidget(self.insp_group)

            self.inspect_output = QtWidgets.QPlainTextEdit()
            self.inspect_output.setReadOnly(True)
            self.inspect_output.setStyleSheet(f"""
                QPlainTextEdit {{
                    background-color: {BG_INPUT};
                    border: 1px solid {BORDER};
                    border-radius: 6px;
                    padding: 10px;
                    font-family: 'Consolas', monospace;
                }}
            """)
            layout.addWidget(self.inspect_output)

            scroll_area = QtWidgets.QScrollArea()
            scroll_area.setWidgetResizable(True)
            scroll_area.setWidget(container)
            self.tabs.addTab(scroll_area, self.ui_strings.tab_inspect)

        def _build_footer(self) -> None:
            footer = QtWidgets.QWidget()
            layout = QtWidgets.QVBoxLayout(footer)
            layout.setContentsMargins(30, 10, 30, 15)
            layout.setSpacing(10)

            self.progress_bar = QtWidgets.QProgressBar()
            self.progress_bar.setTextVisible(False)
            self.progress_bar.setVisible(False)
            layout.addWidget(self.progress_bar)

            status_row = QtWidgets.QHBoxLayout()

            self.status_icon = QtWidgets.QLabel("●")
            self.status_icon.setObjectName("StatusIcon")
            self.status_icon.setStyleSheet(f"color: {SUCCESS_COLOR}; margin-top: -2px;")

            self.status_lbl = QtWidgets.QLabel(self.ui_strings.status_ready)
            self.status_lbl.setObjectName("StatusReady")

            # --- Кнопка "Открыть папку" теперь скрыта по умолчанию и имеет смысл ---
            self.open_folder_btn = QtWidgets.QPushButton(self.ui_strings.open_folder)
            self.open_folder_btn.setObjectName("GhostButton")
            self.open_folder_btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.open_folder_btn.clicked.connect(self._open_output_folder)
            self.open_folder_btn.setVisible(False) # Hidden initially

            status_row.addWidget(self.status_icon)
            status_row.addSpacing(6)
            status_row.addWidget(self.status_lbl)
            status_row.addStretch()
            status_row.addWidget(self.open_folder_btn)

            layout.addLayout(status_row)
            self.main_layout.addWidget(footer)

        def _create_path_picker(self, placeholder: str, slot: Callable[[], None]) -> dict[str, Any]:
            layout = QtWidgets.QHBoxLayout()
            layout.setSpacing(8)

            edit = QtWidgets.QLineEdit()
            edit.setPlaceholderText(placeholder)
            edit.setMinimumHeight(38)
            edit.textChanged.connect(self._on_input_changed)

            btn = QtWidgets.QPushButton(self.ui_strings.browse)
            btn.setFixedSize(80, 38)
            btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(slot)

            layout.addWidget(edit)
            layout.addWidget(btn)
            return {"layout": layout, "edit": edit, "btn": btn}

        def _on_lang_changed(self, index: int) -> None:
            lang_value = self.lang_combo.itemData(index) or "en"
            self._lang = cast(Lang, lang_value)
            self.ui_strings = get_strings(self._lang)
            self._retranslate_ui()

        def _retranslate_ui(self) -> None:
            self.setWindowTitle(f"{self.ui_strings.app_title} v{__version__}")
            self.title_lbl.setText(self.ui_strings.app_title)
            self.subtitle_lbl.setText(self.ui_strings.subtitle)
            self.about_btn.setText(self.ui_strings.about)

            self.tabs.setTabText(0, self.ui_strings.tab_encrypt)
            self.tabs.setTabText(1, self.ui_strings.tab_inspect)

            self.encrypt_radio.setText(self.ui_strings.encrypt)
            self.decrypt_radio.setText(self.ui_strings.decrypt)

            self.io_group.setTitle(self.ui_strings.input_output_group)
            self.type_label.setText(self.ui_strings.source_type)
            self.file_radio.setText(self.ui_strings.single_file)
            self.dir_radio.setText(self.ui_strings.directory_zip)

            self.input_label.setText(self.ui_strings.input_path)
            self.output_label.setText(self.ui_strings.output_path)
            self.input_edit["edit"].setPlaceholderText(self.ui_strings.select_input_ph)
            self.output_edit["edit"].setPlaceholderText(self.ui_strings.select_output_ph)
            self.input_edit["btn"].setText(self.ui_strings.browse)
            self.output_edit["btn"].setText(self.ui_strings.browse)

            self.overwrite_checkbox.setText(self.ui_strings.overwrite_checkbox)

            self.sec_group.setTitle(self.ui_strings.security_group)
            self.mode_password_radio.setText(self.ui_strings.mode_standard)
            self.mode_pq_radio.setText(self.ui_strings.mode_pq)
            self.pass_label.setText(self.ui_strings.password_ph)
            self.show_pass_check.setText(self.ui_strings.show_password)

            self.decoy_group.setTitle(self.ui_strings.decoy_group)
            self.decoy_info_lbl.setText(self.ui_strings.decoy_subtitle)
            self.decoy_password_edit.setPlaceholderText(self.ui_strings.decoy_password)
            self.decoy_input_picker["edit"].setPlaceholderText(self.ui_strings.decoy_select_ph)
            self.decoy_input_picker["btn"].setText(self.ui_strings.browse)

            self.decrypt_opts_frame.setTitle(self.ui_strings.decrypt_target_label)
            self.auto_vol_radio.setText(self.ui_strings.auto_volume)
            self.force_main_radio.setText(self.ui_strings.force_main)
            self.force_decoy_radio.setText(self.ui_strings.force_decoy)

            self.action_button.setText(
                self.ui_strings.start_encrypt if self.encrypt_radio.isChecked() else self.ui_strings.start_decrypt
            )

            self.insp_group.setTitle(self.ui_strings.inspect_group)
            self.inspect_picker["edit"].setPlaceholderText(self.ui_strings.inspect_select_ph)
            self.inspect_picker["btn"].setText(self.ui_strings.browse)
            self.inspect_auth_check.setText(self.ui_strings.inspect_verify)
            self.inspect_pass_edit.setPlaceholderText(self.ui_strings.inspect_password_ph)
            self.inspect_btn.setText(self.ui_strings.inspect_button)

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
                self.ui_strings.start_encrypt if is_encrypt else self.ui_strings.start_decrypt
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
            mode = QtWidgets.QLineEdit.EchoMode.Normal if checked else QtWidgets.QLineEdit.EchoMode.Password
            self.password_edit.setEchoMode(mode)

        def _toggle_inspect_password(self, state: int) -> None:
            checked = state == QtCore.Qt.CheckState.Checked.value
            self.inspect_pass_edit.setEnabled(checked)
            if not checked:
                self.inspect_pass_edit.clear()

        # --- Logic ---

        def _browse_input(self) -> None:
            if self.encrypt_radio.isChecked() and self.dir_radio.isChecked():
                path = QtWidgets.QFileDialog.getExistingDirectory(self, self.ui_strings.dialog_select_folder_encrypt)
            else:
                path, _ = QtWidgets.QFileDialog.getOpenFileName(self, self.ui_strings.dialog_select_file)

            if path:
                self.input_edit["edit"].setText(path)

        def _browse_output(self) -> None:
            if self.encrypt_radio.isChecked():
                path, _ = QtWidgets.QFileDialog.getSaveFileName(
                    self, self.ui_strings.dialog_save_container, filter="Zilant Container (*.zil)"
                )
            else:
                path = QtWidgets.QFileDialog.getExistingDirectory(self, self.ui_strings.dialog_select_output_dir)

            if path:
                self.output_edit["edit"].setText(path)

        def _browse_decoy_input(self) -> None:
            if self.dir_radio.isChecked():
                path = QtWidgets.QFileDialog.getExistingDirectory(self, self.ui_strings.dialog_select_decoy_folder)
            else:
                path, _ = QtWidgets.QFileDialog.getOpenFileName(self, self.ui_strings.dialog_select_decoy_file)
            if path:
                self.decoy_input_picker["edit"].setText(path)

        def _browse_inspect_input(self) -> None:
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, self.ui_strings.dialog_select_container, filter="Zilant Container (*.zil)"
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
            is_enc = self.encrypt_radio.isChecked()

            if not self.output_edit["edit"].text().strip():
                if is_enc:
                    sug = path.with_suffix(path.suffix + ".zil") if path.is_file() else path.with_name(path.name + ".zil")
                else:
                    sug = path.with_suffix("")
                self.output_edit["edit"].setPlaceholderText(str(sug))

        def _on_action_clicked(self) -> None:
            is_encrypt = self.encrypt_radio.isChecked()
            in_path = self.input_edit["edit"].text().strip()
            out_path = self.output_edit["edit"].text().strip() or self.output_edit["edit"].placeholderText()
            password = self.password_edit.text()

            if not in_path or not Path(in_path).exists():
                self._show_error(self.ui_strings.input_missing)
                return
            if not password:
                self._show_error(self.ui_strings.password_required)
                return

            overwrite = self.overwrite_checkbox.isChecked()
            if Path(out_path).exists() and not overwrite:
                res = QtWidgets.QMessageBox.question(
                    self,
                    self.ui_strings.overwrite_prompt_title,
                    self.ui_strings.overwrite_prompt_body.format(path=out_path),
                )
                if res != QtWidgets.QMessageBox.StandardButton.Yes:
                    return
                overwrite = True

            mode = normalize_mode("pq-hybrid") if self.mode_pq_radio.isChecked() else normalize_mode("password")
            self._set_busy(True)

            def enc_task() -> None:
                if self.decoy_group.isChecked():
                    d_pass = self.decoy_password_edit.text()
                    if not d_pass:
                        raise InvalidPassword(self.ui_strings.decoy_password_required)
                    d_in = self.decoy_input_picker["edit"].text().strip()
                    encrypt_with_decoy(
                        Path(in_path), Path(d_in) if d_in else None, Path(out_path),
                        main_password=password, decoy_password=d_pass, mode=mode, overwrite=overwrite
                    )
                else:
                    encrypt_file(Path(in_path), Path(out_path), password, mode=mode, overwrite=overwrite)

            def dec_task() -> None:
                vol: Literal["main", "decoy"] | None = None
                if self.force_main_radio.isChecked():
                    vol = "main"
                elif self.force_decoy_radio.isChecked():
                    vol = "decoy"

                if vol:
                    decrypt_file(
                        Path(in_path), Path(out_path), password, volume_selector=vol, mode=mode, overwrite=overwrite
                    )
                else:
                    # FIX: Explicit calls to avoid MyPy confusion with kwargs unpacking
                    if _DECRYPT_AUTO_SUPPORTS_OVERWRITE:
                        decrypt_auto_volume(
                            Path(in_path), Path(out_path), password=password, mode=mode, overwrite=overwrite
                        )
                    else:
                        decrypt_auto_volume(
                            Path(in_path), Path(out_path), password=password, mode=mode
                        )

            self._start_worker(enc_task if is_encrypt else dec_task, Path(out_path))

        def _handle_inspect(self) -> None:
            p_str = self.inspect_picker["edit"].text().strip()
            if not p_str or not Path(p_str).exists():
                self._show_error(self.ui_strings.container_not_found)
                return

            pwd = self.inspect_pass_edit.text() if self.inspect_auth_check.isChecked() else None
            self._set_busy(True)

            def logic() -> None:
                overview, validated = check_container(Path(p_str), password=pwd, volume_selector="all")
                self._temp_report = _format_overview_report(
                    Path(p_str), overview, validated, overview.pq_available, self.ui_strings
                )

            self._start_worker(logic, None)

        def _start_worker(self, func: Callable[[], None], target: Path | None) -> None:
            self.progress_bar.setRange(0, 0)
            self.progress_bar.setVisible(True)
            self._status_state = "processing"
            self._update_status_text()

            # Hide the open button while working
            self.open_folder_btn.setVisible(False)
            self._output_path = target

            self._worker = TaskWorker(func, self.ui_strings)
            self._worker.finished_success.connect(lambda msg: self._on_worker_finished(True, msg))
            self._worker.finished_error.connect(lambda msg: self._on_worker_finished(False, msg))
            self._worker.start()

        def _on_worker_finished(self, success: bool, message: str) -> None:
            self._set_busy(False)
            self.progress_bar.setVisible(False)

            if success:
                self._status_state = "ready"
                # Show open button ONLY if we have a target path (encryption/decryption result)
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
                target = self._output_path if self._output_path.is_dir() else self._output_path.parent
                QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(target)))

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

    # FIX: Return Any to match signature in else block and allow generic return
    def create_app() -> Any:
        app = QtWidgets.QApplication(sys.argv)
        # Set a global fusion style as a base
        app.setStyle("Fusion")
        window = ZilantWindow()
        window.show()
        # FIX: Ignore attribute error for monkey patching
        app._zilant_window = window  # type: ignore[attr-defined]
        return app

else:
    def create_app() -> Any:
        raise ImportError("PySide6 not installed.")

def main() -> None:
    if not QT_AVAILABLE:
        print("Error: PySide6 library is missing.")
        sys.exit(1)
    app = create_app()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
