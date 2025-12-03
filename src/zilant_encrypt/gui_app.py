"""Desktop GUI for Zilant Encrypt - Silicon Valley Edition.

Premium "Dark Zinc" theme, Gradient accents, Robust Type checking.
"""
from __future__ import annotations

import importlib.util
import inspect
import locale
import sys
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Literal, cast

# --- ZILANT LIBRARY IMPORTS ---
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

# --- QT CHECK ---
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

# --- "SILICON VALLEY" THEME CONFIGURATION ---
THEME = {
    # Deep, expensive dark tones
    "bg_app": "#09090B",        # Almost black (Zinc-950)
    "bg_panel": "#141417",      # Slightly lighter
    "bg_input": "#1C1C1F",      # Input background
    "bg_hover": "#27272A",      # Input hover

    # Borders
    "border_dim": "#27272A",
    "border_active": "#3F3F46",

    # Typography
    "text_main": "#FAFAFA",     # Pure white
    "text_sec": "#A1A1AA",      # Zinc-400
    "text_dim": "#52525B",      # Zinc-600

    # Gradients (Simulated via QSS)
    "accent_blue": "#3B82F6",   # Encrypt Primary
    "accent_cyan": "#06B6D4",   # Encrypt Secondary (Gradient target)
    "accent_purp": "#8B5CF6",   # Decrypt Primary
    "accent_pink": "#EC4899",   # Decrypt Secondary

    "success": "#10B981",       # Emerald
    "error": "#EF4444",         # Red
}

FONT_FAMILY = (
    "Segoe UI Variable Display, Segoe UI, Inter, Roboto, Helvetica, sans-serif"
)

STYLESHEET = f"""
/* GLOBAL RESET */
* {{
    font-family: "{FONT_FAMILY}";
    font-size: 14px;
    outline: none;
    color: {THEME['text_main']};
    border: none;
}}

QMainWindow, QWidget#Content {{
    background-color: {THEME['bg_app']};
}}

/* TYPOGRAPHY */
QLabel {{ color: {THEME['text_main']}; }}
QLabel#H1 {{
    font-size: 26px;
    font-weight: 800;
    letter-spacing: -0.5px;
    background-color: transparent;
}}
QLabel#Subtitle {{
    color: {THEME['text_sec']};
    font-size: 13px;
    font-weight: 500;
    margin-bottom: 10px;
}}
QLabel#H2 {{
    font-size: 12px;
    font-weight: 700;
    color: {THEME['text_sec']};
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 4px;
    margin-bottom: 4px;
}}
QLabel#Tip {{
    color: {THEME['text_dim']};
    font-size: 12px;
    font-style: italic;
}}

/* PANELS (CARDS) */
QGroupBox {{
    background-color: {THEME['bg_panel']};
    border: 1px solid {THEME['border_dim']};
    border-radius: 16px;
    margin-top: 1.2em;
    padding: 24px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 20px;
    padding: 0 5px;
    color: {THEME['accent_blue']};
    font-weight: 700;
    font-size: 12px;
}}

/* INPUT FIELDS */
QLineEdit {{
    background-color: {THEME['bg_input']};
    border: 1px solid {THEME['border_dim']};
    border-radius: 10px;
    padding: 12px 16px;
    font-size: 14px;
    selection-background-color: {THEME['accent_blue']};
}}
QLineEdit:hover {{
    background-color: {THEME['bg_hover']};
    border: 1px solid {THEME['border_active']};
}}
QLineEdit:focus {{
    background-color: {THEME['bg_input']};
    border: 1px solid {THEME['accent_blue']};
    color: white;
}}
QLineEdit:disabled {{
    background-color: {THEME['bg_app']};
    color: {THEME['text_dim']};
    border: 1px dashed {THEME['border_dim']};
}}

/* TEXT AREA (LOG) */
QPlainTextEdit {{
    background-color: {THEME['bg_input']};
    border: 1px solid {THEME['border_dim']};
    border-radius: 12px;
    padding: 16px;
    font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 13px;
    line-height: 1.4;
    color: {THEME['text_sec']};
}}

/* BUTTONS */
QPushButton {{
    background-color: {THEME['bg_hover']};
    border: 1px solid {THEME['border_active']};
    border-radius: 8px;
    padding: 10px 18px;
    font-weight: 600;
    font-size: 13px;
}}
QPushButton:hover {{
    background-color: #3F3F46;
    border-color: #52525B;
}}
QPushButton:pressed {{ background-color: {THEME['bg_app']}; }}

/* PRIMARY ACTION BUTTON - Gradient & Glow */
QPushButton#PrimaryButton {{
    background-color: {THEME['accent_blue']};
    border: none;
    color: white;
    font-size: 16px;
    font-weight: 800;
    letter-spacing: 0.5px;
    padding: 16px 32px;
    border-radius: 12px;
}}
QPushButton#PrimaryButton:hover {{
    margin-top: -1px;
    margin-bottom: 1px;
}}

/* GHOST BUTTON */
QPushButton#GhostButton {{
    background: transparent;
    border: none;
    color: {THEME['text_sec']};
    text-align: right;
}}
QPushButton#GhostButton:hover {{ color: white; text-decoration: underline; }}

/* CHECKBOX & RADIO */
QRadioButton, QCheckBox {{
    spacing: 12px;
    color: {THEME['text_main']};
    font-size: 14px;
    font-weight: 400;
}}
QRadioButton::indicator, QCheckBox::indicator {{
    width: 20px;
    height: 20px;
    border-radius: 10px;
    border: 2px solid {THEME['border_active']};
    background-color: {THEME['bg_input']};
}}
QCheckBox::indicator {{ border-radius: 6px; }}

QRadioButton::indicator:checked, QCheckBox::indicator:checked {{
    border-color: {THEME['accent_blue']};
    background-color: {THEME['accent_blue']};
    image: url("data:image/svg+xml;charset=UTF-8,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='white' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='20 6 9 17 4 12'/%3E%3C/svg%3E");
}}
QRadioButton::indicator:checked {{
    image: none;
    background-color: {THEME['accent_blue']};
    border: 5px solid {THEME['bg_input']};
}}

/* TABS */
QTabWidget::pane {{ border: none; }}
QTabBar::tab {{
    background: transparent;
    color: {THEME['text_dim']};
    padding: 12px 24px;
    font-size: 14px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-bottom: 3px solid transparent;
    margin-right: 10px;
}}
QTabBar::tab:hover {{ color: {THEME['text_sec']}; }}
QTabBar::tab:selected {{
    color: {THEME['text_main']};
    border-bottom: 3px solid {THEME['accent_blue']};
}}

/* SCROLLBAR */
QScrollBar:vertical {{
    background: {THEME['bg_app']};
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {THEME['bg_hover']};
    min-height: 40px;
    border-radius: 5px;
    border: 2px solid {THEME['bg_app']};
}}
QScrollBar::handle:vertical:hover {{ background: {THEME['text_dim']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
"""


def _detect_lang() -> Lang:
    """Detect UI language from current locale without using deprecated APIs."""
    try:
        lang, _ = locale.getlocale()
        if isinstance(lang, str) and lang.lower().startswith("ru"):
            return "ru"
    except Exception:
        pass
    return "en"


def _format_report(
    path: Path,
    overview: ContainerOverview,
    validated: list[int],
    pq_available: bool,
    strings: Strings,
) -> str:
    lines: list[str] = [
        f"TARGET:  {path.name}",
        f"PATH:    {path.parent}",
        f"VERSION: v{overview.header.version}",
        "=" * 50,
        f"{strings.overview_volumes.upper()}",
        "",
        f"{'ID':<4} {'STATUS':<10} {'LABEL':<12} {'ALGORITHM'}",
        f"{'-' * 4} {'-' * 10} {'-' * 12} {'-' * 20}",
    ]

    has_auth = bool(validated)

    for desc in overview.descriptors:
        if desc.volume_index == 0:
            label = "MAIN"
        elif desc.volume_index == 1:
            label = "DECOY"
        else:
            label = f"#{desc.volume_index}"

        mode_str = "PQ-Hybrid" if desc.key_mode == KEY_MODE_PQ_HYBRID else "AES-GCM"

        status_txt = "?"
        if has_auth:
            status_txt = "UNLOCKED" if desc.volume_index in validated else "LOCKED"

        lines.append(
            f"{desc.volume_index:<4} {status_txt:<10} {label:<12} {mode_str}"
        )

    lines.append("")
    lines.append("=" * 50)
    pq_str = "DETECTED" if pq_available else "NOT FOUND"
    lines.append(f"QUANTUM SHIELD: {pq_str}")

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
                msg = str(e).split("(")[0] if "(" in str(e) else str(e)
                self.finished_error.emit(
                    self._strings.processing_integrity_error.format(error=msg)
                )
            except Exception as e:  # pragma: no cover - debug path
                traceback.print_exc()
                self.finished_error.emit(
                    self._strings.processing_unexpected_error.format(error=str(e))
                )

    class ZilantWindow(QtWidgets.QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self._lang: Lang = _detect_lang()
            self.ui_strings: Strings = get_strings(self._lang)

            self.setWindowTitle("Zilant Encrypt")
            self.setMinimumSize(1000, 780)

            self._worker: TaskWorker | None = None
            self._output_path: Path | None = None
            self._temp_report: str | None = None

            container = QtWidgets.QWidget()
            container.setObjectName("Content")
            self.setCentralWidget(container)

            self.main_layout = QtWidgets.QVBoxLayout(container)
            self.main_layout.setContentsMargins(40, 40, 40, 30)
            self.main_layout.setSpacing(24)

            self._build_header()

            self.tabs = QtWidgets.QTabWidget()
            self.main_layout.addWidget(self.tabs)

            self._build_encrypt_tab()
            self._build_inspect_tab()
            self._build_footer()

            self.setStyleSheet(STYLESHEET)
            self._retranslate_ui()
            self._validate_encrypt_tab()

        # ---------- HEADER ----------

        def _build_header(self) -> None:
            top = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout(top)
            layout.setContentsMargins(0, 0, 0, 0)

            title_box = QtWidgets.QVBoxLayout()
            title_box.setSpacing(2)

            self.lbl_title = QtWidgets.QLabel("Zilant Encrypt")
            self.lbl_title.setObjectName("H1")

            self.lbl_subtitle = QtWidgets.QLabel(
                "Zero-knowledge | Post-Quantum | Plausible Deniability"
            )
            self.lbl_subtitle.setObjectName("Subtitle")

            title_box.addWidget(self.lbl_title)
            title_box.addWidget(self.lbl_subtitle)
            layout.addLayout(title_box)
            layout.addStretch()

            controls = QtWidgets.QHBoxLayout()
            controls.setSpacing(10)

            self.combo_lang = QtWidgets.QComboBox()
            self.combo_lang.setFixedWidth(110)
            self.combo_lang.addItems(["English", "Русский"])
            self.combo_lang.setItemData(0, "en")
            self.combo_lang.setItemData(1, "ru")
            self.combo_lang.setCurrentIndex(1 if self._lang == "ru" else 0)
            self.combo_lang.currentIndexChanged.connect(self._on_lang_changed)

            self.btn_about = QtWidgets.QPushButton("?")
            self.btn_about.setFixedWidth(40)
            self.btn_about.clicked.connect(self._show_about)

            controls.addWidget(self.combo_lang)
            controls.addWidget(self.btn_about)
            layout.addLayout(controls)

            self.main_layout.addWidget(top)

        # ---------- ENCRYPT TAB ----------

        def _build_encrypt_tab(self) -> None:
            page = QtWidgets.QWidget()
            page.setObjectName("Content")

            scroll = QtWidgets.QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
            scroll.setStyleSheet("background: transparent;")

            wrapper = QtWidgets.QWidget()
            wrapper.setObjectName("Content")
            scroll.setWidget(wrapper)

            layout = QtWidgets.QVBoxLayout(wrapper)
            layout.setContentsMargins(0, 10, 0, 10)
            layout.setSpacing(24)

            center_lay = QtWidgets.QHBoxLayout(page)
            center_lay.addWidget(scroll)

            # 1. Operation mode
            self.grp_action = QtWidgets.QGroupBox()
            act_lay = QtWidgets.QHBoxLayout(self.grp_action)
            act_lay.setSpacing(30)

            self.rad_enc = QtWidgets.QRadioButton()
            self.rad_enc.setChecked(True)
            self.rad_enc.toggled.connect(self._on_mode_switched)
            self.rad_dec = QtWidgets.QRadioButton()

            act_lay.addWidget(self.rad_enc)
            act_lay.addWidget(self.rad_dec)
            act_lay.addStretch()
            layout.addWidget(self.grp_action)

            # 2. Source & Dest
            self.grp_io = QtWidgets.QGroupBox()
            io_lay = QtWidgets.QVBoxLayout(self.grp_io)
            io_lay.setSpacing(20)

            type_row = QtWidgets.QHBoxLayout()
            self.lbl_type = QtWidgets.QLabel()
            self.lbl_type.setObjectName("H2")

            self.rad_file = QtWidgets.QRadioButton()
            self.rad_dir = QtWidgets.QRadioButton()
            self.rad_file.setChecked(True)
            self.rad_file.toggled.connect(self._on_src_type_changed)

            type_row.addWidget(self.lbl_type)
            type_row.addSpacing(20)
            type_row.addWidget(self.rad_file)
            type_row.addWidget(self.rad_dir)
            type_row.addStretch()
            io_lay.addLayout(type_row)

            self.wdg_input = self._create_path_field("SOURCE PATH", self._browse_input)
            io_lay.addLayout(self.wdg_input["layout"])

            self.wdg_output = self._create_path_field(
                "DESTINATION", self._browse_output
            )
            io_lay.addLayout(self.wdg_output["layout"])

            self.chk_overwrite = QtWidgets.QCheckBox()
            io_lay.addWidget(self.chk_overwrite)
            layout.addWidget(self.grp_io)

            # 3. Security
            self.grp_sec = QtWidgets.QGroupBox()
            sec_lay = QtWidgets.QVBoxLayout(self.grp_sec)
            sec_lay.setSpacing(20)

            algo_row = QtWidgets.QHBoxLayout()
            self.rad_std = QtWidgets.QRadioButton()
            self.rad_pq = QtWidgets.QRadioButton()
            self.rad_std.setChecked(True)
            algo_row.addWidget(self.rad_std)
            algo_row.addWidget(self.rad_pq)
            algo_row.addStretch()
            sec_lay.addLayout(algo_row)

            self.lbl_pass = QtWidgets.QLabel()
            self.lbl_pass.setObjectName("H2")
            sec_lay.addWidget(self.lbl_pass)

            pass_field = QtWidgets.QHBoxLayout()
            pass_field.setSpacing(10)

            self.txt_pass = QtWidgets.QLineEdit()
            self.txt_pass.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.txt_pass.textChanged.connect(self._validate_encrypt_tab)

            self.btn_eye = QtWidgets.QPushButton("👁")
            self.btn_eye.setFixedWidth(46)
            self.btn_eye.setCheckable(True)
            self.btn_eye.toggled.connect(lambda c: self._toggle_eye(self.txt_pass, c))

            pass_field.addWidget(self.txt_pass)
            pass_field.addWidget(self.btn_eye)
            sec_lay.addLayout(pass_field)

            self.grp_decoy = QtWidgets.QGroupBox()
            self.grp_decoy.setCheckable(True)
            self.grp_decoy.setChecked(False)
            self.grp_decoy.toggled.connect(self._validate_encrypt_tab)

            dec_lay = QtWidgets.QVBoxLayout(self.grp_decoy)
            dec_lay.setSpacing(16)

            self.lbl_decoy_info = QtWidgets.QLabel()
            self.lbl_decoy_info.setWordWrap(True)
            self.lbl_decoy_info.setObjectName("Tip")
            dec_lay.addWidget(self.lbl_decoy_info)

            self.txt_decoy_pass = QtWidgets.QLineEdit()
            self.txt_decoy_pass.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            dec_lay.addWidget(self.txt_decoy_pass)

            self.wdg_decoy = self._create_path_field("HIDDEN DATA", self._browse_decoy)
            dec_lay.addLayout(self.wdg_decoy["layout"])

            sec_lay.addWidget(self.grp_decoy)

            self.frm_dec_opts = QtWidgets.QWidget()
            do_lay = QtWidgets.QHBoxLayout(self.frm_dec_opts)
            do_lay.setContentsMargins(0, 10, 0, 0)

            lbl_targ = QtWidgets.QLabel("TARGET VOLUME:")
            lbl_targ.setObjectName("H2")

            self.rad_d_auto = QtWidgets.QRadioButton()
            self.rad_d_main = QtWidgets.QRadioButton()
            self.rad_d_decoy = QtWidgets.QRadioButton()
            self.rad_d_auto.setChecked(True)

            do_lay.addWidget(lbl_targ)
            do_lay.addSpacing(15)
            do_lay.addWidget(self.rad_d_auto)
            do_lay.addWidget(self.rad_d_main)
            do_lay.addWidget(self.rad_d_decoy)
            do_lay.addStretch()
            self.frm_dec_opts.setVisible(False)
            sec_lay.addWidget(self.frm_dec_opts)

            layout.addWidget(self.grp_sec)

            layout.addSpacing(10)
            self.btn_action = QtWidgets.QPushButton("INITIALIZE SYSTEM")
            self.btn_action.setObjectName("PrimaryButton")
            self.btn_action.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.btn_action.clicked.connect(self._run_action)
            layout.addWidget(self.btn_action)
            layout.addStretch()

            self.tabs.addTab(page, "")

        # ---------- INSPECT TAB ----------

        def _build_inspect_tab(self) -> None:
            page = QtWidgets.QWidget()
            page.setObjectName("Content")
            lay = QtWidgets.QVBoxLayout(page)
            lay.setContentsMargins(0, 20, 0, 20)
            lay.setSpacing(20)

            box = QtWidgets.QGroupBox()
            box_l = QtWidgets.QVBoxLayout(box)
            box_l.setSpacing(16)

            self.wdg_insp = self._create_path_field(
                "CONTAINER (.zil)", self._browse_inspect
            )
            box_l.addLayout(self.wdg_insp["layout"])

            row = QtWidgets.QHBoxLayout()
            self.chk_insp_auth = QtWidgets.QCheckBox()
            self.chk_insp_auth.stateChanged.connect(self._toggle_insp_auth)
            row.addWidget(self.chk_insp_auth)

            self.txt_insp_pass = QtWidgets.QLineEdit()
            self.txt_insp_pass.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.txt_insp_pass.setEnabled(False)
            row.addWidget(self.txt_insp_pass)

            self.btn_insp = QtWidgets.QPushButton()
            self.btn_insp.clicked.connect(self._run_inspect)
            row.addWidget(self.btn_insp)
            box_l.addLayout(row)

            lay.addWidget(box)

            self.txt_log = QtWidgets.QPlainTextEdit()
            self.txt_log.setReadOnly(True)
            self.txt_log.setPlaceholderText("> Waiting for input...")
            lay.addWidget(self.txt_log)

            self.tabs.addTab(page, "")

        # ---------- FOOTER ----------

        def _build_footer(self) -> None:
            foot = QtWidgets.QWidget()
            lay = QtWidgets.QHBoxLayout(foot)
            lay.setContentsMargins(0, 0, 0, 0)

            self.lbl_dot = QtWidgets.QLabel("●")
            self.lbl_dot.setStyleSheet(f"color: {THEME['success']}; font-size: 16px;")
            self.lbl_stat = QtWidgets.QLabel("SYSTEM READY")
            self.lbl_stat.setObjectName("H2")

            self.prog = QtWidgets.QProgressBar()
            self.prog.setFixedWidth(200)
            self.prog.setRange(0, 0)
            self.prog.setTextVisible(False)
            self.prog.setVisible(False)

            self.btn_open = QtWidgets.QPushButton("REVEAL FILE")
            self.btn_open.setObjectName("GhostButton")
            self.btn_open.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.btn_open.clicked.connect(self._open_result)
            self.btn_open.setVisible(False)

            lay.addWidget(self.lbl_dot)
            lay.addSpacing(8)
            lay.addWidget(self.lbl_stat)
            lay.addSpacing(16)
            lay.addWidget(self.prog)
            lay.addStretch()
            lay.addWidget(self.btn_open)

            self.main_layout.addWidget(foot)

        # ---------- HELPERS ----------

        def _create_path_field(
            self, label: str, browse_cb: Callable[[], None]
        ) -> dict[str, Any]:
            v = QtWidgets.QVBoxLayout()
            v.setSpacing(6)

            lbl = QtWidgets.QLabel(label)
            lbl.setObjectName("H2")
            v.addWidget(lbl)

            h = QtWidgets.QHBoxLayout()
            h.setSpacing(10)

            txt = QtWidgets.QLineEdit()
            txt.textChanged.connect(self._validate_encrypt_tab)

            btn = QtWidgets.QPushButton("BROWSE")
            btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(browse_cb)

            h.addWidget(txt)
            h.addWidget(btn)
            v.addLayout(h)
            return {"layout": v, "txt": txt, "btn": btn, "lbl": lbl}

        # ---------- UI LOGIC ----------

        def _retranslate_ui(self) -> None:
            s = self.ui_strings

            self.btn_about.setText("?")
            self.tabs.setTabText(0, s.tab_encrypt.upper())
            self.tabs.setTabText(1, s.tab_inspect.upper())

            self.grp_action.setTitle(s.action_label.upper())
            self.rad_enc.setText(s.encrypt)
            self.rad_dec.setText(s.decrypt)

            self.grp_io.setTitle(s.input_output_group.upper())
            self.lbl_type.setText(s.source_type.upper())
            self.rad_file.setText(s.single_file)
            self.rad_dir.setText(s.directory_zip)

            self.wdg_input["lbl"].setText(s.input_path.upper())
            self.wdg_output["lbl"].setText(s.output_path.upper())
            self.chk_overwrite.setText(s.overwrite_checkbox)

            self.grp_sec.setTitle(s.security_group.upper())
            self.rad_std.setText(s.mode_standard)
            self.rad_pq.setText(s.mode_pq)
            self.lbl_pass.setText(s.password_ph.upper())

            self.grp_decoy.setTitle(s.decoy_group.upper())
            self.lbl_decoy_info.setText(s.decoy_subtitle)
            self.txt_decoy_pass.setPlaceholderText(s.decoy_password)
            self.wdg_decoy["lbl"].setText(s.input_path.upper())

            self.rad_d_auto.setText(s.auto_volume)
            self.rad_d_main.setText(s.force_main)
            self.rad_d_decoy.setText(s.force_decoy)

            self.chk_insp_auth.setText(s.inspect_verify)
            self.txt_insp_pass.setPlaceholderText(s.inspect_password_ph)
            self.btn_insp.setText(s.inspect_button.upper())
            self.btn_open.setText(s.open_folder.upper())

            self._update_ui_state()

        def _update_ui_state(self) -> None:
            is_enc = self.rad_enc.isChecked()

            if is_enc:
                c1, c2 = THEME["accent_blue"], THEME["accent_cyan"]
                text = self.ui_strings.start_encrypt
                self.grp_decoy.setVisible(True)
                self.frm_dec_opts.setVisible(False)
            else:
                c1, c2 = THEME["accent_purp"], THEME["accent_pink"]
                text = self.ui_strings.start_decrypt
                self.grp_decoy.setVisible(False)
                self.frm_dec_opts.setVisible(True)

            grad = (
                f"qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {c1}, stop:1 {c2})"
            )

            self.btn_action.setText(text.upper())
            self.btn_action.setStyleSheet(f"""
                QPushButton#PrimaryButton {{
                    background: {grad};
                }}
                QPushButton#PrimaryButton:hover {{
                    border: 1px solid white;
                }}
            """)

            grp_style = f"""
            QGroupBox::title {{
                color: {c1};
            }}
            QRadioButton::indicator:checked {{
                background-color: {c1};
                border-color: {c1};
            }}
            """
            self.grp_action.setStyleSheet(grp_style)
            self.grp_sec.setStyleSheet(grp_style)

            if not is_enc:
                self.rad_file.setChecked(True)
                self.rad_dir.setEnabled(False)
            else:
                self.rad_dir.setEnabled(True)

            self._auto_output()

        def _validate_encrypt_tab(self) -> None:
            s = self.wdg_input["txt"].text().strip()
            if s and not self.wdg_output["txt"].text().strip():
                self._auto_output()

            has_pass = bool(self.txt_pass.text())
            self.btn_action.setEnabled(has_pass)

        def _auto_output(self) -> None:
            raw = self.wdg_input["txt"].text().strip()
            if not raw:
                return
            p = Path(raw)
            is_enc = self.rad_enc.isChecked()

            try:
                if is_enc:
                    cand = p.with_name(p.name + ".zil")
                else:
                    if p.suffix == ".zil":
                        stem = p.stem
                        if "." not in stem:
                            stem += ".decrypted"
                        cand = p.with_name(stem)
                    else:
                        cand = p.with_name(p.name + ".decrypted")

                self.wdg_output["txt"].setPlaceholderText(str(cand))
            except Exception:
                pass

        # ---------- BROWSE ACTIONS ----------

        def _browse_input(self) -> None:
            if self.rad_enc.isChecked() and self.rad_dir.isChecked():
                res = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Folder")
            else:
                res, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select File")

            if res:
                self.wdg_input["txt"].setText(res)
                self._auto_output()

        def _browse_output(self) -> None:
            if self.rad_enc.isChecked():
                res, _ = QtWidgets.QFileDialog.getSaveFileName(
                    self, "Save Container", filter="Zilant (*.zil)"
                )
            else:
                res = QtWidgets.QFileDialog.getExistingDirectory(
                    self, "Select Destination"
                )

            if res:
                self.wdg_output["txt"].setText(res)

        def _browse_decoy(self) -> None:
            if self.rad_dir.isChecked():
                res = QtWidgets.QFileDialog.getExistingDirectory(
                    self, "Decoy Data Folder"
                )
            else:
                res, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Decoy Data File")
            if res:
                self.wdg_decoy["txt"].setText(res)

        def _browse_inspect(self) -> None:
            res, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "Select Container", filter="Zilant (*.zil)"
            )
            if res:
                self.wdg_insp["txt"].setText(res)

        # ---------- SMALL UI HELPERS ----------

        def _on_mode_switched(self) -> None:
            self._update_ui_state()

        def _on_src_type_changed(self) -> None:
            self._validate_encrypt_tab()

        def _toggle_eye(self, line_edit: QtWidgets.QLineEdit, checked: bool) -> None:
            mode = (
                QtWidgets.QLineEdit.EchoMode.Normal
                if checked
                else QtWidgets.QLineEdit.EchoMode.Password
            )
            line_edit.setEchoMode(mode)

        def _toggle_insp_auth(self, state: int) -> None:
            on = state == QtCore.Qt.CheckState.Checked.value
            self.txt_insp_pass.setEnabled(on)
            if not on:
                self.txt_insp_pass.clear()

        def _on_lang_changed(self, index: int) -> None:
            code = self.combo_lang.itemData(index)
            self._lang = cast(Lang, code)
            self.ui_strings = get_strings(self._lang)
            self._retranslate_ui()

        # ---------- BUSINESS LOGIC ----------

        def _run_action(self) -> None:
            s_raw = self.wdg_input["txt"].text().strip()
            d_raw = (
                self.wdg_output["txt"].text().strip()
                or self.wdg_output["txt"].placeholderText()
            )
            pwd = self.txt_pass.text()

            if not s_raw or not Path(s_raw).exists():
                self._msg("Missing Input", self.ui_strings.input_missing, True)
                return
            if not d_raw:
                self._msg("Missing Output", "Destination path required.", True)
                return

            src = Path(s_raw).resolve()
            dst = Path(d_raw).resolve()

            if src == dst:
                self._msg(
                    "Collision", "Source and Destination cannot be the same.", True
                )
                return

            is_enc = self.rad_enc.isChecked()
            if is_enc and dst.exists() and not self.chk_overwrite.isChecked():
                ask = QtWidgets.QMessageBox.question(
                    self, "Overwrite?", f"File exists:\n{dst.name}\n\nOverwrite it?"
                )
                if ask != QtWidgets.QMessageBox.StandardButton.Yes:
                    return

            mode = normalize_mode(
                "pq-hybrid" if self.rad_pq.isChecked() else "password"
            )

            if is_enc:
                if self.grp_decoy.isChecked():
                    dp = self.txt_decoy_pass.text()
                    dpath = self.wdg_decoy["txt"].text().strip()
                    if not dp:
                        self._msg("Error", "Decoy password missing.", True)
                        return
                    if not dpath:
                        self._msg("Error", "Decoy data missing.", True)
                        return

                    if Path(dpath).resolve() == src:
                        self._msg("Error", "Decoy source same as Main.", True)
                        return

                    def task_enc_decoy() -> None:
                        encrypt_with_decoy(
                            src,
                            Path(dpath),
                            dst,
                            main_password=pwd,
                            decoy_password=dp,
                            mode=mode,
                            overwrite=True,
                        )

                    worker_task: Callable[[], Any] = task_enc_decoy
                else:

                    def task_enc_std() -> None:
                        encrypt_file(src, dst, password=pwd, mode=mode, overwrite=True)

                    worker_task = task_enc_std
            else:
                v_sel: Literal["main", "decoy"] | None = None
                if self.rad_d_main.isChecked():
                    v_sel = "main"
                elif self.rad_d_decoy.isChecked():
                    v_sel = "decoy"

                ow = self.chk_overwrite.isChecked()

                def task_dec() -> None:
                    if v_sel:
                        decrypt_file(
                            src,
                            dst,
                            password=pwd,
                            volume_selector=v_sel,
                            mode=mode,
                            overwrite=ow,
                        )
                    else:
                        if _DECRYPT_AUTO_SUPPORTS_OVERWRITE:
                            decrypt_auto_volume(
                                src, dst, password=pwd, mode=mode, overwrite=ow
                            )
                        else:
                            decrypt_auto_volume(src, dst, password=pwd, mode=mode)

                worker_task = task_dec

            self._start_worker(worker_task, dst if is_enc or not dst.is_dir() else dst)

        def _run_inspect(self) -> None:
            raw = self.wdg_insp["txt"].text().strip()
            if not raw or not Path(raw).exists():
                self._msg("Error", self.ui_strings.container_not_found, True)
                return

            pwd = (
                self.txt_insp_pass.text()
                if self.chk_insp_auth.isChecked()
                else None
            )
            p = Path(raw)

            def task_insp() -> None:
                ov, val = check_container(p, password=pwd, volume_selector="all")
                self._temp_report = _format_report(
                    p, ov, val, ov.pq_available, self.ui_strings
                )

            self._start_worker(task_insp, None)

        def _start_worker(
            self, func: Callable[[], Any], result_path: Path | None
        ) -> None:
            self._set_busy(True)
            self._output_path = result_path

            self._worker = TaskWorker(func, self.ui_strings)
            self._worker.finished_success.connect(self._on_done)
            self._worker.finished_error.connect(self._on_fail)
            self._worker.start()

        def _on_done(self, msg: str) -> None:
            self._set_busy(False)
            self.lbl_dot.setStyleSheet(f"color: {THEME['success']}")
            self.lbl_stat.setText("COMPLETE")

            if self._temp_report:
                self.txt_log.setPlainText(self._temp_report)
                self.tabs.setCurrentIndex(1)
                self._temp_report = None
            else:
                self.txt_pass.clear()
                self.txt_decoy_pass.clear()
                QtWidgets.QMessageBox.information(self, "Success", msg)

            if self._output_path and self._output_path.exists():
                self.btn_open.setVisible(True)

        def _on_fail(self, msg: str) -> None:
            self._set_busy(False)
            self.lbl_dot.setStyleSheet(f"color: {THEME['error']}")
            self.lbl_stat.setText("ERROR")
            self._msg("Operation Failed", msg, True)

        def _set_busy(self, busy: bool) -> None:
            self.tabs.setEnabled(not busy)
            self.btn_action.setEnabled(not busy)
            self.prog.setVisible(busy)
            self.btn_open.setVisible(False)

            if busy:
                self.lbl_dot.setStyleSheet(f"color: {THEME['accent_blue']}")
                self.lbl_stat.setText("PROCESSING...")
            else:
                self.lbl_stat.setText("READY")

        def _open_result(self) -> None:
            if not self._output_path:
                return
            target = (
                self._output_path.parent
                if self._output_path.is_file()
                else self._output_path
            )
            QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(target)))

        def _msg(self, title: str, text: str, is_err: bool = False) -> None:
            icon = (
                QtWidgets.QMessageBox.Icon.Critical
                if is_err
                else QtWidgets.QMessageBox.Icon.Information
            )
            dlg = QtWidgets.QMessageBox(self)
            dlg.setWindowTitle(title)
            dlg.setText(text)
            dlg.setIcon(icon)
            dlg.exec()

        def _show_about(self) -> None:
            self._msg(
                "System Info",
                f"Zilant Encrypt Core v{__version__}\n\n"
                "Secure containerization featuring:\n"
                "- AES-256-GCM + Argon2id\n"
                "- Kyber768 (Post-Quantum)\n"
                "- Plausible Deniability Routing",
            )


def main() -> None:
    if not QT_AVAILABLE:
        print("Error: PySide6 required.")
        sys.exit(1)

    # HighDPI rounding policy – ставим ДО QApplication, без deprecated атрибутов
    set_rounding = getattr(
        QtCore.QCoreApplication, "setHighDpiScaleFactorRoundingPolicy", None
    )
    if callable(set_rounding):
        try:
            set_rounding(
              QtCore.Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
            )
        except Exception:
            # Если платформа или версия Qt не поддерживает — просто игнорируем
            pass

    app = QtWidgets.QApplication(sys.argv)

    app.setStyle("Fusion")

    font = app.font()
    font.setPointSize(10)
    app.setFont(font)

    w = ZilantWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
