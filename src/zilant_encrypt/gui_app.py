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
from zilant_encrypt.password_strength import evaluate_password

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

OverwriteDecision = Literal["overwrite", "save_as", "auto_rename", "cancel"]


def next_available_path(path: Path) -> Path:
    """Return the first non-existing sibling path using "name (N).ext" suffixes."""
    if not path.exists():
        return path

    stem = path.stem
    suffix = path.suffix
    parent = path.parent

    idx = 1
    while True:
        candidate = parent / f"{stem} ({idx}){suffix}"
        if not candidate.exists():
            return candidate
        idx += 1


def resolve_output_path(
    desired_path: Path,
    *,
    overwrite_enabled: bool,
    choose_action: Callable[[Path], OverwriteDecision],
    choose_save_as: Callable[[Path], Path | None],
) -> tuple[Path | None, bool]:
    """Resolve destination path when output already exists.

    Returns (path, effective_overwrite). Path=None means cancel.
    """
    current = desired_path
    effective_overwrite = overwrite_enabled

    while current.exists() and not effective_overwrite:
        action = choose_action(current)

        if action == "cancel":
            return None, effective_overwrite

        if action == "overwrite":
            # Enable overwrite for this run.
            effective_overwrite = True
            return current, effective_overwrite

        if action == "auto_rename":
            current = next_available_path(current)
            continue

        if action == "save_as":
            selected = choose_save_as(current)
            if selected is None:
                continue
            current = selected
            continue

    return current, effective_overwrite

# ---------------------------------------------------------------------------
# THEMES
# ---------------------------------------------------------------------------

# "Dark Zinc" — deep professional dark (original)
THEME_DARK: dict[str, str] = {
    "bg_app":        "#09090B",
    "bg_panel":      "#141417",
    "bg_input":      "#1C1C1F",
    "bg_hover":      "#27272A",
    "border_dim":    "#27272A",
    "border_active": "#3F3F46",
    "text_main":     "#FAFAFA",
    "text_sec":      "#A1A1AA",
    "text_dim":      "#52525B",
    "accent_blue":   "#3B82F6",
    "accent_cyan":   "#06B6D4",
    "accent_purp":   "#8B5CF6",
    "accent_pink":   "#EC4899",
    "success":       "#10B981",
    "error":         "#EF4444",
}

# "Apple Light" — iOS-inspired clean light theme
THEME_LIGHT: dict[str, str] = {
    "bg_app":        "#F2F2F7",   # iOS system grouped background
    "bg_panel":      "#FFFFFF",   # White cards
    "bg_input":      "#FFFFFF",   # White inputs
    "bg_hover":      "#E9E9EF",   # Slight press state
    "border_dim":    "#E5E5EA",   # iOS separator
    "border_active": "#C7C7CC",   # iOS separator dark
    "text_main":     "#1C1C1E",   # iOS label
    "text_sec":      "#6D6D72",   # iOS secondary label
    "text_dim":      "#AEAEB2",   # iOS tertiary label
    "accent_blue":   "#007AFF",   # iOS system blue
    "accent_cyan":   "#32ADE6",   # iOS system teal
    "accent_purp":   "#AF52DE",   # iOS system purple
    "accent_pink":   "#FF2D55",   # iOS system pink
    "success":       "#34C759",   # iOS system green
    "error":         "#FF3B30",   # iOS system red
}

# Active theme — modified at runtime by theme toggle
THEME: dict[str, str] = THEME_DARK

FONT_FAMILY = (
    "SF Pro Display, SF Pro Text, -apple-system, "
    "Segoe UI Variable Display, Segoe UI, Inter, Helvetica Neue, sans-serif"
)

def _build_stylesheet(t: dict[str, str]) -> str:
    """Build a complete QSS stylesheet from a theme dict."""
    # Determine if this is a light theme to adjust a few specific rules
    is_light = t["bg_app"] > "#888888"  # light backgrounds are higher in hex
    btn_hover_bg = t["bg_hover"] if is_light else "#3F3F46"
    btn_hover_border = t["border_active"] if is_light else "#52525B"
    input_focus_color = t["text_main"] if is_light else "white"
    ghost_hover_color = t["text_main"] if is_light else "white"
    btn_radius = "12px" if is_light else "8px"
    primary_radius = "22px" if is_light else "12px"
    combobox_bg = t["bg_panel"] if is_light else t["bg_hover"]

    return f"""
/* ── GLOBAL RESET ─────────────────────────────────────────────────────── */
* {{
    font-family: "{FONT_FAMILY}";
    font-size: 14px;
    outline: none;
    color: {t['text_main']};
    border: none;
}}

QMainWindow, QWidget#Content {{
    background-color: {t['bg_app']};
}}

/* ── TYPOGRAPHY ────────────────────────────────────────────────────────── */
QLabel {{ color: {t['text_main']}; background: transparent; }}
QLabel#H1 {{
    font-size: 26px;
    font-weight: 800;
    letter-spacing: -0.5px;
    background-color: transparent;
}}
QLabel#Subtitle {{
    color: {t['text_sec']};
    font-size: 13px;
    font-weight: 400;
    margin-bottom: 10px;
}}
QLabel#H2 {{
    font-size: 11px;
    font-weight: 700;
    color: {t['text_dim']};
    text-transform: uppercase;
    letter-spacing: 1.2px;
    margin-top: 4px;
    margin-bottom: 2px;
}}
QLabel#Tip {{
    color: {t['text_dim']};
    font-size: 12px;
}}

/* ── CARDS ─────────────────────────────────────────────────────────────── */
QGroupBox {{
    background-color: {t['bg_panel']};
    border: 1px solid {t['border_dim']};
    border-radius: 18px;
    margin-top: 1.2em;
    padding: 24px 24px 20px 24px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 20px;
    padding: 0 6px;
    color: {t['accent_blue']};
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.8px;
    text-transform: uppercase;
}}

/* ── INPUT FIELDS ──────────────────────────────────────────────────────── */
QLineEdit {{
    background-color: {t['bg_input']};
    border: 1.5px solid {t['border_dim']};
    border-radius: 11px;
    padding: 11px 16px;
    font-size: 14px;
    selection-background-color: {t['accent_blue']};
    color: {t['text_main']};
}}
QLineEdit:hover {{
    border: 1.5px solid {t['border_active']};
}}
QLineEdit:focus {{
    border: 2px solid {t['accent_blue']};
    color: {input_focus_color};
}}
QLineEdit:disabled {{
    background-color: {t['bg_app']};
    color: {t['text_dim']};
    border: 1px dashed {t['border_dim']};
}}

/* ── LOG / TEXT AREA ───────────────────────────────────────────────────── */
QPlainTextEdit {{
    background-color: {t['bg_input']};
    border: 1px solid {t['border_dim']};
    border-radius: 14px;
    padding: 16px;
    font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
    font-size: 13px;
    color: {t['text_sec']};
}}

/* ── BUTTONS ───────────────────────────────────────────────────────────── */
QPushButton {{
    background-color: {t['bg_hover']};
    border: 1px solid {t['border_active']};
    border-radius: {btn_radius};
    padding: 9px 18px;
    font-weight: 600;
    font-size: 13px;
    color: {t['text_main']};
}}
QPushButton:hover {{
    background-color: {btn_hover_bg};
    border-color: {btn_hover_border};
}}
QPushButton:pressed {{
    background-color: {t['bg_app']};
    opacity: 0.8;
}}

/* Primary CTA – iOS pill shape */
QPushButton#PrimaryButton {{
    background-color: {t['accent_blue']};
    border: none;
    color: white;
    font-size: 16px;
    font-weight: 700;
    letter-spacing: 0.3px;
    padding: 16px 32px;
    border-radius: {primary_radius};
}}
QPushButton#PrimaryButton:hover {{
    opacity: 0.92;
}}
QPushButton#PrimaryButton:disabled {{
    background-color: {t['border_active']};
    color: {t['text_dim']};
}}

/* Ghost/link button */
QPushButton#GhostButton {{
    background: transparent;
    border: none;
    color: {t['accent_blue']};
    font-weight: 500;
    text-align: right;
}}
QPushButton#GhostButton:hover {{
    color: {ghost_hover_color};
    text-decoration: underline;
}}

/* Theme toggle button */
QPushButton#ThemeToggle {{
    background: transparent;
    border: 1.5px solid {t['border_active']};
    border-radius: 10px;
    padding: 6px 12px;
    font-size: 16px;
    color: {t['text_sec']};
}}
QPushButton#ThemeToggle:hover {{
    background: {t['bg_hover']};
    color: {t['text_main']};
}}

/* ── COMBOBOX ──────────────────────────────────────────────────────────── */
QComboBox {{
    background-color: {combobox_bg};
    border: 1px solid {t['border_active']};
    border-radius: 10px;
    padding: 7px 12px;
    font-size: 13px;
    color: {t['text_main']};
}}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background-color: {t['bg_panel']};
    border: 1px solid {t['border_active']};
    border-radius: 10px;
    color: {t['text_main']};
    selection-background-color: {t['accent_blue']};
    selection-color: white;
}}

/* ── CHECKBOX & RADIO ──────────────────────────────────────────────────── */
QRadioButton, QCheckBox {{
    spacing: 10px;
    color: {t['text_main']};
    font-size: 14px;
    font-weight: 400;
}}
QRadioButton::indicator, QCheckBox::indicator {{
    width: 20px;
    height: 20px;
    border-radius: 10px;
    border: 2px solid {t['border_active']};
    background-color: {t['bg_input']};
}}
QCheckBox::indicator {{ border-radius: 6px; }}
QRadioButton::indicator:checked, QCheckBox::indicator:checked {{
    border-color: {t['accent_blue']};
    background-color: {t['accent_blue']};
}}
QRadioButton::indicator:checked {{
    border: 5px solid {t['bg_input']};
    background-color: {t['accent_blue']};
}}

/* ── TABS ──────────────────────────────────────────────────────────────── */
QTabWidget::pane {{ border: none; background: transparent; }}
QTabBar {{
    background: transparent;
}}
QTabBar::tab {{
    background: transparent;
    color: {t['text_dim']};
    padding: 10px 22px;
    font-size: 14px;
    font-weight: 600;
    border-bottom: 2px solid transparent;
    margin-right: 4px;
}}
QTabBar::tab:hover {{ color: {t['text_sec']}; }}
QTabBar::tab:selected {{
    color: {t['accent_blue']};
    border-bottom: 2px solid {t['accent_blue']};
    font-weight: 700;
}}

/* ── SCROLLBAR ─────────────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background: {t['bg_app']};
    width: 8px;
    margin: 4px 2px;
}}
QScrollBar::handle:vertical {{
    background: {t['border_active']};
    min-height: 36px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical:hover {{ background: {t['text_dim']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}

/* ── PROGRESS BAR ──────────────────────────────────────────────────────── */
QProgressBar {{
    background-color: {t['border_dim']};
    border: none;
    border-radius: 4px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {t['accent_blue']};
    border-radius: 4px;
}}
"""


# Module-level default (dark) — ZilantWindow rebuilds on theme toggle
STYLESHEET = _build_stylesheet(THEME_DARK)


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
            self._is_dark_mode: bool = True

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

            # Enable drag & drop
            self.setAcceptDrops(True)

        def dragEnterEvent(self, event: QtGui.QDragEnterEvent) -> None:
            if event.mimeData().hasUrls():
                event.acceptProposedAction()

        def dropEvent(self, event: QtGui.QDropEvent) -> None:
            urls = event.mimeData().urls()
            if not urls:
                return
            path = urls[0].toLocalFile()
            if not path:
                return

            # If .zil file dropped -> switch to decrypt mode and fill input
            if path.endswith(".zil"):
                self.rad_dec.setChecked(True)
                self.wdg_input["txt"].setText(path)
                self._auto_output()
            else:
                self.rad_enc.setChecked(True)
                p = Path(path)
                if p.is_dir():
                    self.rad_dir.setChecked(True)
                else:
                    self.rad_file.setChecked(True)
                self.wdg_input["txt"].setText(path)
                self._auto_output()

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

            self.btn_theme = QtWidgets.QPushButton("☀️")
            self.btn_theme.setObjectName("ThemeToggle")
            self.btn_theme.setFixedSize(44, 36)
            self.btn_theme.setToolTip("Switch Light / Dark theme")
            self.btn_theme.clicked.connect(self._toggle_theme)

            self.btn_about = QtWidgets.QPushButton("?")
            self.btn_about.setFixedWidth(40)
            self.btn_about.clicked.connect(self._show_about)

            controls.addWidget(self.combo_lang)
            controls.addWidget(self.btn_theme)
            controls.addWidget(self.btn_about)
            layout.addLayout(controls)

            self.main_layout.addWidget(top)

        # ---------- THEME TOGGLE ----------

        def _toggle_theme(self) -> None:
            """Switch between dark (Zinc) and light (Apple iOS) themes."""
            global THEME  # noqa: PLW0603
            self._is_dark_mode = not self._is_dark_mode
            THEME = THEME_DARK if self._is_dark_mode else THEME_LIGHT
            self.btn_theme.setText("☀️" if self._is_dark_mode else "🌙")
            self.setStyleSheet(_build_stylesheet(THEME))
            # Refresh dynamic inline styles that reference THEME
            self._update_ui_state()
            self._update_password_strength(self.txt_pass.text())
            self.lbl_dot.setStyleSheet(
                f"color: {THEME['success']}; font-size: 16px;"
            )

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
            self.txt_pass.textChanged.connect(self._update_password_strength)

            self.btn_eye = QtWidgets.QPushButton("👁")
            self.btn_eye.setFixedWidth(46)
            self.btn_eye.setCheckable(True)
            self.btn_eye.toggled.connect(lambda c: self._toggle_eye(self.txt_pass, c))

            pass_field.addWidget(self.txt_pass)
            pass_field.addWidget(self.btn_eye)
            sec_lay.addLayout(pass_field)

            # Password strength meter
            strength_row = QtWidgets.QHBoxLayout()
            strength_row.setSpacing(8)
            self.password_strength_bar = QtWidgets.QProgressBar()
            self.password_strength_bar.setRange(0, 100)
            self.password_strength_bar.setValue(0)
            self.password_strength_bar.setFixedHeight(6)
            self.password_strength_bar.setTextVisible(False)
            # No hardcoded inline style — the global stylesheet handles it;
            # _update_password_strength() updates the chunk color dynamically.
            self.lbl_strength = QtWidgets.QLabel("")
            self.lbl_strength.setObjectName("Tip")
            self.lbl_strength.setFixedWidth(120)
            strength_row.addWidget(self.password_strength_bar)
            strength_row.addWidget(self.lbl_strength)
            sec_lay.addLayout(strength_row)

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

            # Light theme: solid iOS-style color; Dark theme: gradient
            if self._is_dark_mode:
                bg = f"qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {c1}, stop:1 {c2})"
                hover_extra = "border: 1px solid rgba(255,255,255,0.3);"
            else:
                bg = c1
                hover_extra = f"background: {c2};"

            self.btn_action.setText(text.upper())
            self.btn_action.setStyleSheet(f"""
                QPushButton#PrimaryButton {{
                    background: {bg};
                }}
                QPushButton#PrimaryButton:hover {{
                    {hover_extra}
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

        def _choose_output_path(self, current: Path) -> Path | None:
            if self.rad_enc.isChecked():
                res, _ = QtWidgets.QFileDialog.getSaveFileName(
                    self,
                    "Save As",
                    str(current),
                    filter="Zilant (*.zil)",
                )
            else:
                res = QtWidgets.QFileDialog.getExistingDirectory(
                    self, "Select Destination"
                )
            if not res:
                return None
            return Path(res).resolve()

        def _ask_overwrite_action(self, target: Path) -> OverwriteDecision:
            dlg = QtWidgets.QMessageBox(self)
            dlg.setWindowTitle("Output already exists")
            dlg.setText(
                "The selected output path already exists. Choose how to continue."
            )
            dlg.setInformativeText(str(target))
            dlg.setIcon(QtWidgets.QMessageBox.Icon.Warning)

            btn_overwrite = dlg.addButton(
                "Overwrite", QtWidgets.QMessageBox.ButtonRole.AcceptRole
            )
            btn_save_as = dlg.addButton(
                "Save As…", QtWidgets.QMessageBox.ButtonRole.ActionRole
            )
            btn_auto = dlg.addButton(
                "Auto-rename", QtWidgets.QMessageBox.ButtonRole.ActionRole
            )
            btn_cancel = dlg.addButton(
                QtWidgets.QMessageBox.StandardButton.Cancel
            )
            dlg.exec()

            clicked = dlg.clickedButton()
            if clicked is btn_overwrite:
                return "overwrite"
            if clicked is btn_save_as:
                return "save_as"
            if clicked is btn_auto:
                return "auto_rename"
            if clicked is btn_cancel:
                return "cancel"
            return "cancel"

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

        def _update_password_strength(self, text: str) -> None:
            """Update the password strength meter."""
            if not text:
                self.password_strength_bar.setValue(0)
                self.lbl_strength.setText("")
                self.password_strength_bar.setStyleSheet(f"""
                    QProgressBar {{ background-color: {THEME['bg_input']}; border: none; border-radius: 3px; }}
                    QProgressBar::chunk {{ background-color: {THEME['text_dim']}; border-radius: 3px; }}
                """)
                return

            strength = evaluate_password(text)
            self.password_strength_bar.setValue(strength.score)

            colors = {
                "weak": THEME["error"],
                "fair": "#F59E0B",
                "good": THEME["accent_blue"],
                "strong": THEME["success"],
            }
            labels = {
                "weak": self.ui_strings.password_strength_weak,
                "fair": self.ui_strings.password_strength_fair,
                "good": self.ui_strings.password_strength_good,
                "strong": self.ui_strings.password_strength_strong,
            }

            color = colors[strength.level]
            self.lbl_strength.setText(labels[strength.level])
            self.lbl_strength.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: 600;")
            self.password_strength_bar.setStyleSheet(f"""
                QProgressBar {{ background-color: {THEME['bg_input']}; border: none; border-radius: 3px; }}
                QProgressBar::chunk {{ background-color: {color}; border-radius: 3px; }}
            """)

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

            if is_enc and dst.suffix != ".zil":
                ask_suffix = QtWidgets.QMessageBox.question(
                    self,
                    "Append .zil suffix?",
                    "Encryption output usually uses .zil extension. Append it?",
                    QtWidgets.QMessageBox.StandardButton.Yes
                    | QtWidgets.QMessageBox.StandardButton.No
                    | QtWidgets.QMessageBox.StandardButton.Cancel,
                    QtWidgets.QMessageBox.StandardButton.Yes,
                )
                if ask_suffix == QtWidgets.QMessageBox.StandardButton.Cancel:
                    return
                if ask_suffix == QtWidgets.QMessageBox.StandardButton.Yes:
                    dst = dst.with_name(dst.name + ".zil")
                    self.wdg_output["txt"].setText(str(dst))

            resolved_dst, effective_ow = resolve_output_path(
                dst,
                overwrite_enabled=self.chk_overwrite.isChecked(),
                choose_action=self._ask_overwrite_action,
                choose_save_as=self._choose_output_path,
            )
            if resolved_dst is None:
                return
            dst = resolved_dst
            self.wdg_output["txt"].setText(str(dst))

            if is_enc and dst.is_dir():
                self._msg(
                    "Invalid Output",
                    "Encryption output must be a file path, not a directory.",
                    True,
                )
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

                ow = effective_ow

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
            if "Refusing to overwrite existing file" in msg and self._output_path:
                resolved_dst, effective_ow = resolve_output_path(
                    self._output_path,
                    overwrite_enabled=self.chk_overwrite.isChecked(),
                    choose_action=self._ask_overwrite_action,
                    choose_save_as=self._choose_output_path,
                )
                if resolved_dst is None:
                    return
                self.wdg_output["txt"].setText(str(resolved_dst))
                if effective_ow:
                    self.chk_overwrite.setChecked(True)
                QtCore.QTimer.singleShot(0, self._run_action)
                return
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
