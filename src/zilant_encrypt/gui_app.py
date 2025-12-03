"""Desktop GUI for Zilant Encrypt."""
from __future__ import annotations

import importlib.util
import inspect
import sys
import traceback
from pathlib import Path
from typing import Any, Callable, Literal

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

QT_AVAILABLE = importlib.util.find_spec("PySide6") is not None

if QT_AVAILABLE:
    from PySide6 import QtCore, QtGui, QtWidgets
else:  # pragma: no cover
    QtCore = QtGui = QtWidgets = None  # type: ignore[assignment]

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

APP_TITLE = f"Zilant Encrypt v{__version__}"
STATUS_READY = "Ready"
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


def _format_overview_report(
    path: Path,
    overview: ContainerOverview,
    validated: list[int],
    pq_available: bool,
) -> str:
    """Return a human-readable overview of a container."""
    version = overview.header.version
    lines: list[str] = [f"File: {path}", f"Version: v{version}", "Volumes:"]

    password_used = bool(validated)

    for desc in overview.descriptors:
        if desc.volume_index == 0:
            label = "main"
        elif desc.volume_index == 1:
            label = "decoy"
        else:
            label = str(desc.volume_index)

        mode = "pq-hybrid" if desc.key_mode == KEY_MODE_PQ_HYBRID else "password"

        if password_used:
            status = "OK" if desc.volume_index in validated else "NOT CHECKED"
        else:
            status = "SKIPPED (no password)"

        lines.append(
            f"  [{desc.volume_index}] {label:<5} mode={mode:<10} status={status}"
        )

    pq_line = "available" if pq_available else "not available"
    lines.append(f"PQ support: {pq_line}")

    return "\n".join(lines)


if QT_AVAILABLE:

    # --- Worker Thread for Async Crypto -------------------------------------

    class TaskWorker(QtCore.QThread):
        """Background thread to prevent GUI freezing during crypto ops."""

        finished_success = QtCore.Signal(str)  # Message
        finished_error = QtCore.Signal(str)  # Error message

        def __init__(self, func: Callable[[], Any]) -> None:
            super().__init__()
            self._func = func

        def run(self) -> None:
            try:
                self._func()
                self.finished_success.emit("Operation completed successfully.")
            except InvalidPassword:
                self.finished_error.emit("Invalid password or key.")
            except PqSupportError:
                self.finished_error.emit(
                    "Operation requires PQ support (liboqs) which is missing."
                )
            except (ContainerFormatError, IntegrityError) as e:
                self.finished_error.emit(f"Data integrity/format error: {e}")
            except Exception as e:  # pragma: no cover - debug path
                traceback.print_exc()
                self.finished_error.emit(f"Unexpected error: {str(e)}")

    # --- Main Window --------------------------------------------------------

    class ZilantWindow(QtWidgets.QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle(APP_TITLE)
            self.resize(900, 750)
            self.setMinimumSize(800, 600)

            # State
            self._output_path: Path | None = None
            self._worker: TaskWorker | None = None
            self._temp_report: str | None = None

            # Setup UI
            self.setStyleSheet(STYLESHEET)

            central = QtWidgets.QWidget(self)
            self.setCentralWidget(central)

            self.main_layout = QtWidgets.QVBoxLayout(central)
            self.main_layout.setContentsMargins(24, 24, 24, 24)
            self.main_layout.setSpacing(20)

            self._build_header()
            self.tabs = QtWidgets.QTabWidget()
            self.main_layout.addWidget(self.tabs)

            self._build_encrypt_decrypt_tab()
            self._build_inspect_tab()
            self._build_footer()
            self._update_defaults()

        # --- UI Construction -------------------------------------------------

        def _build_header(self) -> None:
            header_widget = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout(header_widget)
            layout.setContentsMargins(0, 0, 0, 0)

            titles_layout = QtWidgets.QVBoxLayout()
            title = QtWidgets.QLabel("Zilant Encrypt")
            title.setStyleSheet(
                f"font-size: 24px; font-weight: bold; color: {TEXT_COLOR};"
            )

            subtitle = QtWidgets.QLabel(
                "Secure containers · Decoy volumes · Post-Quantum Hybrid"
            )
            subtitle.setStyleSheet("font-size: 13px; color: #888;")

            titles_layout.addWidget(title)
            titles_layout.addWidget(subtitle)

            layout.addLayout(titles_layout)
            layout.addStretch()

            about_btn = QtWidgets.QPushButton("About")
            about_btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            about_btn.clicked.connect(self._show_about_dialog)
            layout.addWidget(about_btn)

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

            self.mode_label = QtWidgets.QLabel("Action:")
            self.mode_label.setStyleSheet("font-weight: bold;")
            self.encrypt_radio = QtWidgets.QRadioButton("Encrypt")
            self.decrypt_radio = QtWidgets.QRadioButton("Decrypt")
            self.encrypt_radio.setChecked(True)
            self.encrypt_radio.toggled.connect(self._on_op_mode_changed)

            mode_layout.addWidget(self.mode_label)
            mode_layout.addWidget(self.encrypt_radio)
            mode_layout.addWidget(self.decrypt_radio)
            mode_layout.addStretch()
            self.workflow_layout.addWidget(mode_frame)

            # 2. IO Card
            io_group = QtWidgets.QGroupBox("Input / Output")
            io_layout = QtWidgets.QVBoxLayout()

            type_layout = QtWidgets.QHBoxLayout()
            type_label = QtWidgets.QLabel("Source Type:")
            type_label.setStyleSheet("color: #888;")
            self.file_radio = QtWidgets.QRadioButton("Single File")
            self.dir_radio = QtWidgets.QRadioButton("Directory (Zip)")
            self.file_radio.setChecked(True)
            self.file_radio.toggled.connect(self._on_input_type_changed)

            type_layout.addWidget(type_label)
            type_layout.addWidget(self.file_radio)
            type_layout.addWidget(self.dir_radio)
            type_layout.addStretch()
            io_layout.addLayout(type_layout)

            self.input_edit = self._create_path_picker(
                "Select Input...", self._browse_input
            )
            self.output_edit = self._create_path_picker(
                "Select Output...", self._browse_output
            )

            io_layout.addWidget(QtWidgets.QLabel("Input Path"))
            io_layout.addLayout(self.input_edit["layout"])
            io_layout.addWidget(QtWidgets.QLabel("Output Path"))
            io_layout.addLayout(self.output_edit["layout"])

            self.overwrite_checkbox = QtWidgets.QCheckBox(
                "Overwrite existing files without asking"
            )
            io_layout.addWidget(self.overwrite_checkbox)

            io_group.setLayout(io_layout)
            self.workflow_layout.addWidget(io_group)

            # 3. Security / Password
            sec_group = QtWidgets.QGroupBox("Security")
            sec_layout = QtWidgets.QVBoxLayout()

            algo_layout = QtWidgets.QHBoxLayout()
            self.mode_password_radio = QtWidgets.QRadioButton(
                "Standard (AES-256-GCM + Argon2id)"
            )
            self.mode_pq_radio = QtWidgets.QRadioButton("PQ-Hybrid (Kyber768 + AES)")
            self.mode_password_radio.setChecked(True)
            self.mode_password_radio.setToolTip("Compatible everywhere. Very secure.")
            self.mode_pq_radio.setToolTip(
                "Protects against quantum computers. Requires liboqs."
            )

            algo_layout.addWidget(self.mode_password_radio)
            algo_layout.addWidget(self.mode_pq_radio)
            algo_layout.addStretch()
            sec_layout.addLayout(algo_layout)

            self.password_edit = QtWidgets.QLineEdit()
            self.password_edit.setPlaceholderText("Enter secure password")
            self.password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

            self.show_pass_check = QtWidgets.QCheckBox("Show password")
            self.show_pass_check.stateChanged.connect(self._toggle_password_visibility)

            sec_layout.addWidget(self.password_edit)
            sec_layout.addWidget(self.show_pass_check)
            sec_group.setLayout(sec_layout)
            self.workflow_layout.addWidget(sec_group)

            # 4. Decoy
            self.decoy_group = QtWidgets.QGroupBox(
                "Decoy Volume (Plausible Deniability)"
            )
            self.decoy_group.setCheckable(True)
            self.decoy_group.setChecked(False)
            self.decoy_group.toggled.connect(self._update_ui_state)

            decoy_layout = QtWidgets.QVBoxLayout()
            self.decoy_info_lbl = QtWidgets.QLabel(
                "Create a hidden volume inside the main container. "
                "It requires a separate password."
            )
            self.decoy_info_lbl.setStyleSheet("color: #888; font-style: italic;")
            self.decoy_password_edit = QtWidgets.QLineEdit()
            self.decoy_password_edit.setPlaceholderText("Decoy Password")
            self.decoy_password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

            self.decoy_input_picker = self._create_path_picker(
                "Select Decoy Payload...", self._browse_decoy_input
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

            self.auto_vol_radio = QtWidgets.QRadioButton("Auto-detect Volume")
            self.auto_vol_radio.setChecked(True)
            self.force_main_radio = QtWidgets.QRadioButton("Force Main")
            self.force_decoy_radio = QtWidgets.QRadioButton("Force Decoy")

            d_layout.addWidget(QtWidgets.QLabel("Decrypt Target:"))
            d_layout.addWidget(self.auto_vol_radio)
            d_layout.addWidget(self.force_main_radio)
            d_layout.addWidget(self.force_decoy_radio)
            d_layout.addStretch()
            self.workflow_layout.addWidget(self.decrypt_opts_frame)

            # 6. Action Button
            self.action_button = QtWidgets.QPushButton("START ENCRYPTION")
            self.action_button.setProperty("class", "primary")
            self.action_button.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            self.action_button.setMinimumHeight(50)
            self.action_button.clicked.connect(self._on_action_clicked)

            self.workflow_layout.addStretch()
            self.workflow_layout.addWidget(self.action_button)

            self.tabs.addTab(tab, "Encrypt / Decrypt")

        def _build_inspect_tab(self) -> None:
            tab = QtWidgets.QWidget()
            layout = QtWidgets.QVBoxLayout(tab)
            layout.setSpacing(16)
            layout.setContentsMargins(16, 24, 16, 16)

            insp_group = QtWidgets.QGroupBox("Container to Inspect")
            insp_layout = QtWidgets.QVBoxLayout()
            self.inspect_picker = self._create_path_picker(
                "Select .zil container...", self._browse_inspect_input
            )
            insp_layout.addLayout(self.inspect_picker["layout"])

            opt_layout = QtWidgets.QHBoxLayout()
            self.inspect_auth_check = QtWidgets.QCheckBox(
                "Verify Integrity (requires password)"
            )
            self.inspect_auth_check.stateChanged.connect(self._toggle_inspect_password)
            self.inspect_pass_edit = QtWidgets.QLineEdit()
            self.inspect_pass_edit.setPlaceholderText("Password")
            self.inspect_pass_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            self.inspect_pass_edit.setEnabled(False)

            opt_layout.addWidget(self.inspect_auth_check)
            opt_layout.addWidget(self.inspect_pass_edit)
            insp_layout.addLayout(opt_layout)
            insp_group.setLayout(insp_layout)
            layout.addWidget(insp_group)

            self.inspect_btn = QtWidgets.QPushButton("Analyze Container")
            self.inspect_btn.setProperty("class", "primary")
            self.inspect_btn.clicked.connect(self._handle_inspect)
            layout.addWidget(self.inspect_btn)

            self.inspect_output = QtWidgets.QPlainTextEdit()
            self.inspect_output.setReadOnly(True)
            self.inspect_output.setStyleSheet("font-size: 12px; line-height: 1.4;")
            layout.addWidget(self.inspect_output, 1)

            self.tabs.addTab(tab, "Inspect / Audit")

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
            self.status_lbl = QtWidgets.QLabel(STATUS_READY)
            self.status_lbl.setStyleSheet("font-weight: bold;")

            open_folder_btn = QtWidgets.QPushButton("Open Folder")
            open_folder_btn.setStyleSheet(
                "background: transparent; color: #888; "
                "border: 1px solid #444; padding: 2px 8px;"
            )
            open_folder_btn.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
            open_folder_btn.clicked.connect(self._open_output_folder)

            status_layout.addWidget(self.status_icon)
            status_layout.addWidget(self.status_lbl)
            status_layout.addStretch()
            status_layout.addWidget(open_folder_btn)

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

            btn = QtWidgets.QPushButton("Browse")
            btn.setFixedWidth(80)
            btn.clicked.connect(slot)

            layout.addWidget(edit)
            layout.addWidget(btn)
            return {"layout": layout, "edit": edit, "btn": btn}

        def _on_op_mode_changed(self) -> None:
            is_encrypt = self.encrypt_radio.isChecked()
            self.action_button.setText(
                "START ENCRYPTION" if is_encrypt else "START DECRYPTION"
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
                    self, "Select Folder to Encrypt"
                )
            else:
                path, _ = QtWidgets.QFileDialog.getOpenFileName(
                    self, "Select File"
                )

            if path:
                self.input_edit["edit"].setText(path)

        def _browse_output(self) -> None:
            if self.encrypt_radio.isChecked():
                path, _ = QtWidgets.QFileDialog.getSaveFileName(
                    self,
                    "Save Container As",
                    filter="Zilant Container (*.zil)",
                )
            else:
                path = QtWidgets.QFileDialog.getExistingDirectory(
                    self, "Select Output Directory"
                )

            if path:
                self.output_edit["edit"].setText(path)

        def _browse_decoy_input(self) -> None:
            if self.dir_radio.isChecked():
                path = QtWidgets.QFileDialog.getExistingDirectory(
                    self, "Select Decoy Folder"
                )
            else:
                path, _ = QtWidgets.QFileDialog.getOpenFileName(
                    self, "Select Decoy File"
                )

            if path:
                self.decoy_input_picker["edit"].setText(path)

        def _browse_inspect_input(self) -> None:
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self,
                "Select Container",
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
                self._show_error("Input path does not exist.")
                return
            if not password:
                self._show_error("Password is required.")
                return

            in_path = Path(in_path_str)
            out_path = Path(out_path_str)

            overwrite_mode = self.overwrite_checkbox.isChecked()
            if out_path.exists() and not overwrite_mode:
                res = QtWidgets.QMessageBox.question(
                    self,
                    "Overwrite?",
                    f"Output exists:\n{out_path}\n\nOverwrite?",
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
                        raise InvalidPassword("Decoy password required")
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
                self._show_error("Container not found.")
                return

            path = Path(path_str)
            pwd = (
                self.inspect_pass_edit.text()
                if self.inspect_auth_check.isChecked()
                else None
            )

            self._set_busy(True)
            self._worker = TaskWorker(lambda: self._run_inspect_logic(path, pwd))
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
                path, overview, validated, overview.pq_available
            )
            self._temp_report = report

        # --- Worker plumbing -------------------------------------------------

        def _start_worker(
            self, func: Callable[[], None], output_target: Path | None
        ) -> None:
            self.progress_bar.setRange(0, 0)
            self.progress_bar.setVisible(True)
            self.status_lbl.setText("Processing... Please wait.")
            self.status_icon.setStyleSheet(f"color: {ACCENT_COLOR};")

            self._output_path = output_target
            self._worker = TaskWorker(func)
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
                self.status_lbl.setText(STATUS_READY)
                self.status_icon.setStyleSheet(f"color: {SUCCESS_COLOR};")

                if self._temp_report is not None:
                    self.inspect_output.setPlainText(self._temp_report)
                    self._temp_report = None
                    self.inspect_pass_edit.clear()
                else:
                    self.password_edit.clear()
                    self.decoy_password_edit.clear()
                    self._show_info("Success", message)
            else:
                self.status_lbl.setText("Error occurred")
                self.status_icon.setStyleSheet(f"color: {ERROR_COLOR};")
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
            QtWidgets.QMessageBox.critical(self, "Error", msg)

        def _show_info(self, title: str, msg: str) -> None:
            QtWidgets.QMessageBox.information(self, title, msg)

        def _show_about_dialog(self) -> None:
            QtWidgets.QMessageBox.about(
                self,
                "About Zilant Encrypt",
                f"<h3>Zilant Encrypt v{__version__}</h3>"
                "<p>Secure, local-only encryption tool.</p>"
                "<p>Features: <b>Argon2id</b>, <b>AES-GCM</b>, "
                "<b>Kyber768 (PQ)</b>, <b>Decoy Volumes</b>.</p>"
                "<p>License: MIT</p>",
            )


    def create_app() -> QtWidgets.QApplication:
        app = QtWidgets.QApplication(sys.argv)
        font = QtGui.QFont("Segoe UI", 10)
        app.setFont(font)

        window = ZilantWindow()
        window.show()

        # Keep reference so it isn't GC'ed
        app._zilant_window = window  # type: ignore[attr-defined]
        return app

else:

    def create_app() -> Any:  # type: ignore[misc]
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
