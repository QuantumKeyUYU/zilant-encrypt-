"""Desktop GUI for Zilant Encrypt."""
from __future__ import annotations

from pathlib import Path
import importlib.util
import sys

from zilant_encrypt.container import decrypt_auto_volume, decrypt_file, encrypt_file, encrypt_with_decoy, normalize_mode
from zilant_encrypt.errors import (
    ContainerFormatError,
    IntegrityError,
    InvalidPassword,
    PqSupportError,
    UnsupportedFeatureError,
)

QT_AVAILABLE = importlib.util.find_spec("PySide6") is not None

if QT_AVAILABLE:
    from PySide6 import QtCore, QtGui, QtWidgets
else:  # pragma: no cover - executed only when GUI extras are missing
    QtCore = QtGui = QtWidgets = None  # type: ignore[assignment]


STATUS_READY = "Ready"


class _Status:
    READY = STATUS_READY
    ENCRYPTING = "Encrypting…"
    DECRYPTING = "Decrypting…"


if QT_AVAILABLE:

    class ZilantWindow(QtWidgets.QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("Zilant Encrypt")
            self.resize(760, 680)

            self._output_path: Path | None = None

            central = QtWidgets.QWidget(self)
            self.setCentralWidget(central)
            self.layout = QtWidgets.QVBoxLayout(central)
            self.layout.setSpacing(14)

            self._build_header()
            self._build_mode_switch()
            self._build_io_section()
            self._build_password_section()
            self._build_security_section()
            self._build_decoy_section()
            self._build_decrypt_advanced()
            self._build_action_section()
            self._build_status_bar()

            self._apply_dark_theme()
            self._update_defaults()

        # UI builders
        def _build_header(self) -> None:
            title = QtWidgets.QLabel("Zilant Encrypt")
            title_font = QtGui.QFont()
            title_font.setPointSize(20)
            title_font.setBold(True)
            title.setFont(title_font)

            subtitle = QtWidgets.QLabel("Secure containers for your secrets")
            subtitle_font = QtGui.QFont()
            subtitle_font.setPointSize(12)
            subtitle.setFont(subtitle_font)
            subtitle.setStyleSheet("color: #A0A0A0;")

            header_layout = QtWidgets.QVBoxLayout()
            header_layout.addWidget(title)
            header_layout.addWidget(subtitle)
            header_layout.addStretch(1)
            self.layout.addLayout(header_layout)

        def _build_mode_switch(self) -> None:
            group_box = QtWidgets.QGroupBox("Mode")
            mode_layout = QtWidgets.QHBoxLayout()
            self.encrypt_radio = QtWidgets.QRadioButton("Encrypt")
            self.decrypt_radio = QtWidgets.QRadioButton("Decrypt")
            self.encrypt_radio.setChecked(True)
            mode_layout.addWidget(self.encrypt_radio)
            mode_layout.addWidget(self.decrypt_radio)
            mode_layout.addStretch(1)
            group_box.setLayout(mode_layout)
            self.layout.addWidget(group_box)

            self.encrypt_radio.toggled.connect(self._on_mode_changed)

        def _build_io_section(self) -> None:
            container = QtWidgets.QGroupBox("Source and destination")
            vbox = QtWidgets.QVBoxLayout()

            # Input type
            input_type_layout = QtWidgets.QHBoxLayout()
            self.file_radio = QtWidgets.QRadioButton("File")
            self.dir_radio = QtWidgets.QRadioButton("Directory")
            self.file_radio.setChecked(True)
            input_type_layout.addWidget(QtWidgets.QLabel("Input type:"))
            input_type_layout.addWidget(self.file_radio)
            input_type_layout.addWidget(self.dir_radio)
            input_type_layout.addStretch(1)
            vbox.addLayout(input_type_layout)

            # Input path
            self.input_edit = QtWidgets.QLineEdit()
            input_button = QtWidgets.QPushButton("Browse…")
            input_button.clicked.connect(self._browse_input)
            input_layout = QtWidgets.QHBoxLayout()
            input_layout.addWidget(QtWidgets.QLabel("Input"))
            input_layout.addWidget(self.input_edit)
            input_layout.addWidget(input_button)
            vbox.addLayout(input_layout)

            # Output path
            self.output_edit = QtWidgets.QLineEdit()
            output_button = QtWidgets.QPushButton("Browse…")
            output_button.clicked.connect(self._browse_output)
            output_layout = QtWidgets.QHBoxLayout()
            output_layout.addWidget(QtWidgets.QLabel("Output"))
            output_layout.addWidget(self.output_edit)
            output_layout.addWidget(output_button)
            vbox.addLayout(output_layout)

            self.overwrite_checkbox = QtWidgets.QCheckBox("Overwrite existing output")
            vbox.addWidget(self.overwrite_checkbox)

            container.setLayout(vbox)
            self.layout.addWidget(container)

            self.file_radio.toggled.connect(self._on_input_type_changed)
            self.input_edit.textChanged.connect(self._on_input_changed)

        def _build_password_section(self) -> None:
            container = QtWidgets.QGroupBox("Password")
            vbox = QtWidgets.QVBoxLayout()

            self.password_edit = QtWidgets.QLineEdit()
            self.password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            show_password = QtWidgets.QCheckBox("Show password")
            show_password.stateChanged.connect(self._toggle_password_visibility)

            vbox.addWidget(self.password_edit)
            vbox.addWidget(show_password)
            container.setLayout(vbox)
            self.layout.addWidget(container)

        def _build_security_section(self) -> None:
            container = QtWidgets.QGroupBox("Security mode")
            layout = QtWidgets.QHBoxLayout()
            self.mode_password_radio = QtWidgets.QRadioButton("Password only")
            self.mode_pq_radio = QtWidgets.QRadioButton("PQ-hybrid (password + Kyber)")
            self.mode_password_radio.setChecked(True)
            layout.addWidget(self.mode_password_radio)
            layout.addWidget(self.mode_pq_radio)
            layout.addStretch(1)
            container.setLayout(layout)
            self.layout.addWidget(container)

        def _build_decoy_section(self) -> None:
            self.decoy_group = QtWidgets.QGroupBox("Decoy volume (optional)")
            self.decoy_group.setCheckable(True)
            self.decoy_group.setChecked(False)

            vbox = QtWidgets.QVBoxLayout()
            self.decoy_password_edit = QtWidgets.QLineEdit()
            self.decoy_password_edit.setPlaceholderText("Decoy password")
            self.decoy_password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

            self.decoy_input_edit = QtWidgets.QLineEdit()
            browse = QtWidgets.QPushButton("Browse…")
            browse.clicked.connect(self._browse_decoy_input)
            decoy_input_layout = QtWidgets.QHBoxLayout()
            decoy_input_layout.addWidget(QtWidgets.QLabel("Decoy input (optional)"))
            decoy_input_layout.addWidget(self.decoy_input_edit)
            decoy_input_layout.addWidget(browse)

            vbox.addWidget(QtWidgets.QLabel("Provide a decoy password for the plausible volume."))
            vbox.addWidget(self.decoy_password_edit)
            vbox.addLayout(decoy_input_layout)
            self.decoy_group.setLayout(vbox)
            self.layout.addWidget(self.decoy_group)

        def _build_decrypt_advanced(self) -> None:
            self.advanced_group = QtWidgets.QGroupBox("Advanced decrypt options")
            self.advanced_group.setCheckable(True)
            self.advanced_group.setChecked(False)

            vbox = QtWidgets.QVBoxLayout()
            volume_layout = QtWidgets.QHBoxLayout()
            self.auto_volume_radio = QtWidgets.QRadioButton("Auto volume")
            self.main_only_radio = QtWidgets.QRadioButton("Main only")
            self.decoy_only_radio = QtWidgets.QRadioButton("Decoy only")
            self.auto_volume_radio.setChecked(True)
            volume_layout.addWidget(self.auto_volume_radio)
            volume_layout.addWidget(self.main_only_radio)
            volume_layout.addWidget(self.decoy_only_radio)
            volume_layout.addStretch(1)

            self.assume_pq_checkbox = QtWidgets.QCheckBox("Assume PQ-hybrid")

            vbox.addLayout(volume_layout)
            vbox.addWidget(self.assume_pq_checkbox)
            self.advanced_group.setLayout(vbox)
            self.layout.addWidget(self.advanced_group)

        def _build_action_section(self) -> None:
            action_layout = QtWidgets.QVBoxLayout()
            self.action_button = QtWidgets.QPushButton("Encrypt")
            self.action_button.setMinimumHeight(46)
            self.action_button.clicked.connect(self._on_action_clicked)
            action_layout.addWidget(self.action_button)

            self.open_output_button = QtWidgets.QPushButton("Open output folder")
            self.open_output_button.setEnabled(False)
            self.open_output_button.clicked.connect(self._open_output_folder)
            action_layout.addWidget(self.open_output_button)

            self.layout.addLayout(action_layout)

        def _build_status_bar(self) -> None:
            self.status_label = QtWidgets.QLabel(STATUS_READY)
            footer = QtWidgets.QLabel("No telemetry. Local-only crypto.")
            footer.setStyleSheet("color: #A0A0A0; font-size: 11px;")

            status_layout = QtWidgets.QVBoxLayout()
            status_layout.addWidget(self.status_label)
            status_layout.addWidget(footer)
            self.layout.addLayout(status_layout)

        # UI helpers
        def _apply_dark_theme(self) -> None:
            palette = QtGui.QPalette()
            palette.setColor(QtGui.QPalette.ColorRole.Window, QtGui.QColor(24, 24, 24))
            palette.setColor(QtGui.QPalette.ColorRole.WindowText, QtGui.QColor(235, 235, 235))
            palette.setColor(QtGui.QPalette.ColorRole.Base, QtGui.QColor(30, 30, 30))
            palette.setColor(QtGui.QPalette.ColorRole.AlternateBase, QtGui.QColor(45, 45, 45))
            palette.setColor(QtGui.QPalette.ColorRole.ToolTipBase, QtGui.QColor(255, 255, 255))
            palette.setColor(QtGui.QPalette.ColorRole.ToolTipText, QtGui.QColor(0, 0, 0))
            palette.setColor(QtGui.QPalette.ColorRole.Text, QtGui.QColor(235, 235, 235))
            palette.setColor(QtGui.QPalette.ColorRole.Button, QtGui.QColor(45, 45, 45))
            palette.setColor(QtGui.QPalette.ColorRole.ButtonText, QtGui.QColor(235, 235, 235))
            palette.setColor(QtGui.QPalette.ColorRole.BrightText, QtCore.Qt.GlobalColor.red)
            palette.setColor(QtGui.QPalette.ColorRole.Highlight, QtGui.QColor("#5ac8fa"))
            palette.setColor(QtGui.QPalette.ColorRole.HighlightedText, QtGui.QColor(0, 0, 0))
            self.setPalette(palette)

        def _toggle_password_visibility(self, state: int) -> None:
            self.password_edit.setEchoMode(
                QtWidgets.QLineEdit.EchoMode.Normal
                if state == QtCore.Qt.CheckState.Checked
                else QtWidgets.QLineEdit.EchoMode.Password
            )

        def _browse_input(self) -> None:
            if self.encrypt_radio.isChecked() and self.dir_radio.isChecked():
                path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select directory")
            else:
                path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select file")
            if path:
                self.input_edit.setText(path)

        def _browse_output(self) -> None:
            caption = "Select output location"
            if self.encrypt_radio.isChecked():
                path, _ = QtWidgets.QFileDialog.getSaveFileName(self, caption)
            else:
                if self.dir_radio.isChecked():
                    path = QtWidgets.QFileDialog.getExistingDirectory(self, caption)
                else:
                    path, _ = QtWidgets.QFileDialog.getSaveFileName(self, caption)
            if path:
                self.output_edit.setText(path)

        def _browse_decoy_input(self) -> None:
            if self.dir_radio.isChecked():
                path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select decoy directory")
            else:
                path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select decoy file")
            if path:
                self.decoy_input_edit.setText(path)

        def _on_input_type_changed(self) -> None:
            if self.decrypt_radio.isChecked():
                self.dir_radio.setChecked(False)
                self.dir_radio.setEnabled(False)
                self.file_radio.setChecked(True)
            else:
                self.dir_radio.setEnabled(True)
            self._update_defaults()

        def _on_mode_changed(self) -> None:
            if self.encrypt_radio.isChecked():
                self.action_button.setText("Encrypt")
                self.dir_radio.setEnabled(True)
            else:
                self.action_button.setText("Decrypt")
                self.dir_radio.setChecked(False)
                self.dir_radio.setEnabled(False)
                self.file_radio.setChecked(True)
            self._update_defaults()

        def _on_input_changed(self) -> None:
            self._update_defaults()

        def _update_defaults(self) -> None:
            text = self.input_edit.text().strip()
            if not text:
                return
            path = Path(text)
            if self.encrypt_radio.isChecked():
                suffix = ".zil"
                default_out = path.with_suffix(path.suffix + suffix) if path.is_file() else path.with_suffix("")
                if path.is_dir():
                    default_out = path.with_name(f"{path.name}.zil")
                self.output_edit.setPlaceholderText(str(default_out))
            else:
                default_out = path.with_suffix("")
                self.output_edit.setPlaceholderText(f"{default_out}.out")

        def _open_output_folder(self) -> None:
            if not self._output_path:
                return
            QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(self._output_path.parent)))

        def _set_status(self, message: str) -> None:
            self.status_label.setText(message)

        def _set_busy(self, busy: bool) -> None:
            for widget in [
                self.input_edit,
                self.output_edit,
                self.password_edit,
                self.decoy_password_edit,
                self.decoy_input_edit,
                self.action_button,
                self.file_radio,
                self.dir_radio,
                self.encrypt_radio,
                self.decrypt_radio,
                self.mode_password_radio,
                self.mode_pq_radio,
                self.overwrite_checkbox,
                self.decoy_group,
                self.advanced_group,
            ]:
                widget.setEnabled(not busy)
            QtWidgets.QApplication.setOverrideCursor(
                QtCore.Qt.CursorShape.BusyCursor if busy else QtCore.Qt.CursorShape.ArrowCursor
            )

        def _active_mode(self) -> str:
            return "encrypt" if self.encrypt_radio.isChecked() else "decrypt"

        def _selected_security_mode(self) -> str | None:
            if self.mode_pq_radio.isChecked():
                return normalize_mode("pq-hybrid")
            if self.mode_password_radio.isChecked():
                return normalize_mode("password")
            return None

        def _selected_volume(self) -> str | None:
            if not self.advanced_group.isChecked():
                return None
            if self.main_only_radio.isChecked():
                return "main"
            if self.decoy_only_radio.isChecked():
                return "decoy"
            return None

        def _confirm_overwrite(self, path: Path) -> bool:
            if self.overwrite_checkbox.isChecked():
                return True
            dialog = QtWidgets.QMessageBox(self)
            dialog.setIcon(QtWidgets.QMessageBox.Icon.Warning)
            dialog.setWindowTitle("Overwrite?")
            dialog.setText(f"{path} exists. Overwrite?")
            dialog.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No)
            return dialog.exec() == QtWidgets.QMessageBox.StandardButton.Yes

        def _on_action_clicked(self) -> None:
            if self._active_mode() == "encrypt":
                self._handle_encrypt()
            else:
                self._handle_decrypt()

        def _handle_encrypt(self) -> None:
            input_text = self.input_edit.text().strip()
            if not input_text:
                self._show_error("Input path is required")
                return

            input_path = Path(input_text)
            output_path = Path(self.output_edit.text() or self.output_edit.placeholderText())
            password = self.password_edit.text()

            if not input_path.exists():
                self._show_error("Input path does not exist")
                return
            if not password:
                self._show_error("Password cannot be empty")
                return
            if output_path.exists() and not self._confirm_overwrite(output_path):
                self._set_status("Output exists; overwrite declined")
                return

            decoy_enabled = self.decoy_group.isChecked()
            decoy_password = self.decoy_password_edit.text()
            decoy_input_text = self.decoy_input_edit.text().strip()
            decoy_input_path = Path(decoy_input_text) if decoy_input_text else None

            security_mode = self._selected_security_mode()

            self._set_busy(True)
            self._set_status(_Status.ENCRYPTING)
            self.open_output_button.setEnabled(False)
            try:
                if decoy_enabled:
                    if not decoy_password:
                        self._show_error("Decoy password is required when decoy volume is enabled")
                        return
                    encrypt_with_decoy(
                        input_path,
                        decoy_input_path,
                        output_path,
                        main_password=password,
                        decoy_password=decoy_password,
                        mode=security_mode,
                        overwrite=self.overwrite_checkbox.isChecked(),
                    )
                else:
                    encrypt_file(
                        input_path,
                        output_path,
                        password=password,
                        mode=security_mode,
                        overwrite=self.overwrite_checkbox.isChecked(),
                    )
            except (InvalidPassword, ContainerFormatError, IntegrityError, UnsupportedFeatureError, PqSupportError) as exc:
                self._show_error(f"Encryption failed: {exc}")
            except Exception:
                self._show_error("Unexpected error, see console")
                raise
            else:
                self._output_path = output_path
                self._set_status(f"Encrypted to {output_path}")
                self._show_info("Success", f"Encrypted to {output_path}")
                self.open_output_button.setEnabled(True)
            finally:
                self.password_edit.clear()
                self.decoy_password_edit.clear()
                self._set_busy(False)

        def _handle_decrypt(self) -> None:
            input_text = self.input_edit.text().strip()
            if not input_text:
                self._show_error("Container path is required")
                return

            input_path = Path(input_text)
            output_path = Path(self.output_edit.text() or self.output_edit.placeholderText())
            password = self.password_edit.text()

            if not input_path.exists():
                self._show_error("Container path does not exist")
                return
            if not password:
                self._show_error("Password cannot be empty")
                return
            if output_path.exists() and not self._confirm_overwrite(output_path):
                self._set_status("Output exists; overwrite declined")
                return

            mode = None
            if self.assume_pq_checkbox.isChecked():
                mode = normalize_mode("pq-hybrid")

            volume_choice = self._selected_volume()

            self._set_busy(True)
            self._set_status(_Status.DECRYPTING)
            self.open_output_button.setEnabled(False)
            try:
                if volume_choice is None:
                    _, volume_label = decrypt_auto_volume(
                        input_path,
                        output_path,
                        password=password,
                        mode=mode,
                    )
                    status_msg = f"Decrypted {volume_label} to {output_path}"
                else:
                    decrypt_file(
                        input_path,
                        output_path,
                        password=password,
                        volume_selector=volume_choice,
                        mode=mode,
                        overwrite=self.overwrite_checkbox.isChecked(),
                    )
                    status_msg = f"Decrypted {volume_choice} volume to {output_path}"
            except InvalidPassword:
                self._show_error("Invalid password or no matching volume found")
            except (ContainerFormatError, IntegrityError, UnsupportedFeatureError, PqSupportError) as exc:
                self._show_error(f"Decryption failed: {exc}")
            except Exception:
                self._show_error("Unexpected error, see console")
                raise
            else:
                self._output_path = output_path
                self._set_status(status_msg)
                self._show_info("Success", status_msg)
                self.open_output_button.setEnabled(True)
            finally:
                self.password_edit.clear()
                self._set_busy(False)

        def _show_error(self, message: str) -> None:
            self._set_status(f"Error: {message}")
            QtWidgets.QMessageBox.critical(self, "Error", message)

        def _show_info(self, title: str, message: str) -> None:
            QtWidgets.QMessageBox.information(self, title, message)


    def create_app() -> QtWidgets.QApplication:
        app = QtWidgets.QApplication(sys.argv)
        window = ZilantWindow()
        window.show()
        return app


else:

    def create_app():  # type: ignore[missing-type-doc]
        raise ImportError("PySide6 is required for the GUI. Install with 'pip install ""zilant-encrypt[gui]""'.")



def main() -> None:
    if not QT_AVAILABLE:
        print("PySide6 is not installed. Install with 'pip install \"zilant-encrypt[gui]\"' to use the desktop app.")
        sys.exit(1)

    app = create_app()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
