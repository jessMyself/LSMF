#!/usr/bin/env python3
"""LSMF unprivileged Qt Widgets desktop application."""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QFont
    from PySide6.QtWidgets import (
        QApplication,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QHeaderView,
        QCheckBox,
        QComboBox,
        QFormLayout,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPlainTextEdit,
        QPushButton,
        QSpinBox,
        QStatusBar,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # pragma: no cover - exercised without GUI dependencies
    raise SystemExit(
        "PySide6 is required. Run ./scripts/install_desktop_deps.sh first."
    ) from exc

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from desktop.controller import LsmfDesktopController
from desktop.helper_actions import QtReadOnlyActionClient


class SummaryCard(QFrame):
    def __init__(self, title: str, value: str = "—") -> None:
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(self)
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #667085;")
        self.value_label = QLabel(value)
        font = QFont()
        font.setPointSize(18)
        font.setBold(True)
        self.value_label.setFont(font)
        layout.addWidget(title_label)
        layout.addWidget(self.value_label)

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)


class LsmfMainWindow(QMainWindow):
    def __init__(
        self, service: object | None = None, action_client: object | None = None
    ) -> None:
        super().__init__()
        self.service = service or LsmfDesktopController()
        self.action_client = action_client
        if self.action_client is None:
            if callable(getattr(self.service, "begin_read_only_action", None)):
                self.action_client = self.service
            elif service is None:
                self.action_client = QtReadOnlyActionClient()
        self._editor_revision: str | None = None
        self._editor_controls: dict[str, QWidget] = {}
        self._editor_initial_values: dict[str, object] = {}
        self._editor_loading = False
        self._action_handle: object | None = None
        self._action_cancellable = False
        self.setWindowTitle("LSMF Desktop — Unprivileged")
        self.resize(1080, 720)

        root = QWidget()
        root_layout = QVBoxLayout(root)
        header = QHBoxLayout()
        title = QLabel("Linux Security Management Framework")
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        title.setFont(title_font)
        header.addWidget(title)
        header.addStretch()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        header.addWidget(refresh)
        root_layout.addLayout(header)

        notice = QLabel(
            "This desktop remains unprivileged. Configuration edits are limited "
            "to validated project files. Every audit, verification, apply, and "
            "rollback request is typed and separately authorized by the helper."
        )
        notice.setWordWrap(True)
        notice.setStyleSheet(
            "background: #fff4ce; color: #5c4300; padding: 10px; border-radius: 4px;"
        )
        root_layout.addWidget(notice)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_overview_tab(), "Overview")
        self.tabs.addTab(self._build_modules_tab(), "Modules")
        self.tabs.addTab(self._build_actions_tab(), "Audit & Verification")
        self.tabs.addTab(self._build_config_tab(), "Configuration")
        self.tabs.addTab(self._build_files_tab(), "Reports & Backups")
        self.tabs.addTab(self._build_logs_tab(), "Logs")
        root_layout.addWidget(self.tabs)
        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar())
        self.refresh()

    def _build_overview_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        cards = QGridLayout()
        self.host_card = SummaryCard("Host")
        self.platform_card = SummaryCard("Platform")
        self.user_card = SummaryCard("Current user")
        self.architecture_card = SummaryCard("Architecture")
        self.module_card = SummaryCard("Implemented modules")
        self.backup_card = SummaryCard("Backups found")
        self.last_run_card = SummaryCard("Last-run evidence")
        self.mode_card = SummaryCard("Privilege mode")
        cards.addWidget(self.host_card, 0, 0)
        cards.addWidget(self.platform_card, 0, 1)
        cards.addWidget(self.user_card, 1, 0)
        cards.addWidget(self.architecture_card, 1, 1)
        cards.addWidget(self.module_card, 2, 0)
        cards.addWidget(self.backup_card, 2, 1)
        cards.addWidget(self.last_run_card, 3, 0)
        cards.addWidget(self.mode_card, 3, 1)
        layout.addLayout(cards)
        layout.addWidget(QLabel("Readiness findings"))
        self.findings_table = self._table(["Severity", "Finding", "Detail"])
        layout.addWidget(self.findings_table)
        return page

    def _build_modules_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("Modules discovered from src/modules (not documentation claims)"))
        self.modules_table = self._table(
            [
                "Module",
                "Description",
                "Version",
                "Enabled state",
                "Configuration key",
                "Capabilities",
                "Script",
            ]
        )
        layout.addWidget(self.modules_table)
        return page

    def _build_config_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.config_status = QLabel("Configuration status: not checked")
        self.config_status.setWordWrap(True)
        layout.addWidget(self.config_status)
        self.config_error = QLabel()
        self.config_error.setWordWrap(True)
        self.config_error.setVisible(False)
        layout.addWidget(self.config_error)
        layout.addWidget(QLabel("Configuration values (read-only, never sourced)"))
        self.config_table = self._table(["Setting", "Value"])
        layout.addWidget(self.config_table)

        layout.addWidget(QLabel("Validated configuration editor"))
        self.editor_status = QLabel("Editor status: unavailable")
        self.editor_status.setWordWrap(True)
        layout.addWidget(self.editor_status)
        self.editor_form = QFormLayout()
        layout.addLayout(self.editor_form)

        editor_actions = QHBoxLayout()
        self.editor_dirty = QLabel("No unsaved changes")
        editor_actions.addWidget(self.editor_dirty)
        editor_actions.addStretch()
        self.editor_reload = QPushButton("Reload")
        self.editor_reload.clicked.connect(self._reload_editor)
        self.editor_save = QPushButton("Save configuration")
        self.editor_save.clicked.connect(self._confirm_and_save_editor)
        editor_actions.addWidget(self.editor_reload)
        editor_actions.addWidget(self.editor_save)
        layout.addLayout(editor_actions)

        layout.addWidget(QLabel("Profile preview"))
        profile_row = QHBoxLayout()
        self.profile_selector = QComboBox()
        self.profile_selector.currentIndexChanged.connect(self._preview_profile)
        profile_row.addWidget(self.profile_selector)
        layout.addLayout(profile_row)
        self.profile_preview = QPlainTextEdit()
        self.profile_preview.setReadOnly(True)
        self.profile_preview.setPlaceholderText("Select a validated profile to preview changes.")
        layout.addWidget(self.profile_preview)
        return page

    def _build_actions_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        explanation = QLabel(
            "Section 3 retains read-only audit and kernel verification, and adds "
            "only the fixed kernel apply, ordered kernel+network apply, and exact "
            "eligible-backup rollback. Every request requires fresh confirmation "
            "and helper authorization. Mutation cancellation remains disabled."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        actions = QHBoxLayout()
        self.audit_button = QPushButton("Run read-only audit")
        self.audit_button.clicked.connect(self._confirm_audit)
        self.verify_button = QPushButton("Verify kernel_hardening")
        self.verify_button.clicked.connect(self._confirm_kernel_verification)
        self.cancel_action_button = QPushButton("Cancel")
        self.cancel_action_button.clicked.connect(self._cancel_read_only_action)
        self.cancel_action_button.setEnabled(False)
        actions.addWidget(self.audit_button)
        actions.addWidget(self.verify_button)
        actions.addStretch()
        actions.addWidget(self.cancel_action_button)
        layout.addLayout(actions)

        mutation_actions = QHBoxLayout()
        self.apply_kernel_button = QPushButton("Apply kernel_hardening")
        self.apply_kernel_button.clicked.connect(self._confirm_kernel_apply)
        self.apply_modules_button = QPushButton("Apply kernel + network")
        self.apply_modules_button.clicked.connect(self._confirm_ordered_apply)
        self.rollback_id = QLineEdit()
        self.rollback_id.setPlaceholderText("Exact eligible backup ID")
        self.rollback_button = QPushButton("Rollback exact backup")
        self.rollback_button.clicked.connect(self._confirm_exact_rollback)
        mutation_actions.addWidget(self.apply_kernel_button)
        mutation_actions.addWidget(self.apply_modules_button)
        mutation_actions.addWidget(self.rollback_id)
        mutation_actions.addWidget(self.rollback_button)
        layout.addLayout(mutation_actions)

        self.action_status = QLabel("Action status: helper unavailable")
        self.action_status.setWordWrap(True)
        layout.addWidget(self.action_status)
        self.action_output = QPlainTextEdit()
        self.action_output.setReadOnly(True)
        self.action_output.setPlaceholderText("Bounded terminal output will appear here.")
        layout.addWidget(self.action_output)
        return page

    def _build_files_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("Recent report and backup files"))
        self.files_table = self._table(["Type", "Name", "Modified", "Bytes", "Path"])
        layout.addWidget(self.files_table)
        return page

    def _build_logs_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.log_status = QLabel("Log status: not checked")
        self.log_status.setWordWrap(True)
        layout.addWidget(self.log_status)
        self.log_source = QLabel("Source: unavailable")
        self.log_source.setWordWrap(True)
        self.log_source.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.log_source)
        self.log_viewer = QPlainTextEdit()
        self.log_viewer.setReadOnly(True)
        self.log_viewer.setPlaceholderText("No log content is available.")
        layout.addWidget(self.log_viewer)
        return page

    @staticmethod
    def _table(headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def refresh(self) -> None:
        try:
            system = self.service.system_summary()
            modules = self.service.modules()
            findings = self.service.readiness_findings()
            config_error: Exception | None = None
            try:
                config = self.service.config_values()
            except Exception as exc:
                # Configuration errors belong on the Configuration tab and must
                # not make unrelated read-only dashboard data unavailable.
                config = {}
                config_error = exc
            reports = self.service.recent_reports()
            backups = self.service.recent_backups()
            backup_summary = self.service.backup_summary()
            last_run_summary = self.service.last_run_summary()
            log_result = self._read_log_result()

            self.host_card.set_value(system.hostname)
            self.platform_card.set_value(f"{system.operating_system} {system.release}")
            self.user_card.set_value(getattr(system, "user", "Unavailable"))
            self.architecture_card.set_value(
                getattr(system, "architecture", "Unavailable")
            )
            self.module_card.set_value(str(len(modules)))
            self.backup_card.set_value(self._backup_evidence(backup_summary))
            self.last_run_card.set_value(self._last_run_evidence(last_run_summary))
            self.mode_card.set_value("Root" if system.is_root else "Unprivileged")

            self._fill(
                self.findings_table,
                [(finding.severity, finding.title, finding.detail) for finding in findings],
            )
            for row, finding in enumerate(findings):
                color = {
                    "Error": QColor("#fecdca"),
                    "Warning": QColor("#fef0c7"),
                    "Ready": QColor("#d1fadf"),
                }.get(finding.severity)
                if color:
                    self.findings_table.item(row, 0).setBackground(color)

            self._fill(
                self.modules_table,
                [
                    (
                        module.name,
                        getattr(module, "description", None) or "Unavailable",
                        module.version,
                        self._module_enabled_state(module),
                        getattr(module, "config_key", None) or "Unavailable",
                        self._module_capabilities(module),
                        module.script,
                    )
                    for module in modules
                ],
            )
            self._fill(self.config_table, sorted(config.items()))
            self._show_config_status(config, config_error)
            self._refresh_editor()
            file_rows = [
                (kind, item.name, item.modified, str(item.size_bytes), item.path)
                for kind, items in (("Report", reports), ("Backup", backups))
                for item in items
            ]
            self._fill(self.files_table, file_rows)
            self._show_log_result(log_result)
            self._refresh_action_availability()
            self.statusBar().showMessage("Read-only data refreshed", 4000)
        except Exception as exc:  # keep the desktop shell usable when a data source fails
            QMessageBox.critical(self, "Refresh failed", str(exc))
            self.statusBar().showMessage("Refresh failed")

    def _refresh_editor(self) -> None:
        """Load editor data through the optional desktop controller contract."""
        loader = getattr(self.service, "configuration_editor_state", None)
        if not callable(loader):
            self._set_editor_unavailable("Configuration editing is not connected.")
            return
        try:
            state = loader()
            self._editor_loading = True
            self._clear_editor_form()
            self._editor_revision = str(getattr(state, "revision", ""))
            values = dict(getattr(state, "values", {}))
            self._editor_initial_values = values
            for field in getattr(state, "fields", ()):
                control = self._make_editor_control(field, values.get(field.key))
                self._editor_controls[field.key] = control
                self.editor_form.addRow(str(field.label), control)
            writable = bool(getattr(state, "writable", False))
            path = str(getattr(state, "path", "unavailable"))
            error = getattr(state, "error", None)
            self.editor_status.setText(
                f"Editor status: {'Ready' if writable else 'Read-only'} — {path}"
                + (f" — {error}" if error else "")
            )
            self.editor_save.setEnabled(writable and bool(self._editor_controls))
            self.editor_reload.setEnabled(True)
            self._editor_loading = False
            self._update_editor_dirty()
            self._load_profiles()
        except Exception as exc:
            self._editor_loading = False
            self._set_editor_unavailable(str(exc))

    def _make_editor_control(self, field: object, value: object) -> QWidget:
        kind = str(getattr(field, "kind", "string"))
        if kind == "boolean":
            control = QCheckBox()
            control.setChecked(bool(value))
            control.stateChanged.connect(self._update_editor_dirty)
        elif kind == "integer":
            control = QSpinBox()
            control.setRange(int(getattr(field, "minimum", 0)), int(getattr(field, "maximum", 999999)))
            control.setValue(int(value or 0))
            control.valueChanged.connect(self._update_editor_dirty)
        elif kind == "choice":
            control = QComboBox()
            control.addItems([str(choice) for choice in getattr(field, "choices", ())])
            index = control.findText(str(value))
            control.setCurrentIndex(max(0, index))
            control.currentIndexChanged.connect(self._update_editor_dirty)
        else:
            control = QLineEdit(str(value or ""))
            control.textChanged.connect(self._update_editor_dirty)
        description = getattr(field, "description", None)
        if description:
            control.setToolTip(str(description))
        return control

    def _editor_values(self) -> dict[str, object]:
        values: dict[str, object] = {}
        for key, control in self._editor_controls.items():
            if isinstance(control, QCheckBox):
                values[key] = control.isChecked()
            elif isinstance(control, QSpinBox):
                values[key] = control.value()
            elif isinstance(control, QComboBox):
                values[key] = control.currentText()
            elif isinstance(control, QLineEdit):
                values[key] = control.text()
        return values

    def _update_editor_dirty(self, *_args: object) -> None:
        if self._editor_loading:
            return
        dirty = self._editor_values() != self._editor_initial_values
        self.editor_dirty.setText("Unsaved changes" if dirty else "No unsaved changes")
        self.editor_dirty.setStyleSheet("color: #b54708;" if dirty else "")

    def _confirm_and_save_editor(self) -> None:
        changes = {
            key: value
            for key, value in self._editor_values().items()
            if self._editor_initial_values.get(key) != value
        }
        if not changes:
            self.statusBar().showMessage("No configuration changes to save", 4000)
            return
        answer = QMessageBox.question(
            self,
            "Save configuration",
            f"Save {len(changes)} validated configuration change(s)?",
            QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Save:
            return
        try:
            result = self.service.save_configuration(
                changes=changes, expected_revision=self._editor_revision
            )
            status = str(getattr(result, "status", "error"))
            message = str(getattr(result, "message", status))
            if status == "saved":
                self.statusBar().showMessage(message, 6000)
                self._refresh_editor()
            elif status == "conflict":
                self.editor_status.setText(f"Editor status: Stale-file conflict — {message}")
                QMessageBox.warning(self, "Configuration changed on disk", message)
            else:
                self.editor_status.setText(f"Editor status: Save failed — {message}")
                QMessageBox.critical(self, "Save failed", message)
        except Exception as exc:
            self.editor_status.setText(f"Editor status: Save failed — {exc}")
            QMessageBox.critical(self, "Save failed", str(exc))

    def _reload_editor(self) -> None:
        if self._editor_values() != self._editor_initial_values:
            answer = QMessageBox.question(
                self,
                "Discard unsaved changes",
                "Reload configuration and discard unsaved changes?",
                QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Discard:
                return
        self._refresh_editor()

    def _load_profiles(self) -> None:
        self.profile_selector.blockSignals(True)
        self.profile_selector.clear()
        self.profile_selector.addItem("Select a profile…", None)
        loader = getattr(self.service, "profiles", None)
        if callable(loader):
            for profile in loader():
                self.profile_selector.addItem(str(profile.name), profile.identifier)
        self.profile_selector.blockSignals(False)
        self.profile_preview.clear()

    def _preview_profile(self, index: int) -> None:
        identifier = self.profile_selector.itemData(index)
        if identifier is None:
            self.profile_preview.clear()
            return
        try:
            preview = self.service.profile_preview(identifier)
            lines = [str(getattr(preview, "summary", "Profile preview"))]
            for change in getattr(preview, "changes", ()):
                lines.append(f"{change.key}: {change.current} → {change.proposed}")
            for warning in getattr(preview, "warnings", ()):
                lines.append(f"Warning: {warning}")
            self.profile_preview.setPlainText("\n".join(lines))
        except Exception as exc:
            self.profile_preview.setPlainText(f"Profile preview unavailable: {exc}")

    def _clear_editor_form(self) -> None:
        while self.editor_form.rowCount():
            self.editor_form.removeRow(0)
        self._editor_controls.clear()

    def _set_editor_unavailable(self, detail: str) -> None:
        self._clear_editor_form()
        self.editor_status.setText(f"Editor status: Unavailable — {detail}")
        self.editor_save.setEnabled(False)
        self.editor_reload.setEnabled(False)
        self.editor_dirty.setText("No unsaved changes")
        self.profile_selector.clear()
        self.profile_preview.clear()

    def _show_config_status(
        self, config: dict[str, str], error: Exception | None
    ) -> None:
        if error is not None:
            self.config_status.setText("Configuration status: Invalid")
            self.config_status.setStyleSheet(
                "background: #fecdca; color: #7a271a; padding: 8px; border-radius: 4px;"
            )
            self.config_error.setText(f"Validation error: {error}")
            self.config_error.setStyleSheet("color: #b42318; padding: 4px;")
            self.config_error.setVisible(True)
            return

        self.config_error.clear()
        self.config_error.setVisible(False)
        if config:
            self.config_status.setText(
                f"Configuration status: Valid canonical configuration ({len(config)} settings)"
            )
            self.config_status.setStyleSheet(
                "background: #d1fadf; color: #05603a; padding: 8px; border-radius: 4px;"
            )
        else:
            self.config_status.setText("Configuration status: Unavailable or empty")
            self.config_status.setStyleSheet(
                "background: #fef0c7; color: #7a2e0e; padding: 8px; border-radius: 4px;"
            )

    def _read_log_result(self) -> object | None:
        """Use the bounded log service when present; never read files in the UI."""
        return self.service.log_view(max_lines=100, max_bytes=131072)

    def _show_log_result(self, result: object | None) -> None:
        if result is None:
            self.log_status.setText("Log status: Unavailable")
            self.log_source.setText("Source: unavailable")
            self.log_viewer.clear()
            return

        source = getattr(result, "source", None)
        error = getattr(result, "error", None)
        content = getattr(result, "content", "")
        status = getattr(result, "status", "unavailable")
        self.log_source.setText(f"Source: {source or 'unavailable'}")
        self.log_viewer.setPlainText(str(content or ""))
        if status == "error" or error:
            self.log_status.setText(f"Log status: Read error — {error}")
        elif status == "available":
            lines = getattr(result, "line_count", 0)
            suffix = ", truncated" if getattr(result, "truncated", False) else ""
            self.log_status.setText(
                f"Log status: Available (bounded read, {lines} lines{suffix})"
            )
        else:
            detail = f" — {error}" if error else ""
            self.log_status.setText(f"Log status: Unavailable{detail}")

    def _refresh_action_availability(self) -> None:
        available = callable(getattr(self.action_client, "begin_read_only_action", None))
        mutation_available = callable(getattr(self.action_client, "begin_mutation_action", None))
        running = self._action_handle is not None
        self.audit_button.setEnabled(available and not running)
        self.verify_button.setEnabled(available and not running)
        self.apply_kernel_button.setEnabled(mutation_available and not running)
        self.apply_modules_button.setEnabled(mutation_available and not running)
        self.rollback_id.setEnabled(mutation_available and not running)
        self.rollback_button.setEnabled(mutation_available and not running)
        self.cancel_action_button.setEnabled(running and self._action_cancellable)
        if not available and not running:
            self.action_status.setText("Action status: helper unavailable")

    def _confirm_audit(self) -> None:
        self._confirm_read_only_action(
            "audit",
            None,
            "Run read-only audit",
            "Authorize one read-only system audit? No hardening will be applied.",
        )

    def _confirm_kernel_verification(self) -> None:
        self._confirm_read_only_action(
            "verify_module",
            "kernel_hardening",
            "Verify kernel_hardening",
            "Authorize verification of exactly kernel_hardening? No settings will be changed.",
        )

    def _confirm_read_only_action(
        self, action: str, module_id: str | None, title: str, prompt: str
    ) -> None:
        if self._action_handle is not None:
            return
        starter = getattr(self.action_client, "begin_read_only_action", None)
        if not callable(starter):
            self.action_status.setText("Action status: helper unavailable")
            return
        answer = QMessageBox.question(
            self,
            title,
            prompt,
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Ok:
            return
        self.action_output.clear()
        self.action_status.setText(f"Action status: running — {action}")
        self.audit_button.setEnabled(False)
        self.verify_button.setEnabled(False)
        self.cancel_action_button.setEnabled(True)
        self._action_cancellable = True
        try:
            handle = starter(action, module_id, self._finish_read_only_action)
            if handle is None:
                raise RuntimeError("helper client returned no cancellable action handle")
            self._action_handle = handle
        except Exception as exc:
            self._action_handle = None
            self._action_cancellable = False
            self.action_status.setText(f"Action status: start failed — {exc}")
            self._refresh_action_availability()

    def _cancel_read_only_action(self) -> None:
        handle = self._action_handle
        if handle is None:
            return
        cancel = getattr(handle, "cancel", None)
        if not callable(cancel):
            self.action_status.setText("Action status: cancellation unavailable")
            return
        self.action_status.setText("Action status: cancellation requested")
        self.cancel_action_button.setEnabled(False)
        try:
            cancel()
        except Exception as exc:
            self.action_status.setText(f"Action status: cancellation failed — {exc}")

    def _confirm_kernel_apply(self) -> None:
        self._confirm_mutation_action(
            "apply_module",
            "kernel_hardening",
            "Apply exactly kernel_hardening",
            "Authorize backup-first apply of exactly kernel_hardening? This will "
            "write /etc/sysctl.d/99-lsmf-kernel.conf and 19 fixed runtime sysctls.",
        )

    def _confirm_ordered_apply(self) -> None:
        self._confirm_mutation_action(
            "apply_modules",
            ("kernel_hardening", "network_hardening"),
            "Apply exactly kernel_hardening then network_hardening",
            "Authorize backup-first apply in this exact order: kernel_hardening, "
            "then network_hardening? This writes two fixed drop-ins and 48 runtime sysctls.",
        )

    def _confirm_exact_rollback(self) -> None:
        backup_id = self.rollback_id.text().strip()
        if not backup_id:
            self.action_status.setText("Action status: exact backup ID is required")
            return
        self._confirm_mutation_action(
            "rollback_backup",
            backup_id,
            f"Rollback exactly {backup_id}",
            f"Authorize rollback of exactly eligible backup {backup_id}? No other "
            "backup can satisfy this request.",
        )

    def _confirm_mutation_action(
        self, action: str, parameter: object, title: str, prompt: str
    ) -> None:
        if self._action_handle is not None:
            return
        starter = getattr(self.action_client, "begin_mutation_action", None)
        if not callable(starter):
            self.action_status.setText("Action status: mutation helper unavailable")
            return
        answer = QMessageBox.question(
            self,
            title,
            prompt + " Mutation cancellation is disabled until the live safety gate passes.",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Ok:
            return
        self.action_output.clear()
        self.action_status.setText(f"Action status: running — {action}")
        self._action_cancellable = False
        self._refresh_action_availability()
        try:
            handle = starter(action, parameter, self._finish_read_only_action)
            if handle is None:
                raise RuntimeError("helper client returned no action handle")
            self._action_handle = handle
            self._refresh_action_availability()
        except Exception as exc:
            self._action_handle = None
            self.action_status.setText(f"Action status: start failed — {exc}")
            self._refresh_action_availability()

    def _finish_read_only_action(self, result: object) -> None:
        """Receive one terminal result; clients must invoke this on the Qt thread."""
        self._action_handle = None
        self._action_cancellable = False
        status = str(getattr(result, "status", "error"))
        if status.startswith("ProductionStatus."):
            status = status.rsplit(".", 1)[-1].lower()
        summary = str(getattr(result, "summary", status))
        error = getattr(result, "error", None)
        error_message = getattr(error, "message", None) if error is not None else None
        suffix = f" — {error_message}" if error_message else ""
        self.action_status.setText(f"Action status: {status} — {summary}{suffix}")
        raw_output = str(getattr(result, "output", ""))
        encoded = raw_output.encode("utf-8")
        bounded = encoded[:65536]
        output = bounded.decode("utf-8", errors="replace")
        truncated = bool(getattr(result, "output_truncated", False)) or len(encoded) > len(bounded)
        if truncated:
            output += "\n[output truncated]"
        backup_id = getattr(result, "backup_id", None)
        if backup_id:
            output = f"Backup ID: {backup_id}" + (f"\n{output}" if output else "")
        self.action_output.setPlainText(output)
        self._refresh_action_availability()
        self._refresh_report_rows()

    def _refresh_report_rows(self) -> None:
        try:
            reports = self.service.recent_reports()
            backups = self.service.recent_backups()
            rows = [
                (kind, item.name, item.modified, str(item.size_bytes), item.path)
                for kind, items in (("Report", reports), ("Backup", backups))
                for item in items
            ]
            self._fill(self.files_table, rows)
        except Exception as exc:
            self.statusBar().showMessage(f"Report refresh failed: {exc}", 6000)

    @staticmethod
    def _backup_evidence(summary: object) -> str:
        if getattr(summary, "status", "unavailable") != "available":
            return "Unavailable"
        return str(getattr(summary, "count", 0))

    @staticmethod
    def _last_run_evidence(summary: object) -> str:
        if getattr(summary, "status", "unavailable") != "available":
            return "Unavailable"
        return str(getattr(summary, "modified", None) or "Unavailable")

    @classmethod
    def _module_capabilities(cls, module: object) -> str:
        capabilities = getattr(module, "capabilities", None)
        if capabilities is not None:
            if isinstance(capabilities, str):
                return capabilities
            return ", ".join(str(item) for item in capabilities) or "None"
        supported = [
            label
            for label, attribute in (
                ("Run", "can_run"),
                ("Verify", "can_verify"),
                ("Rollback", "can_rollback"),
            )
            if getattr(module, attribute, False)
        ]
        return ", ".join(supported) or "None"

    @staticmethod
    def _module_enabled_state(module: object) -> str:
        state = getattr(module, "enabled_state", None)
        if state is not None:
            return str(state)
        enabled = getattr(module, "enabled", None)
        if enabled is None:
            return "Unavailable"
        return "Enabled" if enabled else "Disabled"

    @staticmethod
    def _fill(table: QTableWidget, rows: list[tuple[object, ...]]) -> None:
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for column_index, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                table.setItem(row_index, column_index, item)

    @staticmethod
    def _yes_no(value: bool) -> str:
        return "Yes" if value else "No"


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("LSMF Desktop")
    window = LsmfMainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
