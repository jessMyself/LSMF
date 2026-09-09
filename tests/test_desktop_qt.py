#!/usr/bin/env python3

import gc
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QApplication
except ImportError:  # pragma: no cover - dependency availability is environment-specific
    QApplication = None


@unittest.skipIf(QApplication is None, "PySide6 is not installed")
class LsmfMainWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from desktop.main import LsmfMainWindow

        cls.window_type = LsmfMainWindow
        cls.app = QApplication.instance() or QApplication([])

    def tearDown(self) -> None:
        # Closed top-level widgets can retain Python/Qt reference cycles until
        # cyclic GC runs.  Dispose them on the GUI thread between tests so a
        # later helper worker cannot overlap PySide wrapper collection.
        for widget in self.app.topLevelWidgets():
            widget.close()
            widget.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        self.app.processEvents()
        gc.collect()

    def test_valid_configuration_status_and_values_are_visible(self) -> None:
        window = self.window_type(_FakeService({"MODULE_SSH_ENABLED": "true"}))

        self.assertIn("Valid canonical configuration", window.config_status.text())
        self.assertEqual(1, window.config_table.rowCount())
        self.assertTrue(window.config_error.isHidden())
        window.close()

    def test_invalid_configuration_does_not_hide_other_dashboard_data(self) -> None:
        window = self.window_type(_FakeService(ValueError("line 7: invalid assignment")))

        self.assertEqual("Configuration status: Invalid", window.config_status.text())
        self.assertIn("line 7: invalid assignment", window.config_error.text())
        self.assertFalse(window.config_error.isHidden())
        self.assertEqual("test-host", window.host_card.value_label.text())
        self.assertEqual(0, window.config_table.rowCount())
        window.close()

    def test_read_only_evidence_and_bounded_log_are_visible(self) -> None:
        window = self.window_type(_FakeService({}))

        self.assertEqual("test-user", window.user_card.value_label.text())
        self.assertEqual("test-arch", window.architecture_card.value_label.text())
        self.assertEqual("1", window.backup_card.value_label.text())
        self.assertEqual("2026-07-20T12:30:00", window.last_run_card.value_label.text())
        self.assertEqual("Source: /tmp/lsmf.log", window.log_source.text())
        self.assertIn("bounded read", window.log_status.text())
        self.assertEqual("last line\n", window.log_viewer.toPlainText())
        self.assertTrue(window.log_viewer.isReadOnly())
        self.assertEqual((100, 131072), window.service.log_bounds)
        window.close()

    def test_log_read_error_is_explicit_and_does_not_fabricate_content(self) -> None:
        service = _FakeService({})
        service.log_result = SimpleNamespace(
            status="error",
            source="/var/log/lsmf/lsmf.log",
            content="",
            line_count=0,
            truncated=False,
            error="permission denied",
        )
        window = self.window_type(service)

        self.assertIn("permission denied", window.log_status.text())
        self.assertEqual("", window.log_viewer.toPlainText())
        window.close()

    def test_module_details_are_informational_only(self) -> None:
        service = _FakeService({})
        service.module_rows = [
            SimpleNamespace(
                name="SSH",
                description="Secure Shell policy",
                version="1.0",
                enabled=True,
                config_key="MODULE_SSH_ENABLED",
                capabilities=("Run", "Verify"),
                script="src/modules/ssh.sh",
            )
        ]
        window = self.window_type(service)

        self.assertEqual("Secure Shell policy", window.modules_table.item(0, 1).text())
        self.assertEqual("Enabled", window.modules_table.item(0, 3).text())
        self.assertEqual("MODULE_SSH_ENABLED", window.modules_table.item(0, 4).text())
        self.assertEqual("Run, Verify", window.modules_table.item(0, 5).text())
        self.assertEqual(
            window.modules_table.EditTrigger.NoEditTriggers,
            window.modules_table.editTriggers(),
        )
        window.close()

    def test_typed_configuration_controls_show_unsaved_state(self) -> None:
        window = self.window_type(_FakeService({}))

        self.assertEqual("Ready", window.editor_status.text().split()[2])
        self.assertTrue(window._editor_controls["MODULE_SSH_ENABLED"].isChecked())
        self.assertEqual("No unsaved changes", window.editor_dirty.text())
        window._editor_controls["MODULE_SSH_ENABLED"].setChecked(False)
        self.assertEqual("Unsaved changes", window.editor_dirty.text())
        window.close()

    def test_profile_selection_renders_preview_without_applying_it(self) -> None:
        service = _FakeService({})
        window = self.window_type(service)

        window.profile_selector.setCurrentIndex(1)
        self.assertIn("MODULE_SSH_ENABLED: True → False", window.profile_preview.toPlainText())
        self.assertEqual(["workstation"], service.previewed_profiles)
        self.assertEqual([], service.saved_changes)
        window.close()

    def test_save_requires_confirmation_and_passes_revision(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        service = _FakeService({})
        window = self.window_type(service)
        window._editor_controls["RETRY_COUNT"].setValue(4)

        with patch(
            "desktop.main.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Save,
        ):
            window._confirm_and_save_editor()

        self.assertEqual([({"RETRY_COUNT": 4}, "revision-1")], service.saved_changes)
        self.assertEqual("No unsaved changes", window.editor_dirty.text())
        window.close()

    def test_stale_save_conflict_is_presented_and_keeps_changes(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        service = _FakeService({})
        service.save_status = "conflict"
        window = self.window_type(service)
        window._editor_controls["RETRY_COUNT"].setValue(5)

        with patch("desktop.main.QMessageBox.question", return_value=QMessageBox.StandardButton.Save), patch(
            "desktop.main.QMessageBox.warning"
        ) as warning:
            window._confirm_and_save_editor()

        self.assertIn("Stale-file conflict", window.editor_status.text())
        self.assertEqual("Unsaved changes", window.editor_dirty.text())
        warning.assert_called_once()
        window.close()

    def test_exact_confirmation_starts_only_kernel_verification(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        service = _FakeService({})
        window = self.window_type(service)
        with patch(
            "desktop.main.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Ok,
        ) as question:
            window._confirm_kernel_verification()

        self.assertEqual("verify_module", service.started_actions[0][0])
        self.assertEqual("kernel_hardening", service.started_actions[0][1])
        self.assertIn("exactly kernel_hardening", question.call_args.args[2])
        self.assertIn("running", window.action_status.text())
        self.assertFalse(window.audit_button.isEnabled())
        self.assertTrue(window.cancel_action_button.isEnabled())
        window.close()

    def test_cancel_and_terminal_denial_are_truthful_and_refresh_reports(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        service = _FakeService({})
        window = self.window_type(service)
        with patch(
            "desktop.main.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Ok,
        ):
            window._confirm_audit()
        window._cancel_read_only_action()
        self.assertTrue(service.action_handle.cancelled)
        self.assertIn("cancellation requested", window.action_status.text())

        report_reads = service.report_reads
        service.complete_action(SimpleNamespace(
            status="denied",
            summary="Authorization denied",
            output="x" * 70000,
            output_truncated=False,
            error=SimpleNamespace(message="Administrator authorization was denied"),
        ))
        self.assertIn("denied", window.action_status.text())
        self.assertIn("authorization was denied", window.action_status.text())
        self.assertTrue(window.action_output.toPlainText().endswith("[output truncated]"))
        self.assertGreater(service.report_reads, report_reads)
        self.assertTrue(window.audit_button.isEnabled())
        window.close()

    def test_cancelled_confirmation_never_contacts_helper(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        service = _FakeService({})
        window = self.window_type(service)
        with patch(
            "desktop.main.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Cancel,
        ):
            window._confirm_audit()
        self.assertEqual([], service.started_actions)
        window.close()

    def test_exact_kernel_apply_confirmation_and_mutation_cancel_is_enabled(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        service = _FakeService({})
        window = self.window_type(service)
        with patch(
            "desktop.main.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Ok,
        ) as question:
            window._confirm_kernel_apply()

        self.assertEqual(("apply_module", "kernel_hardening"), service.started_actions[0])
        self.assertIn("19 fixed runtime sysctls", question.call_args.args[2])
        self.assertNotIn("cancellation is disabled", question.call_args.args[2].lower())
        self.assertTrue(window.cancel_action_button.isEnabled())
        self.assertFalse(window.apply_modules_button.isEnabled())

        window._cancel_read_only_action()
        self.assertTrue(service.action_handle.cancelled)

        service.complete_action(SimpleNamespace(
            status="succeeded",
            summary="Sysctl apply complete",
            output="",
            output_truncated=False,
            backup_id="backup-123e4567-e89b-42d3-a456-426614174000",
            error=None,
        ))
        self.assertIn("Backup ID: backup-", window.action_output.toPlainText())
        self.assertFalse(window.cancel_action_button.isEnabled())
        self.assertTrue(window.apply_kernel_button.isEnabled())
        window.close()

    def test_exact_rollback_requires_id_and_confirms_displayed_backup(self) -> None:
        from PySide6.QtWidgets import QMessageBox

        service = _FakeService({})
        window = self.window_type(service)
        window._confirm_exact_rollback()
        self.assertIn("backup ID is required", window.action_status.text())
        backup_id = "backup-123e4567-e89b-42d3-a456-426614174000"
        window.rollback_id.setText(backup_id)
        with patch(
            "desktop.main.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Ok,
        ) as question:
            window._confirm_exact_rollback()
        self.assertEqual(("rollback_backup", backup_id), service.started_actions[0])
        self.assertIn(backup_id, question.call_args.args[1])
        window.close()


class _FakeService:
    def __init__(self, config: dict[str, str] | Exception) -> None:
        self.config = config
        self.module_rows = []
        self.log_result = SimpleNamespace(
            status="available",
            source="/tmp/lsmf.log",
            content="last line\n",
            line_count=1,
            truncated=False,
            error=None,
        )
        self.saved_changes = []
        self.previewed_profiles = []
        self.save_status = "saved"
        self.started_actions = []
        self.action_callback = None
        self.action_handle = _FakeActionHandle()
        self.report_reads = 0

    def system_summary(self):
        return SimpleNamespace(
            user="test-user",
            hostname="test-host",
            operating_system="Linux",
            release="test-release",
            architecture="test-arch",
            is_root=False,
        )

    def modules(self):
        return self.module_rows

    def readiness_findings(self):
        return []

    def config_values(self):
        if isinstance(self.config, Exception):
            raise self.config
        return self.config

    def recent_reports(self):
        self.report_reads += 1
        return [
            SimpleNamespace(
                name="last-report.txt",
                modified="2026-07-20T12:30:00",
                size_bytes=10,
                path="/tmp/last-report.txt",
            )
        ]

    def recent_backups(self):
        return [
            SimpleNamespace(
                name="backup.tar",
                modified="2026-07-20T12:00:00",
                size_bytes=20,
                path="/tmp/backup.tar",
            )
        ]

    def backup_summary(self):
        return SimpleNamespace(
            status="available", count=1, sources=("/tmp",), error=None
        )

    def last_run_summary(self):
        return SimpleNamespace(
            status="available",
            source="/tmp/last-report.txt",
            modified="2026-07-20T12:30:00",
            error=None,
        )

    def log_view(self, max_lines=100, max_bytes=131072):
        self.log_bounds = (max_lines, max_bytes)
        return self.log_result

    def configuration_editor_state(self):
        return SimpleNamespace(
            revision="revision-1",
            path="/tmp/project/lsmf.conf",
            writable=True,
            error=None,
            values={"MODULE_SSH_ENABLED": True, "RETRY_COUNT": 3, "MODE": "safe"},
            fields=(
                SimpleNamespace(
                    key="MODULE_SSH_ENABLED", label="SSH module", kind="boolean",
                    description="Enable SSH configuration", choices=(), minimum=0, maximum=1,
                ),
                SimpleNamespace(
                    key="RETRY_COUNT", label="Retry count", kind="integer",
                    description="Retry limit", choices=(), minimum=0, maximum=10,
                ),
                SimpleNamespace(
                    key="MODE", label="Mode", kind="choice", description="Policy mode",
                    choices=("safe", "strict"), minimum=0, maximum=0,
                ),
            ),
        )

    def profiles(self):
        return [SimpleNamespace(identifier="workstation", name="Workstation")]

    def profile_preview(self, identifier):
        self.previewed_profiles.append(identifier)
        return SimpleNamespace(
            summary="Workstation profile",
            changes=(
                SimpleNamespace(
                    key="MODULE_SSH_ENABLED", current=True, proposed=False
                ),
            ),
            warnings=("Preview only; no settings were applied.",),
        )

    def save_configuration(self, *, changes, expected_revision):
        self.saved_changes.append((changes, expected_revision))
        if self.save_status == "saved":
            state = self.configuration_editor_state()
            state.values.update(changes)
            # Make the subsequent reload reflect the accepted values.
            self.configuration_editor_state = lambda: state
        return SimpleNamespace(status=self.save_status, message=self.save_status)

    def begin_read_only_action(self, action, module_id, callback):
        self.started_actions.append((action, module_id))
        self.action_callback = callback
        self.action_handle = _FakeActionHandle()
        return self.action_handle

    def begin_mutation_action(self, action, parameter, callback):
        self.started_actions.append((action, parameter))
        self.action_callback = callback
        self.action_handle = _FakeActionHandle()
        return self.action_handle

    def complete_action(self, result):
        callback = self.action_callback
        self.action_callback = None
        callback(result)


class _FakeActionHandle:
    def __init__(self):
        self.cancelled = False

    def cancel(self):
        self.cancelled = True


if __name__ == "__main__":
    unittest.main()
