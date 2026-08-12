from pathlib import Path
import tempfile
import unittest

from desktop.controller import LsmfDesktopController
from lsmf.configuration import parse_config


class DesktopControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "config" / "profiles").mkdir(parents=True)
        (self.root / "src" / "modules").mkdir(parents=True)
        (self.root / "config" / "lsmf.conf").write_text(
            'DISABLE_IPV6="false"\nBACKUP_RETENTION_DAYS="30"\n'
            'MODULE_SSH_ENABLED="true"\nFUTURE_SETTING="preserved"\n',
            encoding="utf-8",
        )
        (self.root / "config" / "profiles" / "server.conf").write_text(
            'PROFILE_NAME="Server"\nPROFILE_DESCRIPTION="Server preview"\n'
            'DISABLE_IPV6="true"\nFUTURE_PROFILE_SETTING="value"\n',
            encoding="utf-8",
        )
        self.controller = LsmfDesktopController(self.root)

    def test_state_exposes_only_predefined_typed_fields(self) -> None:
        state = self.controller.configuration_editor_state()

        self.assertTrue(state.writable)
        self.assertEqual(
            {"BACKUP_RETENTION_DAYS", "DISABLE_IPV6", "MODULE_SSH_ENABLED"},
            {field.key for field in state.fields},
        )
        self.assertNotIn("FUTURE_SETTING", state.values)

    def test_save_updates_allowed_fields_and_preserves_unknown_values(self) -> None:
        state = self.controller.configuration_editor_state()
        result = self.controller.save_configuration(
            changes={"DISABLE_IPV6": True, "BACKUP_RETENTION_DAYS": 45},
            expected_revision=state.revision,
        )

        self.assertEqual("saved", result.status)
        values = parse_config(self.root / "config" / "lsmf.conf")
        self.assertEqual("true", values["DISABLE_IPV6"])
        self.assertEqual("45", values["BACKUP_RETENTION_DAYS"])
        self.assertEqual("preserved", values["FUTURE_SETTING"])

    def test_rejects_unexposed_setting_and_revision_conflict(self) -> None:
        state = self.controller.configuration_editor_state()
        rejected = self.controller.save_configuration(
            changes={"FUTURE_SETTING": "changed"}, expected_revision=state.revision
        )
        self.assertEqual("error", rejected.status)

        conflict = self.controller.save_configuration(
            changes={"DISABLE_IPV6": True}, expected_revision="stale"
        )
        self.assertEqual("conflict", conflict.status)

    def test_failed_batch_does_not_leak_partial_changes(self) -> None:
        state = self.controller.configuration_editor_state()
        result = self.controller.save_configuration(
            changes={"DISABLE_IPV6": True, "FUTURE_SETTING": "changed"},
            expected_revision=state.revision,
        )

        self.assertEqual("error", result.status)
        values = parse_config(self.root / "config" / "lsmf.conf")
        self.assertEqual("false", values["DISABLE_IPV6"])
        self.assertEqual("preserved", values["FUTURE_SETTING"])

    def test_profile_is_preview_only_and_reports_unknown_keys(self) -> None:
        choices = self.controller.profiles()
        preview = self.controller.profile_preview("server")

        self.assertEqual(["server"], [choice.identifier for choice in choices])
        self.assertTrue(any("Unknown settings" in warning for warning in preview.warnings))
        self.assertEqual("false", parse_config(self.root / "config" / "lsmf.conf")["DISABLE_IPV6"])


if __name__ == "__main__":
    unittest.main()
