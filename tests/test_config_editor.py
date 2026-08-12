import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from lsmf import configuration
from lsmf.config_editor import SafeConfigEditor, StaleConfigError, TargetRejectedError


CANONICAL = 'SSH_HARDENING="true"\nUNKNOWN_FUTURE_KEY="kept"\n'


class SafeConfigEditorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / "lsmf.conf"
        self.target.write_text(CANONICAL, encoding="utf-8")

    def test_allowed_write_and_unknown_key_preservation(self) -> None:
        editor = SafeConfigEditor(self.target, allowed_roots=[self.root])
        editor.set("SSH_HARDENING", False)
        preview = editor.preview()
        self.assertEqual("SSH_HARDENING", preview.changes[0].key)
        editor.save()
        self.assertEqual("false", configuration.parse_config(self.target)["SSH_HARDENING"])
        self.assertEqual("kept", configuration.parse_config(self.target)["UNKNOWN_FUTURE_KEY"])

    def test_rejects_outside_root_and_etc(self) -> None:
        outside = self.root.parent / "outside-lsmf.conf"
        with self.assertRaises(TargetRejectedError):
            SafeConfigEditor(outside, allowed_roots=[self.root])
        with self.assertRaisesRegex(TargetRejectedError, "/etc/lsmf"):
            SafeConfigEditor("/etc/lsmf/lsmf.conf", allowed_roots=[Path("/")])

    def test_rejects_symlink_target_and_parent(self) -> None:
        link = self.root / "link.conf"
        link.symlink_to(self.target)
        with self.assertRaises(TargetRejectedError):
            SafeConfigEditor(link, allowed_roots=[self.root])
        real_dir = self.root / "real"
        real_dir.mkdir()
        directory_link = self.root / "linked-dir"
        directory_link.symlink_to(real_dir, target_is_directory=True)
        with self.assertRaises(TargetRejectedError):
            SafeConfigEditor(directory_link / "new.conf", allowed_roots=[self.root])

    def test_detects_stale_file_and_preserves_external_change(self) -> None:
        editor = SafeConfigEditor(self.target, allowed_roots=[self.root])
        editor.set("SSH_HARDENING", False)
        external = 'SSH_HARDENING="true"\nEXTERNAL="change"\n'
        self.target.write_text(external, encoding="utf-8")
        with self.assertRaises(StaleConfigError):
            editor.save()
        self.assertEqual(external, self.target.read_text(encoding="utf-8"))

    def test_rejects_invalid_value_before_write(self) -> None:
        editor = SafeConfigEditor(self.target, allowed_roots=[self.root])
        with self.assertRaises(configuration.ConfigError):
            editor.set("SSH_HARDENING", "yes")
        self.assertEqual(CANONICAL, self.target.read_text(encoding="utf-8"))

    def test_writer_failure_preserves_original(self) -> None:
        original = self.target.read_bytes()
        writer = mock.Mock(side_effect=OSError("simulated atomic failure"))
        editor = SafeConfigEditor(self.target, allowed_roots=[self.root], writer=writer)
        editor.set("SSH_HARDENING", False)
        with self.assertRaises(OSError):
            editor.save()
        self.assertEqual(original, self.target.read_bytes())

    def test_rejects_unsafe_parent_permissions(self) -> None:
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o777)
        os.chmod(unsafe, 0o777)
        with self.assertRaises(TargetRejectedError):
            SafeConfigEditor(unsafe / "config", allowed_roots=[self.root])

    def test_rejects_root_owned_target(self) -> None:
        original_stat = Path.stat

        def stat_with_root_owner(path: Path, *args: object, **kwargs: object) -> object:
            result = original_stat(path, *args, **kwargs)
            if path == self.target:
                return SimpleNamespace(st_mode=result.st_mode, st_uid=0)
            return result

        with mock.patch.object(Path, "stat", stat_with_root_owner):
            with self.assertRaisesRegex(TargetRejectedError, "Root-owned"):
                SafeConfigEditor(self.target, allowed_roots=[self.root])

    def test_rejects_target_owned_by_another_user(self) -> None:
        if not hasattr(os, "geteuid"):
            self.skipTest("ownership checks require POSIX user IDs")
        original_stat = Path.stat
        other_uid = os.geteuid() + 1

        def stat_with_other_owner(path: Path, *args: object, **kwargs: object) -> object:
            result = original_stat(path, *args, **kwargs)
            if path == self.target:
                return SimpleNamespace(st_mode=result.st_mode, st_uid=other_uid)
            return result

        with mock.patch.object(Path, "stat", stat_with_other_owner):
            with self.assertRaisesRegex(TargetRejectedError, "current user"):
                SafeConfigEditor(self.target, allowed_roots=[self.root])


if __name__ == "__main__":
    unittest.main()
