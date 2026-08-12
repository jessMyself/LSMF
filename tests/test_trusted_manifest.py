import json
import os
from pathlib import Path
import tempfile
import unittest

from lsmf.privileged_protocol import Action, PrivilegedRequest
from lsmf.trusted_manifest import ManifestError, TrustedManifestPolicy, load_trusted_manifest


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"


class TrustedManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "manifest.json"
        self.value = {
            "version": 1,
            "modules": {
                "synthetic_toggle": {
                    "relative_target": "targets/toggle.conf",
                    "desired_content": "enabled=true\n",
                    "capabilities": ["verify", "apply"],
                },
                "verify_only": {
                    "relative_target": "targets/status.txt",
                    "desired_content": "ready\n",
                    "capabilities": ["verify"],
                },
            },
        }
        self.write(self.value)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, value: object) -> None:
        self.path.write_text(json.dumps(value), encoding="utf-8")
        self.path.chmod(0o600)

    def load(self):
        return load_trusted_manifest(self.path, expected_uid=os.getuid())

    def request(self, action: Action, modules=(), backup_id=None):
        return PrivilegedRequest(1, REQUEST_ID, action, tuple(modules), backup_id)

    def test_exact_manifest_loads_and_policy_checks_capabilities(self) -> None:
        policy = TrustedManifestPolicy(self.load())
        self.assertTrue(policy.validate(self.request(Action.AUDIT)))
        self.assertTrue(policy.validate(self.request(Action.VERIFY_MODULE, ["verify_only"])))
        self.assertTrue(policy.validate(self.request(Action.APPLY_MODULE, ["synthetic_toggle"])))
        self.assertFalse(policy.validate(self.request(Action.APPLY_MODULE, ["verify_only"])))
        self.assertFalse(policy.validate(self.request(Action.VERIFY_MODULE, ["unknown"])))
        self.assertFalse(policy.validate(self.request(Action.ROLLBACK_BACKUP, backup_id="backup-1")))

    def test_rollback_requires_exact_fail_closed_lookup(self) -> None:
        policy = TrustedManifestPolicy(self.load(), backup_eligible=lambda value: value == "backup-1")
        self.assertTrue(policy.validate(self.request(Action.ROLLBACK_BACKUP, backup_id="backup-1")))
        self.assertFalse(policy.validate(self.request(Action.ROLLBACK_BACKUP, backup_id="backup-2")))

    def test_rejects_writable_symlink_traversal_and_unknown_fields(self) -> None:
        self.path.chmod(0o622)
        with self.assertRaises(ManifestError):
            self.load()

        self.write(self.value)
        link = self.root / "link.json"
        link.symlink_to(self.path)
        with self.assertRaises(ManifestError):
            load_trusted_manifest(link, expected_uid=os.getuid())

        bad = json.loads(json.dumps(self.value))
        bad["modules"]["synthetic_toggle"]["relative_target"] = "../host-file"
        self.write(bad)
        with self.assertRaises(ManifestError):
            self.load()

        bad = json.loads(json.dumps(self.value))
        bad["extra"] = True
        self.write(bad)
        with self.assertRaises(ManifestError):
            self.load()

    def test_rejects_duplicate_json_fields(self) -> None:
        self.path.write_text('{"version":1,"version":1,"modules":{}}', encoding="utf-8")
        self.path.chmod(0o600)
        with self.assertRaises(ManifestError):
            self.load()


if __name__ == "__main__":
    unittest.main()
