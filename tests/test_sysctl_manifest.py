from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from lsmf.privileged_protocol import Action
from lsmf.production_protocol import ProductionRequest
from lsmf.sysctl_manifest import (
    SysctlManifestError,
    SysctlManifestPolicy,
    load_sysctl_manifest,
)


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"


class SysctlManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "manifest.json"
        self.value = {
            "version": 2,
            "module_order": ["kernel_hardening", "network_hardening"],
            "single_apply": ["kernel_hardening"],
            "multi_apply": [["kernel_hardening", "network_hardening"]],
            "modules": {
                "kernel_hardening": {
                    "relative_target": "etc/sysctl.d/99-lsmf-kernel.conf",
                    "settings": [{"key": "kernel.kptr_restrict", "value": "2"}],
                },
                "network_hardening": {
                    "relative_target": "etc/sysctl.d/99-lsmf-network.conf",
                    "settings": [{"key": "net.ipv4.ip_forward", "value": "0"}],
                },
            },
        }
        self.write(self.value)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, value: object) -> None:
        self.path.write_text(json.dumps(value), encoding="utf-8")
        self.path.chmod(0o600)

    def load(self):
        return load_sysctl_manifest(self.path, expected_uid=os.getuid())

    def request(self, action: Action, modules=(), backup_id=None):
        return ProductionRequest(1, REQUEST_ID, action, tuple(modules), backup_id)

    def test_exact_policy_allows_only_fixed_single_multi_and_eligible_rollback(self) -> None:
        manifest = self.load()
        policy = SysctlManifestPolicy(manifest, backup_eligible=lambda value: value == "backup-ok")
        self.assertTrue(policy.validate(self.request(Action.APPLY_MODULE, ["kernel_hardening"])))
        self.assertFalse(policy.validate(self.request(Action.APPLY_MODULE, ["network_hardening"])))
        self.assertTrue(policy.validate(self.request(
            Action.APPLY_MODULES, ["kernel_hardening", "network_hardening"]
        )))
        self.assertFalse(policy.validate(self.request(
            Action.APPLY_MODULES, ["network_hardening", "kernel_hardening"]
        )))
        self.assertTrue(policy.validate(self.request(Action.ROLLBACK_BACKUP, backup_id="backup-ok")))
        self.assertFalse(policy.validate(self.request(Action.VERIFY_MODULE, ["kernel_hardening"])))
        self.assertEqual(64, len(manifest.digest))

    def test_rejects_commands_paths_duplicates_overlap_and_wrong_order(self) -> None:
        cases = []
        bad = json.loads(json.dumps(self.value)); bad["command"] = "sysctl -p"; cases.append(bad)
        bad = json.loads(json.dumps(self.value)); bad["modules"]["kernel_hardening"]["relative_target"] = "/etc/passwd"; cases.append(bad)
        bad = json.loads(json.dumps(self.value)); bad["modules"]["network_hardening"]["settings"][0]["key"] = "kernel.kptr_restrict"; cases.append(bad)
        bad = json.loads(json.dumps(self.value)); bad["multi_apply"] = [["network_hardening", "kernel_hardening"]]; cases.append(bad)
        bad = json.loads(json.dumps(self.value)); bad["single_apply"] = ["unknown_module"]; cases.append(bad)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(SysctlManifestError):
                self.write(value)
                self.load()

    def test_rejects_irreversible_keys_from_rollback_capable_manifest(self) -> None:
        for key in ("kernel.kexec_load_disabled", "kernel.unprivileged_bpf_disabled"):
            with self.subTest(key=key):
                value = json.loads(json.dumps(self.value))
                value["modules"]["kernel_hardening"]["settings"][0] = {
                    "key": key,
                    "value": "1",
                }
                self.write(value)
                with self.assertRaisesRegex(SysctlManifestError, "not rollback-capable"):
                    self.load()

    def test_rejects_writable_symlink_and_duplicate_json_fields(self) -> None:
        self.path.chmod(0o622)
        with self.assertRaises(SysctlManifestError):
            self.load()
        self.write(self.value)
        link = self.path.with_name("link.json")
        link.symlink_to(self.path)
        with self.assertRaises(SysctlManifestError):
            load_sysctl_manifest(link, expected_uid=os.getuid())
        self.path.write_text('{"version":2,"version":2}', encoding="utf-8")
        self.path.chmod(0o600)
        with self.assertRaises(SysctlManifestError):
            self.load()


if __name__ == "__main__":
    unittest.main()
