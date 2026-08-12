from __future__ import annotations

import configparser
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

from lsmf.sysctl_manifest import load_sysctl_manifest


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "packaging" / "privileged-helper"
ACTION_IDS = {
    "org.lsmf.helper.audit",
    "org.lsmf.helper.verify-module",
    "org.lsmf.helper.apply-module",
    "org.lsmf.helper.apply-modules",
    "org.lsmf.helper.rollback-backup",
}


class PrivilegedPackagingTests(unittest.TestCase):
    def test_policy_has_exact_distinct_fail_closed_actions(self) -> None:
        root = ET.parse(ARTIFACTS / "org.lsmf.helper.policy").getroot()
        actions = root.findall("action")
        self.assertEqual({action.attrib["id"] for action in actions}, ACTION_IDS)
        self.assertEqual(len(actions), len(ACTION_IDS))
        for action in actions:
            defaults = action.find("defaults")
            self.assertIsNotNone(defaults)
            self.assertEqual(defaults.findtext("allow_any"), "no")
            self.assertEqual(defaults.findtext("allow_inactive"), "no")
            self.assertEqual(defaults.findtext("allow_active"), "auth_admin")
            self.assertNotIn("_keep", ET.tostring(action, encoding="unicode"))

    def test_dbus_interface_is_pinned_and_bounded_to_submit_and_cancel(self) -> None:
        root = ET.parse(ARTIFACTS / "org.lsmf.Helper1.xml").getroot()
        self.assertEqual(root.attrib["name"], "/org/lsmf/Helper1")
        interfaces = root.findall("interface")
        self.assertEqual([item.attrib["name"] for item in interfaces], ["org.lsmf.Helper1"])
        methods = interfaces[0].findall("method")
        self.assertEqual({item.attrib["name"] for item in methods}, {"Submit", "Cancel"})
        for method in methods:
            args = method.findall("arg")
            self.assertEqual([(arg.attrib["type"], arg.attrib["direction"]) for arg in args], [("s", "in"), ("s", "out")])

    def test_dbus_activation_delegates_to_hardened_systemd_unit(self) -> None:
        service = self._parse(ARTIFACTS / "org.lsmf.Helper1.service")
        values = service["D-BUS Service"]
        self.assertEqual(values["Name"], "org.lsmf.Helper1")
        self.assertEqual(values["Exec"], "/usr/libexec/lsmf-privileged-helper")
        self.assertEqual(values["User"], "root")
        self.assertEqual(values["SystemdService"], "lsmf-privileged-helper.service")

    def test_systemd_unit_has_fixed_execution_and_restrictive_sandbox(self) -> None:
        unit = self._parse(ARTIFACTS / "lsmf-privileged-helper.service")
        service = unit["Service"]
        expected = {
            "Type": "dbus",
            "BusName": "org.lsmf.Helper1",
            "ExecStart": "/usr/libexec/lsmf-privileged-helper",
            "User": "root",
            "Group": "root",
            "UMask": "0077",
            "NoNewPrivileges": "yes",
            "PrivateNetwork": "no",
            "ProtectSystem": "strict",
            "ProtectHome": "yes",
            "RestrictAddressFamilies": "AF_UNIX",
            "RestrictSUIDSGID": "yes",
            "CapabilityBoundingSet": "CAP_SYS_ADMIN CAP_NET_ADMIN",
            "AmbientCapabilities": "CAP_SYS_ADMIN CAP_NET_ADMIN",
            "ProtectKernelTunables": "no",
            "Restart": "no",
        }
        for key, value in expected.items():
            self.assertEqual(service[key], value)
        self.assertNotIn("StateDirectory", service)
        self.assertTrue(service["ExecStart"].startswith("/"))
        self.assertNotIn("%", service["ExecStart"])
        self.assertNotIn("$", service["ExecStart"])
        writable = set(service["ReadWritePaths"].split())
        self.assertEqual(writable, {
            "/run/lsmf",
            "/var/lib/lsmf/reports",
            "/var/log/lsmf",
            "/var/backups/lsmf/sysctl",
            "/etc/sysctl.d",
        })
        readonly = set(service["ReadOnlyPaths"].split())
        self.assertIn("/usr/lib/lsmf", readonly)
        self.assertIn("/usr/libexec/lsmf-read-only-runner", readonly)

    def test_directory_contains_only_inactive_staging_and_runtime_inputs(self) -> None:
        names = {item.name for item in ARTIFACTS.iterdir()}
        self.assertEqual(names, {
            "README.md",
            "lsmf-privileged-helper",
            "lsmf-read-only-runner",
            "lsmf-privileged-helper.service",
            "org.lsmf.Helper1.conf",
            "org.lsmf.Helper1.service",
            "org.lsmf.Helper1.xml",
            "org.lsmf.helper.policy",
            "stage-package.sh",
            "synthetic-manifest.json",
            "sysctl-manifest.json",
            "synthetic-toggle.conf",
            "unstage-package.sh",
        })
        for path in ARTIFACTS.iterdir():
            if path.name in {
                "lsmf-privileged-helper", "lsmf-read-only-runner",
                "stage-package.sh", "unstage-package.sh",
            }:
                self.assertTrue(path.stat().st_mode & 0o111, path.name)
            else:
                self.assertFalse(path.stat().st_mode & 0o111, path.name)
        readme = (ARTIFACTS / "README.md").read_text(encoding="utf-8")
        self.assertIn("not installed, registered, enabled, or started", readme)
        self.assertIn("setuid or setgid helper is forbidden", readme)

    def test_staging_and_unstaging_are_bounded_to_explicit_nonroot_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run([str(ARTIFACTS / "stage-package.sh"), str(root)], check=True)
            entry = root / "usr/libexec/lsmf-privileged-helper"
            manifest = root / "etc/lsmf/helper/synthetic-manifest.json"
            sysctl_manifest = root / "etc/lsmf/helper/sysctl-manifest.json"
            target = root / "var/lib/lsmf/synthetic-targets/toggle.conf"
            runtime = root / "usr/lib/python3/dist-packages/lsmf/production_runtime.py"
            runner = root / "usr/libexec/lsmf-read-only-runner"
            launcher = root / "usr/lib/lsmf/lsmf"
            module = root / "usr/lib/lsmf/modules/kernel_hardening.sh"
            self.assertTrue(entry.is_file())
            self.assertEqual(0o755, entry.stat().st_mode & 0o777)
            self.assertEqual(0o644, manifest.stat().st_mode & 0o777)
            self.assertEqual(0o644, sysctl_manifest.stat().st_mode & 0o777)
            self.assertEqual(0o600, target.stat().st_mode & 0o777)
            self.assertTrue(runtime.is_file())
            self.assertEqual(0o755, runner.stat().st_mode & 0o777)
            self.assertEqual(0o755, launcher.stat().st_mode & 0o777)
            self.assertEqual(0o644, module.stat().st_mode & 0o777)
            self.assertEqual(1, json.loads(manifest.read_text())["version"])
            self.assertIn("from lsmf.production_runtime import section3_main", entry.read_text())
            loaded = load_sysctl_manifest(sysctl_manifest, expected_uid=sysctl_manifest.stat().st_uid)
            self.assertEqual(17, len(loaded.modules["kernel_hardening"].settings))
            self.assertEqual(29, len(loaded.modules["network_hardening"].settings))
            runner_source = runner.read_text()
            self.assertIn('"kernel_hardening"', runner_source)
            self.assertIn("initialize_read_only_run", runner_source)
            self.assertIn("export LSMF_INTERACTIVE=false", runner_source)
            self.assertIn("trap - ERR", runner_source)
            self.assertIn("set +e", runner_source)
            self.assertNotIn("init_lsmf", runner_source)
            subprocess.run(
                ["/usr/bin/python3", "-c", "import lsmf.production_runtime"],
                cwd="/",
                env={"PYTHONPATH": str(root / "usr/lib/python3/dist-packages")},
                check=True,
            )

            retained = root / "var/backups/lsmf/sysctl/retained-evidence"
            retained.write_text("preserve\n")
            subprocess.run([str(ARTIFACTS / "unstage-package.sh"), str(root)], check=True)
            self.assertFalse(entry.exists())
            self.assertFalse(manifest.exists())
            self.assertFalse(sysctl_manifest.exists())
            self.assertFalse(target.exists())
            self.assertFalse(runtime.exists())
            self.assertFalse(runner.exists())
            self.assertFalse(launcher.exists())
            self.assertFalse(module.exists())
            self.assertEqual("preserve\n", retained.read_text())

        refused = subprocess.run(
            [str(ARTIFACTS / "stage-package.sh"), "/"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(64, refused.returncode)

    def test_staging_rejects_symlinked_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
            root = Path(temporary)
            (root / "usr").symlink_to(outside, target_is_directory=True)
            completed = subprocess.run(
                [str(ARTIFACTS / "stage-package.sh"), str(root)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(64, completed.returncode)
            self.assertEqual([], list(Path(outside).iterdir()))

    def test_bus_policy_allows_only_root_ownership_and_two_methods(self) -> None:
        root = ET.parse(ARTIFACTS / "org.lsmf.Helper1.conf").getroot()
        policies = root.findall("policy")
        self.assertEqual(2, len(policies))
        self.assertEqual("root", policies[0].attrib["user"])
        self.assertEqual("org.lsmf.Helper1", policies[0].find("allow").attrib["own"])
        allows = policies[1].findall("allow")
        self.assertEqual({"Submit", "Cancel"}, {item.attrib["send_member"] for item in allows})
        self.assertTrue(all(item.attrib["send_destination"] == "org.lsmf.Helper1" for item in allows))

    @staticmethod
    def _parse(path: Path) -> configparser.ConfigParser:
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        parser.read(path, encoding="utf-8")
        return parser


if __name__ == "__main__":
    unittest.main()
