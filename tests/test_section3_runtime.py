from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from lsmf.ipc_security import TransportCredentials
from lsmf.privileged_protocol import Action
from lsmf.production_protocol import ProductionRequest, ProductionStatus, decode_result, encode_request
from lsmf.production_runtime import (
    ProductionRuntimeError,
    Section3RuntimeConfig,
    build_section3_boundary,
)
from lsmf.system_session import SystemdLoginSessionAdapter


REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"


class AllowAuthorizer:
    def __init__(self): self.calls = []
    async def authorize(self, authorization_id, binding):
        self.calls.append(authorization_id)
        return True


class Credentials:
    async def credentials(self, owner): return TransportCredentials(123, os.getuid(), owner)


class Sessions:
    def session_for_pid(self, pid): return "c2"
    def session_uid(self, session_id): return os.getuid()
    def session_seat(self, session_id): return "seat0"
    def session_active(self, session_id): return True
    def session_remote(self, session_id): return False
    def session_type(self, session_id): return "wayland"


class Section3RuntimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name); root.chmod(0o700)
        self.targets = root / "targets"; self.targets.mkdir(mode=0o700)
        (self.targets / "etc/sysctl.d").mkdir(parents=True)
        self.proc = root / "proc/sys"; (self.proc / "kernel").mkdir(parents=True)
        self.value = self.proc / "kernel/kptr_restrict"; self.value.write_text("1\n")
        self.backups = root / "backups"; self.backups.mkdir(mode=0o700)
        self.audit = root / "audit"; self.audit.mkdir(mode=0o700)
        self.manifest = root / "manifest.json"
        self.manifest.write_text(json.dumps({
            "version": 2,
            "module_order": ["kernel_hardening"],
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
        }))
        value = json.loads(self.manifest.read_text()); value["module_order"] = ["kernel_hardening", "network_hardening"]
        self.manifest.write_text(json.dumps(value)); self.manifest.chmod(0o600)
        executable = Path(sys.executable).resolve()
        self.config = Section3RuntimeConfig(
            runner_path=Path(__file__).resolve().parents[1] / "packaging/privileged-helper/lsmf-read-only-runner",
            manifest_path=self.manifest,
            target_root=self.targets,
            sysctl_root=self.proc,
            backup_root=self.backups,
            audit_path=self.audit / "helper.jsonl",
            worker_executable=executable,
            pkcheck_executable=Path("/usr/bin/false"),
            expected_uid=os.getuid(),
            worker_executable_uid=executable.stat().st_uid,
        )

    def tearDown(self): self.temporary.cleanup()

    async def test_composition_authorizes_applies_and_audits_exact_action(self):
        authorizer = AllowAuthorizer()
        boundary = build_section3_boundary(
            self.config,
            credentials=Credentials(),
            sessions=SystemdLoginSessionAdapter(Sessions()),
            authorizer=authorizer,
        )
        request = ProductionRequest(1, REQUEST_ID, Action.APPLY_MODULE, ("kernel_hardening",))
        result = decode_result(await boundary.submit(":1.42", encode_request(request)))
        self.assertEqual(ProductionStatus.SUCCEEDED, result.status)
        self.assertEqual(["org.lsmf.helper.apply-module"], authorizer.calls)
        self.assertEqual("2\n", self.value.read_text())
        records = [json.loads(line) for line in self.config.audit_path.read_text().splitlines()]
        self.assertEqual(["started", "succeeded"], [item["lifecycle"] for item in records])

    async def test_reversed_multi_rejects_before_authorization(self):
        authorizer = AllowAuthorizer()
        boundary = build_section3_boundary(
            self.config,
            credentials=Credentials(),
            sessions=SystemdLoginSessionAdapter(Sessions()),
            authorizer=authorizer,
        )
        request = ProductionRequest(
            1, REQUEST_ID, Action.APPLY_MODULES,
            ("network_hardening", "kernel_hardening"),
        )
        result = decode_result(await boundary.submit(":1.42", encode_request(request)))
        self.assertEqual(ProductionStatus.REJECTED, result.status)
        self.assertEqual([], authorizer.calls)
        self.assertEqual("1\n", self.value.read_text())

    def test_root_runtime_rejects_nonfixed_mutation_roots(self):
        with self.assertRaises(ProductionRuntimeError):
            Section3RuntimeConfig(
                runner_path=Path("/usr/libexec/lsmf-read-only-runner"),
                manifest_path=Path("/etc/lsmf/helper/sysctl-manifest.json"),
                target_root=Path("/tmp/root"),
                sysctl_root=Path("/tmp/proc"),
                backup_root=Path("/var/backups/lsmf/sysctl"),
                audit_path=Path("/var/log/lsmf/helper.jsonl"),
            )


if __name__ == "__main__": unittest.main()
