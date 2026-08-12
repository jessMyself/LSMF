import tempfile
import unittest
from pathlib import Path

from lsmf.module_catalog import discover_modules


VALID_MODULE = '''#!/usr/bin/env bash
# Description: Secures the test surface.
MODULE_NAME="ssh_hardening"
MODULE_VERSION="2.1.0"
run_ssh_hardening() { :; }
verify_ssh_hardening() { :; }
'''


class ModuleCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.modules = self.root / "modules"
        self.modules.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, name, content):
        path = self.modules / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_discovers_only_scripts_and_reports_truthful_metadata(self):
        script = self.write("ssh_hardening.sh", VALID_MODULE)
        self.write("ignored.txt", 'MODULE_NAME="phantom"')

        result = discover_modules(self.modules)

        self.assertEqual((), result.errors)
        self.assertEqual(1, len(result.modules))
        module = result.modules[0]
        self.assertEqual("ssh_hardening", module.module_id)
        self.assertEqual("Ssh Hardening", module.name)
        self.assertEqual("2.1.0", module.version)
        self.assertEqual(script, module.script)
        self.assertEqual("Secures the test surface.", module.description)
        self.assertTrue(module.can_run)
        self.assertTrue(module.can_verify)
        self.assertFalse(module.can_rollback)
        self.assertIsNone(module.enabled)
        self.assertEqual("MODULE_SSH_ENABLED", module.config_key)

    def test_uses_canonical_config_without_executing_it(self):
        self.write("ssh_hardening.sh", VALID_MODULE)
        config = self.root / "lsmf.conf"
        config.write_text('MODULE_SSH_ENABLED="false"\n', encoding="utf-8")

        module = discover_modules(self.modules, config).modules[0]

        self.assertFalse(module.enabled)

    def test_invalid_config_is_reported_and_state_is_unknown(self):
        self.write("ssh_hardening.sh", VALID_MODULE)
        config = self.root / "lsmf.conf"
        config.write_text('MODULE_SSH_ENABLED="maybe"\n', encoding="utf-8")

        result = discover_modules(self.modules, config)

        self.assertIsNone(result.modules[0].enabled)
        self.assertIn("cannot load configuration", result.errors[0])

    def test_malformed_scripts_are_omitted_with_clear_errors(self):
        self.write("missing.sh", 'MODULE_NAME="missing"\n')
        self.write(
            "wrong.sh",
            'MODULE_NAME="different"\nMODULE_VERSION="1.0"\n',
        )

        result = discover_modules(self.modules)

        self.assertEqual((), result.modules)
        self.assertEqual(2, len(result.errors))
        self.assertTrue(any("missing MODULE_VERSION" in error for error in result.errors))
        self.assertTrue(any("does not match filename" in error for error in result.errors))

    def test_missing_paths_are_reported(self):
        result = discover_modules(self.root / "absent", self.root / "absent.conf")

        self.assertEqual((), result.modules)
        self.assertEqual(2, len(result.errors))
        self.assertIn("configuration file not found", result.errors[0])
        self.assertIn("module directory not found", result.errors[1])


if __name__ == "__main__":
    unittest.main()
