from pathlib import Path
import tempfile
import unittest
from unittest import mock

from lsmf.configuration import (
    ConfigError,
    ConfigStore,
    parse_config,
    parse_legacy_mixed,
    write_config_atomic,
)


FIXTURES = Path(__file__).parent / "fixtures" / "config"


class ConfigurationTests(unittest.TestCase):
    def test_canonical_fixture_values_match_bash_expectations(self) -> None:
        values = parse_config(FIXTURES / "canonical.conf")

        self.assertEqual("false", values["DISABLE_IPV6"])
        self.assertEqual("true", values["MODULE_SSH_ENABLED"])
        self.assertEqual("preserved", values["FUTURE_SETTING"])

    def test_malformed_fixture_fails_clearly(self) -> None:
        with self.assertRaisesRegex(ConfigError, "invalid configuration line"):
            parse_config(FIXTURES / "malformed.conf")

    def test_legacy_migration_preserves_global_module_and_feature_values(self) -> None:
        values = parse_legacy_mixed(FIXTURES / "legacy-mixed.conf")

        self.assertEqual("1.0.0", values["LSMF_VERSION"])
        self.assertEqual("false", values["DISABLE_IPV6"])
        self.assertEqual("true", values["MODULE_SSH_ENABLED"])
        self.assertEqual("true", values["FEATURE_SSH_ROOT_LOGIN"])

    def test_legacy_migration_preserves_unknown_section_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.conf"
            path.write_text('[future_hardening]\nnew_option="preserved"\n', encoding="utf-8")

            values = parse_legacy_mixed(path)

            self.assertEqual("preserved", values["FUTURE_HARDENING_NEW_OPTION"])

    def test_atomic_write_round_trip_and_unknown_key_preservation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lsmf.conf"
            write_config_atomic(path, parse_config(FIXTURES / "canonical.conf"))
            before_inode = path.stat().st_ino
            store = ConfigStore(path)
            store.set("DISABLE_IPV6", True)
            store.save()

            self.assertEqual("true", parse_config(path)["DISABLE_IPV6"])
            self.assertEqual("preserved", parse_config(path)["FUTURE_SETTING"])
            self.assertNotEqual(before_inode, path.stat().st_ino)

    def test_atomic_write_failure_preserves_original_and_removes_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lsmf.conf"
            original = 'FUTURE_SETTING="original"\n'
            path.write_text(original, encoding="utf-8")

            with mock.patch("lsmf.configuration.os.replace", side_effect=OSError("failed")):
                with self.assertRaises(OSError):
                    write_config_atomic(path, {"FUTURE_SETTING": "replacement"})

            self.assertEqual(original, path.read_text(encoding="utf-8"))
            self.assertEqual([], list(path.parent.glob(f".{path.name}.*")))


if __name__ == "__main__":
    unittest.main()
