from pathlib import Path
import tempfile
import unittest

from lsmf.configuration import parse_config
from lsmf.profiles import discover_profiles, preview_profile


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ProfileTests(unittest.TestCase):
    def test_discovers_real_repository_profiles(self) -> None:
        base = parse_config(PROJECT_ROOT / "config" / "lsmf.conf")
        result = discover_profiles(PROJECT_ROOT / "config" / "profiles", base)

        self.assertEqual([], list(result.errors))
        self.assertEqual(
            ["desktop", "maximum-lockdown", "server"],
            [profile.profile_id for profile in result.profiles],
        )
        maximum = next(p for p in result.profiles if p.profile_id == "maximum-lockdown")
        self.assertEqual(("COMPILER_RESTRICTIONS", "USB_RESTRICTIONS"), maximum.unknown_keys)

    def test_preview_contains_only_exact_changes_in_key_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "test.conf").write_text(
                'PROFILE_NAME="Test"\nPROFILE_DESCRIPTION="Test profile"\n'
                'KNOWN="new"\nSAME="same"\nADDED="yes"\n',
                encoding="utf-8",
            )
            profile = discover_profiles(root, {"KNOWN": "old", "SAME": "same"}).profiles[0]

            preview = preview_profile(profile, {"KNOWN": "old", "SAME": "same"})

            self.assertEqual(
                [("ADDED", None, "yes"), ("KNOWN", "old", "new")],
                [(change.key, change.before, change.after) for change in preview.changes],
            )
            self.assertEqual(("ADDED",), preview.unknown_keys)

    def test_missing_directory_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = discover_profiles(Path(directory) / "missing", {})

        self.assertEqual((), result.profiles)
        self.assertIn("missing", result.errors[0].message)

    def test_malformed_and_duplicate_keys_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "malformed.conf").write_text("not configuration\n", encoding="utf-8")
            (root / "duplicate.conf").write_text('KEY="one"\nKEY="two"\n', encoding="utf-8")

            result = discover_profiles(root, {})

        self.assertEqual((), result.profiles)
        self.assertEqual(2, len(result.errors))
        self.assertTrue(any("duplicate key" in error.message for error in result.errors))
        self.assertTrue(any("invalid configuration line" in error.message for error in result.errors))

    def test_symlink_and_non_regular_entry_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text('PROFILE_NAME="Target"\n', encoding="utf-8")
            (root / "linked.conf").symlink_to(target)
            (root / "directory.conf").mkdir()

            result = discover_profiles(root, {})

        self.assertEqual((), result.profiles)
        self.assertEqual(2, len(result.errors))
        self.assertTrue(any("symlink" in error.message for error in result.errors))
        self.assertTrue(any("regular file" in error.message for error in result.errors))

    def test_duplicate_profile_ids_are_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = 'PROFILE_NAME="Test"\nPROFILE_DESCRIPTION="Description"\n'
            (root / "Server.conf").write_text(content, encoding="utf-8")
            (root / "server.conf").write_text(content, encoding="utf-8")

            result = discover_profiles(root, {})

        self.assertEqual(1, len(result.profiles))
        self.assertEqual(1, len(result.errors))
        self.assertIn("duplicate profile ID", result.errors[0].message)

    def test_missing_metadata_makes_profile_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "minimal.conf").write_text('SYSTEM_ROLE="server"\n', encoding="utf-8")

            profile = discover_profiles(root, {"SYSTEM_ROLE": "auto"}).profiles[0]

        self.assertFalse(profile.valid)
        self.assertEqual(
            ("PROFILE_NAME is required", "PROFILE_DESCRIPTION is required"),
            profile.validation_errors,
        )

    def test_nested_profiles_are_not_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            (nested / "hidden.conf").write_text(
                'PROFILE_NAME="Hidden"\nPROFILE_DESCRIPTION="Nested"\n', encoding="utf-8"
            )

            result = discover_profiles(root, {})

        self.assertEqual((), result.profiles)
        self.assertEqual((), result.errors)


if __name__ == "__main__":
    unittest.main()
