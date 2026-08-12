from __future__ import annotations

import shutil
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "packaging" / "debian" / "build-package.sh"
TEST_TEMP = ROOT / "packaging" / "debian" / ".test-tmp"
TEST_TEMP.mkdir(exist_ok=True)


@unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb unavailable")
class ReleasePackagingTests(unittest.TestCase):
    def test_release_candidate_is_bounded_and_excludes_synthetic_fixture(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as temporary:
            output = Path(temporary) / "out"
            subprocess.run(
                [str(BUILDER), "--output", str(output), "--version", "0.4.0~test1"],
                cwd=ROOT,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            artifacts = list(output.glob("*.deb"))
            self.assertEqual(1, len(artifacts))
            listing = subprocess.run(
                ["dpkg-deb", "--contents", str(artifacts[0])],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout
            self.assertIn("./usr/libexec/lsmf-privileged-helper", listing)
            self.assertIn("./usr/bin/lsmf-desktop", listing)
            self.assertIn("./opt/lsmf/app/desktop/main.py", listing)
            self.assertIn("./opt/lsmf/qt/PySide6/QtWidgets.abi3.so", listing)
            self.assertIn("./etc/lsmf/helper/sysctl-manifest.json", listing)
            self.assertNotIn("synthetic-manifest.json", listing)
            self.assertNotIn("synthetic-toggle.conf", listing)
            self.assertNotIn("var/backups/lsmf/synthetic", listing)
            self.assertNotRegex(listing, r"^-.[rwx]*[sS]")
            self.assertNotRegex(listing, r"^.....w|^........w")

            control = subprocess.run(
                ["dpkg-deb", "--field", str(artifacts[0])],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout
            self.assertIn("Package: lsmf", control)
            self.assertIn("Version: 0.4.0~test1", control)
            self.assertIn("Architecture: amd64", control)

            extracted = Path(temporary) / "extracted"
            subprocess.run(
                ["dpkg-deb", "--extract", str(artifacts[0]), str(extracted)],
                check=True,
            )
            launcher = extracted / "usr/bin/lsmf-desktop"
            launcher_source = launcher.read_text(encoding="utf-8")
            self.assertIn('if [[ ${EUID} -eq 0 ]]', launcher_source)
            self.assertLess(launcher_source.index('if [[ ${EUID} -eq 0 ]]'), launcher_source.index("exec /usr/bin/python3"))
            refused = subprocess.run(
                [str(launcher)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0:
                self.assertEqual(1, refused.returncode)
                self.assertIn("Do not run", refused.stderr)

            qt_root = extracted / "opt/lsmf/qt"
            app_root = extracted / "opt/lsmf/app"
            imported = subprocess.run(
                [
                    "/usr/bin/python3",
                    "-c",
                    "from PySide6.QtWidgets import QApplication; import desktop.main; print('packaged-qt-import-ok')",
                ],
                env={
                    "PYTHONPATH": f"{qt_root}:{app_root}:{extracted}/usr/lib/python3/dist-packages",
                    "PYTHONNOUSERSITE": "1",
                    "QT_QPA_PLATFORM": "offscreen",
                },
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertIn("packaged-qt-import-ok", imported.stdout)

    def test_builder_rejects_relative_output(self) -> None:
        completed = subprocess.run(
            [str(BUILDER), "--output", "relative"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(64, completed.returncode)

    def test_repeat_build_is_byte_for_byte_reproducible(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TEMP) as temporary:
            root = Path(temporary)
            artifacts = []
            for name in ("first", "second"):
                output = root / name
                subprocess.run(
                    [str(BUILDER), "--output", str(output), "--version", "0.4.0~repeat1"],
                    cwd=ROOT,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                artifacts.append(next(output.glob("*.deb")))
            digests = [hashlib.sha256(path.read_bytes()).hexdigest() for path in artifacts]
            self.assertEqual(digests[0], digests[1])


if __name__ == "__main__":
    unittest.main()
