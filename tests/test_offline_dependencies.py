from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify_offline_dependencies.sh"
CACHE = ROOT / "packaging" / "debian" / ".ubuntu-deps"


class OfflineDependencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (ROOT / "packaging" / "debian" / ".test-tmp").mkdir(exist_ok=True)

    def test_exact_noble_dependency_closure_is_verified(self) -> None:
        completed = subprocess.run(
            [str(VERIFIER), str(CACHE.resolve())],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertIn("closure verified", completed.stdout)

    def test_tampered_dependency_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "packaging" / "debian" / ".test-tmp") as temporary:
            target = Path(temporary) / "libxcb-cursor0_0.1.4-1build1_amd64.deb"
            target.write_bytes((CACHE / target.name).read_bytes() + b"tampered")
            completed = subprocess.run(
                [str(VERIFIER), temporary],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)


if __name__ == "__main__":
    unittest.main()
