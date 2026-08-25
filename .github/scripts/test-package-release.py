"""Regression tests for deterministic release archives."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("package-release.py")
EPOCH = 1_787_500_800


class PackageReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source-bin"
        self.source.write_bytes(bytes(range(256)) * 8)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def package(self, kind: str, output: Path, name: str) -> None:
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--format",
                kind,
                "--input",
                str(self.source),
                "--output",
                str(output),
                "--name",
                name,
                "--source-date-epoch",
                str(EPOCH),
            ],
            check=True,
        )

    def assert_same_digest(self, first: Path, second: Path) -> None:
        digest = lambda path: hashlib.sha256(path.read_bytes()).digest()
        self.assertEqual(digest(first), digest(second))

    def test_tar_gz_is_deterministic_and_normalized(self) -> None:
        first = self.root / "first.tar.gz"
        second = self.root / "second.tar.gz"
        self.package("tar.gz", first, "yon")
        self.source.touch()
        self.package("tar.gz", second, "yon")
        self.assert_same_digest(first, second)
        with tarfile.open(first, "r:gz") as archive:
            members = archive.getmembers()
            self.assertEqual(len(members), 1)
            member = members[0]
            self.assertEqual(member.name, "yon")
            self.assertEqual(member.mode, 0o755)
            self.assertEqual((member.uid, member.gid), (0, 0))
            self.assertEqual((member.uname, member.gname), ("", ""))
            self.assertEqual(member.mtime, EPOCH)
            self.assertEqual(archive.extractfile(member).read(), self.source.read_bytes())

    def test_zip_is_deterministic_and_normalized(self) -> None:
        first = self.root / "first.zip"
        second = self.root / "second.zip"
        self.package("zip", first, "yon.exe")
        self.source.touch()
        self.package("zip", second, "yon.exe")
        self.assert_same_digest(first, second)
        with zipfile.ZipFile(first) as archive:
            members = archive.infolist()
            self.assertEqual(len(members), 1)
            member = members[0]
            self.assertEqual(member.filename, "yon.exe")
            self.assertEqual(member.external_attr >> 16, 0o100755)
            self.assertEqual(archive.read(member), self.source.read_bytes())


if __name__ == "__main__":
    unittest.main()
