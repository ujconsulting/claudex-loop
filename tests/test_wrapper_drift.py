#!/usr/bin/env python3
"""Tests for the drift reporter, which is the one tool here that WRITES.

`--update` walks repos it did not create and overwrites files in them. That makes
its destination checks a security surface, not a convenience: `shutil.copyfile`
writes through a symlink, so a scanned repo could aim `tools/codex_ro.py` at any
file the user can write and have an update clobber it (audit 2026-08-30, HIGH).

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import wrapper_drift  # noqa: E402


class DestinationSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name).resolve()
        (self.repo / "tools").mkdir()
        self.addCleanup(self.tmp.cleanup)

    def _symlink(self, link: Path, target: Path):
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("this platform will not let the test create a symlink")

    def test_a_plain_destination_is_fine(self):
        copy = self.repo / "tools" / "codex_ro.py"
        copy.write_text("old", encoding="utf-8")
        self.assertIsNone(wrapper_drift.unsafe_destination(self.repo, copy))

    def test_a_missing_destination_is_fine(self):
        self.assertIsNone(
            wrapper_drift.unsafe_destination(self.repo, self.repo / "tools" / "codex_ro.py")
        )

    def test_a_symlinked_destination_is_refused(self):
        victim = self.repo / "precious.txt"
        victim.write_text("do not clobber me", encoding="utf-8")
        copy = self.repo / "tools" / "codex_ro.py"
        self._symlink(copy, victim)
        self.assertIn("symlink", wrapper_drift.unsafe_destination(self.repo, copy) or "")
        self.assertEqual(victim.read_text(encoding="utf-8"), "do not clobber me")

    def test_a_symlinked_tools_directory_is_refused(self):
        elsewhere = Path(self.tmp.name).resolve() / "elsewhere"
        elsewhere.mkdir()
        repo = Path(self.tmp.name).resolve() / "other-repo"
        repo.mkdir()
        self._symlink(repo / "tools", elsewhere)
        self.assertIn(
            "symlink", wrapper_drift.unsafe_destination(repo, repo / "tools" / "codex_ro.py") or ""
        )

    def test_a_directory_where_the_file_belongs_is_refused(self):
        copy = self.repo / "tools" / "codex_ro.py"
        copy.mkdir()
        self.assertIsNotNone(wrapper_drift.unsafe_destination(self.repo, copy))


class AtomicWriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def test_the_content_arrives(self):
        source = self.root / "canonical.py"
        source.write_text("WRAPPER_VERSION = \"9.9.9\"\n", encoding="utf-8")
        destination = self.root / "copy.py"
        wrapper_drift.write_atomically(source, destination)
        self.assertEqual(destination.read_text(encoding="utf-8"), source.read_text(encoding="utf-8"))

    def test_no_staging_file_is_left_behind(self):
        source = self.root / "canonical.py"
        source.write_text("x", encoding="utf-8")
        destination = self.root / "copy.py"
        wrapper_drift.write_atomically(source, destination)
        self.assertEqual(
            [p.name for p in self.root.iterdir() if p.name.endswith(".claudex-new")], []
        )


class VersionTests(unittest.TestCase):
    def test_the_declared_version_wins_over_the_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "codex_ro.py"
            path.write_text('WRAPPER_VERSION = "2.2.0"\n', encoding="utf-8")
            self.assertEqual(wrapper_drift.version_of(path), "2.2.0")

    def test_a_file_without_a_version_falls_back_to_its_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "other.py"
            path.write_text("no version here\n", encoding="utf-8")
            self.assertEqual(wrapper_drift.version_of(path), wrapper_drift.digest(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
