#!/usr/bin/env python3
"""wrapper_drift.py 2.6.0, package W: the writer that reaches into 13 repos.

Plan docs/plans/2026-09-23-codex-heben-wrapper-2.6.0 §5b (git-ignored). Every
test here was red before the change. Reparse points are simulated by patching
the check, so the tests hold on Windows without symlink privileges too -- the
lesson of the gate_reminder mutation probe: a test that skips on Windows
protects nothing on the platform this plugin actually runs on.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import os
import stat
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import wrapper_drift  # noqa: E402


class _Tree:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.base / "projects"
        self.repo = self.root / "repo-a"
        (self.repo / "tools").mkdir(parents=True)
        (self.repo / "tools" / "codex_ro.py").write_text('WRAPPER_VERSION = "2.4.0"\n', encoding="utf-8")
        self.scripts = Path(wrapper_drift.__file__).resolve().parent

    def run_main(self, *argv):
        err, out = io.StringIO(), io.StringIO()
        with unittest.mock.patch("sys.stderr", err), unittest.mock.patch("sys.stdout", out):
            code = wrapper_drift.main(list(argv))
        return code, out.getvalue() + err.getvalue()

    def copy_text(self):
        return (self.repo / "tools" / "codex_ro.py").read_text(encoding="utf-8")


class PrivateRootTests(_Tree, unittest.TestCase):
    """W4: --update writes only below a root the operator attests on every call."""

    def test_update_without_a_private_root_is_refused(self):
        code, text = self.run_main("--repo", str(self.repo), "--update")
        self.assertEqual(code, 2)
        self.assertIn("needs --private-root", text, "say what is missing, not only that it failed")
        self.assertIn("2.4.0", self.copy_text())

    def test_update_inside_the_root_writes(self):
        code, _ = self.run_main("--repo", str(self.repo), "--update", "--private-root", str(self.root))
        self.assertEqual(code, 0)
        self.assertNotIn("2.4.0", self.copy_text())

    def test_a_repo_outside_the_root_is_refused(self):
        other = self.base / "elsewhere"
        other.mkdir()
        code, _ = self.run_main("--repo", str(self.repo), "--update", "--private-root", str(other))
        self.assertEqual(code, 2)
        self.assertIn("2.4.0", self.copy_text())

    def test_the_prefix_trap(self):
        """W-T5c: a sibling whose name merely starts like the root is not under it."""
        evil = self.base / "projects-evil" / "r"
        (evil / "tools").mkdir(parents=True)
        (evil / "tools" / "codex_ro.py").write_text("old", encoding="utf-8")
        code, _ = self.run_main("--repo", str(evil), "--update", "--private-root", str(self.root))
        self.assertEqual(code, 2)
        self.assertEqual((evil / "tools" / "codex_ro.py").read_text(encoding="utf-8"), "old")

    def test_case_differences_are_accepted_on_windows(self):
        if os.name != "nt":
            return
        code, _ = self.run_main("--repo", str(self.repo), "--update",
                                "--private-root", str(self.root).upper())
        self.assertEqual(code, 0)

    def test_invalid_roots_are_refused(self):
        """W-T5b."""
        drive_root = Path(self.base.anchor)
        a_file = self.base / "file.txt"
        a_file.write_text("x", encoding="utf-8")
        for bad in (str(drive_root), "relative/dir", "\\\\server\\share\\x", "//server/share/x",
                    str(self.root) + "\x07", str(self.base / "missing"), str(a_file), ""):
            with self.subTest(root=repr(bad)):
                code, _ = self.run_main("--repo", str(self.repo), "--update", "--private-root", bad)
                self.assertEqual(code, 2)
        self.assertIn("2.4.0", self.copy_text())

    def test_a_root_that_is_or_sits_below_a_reparse_point_is_refused(self):
        """W-T5d: refused, never resolved."""
        for alias in (self.root, self.base):
            with self.subTest(alias=alias.name):
                real = wrapper_drift._is_reparse_point
                with unittest.mock.patch.object(
                        wrapper_drift, "_is_reparse_point",
                        lambda p, a=alias: Path(p) == a or real(p)):
                    code, _ = self.run_main("--repo", str(self.repo), "--update",
                                            "--private-root", str(self.root))
                self.assertEqual(code, 2)
        self.assertIn("2.4.0", self.copy_text())

    def test_the_help_states_the_narrow_claim(self):
        out = io.StringIO()
        with unittest.mock.patch("sys.stdout", out), self.assertRaises(SystemExit):
            wrapper_drift.main(["--help"])
        text = " ".join(out.getvalue().split())
        self.assertIn("ACL", text)
        self.assertIn("attest", text)


class SourceAndRawPathTests(_Tree, unittest.TestCase):
    def test_scripts_dir_with_update_is_refused(self):
        """W-T0b: a caller-chosen Python file must not replace tools/codex_ro.py."""
        fake = self.base / "fake-scripts"
        fake.mkdir()
        (fake / "codex_ro.py").write_text("print('not the wrapper')\n", encoding="utf-8")
        code, _ = self.run_main("--repo", str(self.repo), "--update", "--private-root", str(self.root),
                                "--scripts-dir", str(fake))
        self.assertEqual(code, 2)
        self.assertIn("2.4.0", self.copy_text())

    def test_scripts_dir_for_a_report_is_still_fine(self):
        code, _ = self.run_main("--repo", str(self.repo), "--scripts-dir", str(self.scripts))
        self.assertIn(code, (0, 1))

    def test_an_aliased_repo_is_refused_before_anything_resolves_it(self):
        """W-T0c."""
        real = wrapper_drift._is_reparse_point
        with unittest.mock.patch.object(
                wrapper_drift, "_is_reparse_point", lambda p: Path(p) == self.repo or real(p)), \
                unittest.mock.patch.object(Path, "resolve", side_effect=AssertionError("resolved first")):
            code, _ = self.run_main("--repo", str(self.repo), "--update", "--private-root", str(self.root))
        self.assertEqual(code, 2)
        self.assertIn("2.4.0", self.copy_text())

    def test_an_ancestor_between_root_and_repo_that_is_a_reparse_point_is_refused(self):
        """W-T6."""
        mid = self.root / "group"
        repo = mid / "repo-b"
        (repo / "tools").mkdir(parents=True)
        (repo / "tools" / "codex_ro.py").write_text("old", encoding="utf-8")
        real = wrapper_drift._is_reparse_point
        with unittest.mock.patch.object(wrapper_drift, "_is_reparse_point",
                                        lambda p: Path(p) == mid or real(p)):
            code, _ = self.run_main("--repo", str(repo), "--update", "--private-root", str(self.root))
        self.assertEqual(code, 2)
        self.assertEqual((repo / "tools" / "codex_ro.py").read_text(encoding="utf-8"), "old")


class PosixOwnershipTests(unittest.TestCase):
    """W4 on POSIX, tested on every platform through the pure predicate."""

    def _st(self, mode, uid):
        return os.stat_result((stat.S_IFDIR | mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))

    def test_group_or_other_writable_is_a_problem(self):
        for mode in (0o775, 0o757, 0o777):
            with self.subTest(mode=oct(mode)):
                self.assertIsNotNone(wrapper_drift.ownership_problem(self._st(mode, 1000), uid=1000))

    def test_a_foreign_owner_is_a_problem_root_is_not(self):
        self.assertIsNotNone(wrapper_drift.ownership_problem(self._st(0o755, 1001), uid=1000))
        self.assertIsNone(wrapper_drift.ownership_problem(self._st(0o755, 0), uid=1000))
        self.assertIsNone(wrapper_drift.ownership_problem(self._st(0o700, 1000), uid=1000))


class MissingToolsDirTests(_Tree, unittest.TestCase):
    def test_a_missing_tools_directory_is_created_and_rechecked(self):
        """W-T7 / W5."""
        repo = self.root / "fresh"
        repo.mkdir()
        code, _ = self.run_main("--repo", str(repo), "--update", "--private-root", str(self.root))
        self.assertEqual(code, 0)
        self.assertTrue((repo / "tools" / "codex_ro.py").is_file())

    def test_a_tools_directory_that_turns_into_a_junction_is_abandoned(self):
        repo = self.root / "fresh2"
        repo.mkdir()
        real = wrapper_drift._is_reparse_point
        created = repo / "tools"
        with unittest.mock.patch.object(
                wrapper_drift, "_is_reparse_point",
                lambda p: (Path(p) == created and created.exists()) or real(p)):
            code, _ = self.run_main("--repo", str(repo), "--update", "--private-root", str(self.root))
        self.assertEqual(code, 1)
        self.assertFalse((created / "codex_ro.py").exists())


class GuardedWriteTests(_Tree, unittest.TestCase):
    """W2 / W-T1..W-T3: random staging, three checks, nothing written past a swap."""

    def setUp(self):
        super().setUp()
        self.source = self.base / "canonical.py"
        self.source.write_text('WRAPPER_VERSION = "2.6.0"\n', encoding="utf-8")
        self.dest = self.repo / "tools" / "codex_ro.py"

    def _staging(self):
        return [p for p in (self.repo / "tools").iterdir() if p.name.startswith(".claudex-")]

    def test_staging_names_are_random_and_nothing_is_left(self):
        names = []
        real = wrapper_drift.tempfile.mkstemp

        def spy(*a, **k):
            fd, name = real(*a, **k)
            names.append(Path(name).name)
            return fd, name

        with unittest.mock.patch.object(wrapper_drift.tempfile, "mkstemp", spy):
            wrapper_drift.write_atomically(self.source, self.dest)
            wrapper_drift.write_atomically(self.source, self.dest)
        self.assertEqual(len(set(names)), 2)
        self.assertEqual(self._staging(), [])
        self.assertEqual(self.dest.read_text(encoding="utf-8"), 'WRAPPER_VERSION = "2.6.0"\n')

    def _swap_on_call(self, n):
        calls = {"n": 0}
        folder = self.dest.parent

        def check(path):
            if Path(path) == folder:
                calls["n"] += 1
                return calls["n"] >= n
            return False

        return check

    def test_a_swap_at_each_window_writes_nothing_and_leaves_nothing(self):
        for window in (1, 2, 3):
            with self.subTest(window=window):
                self.dest.write_text("original", encoding="utf-8")
                with unittest.mock.patch.object(wrapper_drift, "_is_reparse_point",
                                                self._swap_on_call(window)):
                    with self.assertRaises(wrapper_drift.Refused):
                        wrapper_drift.write_atomically(self.source, self.dest)
                self.assertEqual(self.dest.read_text(encoding="utf-8"), "original")
                self.assertEqual(self._staging(), [])

    def test_a_failure_while_writing_leaves_no_staging_file(self):
        with unittest.mock.patch.object(wrapper_drift.os, "fsync", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                wrapper_drift.write_atomically(self.source, self.dest)
        self.assertEqual(self._staging(), [])


class DocumentedUpdateCallsTests(unittest.TestCase):
    """K-T6: every documented `wrapper_drift.py ... --update` carries --private-root."""

    def test_every_documented_update_names_a_private_root(self):
        repo = Path(__file__).resolve().parent.parent
        files = [repo / "README.md", repo / "README_DE.md", repo / "docs" / "betrieb.md",
                 *sorted((repo / "skills").glob("*/SKILL.md"))]
        for path in files:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "wrapper_drift.py" in line and "--update" in line:
                    with self.subTest(file=path.name, line=number):
                        self.assertIn("--private-root", line)


if __name__ == "__main__":
    unittest.main(verbosity=2)
