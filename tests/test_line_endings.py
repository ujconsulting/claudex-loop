#!/usr/bin/env python3
"""T17: one line-ending form, at the source and in the drift tool.

Measured 2026-09-30: with `core.autocrlf=true` (Git for Windows' system default)
and no `.gitattributes`, the plugin install checked out every file with CRLF,
the repo's own working tree was mixed, and wrapper_drift.py compared raw bytes --
so 26 identical copies were reported as DRIFT. Seven tests here were red before the change; the
four that were already green are guards (a lone CR, a real change, the byte-exact
checks before and after the replace) and must stay green through it.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import wrapper_drift  # noqa: E402

BODY = 'WRAPPER_VERSION = "9.9.9"\nprint("a")\nprint("b")\n'


class _Files:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def put(self, name: str, data: bytes) -> Path:
        path = self.base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path


class DigestTests(_Files, unittest.TestCase):
    def test_crlf_and_lf_of_the_same_content_have_the_same_digest(self):
        lf = self.put("lf.py", BODY.encode())
        crlf = self.put("crlf.py", BODY.replace("\n", "\r\n").encode())
        self.assertEqual(wrapper_drift.digest(lf), wrapper_drift.digest(crlf))

    def test_a_lone_carriage_return_is_still_a_difference(self):
        lf = self.put("lf.py", BODY.encode())
        odd = self.put("odd.py", BODY.replace('"a"', '"a"\r').encode())
        self.assertNotEqual(wrapper_drift.digest(lf), wrapper_drift.digest(odd))


class InspectTests(_Files, unittest.TestCase):
    def test_copy_crlf_canonical_lf_is_level(self):
        canonical = self.put("scripts/codex_ro.py", BODY.encode())
        self.put("repo/tools/codex_ro.py", BODY.replace("\n", "\r\n").encode())
        report = wrapper_drift.inspect_file(self.base / "repo", canonical, True)
        self.assertEqual(report["status"], wrapper_drift.LEVEL)

    def test_copy_lf_canonical_crlf_is_level(self):
        canonical = self.put("scripts/codex_ro.py", BODY.replace("\n", "\r\n").encode())
        self.put("repo/tools/codex_ro.py", BODY.encode())
        report = wrapper_drift.inspect_file(self.base / "repo", canonical, True)
        self.assertEqual(report["status"], wrapper_drift.LEVEL)

    def test_a_real_change_is_still_drift(self):
        canonical = self.put("scripts/codex_ro.py", BODY.encode())
        self.put("repo/tools/codex_ro.py", BODY.replace('"b"', '"c"').replace("\n", "\r\n").encode())
        report = wrapper_drift.inspect_file(self.base / "repo", canonical, True)
        self.assertEqual(report["status"], wrapper_drift.DRIFTED)


class WriteTests(_Files, unittest.TestCase):
    def test_a_crlf_source_is_written_as_lf(self):
        source = self.put("scripts/codex_ro.py", BODY.replace("\n", "\r\n").encode())
        dest = self.put("repo/tools/codex_ro.py", b"old\n")
        wrapper_drift.write_atomically(source, dest, self.base)
        self.assertEqual(dest.read_bytes(), BODY.encode())

    def test_the_written_bytes_are_still_verified_exactly(self):
        source = self.put("scripts/codex_ro.py", BODY.encode())
        dest = self.put("repo/tools/codex_ro.py", b"old\n")
        real_replace = wrapper_drift.os.replace

        def tampering_replace(src, dst):
            real_replace(src, dst)
            Path(dst).write_bytes(BODY.replace("\n", "\r\n").encode())  # same text, other bytes

        with unittest.mock.patch.object(wrapper_drift.os, "replace", tampering_replace):
            with self.assertRaises(wrapper_drift.Refused):
                wrapper_drift.write_atomically(source, dest, self.base)


    def test_the_staged_bytes_are_verified_exactly_before_the_replace(self):
        """Plan round 1 (HIGH): a staging file with the right text but CRLF bytes must
        not replace the target -- the check before os.replace is byte-exact."""
        source = self.put("scripts/codex_ro.py", BODY.encode())
        dest = self.put("repo/tools/codex_ro.py", b"old\n")
        real_write_all = wrapper_drift._write_all

        def crlf_write_all(fd, data):
            real_write_all(fd, data.replace(b"\n", b"\r\n"))

        with unittest.mock.patch.object(wrapper_drift, "_write_all", crlf_write_all):
            with self.assertRaises(wrapper_drift.Refused):
                wrapper_drift.write_atomically(source, dest, self.base)
        self.assertEqual(dest.read_bytes(), b"old\n")


class ShimBytesTests(unittest.TestCase):
    """Plan round 1 (MEDIUM): a local plugin install copies the working tree, not
    the index -- and bash reads `set -e\\r` as a different command."""

    def test_the_shell_shim_in_the_working_tree_has_no_carriage_return(self):
        self.assertNotIn(b"\r", (REPO / "hooks" / "claudex-python.sh").read_bytes())


class GitAttributesTests(unittest.TestCase):
    """The source end: every checkout -- the plugin install included -- is LF."""

    def test_the_repo_pins_lf(self):
        attributes = (REPO / ".gitattributes").read_text(encoding="utf-8")
        self.assertIn("* text=auto eol=lf", attributes.splitlines())

    @unittest.skipUnless(shutil.which("git") and (REPO / ".git").exists(), "needs git and a checkout")
    def test_git_resolves_lf_for_the_shim_and_the_wrapper(self):
        out = subprocess.run(
            ["git", "-C", str(REPO), "check-attr", "eol", "--",
             "hooks/claudex-python.sh", "scripts/codex_ro.py"],
            capture_output=True, text=True, check=True).stdout
        self.assertEqual(out.count("eol: lf"), 2, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
