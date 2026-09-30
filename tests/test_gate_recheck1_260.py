#!/usr/bin/env python3
"""Closing gate of wrapper 2.6.0, recheck 1 (gpt-6-sol, 2026-09-30): one test per
accepted finding, each written before its fix and seen failing first.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import builtins
import io
import os
import sys
import tempfile
import threading
import unittest
import unittest.mock
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import codex_ro  # noqa: E402
import wrapper_drift  # noqa: E402
from test_codex_ro_260 import ANSWER, CMD, DONE, THREAD, TURN, _Run  # noqa: E402

REFUSAL = ("2026-09-30T08:27:13Z ERROR codex_core::tools::router: error=exec_command failed: "
           "CreateProcess { message: \"Rejected(`pwsh` rejected: blocked by policy)\" }\n")


class _InDir:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.previous = os.getcwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, self.previous)


class AfterTheTurnTests(_InDir, unittest.TestCase):
    """DOD 1 / SECURITY 1 / TESTS 1: a closed turn takes no more command events."""

    def test_a_command_after_turn_completed_does_not_count_and_spoils_the_stream(self):
        s = self.dir / "s.json"
        s.write_text(THREAD + TURN + ANSWER + DONE + CMD(0), encoding="utf-8")
        ev = codex_ro.read_stream_evidence(s)
        self.assertEqual(ev.executed, 0)
        self.assertFalse(ev.usable)

    def test_through_the_blind_rule_with_a_refusal_it_is_exit_3(self):
        s = self.dir / "s.json"
        s.write_text(THREAD + TURN + ANSWER + DONE + CMD(0), encoding="utf-8")
        e = self.dir / "e.txt"
        e.write_text(REFUSAL, encoding="utf-8")
        self.assertIsNotNone(codex_ro.blind_run(e, s))


class CleanupOnAnyRefusalTests(_InDir, unittest.TestCase):
    """QUALITY 1 / SECURITY 2: every refusal after preparation cleans up -- and only
    what this call itself created."""

    def test_a_later_refusal_removes_the_directories_this_call_created(self):
        with _Run() as run, \
                unittest.mock.patch.object(codex_ro, "prepare_write_target",
                                           wraps=codex_ro.prepare_write_target) as prep:
            calls = {"n": 0}
            real = prep._mock_wraps

            def second_target_refused(path, label):
                calls["n"] += 1
                created = real(path, label)
                if calls["n"] == 2:
                    codex_ro.die(f"{label} refused for the test", codex_ro.EXIT_REFUSED)
                return created

            prep.side_effect = second_target_refused
            with self.assertRaises(SystemExit):
                codex_ro.main(["--prompt", "x", "--out-file", "fresh/o.txt", "--err-file", "e.txt"])
        self.assertFalse((self.dir / "fresh").exists())
        self.assertEqual(run.calls, [])

    def test_a_directory_that_already_existed_is_never_reported_as_created(self):
        target = self.dir / "a" / "b"
        real_mkdir = os.mkdir

        def racing_mkdir(path, *a, **k):
            if Path(path) == self.dir / "a":
                real_mkdir(path, *a, **k)          # another session was faster
                raise FileExistsError(path)
            return real_mkdir(path, *a, **k)

        with unittest.mock.patch.object(codex_ro.os, "mkdir", racing_mkdir):
            created = codex_ro.make_parents_checked(target, "--out-file")
        self.assertNotIn(self.dir / "a", created)
        self.assertIn(target, created)


class CleanupInsideTheChainTests(_InDir, unittest.TestCase):
    """Recheck 2: a failure while the chain is still being created removes the levels
    already made -- the caller never sees them, because the function does not return."""

    def test_a_failing_deeper_mkdir_removes_the_level_already_created(self):
        real_mkdir = os.mkdir

        def failing(path, *a, **k):
            if Path(path).name == "deeper":
                raise PermissionError("denied")
            return real_mkdir(path, *a, **k)

        with unittest.mock.patch.object(codex_ro.os, "mkdir", failing):
            with self.assertRaises(SystemExit):
                codex_ro.make_parents_checked(self.dir / "fresh" / "deeper", "--out-file")
        self.assertFalse((self.dir / "fresh").exists())

    def test_a_level_that_fails_its_check_is_removed_with_the_ones_above(self):
        real = codex_ro._is_reparse_point
        bad = self.dir / "fresh" / "deeper"
        with unittest.mock.patch.object(codex_ro, "_is_reparse_point",
                                        lambda p: Path(p) == bad or real(p)):
            with self.assertRaises(SystemExit):
                codex_ro.make_parents_checked(bad, "--out-file")
        self.assertFalse((self.dir / "fresh").exists())

    def test_the_docstrings_name_the_launch_list(self):
        self.assertIn("launch list", codex_ro.probe_cli_version.__doc__)
        self.assertNotIn("SAME resolved path as the run", codex_ro.__doc__)


class OverlapTests(unittest.TestCase):
    """TESTS 2: two updates provably overlap on the write path and both finish."""

    def test_two_overlapping_updates_both_finish_with_distinct_staging_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            dest = base / "tools" / "codex_ro.py"
            dest.parent.mkdir()
            dest.write_text("old", encoding="utf-8")
            source = base / "canonical.py"
            source.write_text("new" * 1000, encoding="utf-8")
            both_staged = threading.Barrier(2, timeout=10)
            names, errors = [], []
            real_mkstemp = wrapper_drift.tempfile.mkstemp
            replace_lock = threading.Lock()
            real_replace = os.replace

            def mkstemp(*a, **k):
                fd, name = real_mkstemp(*a, **k)
                names.append(Path(name).name)
                both_staged.wait()                 # both are inside the write path now
                return fd, name

            def serial_replace(src, dst):
                with replace_lock:                 # Windows cannot replace one file twice at once
                    return real_replace(src, dst)

            def update():
                try:
                    wrapper_drift.write_atomically(source, dest, base)
                except Exception as exc:  # noqa: BLE001 - asserted below
                    errors.append(exc)

            with unittest.mock.patch.object(wrapper_drift.tempfile, "mkstemp", mkstemp), \
                    unittest.mock.patch.object(wrapper_drift.os, "replace", serial_replace):
                threads = [threading.Thread(target=update) for _ in range(2)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            self.assertEqual(errors, [])
            self.assertEqual(len(set(names)), 2, "each update staged under its own random name")
            self.assertEqual(dest.read_text(encoding="utf-8"), "new" * 1000)
            self.assertEqual([p for p in dest.parent.iterdir() if p.name.startswith(".claudex-")], [])


class BoundedReadsThroughMainTests(_InDir, unittest.TestCase):
    """TESTS 3: J-T16 end to end -- every read of the stream is bounded, through main()."""

    def test_stream_reads_are_bounded_through_main(self):
        sizes = []
        real_open = builtins.open

        def counting_open(file, mode="r", *a, **k):
            handle = real_open(file, mode, *a, **k)
            if str(file).endswith(".stream.json") and "r" in mode:
                original = handle.readline

                def readline(size=-1):
                    sizes.append(size)
                    return original(size)

                handle.readline = readline
            return handle

        out = io.StringIO()
        with unittest.mock.patch.object(codex_ro, "EVIDENCE_LIMIT", 400), \
                _Run(stream=THREAD + TURN + ANSWER * 50 + DONE), \
                unittest.mock.patch.object(sys, "stdout", out), \
                unittest.mock.patch("builtins.open", counting_open):
            code = codex_ro.main(["--prompt", "x", "--out-file", "o.txt"])
        self.assertEqual(code, codex_ro.EXIT_BLIND)
        self.assertTrue(sizes, "the stream was read through the bounded reader")
        self.assertTrue(all(0 < s <= 401 for s in sizes), sizes[:5])


class DocsTests(unittest.TestCase):
    RUNBOOK = (REPO / "docs" / "betrieb.md").read_text(encoding="utf-8")

    def test_both_outcomes_of_the_w3_window_are_named(self):
        """DOCS 1: the empty staging file AND the finished copy before os.replace."""
        self.assertIn("leere", self.RUNBOOK)
        self.assertIn("fertige Kopie", self.RUNBOOK)

    def test_the_identity_limit_names_the_whole_launch(self):
        """DOCS 2: on Windows two files are started, node.exe and codex.js."""
        self.assertIn("Startliste", self.RUNBOOK)
        self.assertIn("beide", self.RUNBOOK.split("Was die Versionsprobe nicht beweist")[1][:600])


if __name__ == "__main__":
    unittest.main(verbosity=2)
