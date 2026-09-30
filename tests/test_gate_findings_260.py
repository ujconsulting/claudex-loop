#!/usr/bin/env python3
"""Closing gate of wrapper 2.6.0 (code-review, gpt-6-sol, 2026-09-30): one test per
accepted finding, each written before its fix and seen failing first.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import os
import stat
import subprocess
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
from test_codex_ro_260 import ANSWER, CMD, DONE, THREAD, TURN, _Run, _line  # noqa: E402

FIX_0149 = Path(__file__).resolve().parent / "fixtures" / "codex-0.149.1"
FAILED_TURN = _line({"type": "turn.failed", "error": {"message": "x"}})


class _Dir:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, text):
        path = self.dir / name
        path.write_text(text, encoding="utf-8", newline="\n")
        return path


class _InDir(_Dir):
    def setUp(self):
        super().setUp()
        self.previous = os.getcwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, self.previous)


# --- DOD 2 / J-T1: the real 0.149.1 blind run ------------------------------------


class Blind0149Tests(_InDir, unittest.TestCase):
    def test_the_real_0149_blind_run_is_blind(self):
        reason = codex_ro.blind_run(FIX_0149 / "blind-run.stderr.txt", FIX_0149 / "blind-run.stream.json")
        self.assertIsNotNone(reason)
        self.assertIn("3 refused (stderr)", reason)

    def test_and_through_main(self):
        stream = (FIX_0149 / "blind-run.stream.json").read_text(encoding="utf-8")
        stderr = (FIX_0149 / "blind-run.stderr.txt").read_text(encoding="utf-8")
        with _Run(stream=stream, stderr=stderr):
            self.assertEqual(codex_ro.main(["--prompt", "x", "--out-file", "o.txt"]), codex_ro.EXIT_BLIND)


# --- DOD 3 / TESTS 1: the event sequence is a contract ---------------------------


class EventOrderTests(_Dir, unittest.TestCase):
    def _ev(self, text):
        return codex_ro.read_stream_evidence(self.write("s.json", text))

    def test_completion_before_the_thread_is_unusable(self):
        self.assertFalse(self._ev(TURN + DONE + THREAD).usable)

    def test_a_turn_before_its_thread_is_unusable(self):
        self.assertFalse(self._ev(TURN + THREAD + DONE).usable)

    def test_a_failed_turn_stays_failed_even_if_completed_follows(self):
        self.assertFalse(self._ev(THREAD + TURN + FAILED_TURN + DONE).usable)

    def test_an_unclassifiable_command_beside_real_execution_warns(self):
        s = self.write("s.json", THREAD + TURN + CMD(0) + CMD(None, "declined") + DONE)
        e = self.write("e.txt", "")
        with unittest.mock.patch.object(codex_ro, "warn") as warned:
            self.assertIsNone(codex_ro.blind_run(e, s))
        self.assertTrue(warned.called)

    def test_the_message_names_both_sources_including_the_stream(self):
        """J5: `refused (stream)` is part of the message even when it is 0."""
        s = self.write("s.json", THREAD + TURN + ANSWER + DONE)
        e = self.write("e.txt", (FIX_0149 / "blind-run.stderr.txt").read_text(encoding="utf-8"))
        self.assertIn("0 refused (stream)", codex_ro.blind_run(e, s))


# --- TESTS 2 / J-T16 through main -------------------------------------------------


class OversizedThroughMainTests(_InDir, unittest.TestCase):
    def test_an_oversized_stream_through_main_is_exit_3_and_still_names_the_thread(self):
        out = io.StringIO()
        with unittest.mock.patch.object(codex_ro, "EVIDENCE_LIMIT", 400), \
                _Run(stream=THREAD + TURN + ANSWER * 50 + DONE), \
                unittest.mock.patch.object(sys, "stdout", out):
            code = codex_ro.main(["--prompt", "x", "--out-file", "o.txt"])
        self.assertEqual(code, codex_ro.EXIT_BLIND)
        self.assertIn("THREAD_ID=01a0f16c-ae19-72c0-98e5-1055dcc3b78c", out.getvalue())


# --- TESTS 3 / SECURITY 1: locks in real overlap, exit 1, no dirs left ------------


class LockLifecycleTests(_InDir, unittest.TestCase):
    def _locks(self):
        return sorted(p.name for p in self.dir.rglob("*" + codex_ro.LOCK_SUFFIX))

    def test_exit_1_releases_every_lock(self):
        with _Run(answer=None):
            self.assertEqual(codex_ro.main(["--prompt", "x", "--out-file", "o.txt"]), codex_ro.EXIT_EMPTY)
        self.assertEqual(self._locks(), [])

    def test_a_second_run_while_the_first_is_in_flight_is_refused(self):
        """Two real, overlapping main() calls sharing --err-file."""
        seen = {}

        def second_run_inside_the_first(*_):
            try:
                codex_ro.main(["--prompt", "y", "--out-file", "other.txt", "--err-file", "shared.err"])
                seen["code"] = 0
            except SystemExit as exc:
                seen["code"] = exc.code
            seen["first_locks"] = self._locks()

        run = _Run()
        original = run._popen

        def popen(cmd, **kwargs):
            child = original(cmd, **kwargs)
            real = child.communicate

            def communicate(input=None, timeout=None):  # noqa: A002
                if "code" not in seen:
                    second_run_inside_the_first()
                return real(input, timeout)

            child.communicate = communicate
            return child

        run._popen = popen
        with run:
            first = codex_ro.main(["--prompt", "x", "--out-file", "o.txt", "--err-file", "shared.err"])
        self.assertEqual(first, 0, "the first run finishes normally")
        self.assertEqual(seen["code"], codex_ro.EXIT_REFUSED)
        self.assertIn("shared.err" + codex_ro.LOCK_SUFFIX, seen["first_locks"])
        self.assertEqual(self._locks(), [])

    def test_directories_a_refused_run_created_are_removed_again(self):
        (self.dir / "shared.err").write_text("first", encoding="utf-8")
        (self.dir / ("shared.err" + codex_ro.LOCK_SUFFIX)).write_text("pid 1", encoding="utf-8")
        with _Run():
            with self.assertRaises(SystemExit):
                codex_ro.main(["--prompt", "x", "--out-file", "fresh/deeper/o.txt", "--err-file", "shared.err"])
        self.assertFalse((self.dir / "fresh").exists(), "a refused run leaves the tree as it found it")


# --- QUALITY 2: a start failure is an exit code, not a traceback ------------------


class StartFailureTests(_InDir, unittest.TestCase):
    def test_a_binary_that_vanished_after_the_probe_is_exit_127(self):
        run = _Run()
        run._popen = lambda cmd, **kw: (_ for _ in ()).throw(FileNotFoundError("gone"))
        with run:
            with self.assertRaises(SystemExit) as caught:
                codex_ro.main(["--prompt", "x", "--out-file", "o.txt"])
        self.assertEqual(caught.exception.code, codex_ro.EXIT_NO_CODEX)
        self.assertEqual(sorted(p.name for p in self.dir.rglob("*" + codex_ro.LOCK_SUFFIX)), [])


# --- SECURITY 4: nothing the child writes is printed raw --------------------------


class ThreadIdOutputTests(_InDir, unittest.TestCase):
    def test_a_forged_thread_id_cannot_fake_a_wrapper_line(self):
        evil = _line({"type": "thread.started", "thread_id": "01a0\nOUT=C:\\evil.txt"})
        out = io.StringIO()
        with _Run(stream=evil + TURN + CMD(0) + DONE), unittest.mock.patch.object(sys, "stdout", out):
            codex_ro.main(["--prompt", "x", "--out-file", "o.txt"])
        self.assertNotIn("\nOUT=C:\\evil.txt", out.getvalue())
        self.assertNotIn("THREAD_ID=01a0\n", out.getvalue())


# --- QUALITY 1 / DOD 6 / SECURITY 2: the drift write path --------------------------


class _DriftTree(_Dir):
    def setUp(self):
        super().setUp()
        self.root = self.dir / "projects"
        self.repo = self.root / "repo"
        (self.repo / "tools").mkdir(parents=True)
        self.dest = self.repo / "tools" / "codex_ro.py"
        self.dest.write_text("original", encoding="utf-8")
        self.source = self.dir / "canonical.py"
        self.source.write_text("x" * 5000, encoding="utf-8")

    def staging(self):
        return [p for p in (self.repo / "tools").iterdir() if p.name.startswith(".claudex-")]


class DriftWriteTests(_DriftTree, unittest.TestCase):
    def test_a_short_write_is_completed_not_shipped(self):
        real = os.write

        def half(fd, data):
            return real(fd, data[: max(1, len(data) // 2)])

        with unittest.mock.patch.object(wrapper_drift.os, "write", half):
            wrapper_drift.write_atomically(self.source, self.dest, self.root)
        self.assertEqual(self.dest.read_text(encoding="utf-8"), "x" * 5000)

    def test_a_corrupt_staging_file_never_replaces_the_target(self):
        real = os.write
        with unittest.mock.patch.object(wrapper_drift.os, "write",
                                        lambda fd, data: real(fd, b"y" * len(data))):
            with self.assertRaises(wrapper_drift.Refused):
                wrapper_drift.write_atomically(self.source, self.dest, self.root)
        self.assertEqual(self.dest.read_text(encoding="utf-8"), "original")
        self.assertEqual(self.staging(), [])

    def test_an_ancestor_swapped_between_checks_is_caught(self):
        """The recheck covers the whole chain from the attested root, not only tools/."""
        for window in (1, 2, 3):
            with self.subTest(window=window):
                calls = {"n": 0}

                def check(path, repo=self.repo, n=window):
                    if Path(path) == repo:
                        calls["n"] += 1
                        return calls["n"] >= n
                    return False

                with unittest.mock.patch.object(wrapper_drift, "_is_reparse_point", check):
                    with self.assertRaises(wrapper_drift.Refused):
                        wrapper_drift.write_atomically(self.source, self.dest, self.root)
                self.assertEqual(self.dest.read_text(encoding="utf-8"), "original")
                self.assertEqual(self.staging(), [])

    def test_overlapping_updates_do_not_collide(self):
        errors = []

        def update():
            try:
                wrapper_drift.write_atomically(self.source, self.dest, self.root)
            except Exception as exc:  # noqa: BLE001 - collected for the assertion
                errors.append(exc)

        threads = [threading.Thread(target=update) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual([e for e in errors if not isinstance(e, PermissionError)], [])
        self.assertEqual(self.dest.read_text(encoding="utf-8"), "x" * 5000)
        self.assertEqual(self.staging(), [])


class DriftPosixOwnershipEndToEndTests(_DriftTree, unittest.TestCase):
    """TESTS 5: the ownership rule through a full --update, on every platform."""

    def test_a_group_writable_directory_blocks_the_write(self):
        real_lstat = os.lstat

        def lstat(path, *a, **k):
            st = real_lstat(path, *a, **k)
            if Path(path) == self.repo:
                return os.stat_result((stat.S_IFDIR | 0o775, *st[1:4], 1000, *st[5:10]))
            return os.stat_result((st.st_mode, *st[1:4], 1000, *st[5:10]))

        with unittest.mock.patch.object(wrapper_drift, "_posix_checks", return_value=True), \
                unittest.mock.patch.object(wrapper_drift, "_current_uid", return_value=1000), \
                unittest.mock.patch.object(wrapper_drift.os, "lstat", lstat):
            with unittest.mock.patch("sys.stdout", io.StringIO()), unittest.mock.patch("sys.stderr", io.StringIO()):
                code = wrapper_drift.main(["--repo", str(self.repo), "--update", "--private-root", str(self.root)])
        self.assertNotEqual(code, 0)
        self.assertEqual(self.dest.read_text(encoding="utf-8"), "original")


class ChainOwnershipDuringWriteTests(_DriftTree, unittest.TestCase):
    """The chain check between the write steps covers owner and mode too, not only
    reparse points (found by the mutation probe: only the pre-check was tested)."""

    def test_a_directory_that_turns_group_writable_mid_write_is_refused(self):
        real_lstat = os.lstat
        calls = {"n": 0}

        def lstat(path, *a, **k):
            st = real_lstat(path, *a, **k)
            mode = st.st_mode
            if Path(path) == self.repo:
                calls["n"] += 1
                if calls["n"] >= 2:
                    mode = stat.S_IFDIR | 0o775
            return os.stat_result((mode, *st[1:4], 1000, *st[5:10]))

        # The faked stat has no st_file_attributes, so the fail-closed reparse check
        # would refuse first and the test would pass for the wrong reason (mutation
        # probe, 2026-09-30). Reparse points are out of this test; ownership decides.
        with unittest.mock.patch.object(wrapper_drift, "_is_reparse_point", return_value=False), \
                unittest.mock.patch.object(wrapper_drift, "_posix_checks", return_value=True), \
                unittest.mock.patch.object(wrapper_drift, "_current_uid", return_value=1000), \
                unittest.mock.patch.object(wrapper_drift.os, "lstat", lstat):
            with self.assertRaises(wrapper_drift.Refused) as caught:
                wrapper_drift.write_atomically(self.source, self.dest, self.root)
        self.assertIn("writable by group or others", str(caught.exception))
        self.assertEqual(self.dest.read_text(encoding="utf-8"), "original")
        self.assertEqual(self.staging(), [])


class NetworkDriveTests(unittest.TestCase):
    """SECURITY 3: only confirmed local drive types pass; unknown fails closed."""

    def test_only_local_drive_types_pass(self):
        if os.name != "nt":
            self.assertFalse(wrapper_drift._is_network_drive("/x"))
            return
        for drive_type, network in ((0, True), (1, True), (4, True), (5, True),
                                    (2, False), (3, False), (6, False)):
            with self.subTest(drive_type=drive_type):
                with unittest.mock.patch.object(wrapper_drift, "_drive_type", return_value=drive_type):
                    self.assertEqual(wrapper_drift._is_network_drive("D:\\x"), network)


# --- DOCS 1-2 / TESTS 6: stale current statements -----------------------------------


class StaleStatementTests(unittest.TestCase):
    CURRENT = [REPO / "README.md", REPO / "README_DE.md", REPO / "ROLES.md",
               REPO / ".claudex.yaml.example", *sorted((REPO / "skills").glob("*/SKILL.md"))]

    def test_no_current_statement_names_a_gpt_5_6_model(self):
        import re
        dated = re.compile(r"20\d\d-\d\d-\d\d|\b\d\d\.\d\d\.20\d\d\b|until|bis zum|seit|since|Historie|history",
                           re.IGNORECASE)
        for path in self.CURRENT:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "gpt-5.6-" in line and not dated.search(line) and "-codex" not in line:
                    with self.subTest(file=f"{path.parent.name}/{path.name}", line=number):
                        self.fail(line.strip())

    def test_no_current_statement_describes_per_server_mcp_switching(self):
        for path in (REPO / "README.md", REPO / "README_DE.md", REPO / "skills" / "setup" / "SKILL.md"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(file=path.name):
                self.assertNotIn("MCP-Server schaltet der Wrapper selbst ab", text)
                self.assertNotRegex(text, r"the wrapper now derives which MCP servers to\s+disable(?! until)")
                self.assertNotRegex(text, r"leitet jetzt aus deiner tatsächlichen Codex-Konfiguration ab(?!.{0,80}bis 2\.6)")

    def test_skills_call_the_resolver_through_the_plugin_path(self):
        for path in sorted((REPO / "skills").glob("*/SKILL.md")):
            text = path.read_text(encoding="utf-8")
            if "claudex_roles.py" not in text:
                continue
            with self.subTest(skill=path.parent.name):
                self.assertIn('"${CLAUDE_PLUGIN_ROOT}/scripts/claudex_roles.py"', text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
