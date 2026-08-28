#!/usr/bin/env python3
"""Tests for the read-only Codex wrapper.

Stdlib unittest on purpose: this suite has to run on a fresh macOS or Windows
machine with nothing installed but Python, because that is exactly the situation
a repo is in right after `tools/codex_ro.py` was copied into it.

Nothing here starts Codex. What is tested is the part that has to hold before
Codex is ever reached: the refusals. The live behaviour of the sandbox itself is
a measurement, recorded in the wrapper's module docstring, not a unit test.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import codex_ro  # noqa: E402


class ConfigOverrideTests(unittest.TestCase):
    """The wrapper's whole reason to exist: no override may touch the sandbox."""

    def test_each_forbidden_key_is_refused(self):
        for key in codex_ro.FORBIDDEN_CONFIG_KEYS:
            with self.subTest(key=key):
                with self.assertRaises(SystemExit) as caught:
                    codex_ro.check_config_overrides([f"{key}=whatever"])
                self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_dotted_child_keys_are_refused(self):
        with self.assertRaises(SystemExit) as caught:
            codex_ro.check_config_overrides(["sandbox_workspace_write.network_access=true"])
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_surrounding_whitespace_does_not_hide_the_key(self):
        with self.assertRaises(SystemExit):
            codex_ro.check_config_overrides(["  sandbox_mode  =danger-full-access"])

    def test_a_lookalike_key_is_not_refused(self):
        # sandbox_mode_note is a different key; refusing it would be a false positive.
        codex_ro.check_config_overrides(["sandbox_mode_note=hello", "model_verbosity=low"])


class ArgvTests(unittest.TestCase):
    """What actually reaches Codex on each of the two paths."""

    def _args(self, extra=None):
        return codex_ro.parse_args(["--prompt", "x", "--out-file", "out.txt"] + (extra or []))

    def test_exec_path_pins_read_only_with_dash_s(self):
        argv = codex_ro.build_argv(self._args(), Path("out.txt"))
        self.assertIn("-s", argv)
        self.assertEqual(argv[argv.index("-s") + 1], "read-only")

    def test_resume_path_pins_read_only_via_config(self):
        # resume knows no -s; read-only is reachable only through -c there.
        argv = codex_ro.build_argv(self._args(["--resume", "01a047d5-4e4b-7662-8672-0ccbf2f514f0"]), Path("out.txt"))
        self.assertNotIn("-s", argv)
        self.assertIn("sandbox_mode=read-only", argv)

    def test_resume_path_names_sandbox_mode_exactly_once(self):
        # A later -c beats an earlier one, so a second occurrence would decide.
        argv = codex_ro.build_argv(self._args(["--resume", "01a047d5-4e4b-7662-8672-0ccbf2f514f0"]), Path("out.txt"))
        occurrences = [a for a in argv if a.startswith("sandbox_mode=")]
        self.assertEqual(occurrences, ["sandbox_mode=read-only"])

    def test_disable_mcp_is_overridable_and_can_be_emptied(self):
        argv = codex_ro.build_argv(self._args(["--disable-mcp", "foo, bar"]), Path("out.txt"))
        self.assertIn("mcp_servers.foo.enabled=false", argv)
        self.assertIn("mcp_servers.bar.enabled=false", argv)
        argv_none = codex_ro.build_argv(self._args(["--disable-mcp", ""]), Path("out.txt"))
        self.assertFalse([a for a in argv_none if a.startswith("mcp_servers.")])

    def test_prompt_is_never_passed_as_an_argument(self):
        # It goes over stdin; an argument would also have to be quoted, and the
        # missing EOF would hang codex exec under a non-interactive driver.
        argv = codex_ro.build_argv(self._args(), Path("out.txt"))
        self.assertNotIn("x", argv)


class PathConfinementTests(unittest.TestCase):
    """--out-file is deleted before the run, so an unbounded path is a write primitive."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def test_a_path_inside_a_root_is_accepted(self):
        target = self.root / "sub" / "verdict.txt"
        self.assertEqual(codex_ro.resolve_in_roots(str(target), [self.root], "--out-file"), target)

    def test_a_path_outside_every_root_is_refused(self):
        outside = Path(tempfile.gettempdir()).resolve() / "elsewhere" / "verdict.txt"
        with self.assertRaises(SystemExit) as caught:
            codex_ro.resolve_in_roots(str(outside), [self.root], "--out-file")
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_dot_dot_cannot_climb_out_of_a_root(self):
        with self.assertRaises(SystemExit):
            codex_ro.resolve_in_roots(str(self.root / ".." / "escaped.txt"), [self.root], "--out-file")

    def test_a_sibling_with_a_shared_prefix_is_not_inside(self):
        # String prefix matching would accept `<root>-evil`; path matching must not.
        sibling = Path(str(self.root) + "-evil") / "verdict.txt"
        with self.assertRaises(SystemExit):
            codex_ro.resolve_in_roots(str(sibling), [self.root], "--out-file")

    def test_the_repo_and_the_temp_dir_are_roots_by_default(self):
        roots = codex_ro.allowed_roots([])
        self.assertIn(Path(tempfile.gettempdir()).resolve(), roots)
        self.assertTrue(any((r / ".git").exists() for r in roots), "the repo root should be a root")

    def test_an_opt_in_root_is_honoured(self):
        extra = Path(tempfile.gettempdir()).resolve()
        self.assertIn(extra, codex_ro.allowed_roots([str(extra)]))


class RefusalExitCodeTests(unittest.TestCase):
    """main() must refuse before it creates, deletes or reads anything."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self.tmp.name).resolve()
        self.previous = Path.cwd()
        os.chdir(self.cwd)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: os.chdir(self.previous))

    def _refuses(self, argv):
        with self.assertRaises(SystemExit) as caught:
            codex_ro.main(argv)
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_model_may_not_carry_extra_arguments(self):
        self._refuses(["--prompt", "x", "--out-file", "o.txt",
                       "--model", "gpt-5.6-terra -c sandbox_mode=danger-full-access"])

    def test_resume_must_look_like_a_thread_id(self):
        self._refuses(["--prompt", "x", "--out-file", "o.txt", "--resume", "not-an-id; rm -rf /"])

    def test_an_empty_prompt_is_refused(self):
        self._refuses(["--prompt", "   ", "--out-file", "o.txt"])

    def test_a_missing_prompt_file_is_refused(self):
        self._refuses(["--prompt-file", str(self.cwd / "absent.txt"), "--out-file", "o.txt"])

    def test_a_non_positive_timeout_is_refused(self):
        self._refuses(["--prompt", "x", "--out-file", "o.txt", "--timeout", "0"])

    def test_nothing_is_created_on_the_refusal_path(self):
        with self.assertRaises(SystemExit):
            codex_ro.main(["--prompt", "x", "--out-file", "sub/o.txt", "--model", "bad model"])
        self.assertFalse((self.cwd / "sub").exists(), "the output directory must not be created")


class SilentDeathTests(unittest.TestCase):
    """Upstream issue #10.1: a killed binary must not be reported as an auth failure."""

    def test_sigkill_is_named_as_such_and_not_as_auth(self):
        message = codex_ro.diagnose_silent_death("/usr/local/bin/codex", 137)
        self.assertIn("137", message)
        self.assertIn("SIGKILL", message)
        self.assertIn("do not retry", message.lower())
        self.assertNotIn("401", message)

    def test_the_binary_that_failed_is_named(self):
        self.assertIn("/opt/weird/codex", codex_ro.diagnose_silent_death("/opt/weird/codex", 1))

    def test_bundled_lookup_is_darwin_only(self):
        if sys.platform != "darwin":
            self.assertIsNone(codex_ro.bundled_codex())

    def test_an_explicit_binary_override_is_honoured(self):
        with tempfile.NamedTemporaryFile(suffix=".sh", delete=False) as handle:
            fake = handle.name
        self.addCleanup(lambda: os.path.exists(fake) and os.unlink(fake))
        previous = os.environ.get("CLAUDEX_CODEX_BIN")
        os.environ["CLAUDEX_CODEX_BIN"] = fake
        try:
            self.assertEqual(os.path.realpath(codex_ro.find_codex()), os.path.realpath(fake))
        finally:
            if previous is None:
                del os.environ["CLAUDEX_CODEX_BIN"]
            else:
                os.environ["CLAUDEX_CODEX_BIN"] = previous

    def test_an_override_pointing_nowhere_is_refused(self):
        previous = os.environ.get("CLAUDEX_CODEX_BIN")
        os.environ["CLAUDEX_CODEX_BIN"] = str(Path(tempfile.gettempdir()) / "no-such-codex-binary")
        try:
            with self.assertRaises(SystemExit) as caught:
                codex_ro.find_codex()
            self.assertEqual(caught.exception.code, codex_ro.EXIT_NO_CODEX)
        finally:
            if previous is None:
                del os.environ["CLAUDEX_CODEX_BIN"]
            else:
                os.environ["CLAUDEX_CODEX_BIN"] = previous


class ThreadIdTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.stream = Path(self.tmp.name) / "stream.json"
        self.addCleanup(self.tmp.cleanup)

    def test_the_started_event_wins_over_later_mentions(self):
        self.stream.write_text(
            '{"type":"thread.started","thread_id":"01a0-first"}\n'
            '{"type":"item.completed","thread_id":"01a0-second"}\n',
            encoding="utf-8",
        )
        self.assertEqual(codex_ro.read_thread_id(self.stream), "01a0-first")

    def test_a_missing_stream_is_not_an_error(self):
        self.assertIsNone(codex_ro.read_thread_id(Path(self.tmp.name) / "absent.json"))


class KillTreeTests(unittest.TestCase):
    """The PowerShell version had a bare `catch { }` here. A failed kill must speak."""

    def test_a_failing_kill_is_reported(self):
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()

        class _Refuses:
            returncode = 1
            stdout = ""
            stderr = "the process could not be terminated"

        original_run, original_killpg = subprocess.run, getattr(os, "killpg", None)
        subprocess.run = lambda *a, **k: _Refuses()
        if original_killpg is not None:
            os.killpg = lambda *a, **k: (_ for _ in ()).throw(OSError("no such process group"))
        try:
            with _CapturedStderr() as captured:
                codex_ro.kill_tree(proc)
        finally:
            subprocess.run = original_run
            if original_killpg is not None:
                os.killpg = original_killpg

        self.assertIn("codex_ro:", captured.text)
        self.assertNotEqual(captured.text.strip(), "", "a failed kill must not be swallowed")

    def test_a_successful_kill_stops_the_child(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            codex_ro.kill_tree(proc)
            proc.wait(timeout=15)
        finally:
            if proc.poll() is None:  # pragma: no cover - only on a failed kill
                proc.kill()
                proc.wait(timeout=5)
        self.assertIsNotNone(proc.poll(), "the child must be gone after kill_tree")


class _CapturedStderr:
    def __enter__(self):
        import io

        self._previous = sys.stderr
        self._buffer = io.StringIO()
        sys.stderr = self._buffer
        return self

    def __exit__(self, *exc):
        sys.stderr = self._previous
        self.text = self._buffer.getvalue()
        return False


if __name__ == "__main__":
    unittest.main(verbosity=2)
