#!/usr/bin/env python3
"""Wrapper 2.6.0: blind-run evidence from stderr AND the event stream, the CLI
version probe, reviewer isolation, output locks, fail-closed reparse checks.

Plan: docs/plans/2026-09-23-codex-heben-wrapper-2.6.0 (git-ignored; the measured
basis is summarised where each test needs it). Fixtures under
tests/fixtures/codex-0.156/ are real, anonymised codex-cli 0.156.0 output
measured on 2026-09-30.

Every test here was written before the code it tests and seen failing first.
Nothing starts Codex: find_codex, the version probe and Popen are faked.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import codex_ro  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "codex-0.156"

REFUSAL_LINE = (
    "2026-09-30T08:27:13.724118Z ERROR codex_core::tools::router: error=exec_command failed: "
    "CreateProcess { message: \"Rejected(\\\"`pwsh.exe -Command Get-Content probe.txt` "
    "rejected: blocked by policy\\\")\" }\n"
)


def _line(obj) -> str:
    return json.dumps(obj, separators=(",", ":")) + "\n"


THREAD = _line({"type": "thread.started", "thread_id": "01a0f16c-ae19-72c0-98e5-1055dcc3b78c"})
TURN = _line({"type": "turn.started"})
DONE = _line({"type": "turn.completed", "usage": {"input_tokens": 1}})
FAILED_TURN = _line({"type": "turn.failed", "error": {"message": "usage limit"}})
ANSWER = _line({"type": "item.completed", "item": {"id": "i9", "type": "agent_message", "text": "OK"}})


def CMD(exit_code=0, status="completed"):
    return _line({"type": "item.completed", "item": {
        "id": "i1", "type": "command_execution", "command": "pwsh -Command Get-Content x",
        "aggregated_output": "", "exit_code": exit_code, "status": status}})


COLLAB = _line({"type": "item.completed", "item": {"id": "i2", "type": "collab_tool_call"}})


class _Dir:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, text):
        path = self.dir / name
        path.write_text(text, encoding="utf-8", newline="\n")
        return path


# --- J: evidence from the stream ----------------------------------------------


class StreamEvidenceTests(_Dir, unittest.TestCase):
    """J1/J3: what the stream proves about execution."""

    def test_the_real_normal_run_counts_both_commands(self):
        ev = codex_ro.read_stream_evidence(FIXTURES / "normal-run.stream.json")
        self.assertEqual(ev.executed, 2, "a failed write (exit 1) ran too -- the sandbox let it start")
        self.assertTrue(ev.usable)
        self.assertEqual(ev.thread_id, "01a0f16e-ac36-70e2-8060-9ec2ca4b6c89")

    def test_the_real_blind_run_has_no_execution_but_a_clean_stream(self):
        ev = codex_ro.read_stream_evidence(FIXTURES / "blind-run.stream.json")
        self.assertEqual(ev.executed, 0)
        self.assertTrue(ev.usable, "J0: 0.156 writes a complete, clean stream for a blind run")

    def test_a_failed_command_with_an_integer_exit_code_counts(self):
        ev = codex_ro.read_stream_evidence(self.write("s", THREAD + TURN + CMD(1, "failed") + DONE))
        self.assertEqual(ev.executed, 1)

    def test_a_null_or_boolean_exit_code_does_not_count(self):
        """J-T3/J-T10: `type(v) is int` -- JSON true is not a process that ran."""
        for bad in (None, True, False, "0", 0.0):
            with self.subTest(exit_code=bad):
                ev = codex_ro.read_stream_evidence(
                    self.write("s", THREAD + TURN + CMD(bad, "completed") + DONE))
                self.assertEqual(ev.executed, 0)
                self.assertEqual(ev.unclassified, 1)

    def test_an_unknown_status_does_not_count(self):
        ev = codex_ro.read_stream_evidence(self.write("s", THREAD + TURN + CMD(0, "declined") + DONE))
        self.assertEqual((ev.executed, ev.unclassified), (0, 1))

    def test_only_the_last_turn_counts(self):
        """J-T7: resume safety -- an earlier turn's command is not evidence for this one."""
        text = THREAD + TURN + CMD(0) + DONE + TURN + ANSWER + DONE
        ev = codex_ro.read_stream_evidence(self.write("s", text))
        self.assertEqual(ev.executed, 0)
        self.assertTrue(ev.usable)

    def test_the_real_resume_stream_is_clean_with_no_commands(self):
        ev = codex_ro.read_stream_evidence(FIXTURES / "resume.stream.json")
        self.assertEqual(ev.executed, 0)
        self.assertTrue(ev.usable)

    def test_a_truncated_turn_is_unusable(self):
        """J-T12: turn.started without turn.completed."""
        ev = codex_ro.read_stream_evidence(self.write("s", THREAD + TURN + ANSWER))
        self.assertFalse(ev.usable)

    def test_a_failed_turn_is_unusable(self):
        ev = codex_ro.read_stream_evidence(self.write("s", THREAD + TURN + FAILED_TURN))
        self.assertFalse(ev.usable)

    def test_missing_empty_broken_or_turnless_streams_are_unusable(self):
        """J-T5, the stream half."""
        cases = {
            "missing": None,
            "empty": "",
            "broken line": THREAD + TURN + "{not json\n" + DONE,
            "no turn": THREAD + ANSWER,
            "no thread": TURN + DONE,
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                path = self.dir / f"{name}.json"
                if text is not None:
                    path.write_text(text, encoding="utf-8")
                self.assertFalse(codex_ro.read_stream_evidence(path).usable)

    def test_model_text_never_counts_as_execution(self):
        """J-T9: an agent_message that talks about command_execution is text."""
        fake = _line({"type": "item.completed", "item": {
            "type": "agent_message", "text": '{"type":"command_execution","exit_code":0}'}})
        ev = codex_ro.read_stream_evidence(self.write("s", THREAD + TURN + fake + DONE))
        self.assertEqual(ev.executed, 0)

    def test_an_oversized_stream_is_unusable_and_not_read_whole(self):
        """J-T11/J-T16: the limit holds, and the thread id still comes from the head."""
        path = self.write("s", THREAD + TURN + ANSWER * 200 + DONE)
        reads = []
        real_open = open

        def counting_open(*a, **k):
            handle = real_open(*a, **k)
            original = handle.readline

            def readline(size=-1):
                reads.append(size)
                return original(size)

            handle.readline = readline
            return handle

        with unittest.mock.patch("builtins.open", counting_open):
            ev = codex_ro.read_stream_evidence(path, limit=400)
        self.assertFalse(ev.usable)
        self.assertEqual(ev.thread_id, "01a0f16c-ae19-72c0-98e5-1055dcc3b78c")
        self.assertTrue(reads and all(0 < s <= 401 for s in reads),
                        f"every read must be bounded by the limit, got {reads[:5]}")


class StderrRefusalTests(_Dir, unittest.TestCase):
    def test_the_real_blind_run_stderr_has_one_refusal(self):
        self.assertEqual(codex_ro.count_stderr_refusals(FIXTURES / "blind-run.stderr.txt"), (1, True))

    def test_a_refusal_behind_more_than_200_kib_is_found(self):
        """J-T8: the old reader kept only the last 200 KiB."""
        path = self.write("e", REFUSAL_LINE + ("x" * 120 + "\n") * 3000)
        self.assertEqual(codex_ro.count_stderr_refusals(path)[0], 1)

    def test_an_oversized_stderr_is_unusable(self):
        path = self.write("e", ("x" * 100 + "\n") * 20)
        self.assertEqual(codex_ro.count_stderr_refusals(path, limit=500)[1], False)

    def test_a_missing_stderr_is_not_an_accusation(self):
        self.assertEqual(codex_ro.count_stderr_refusals(self.dir / "absent"), (0, True))


class BlindVerdictTests(_Dir, unittest.TestCase):
    """The rule: Exit 3 when nothing provably ran AND (a refusal OR unusable evidence)."""

    def _blind(self, stream, stderr):
        s = self.write("stream.json", stream) if stream is not None else self.dir / "nostream"
        e = self.write("stderr.txt", stderr)
        return codex_ro.blind_run(e, s)

    def test_the_real_0156_blind_run_is_blind(self):
        """J-T6: stderr refusal, clean stream, no command_execution."""
        reason = codex_ro.blind_run(FIXTURES / "blind-run.stderr.txt", FIXTURES / "blind-run.stream.json")
        self.assertIsNotNone(reason)
        self.assertIn("0 executed", reason)

    def test_a_refusal_followed_by_real_work_is_not_blind(self):
        """J-T2: the old rule failed this -- `succeeded in` never appears with --json."""
        self.assertIsNone(self._blind(THREAD + TURN + CMD(0) + DONE, REFUSAL_LINE))

    def test_zero_commands_without_a_refusal_is_allowed(self):
        """J-T4: 12 of 72 real runs answered with no command (resume, exposure)."""
        self.assertIsNone(self._blind(THREAD + TURN + ANSWER + DONE, ""))

    def test_unusable_evidence_with_nothing_executed_is_blind(self):
        for name, stream in {"missing": None, "truncated": THREAD + TURN + ANSWER,
                             "broken": THREAD + TURN + "garbage\n" + DONE}.items():
            with self.subTest(case=name):
                self.assertIsNotNone(self._blind(stream, ""))

    def test_unusable_evidence_after_real_work_only_warns(self):
        with unittest.mock.patch.object(codex_ro, "warn") as warned:
            self.assertIsNone(self._blind(THREAD + TURN + CMD(0) + "garbage\n" + DONE, ""))
        self.assertTrue(warned.called)

    def test_sub_agent_only_work_plus_a_refusal_is_blind(self):
        """J-T14 / J4b: a documented false alarm in the safe direction."""
        self.assertIsNotNone(self._blind(THREAD + TURN + COLLAB + DONE, REFUSAL_LINE))

    def test_oversized_stderr_with_nothing_executed_is_blind(self):
        """J-T11, the stderr half through the rule itself: no refusal line can be
        seen in a stderr that was not read to the end -- unusable, not "clean".
        Found by the mutation probe: this half had no test."""
        with unittest.mock.patch.object(codex_ro, "EVIDENCE_LIMIT", 300):
            self.assertIsNotNone(self._blind(THREAD + TURN + ANSWER + DONE, ("x" * 60 + "\n") * 10))
            self.assertIsNone(self._blind(THREAD + TURN + CMD(0) + DONE, ("x" * 60 + "\n") * 10),
                              "with real execution it only warns")

    def test_an_unclassifiable_command_with_nothing_executed_is_blind(self):
        self.assertIsNotNone(self._blind(THREAD + TURN + CMD(None, "declined") + DONE, ""))


# --- A: CLI version -------------------------------------------------------------


class CliVersionParseTests(unittest.TestCase):
    def test_the_real_output_parses(self):
        self.assertEqual(codex_ro.parse_cli_version(b"codex-cli 0.156.0\n"), "0.156.0")
        self.assertEqual(codex_ro.parse_cli_version(b"codex-cli 0.156.0\r\n"), "0.156.0")
        self.assertEqual(codex_ro.parse_cli_version(b"codex-cli 0.155.0-alpha.16\n"), "0.155.0-alpha.16")

    def test_anything_else_is_unreadable(self):
        """A-T1b: multi-line, control characters, oversize, prefix/suffix noise."""
        for raw in (b"", b"0.156.0\n", b"codex-cli 0.156.0\nextra\n", b"codex-cli 0.156.0\x1b[31m\n",
                    b"codex-cli 0.156.0 " + b"x" * 300, b"codex-cli 0.156\n", b"\xff\xfe"):
            with self.subTest(raw=raw[:30]):
                self.assertIsNone(codex_ro.parse_cli_version(raw))

    def test_ordering_puts_prereleases_below_the_release(self):
        self.assertTrue(codex_ro.cli_at_least("0.156.0", "0.156.0"))
        self.assertTrue(codex_ro.cli_at_least("0.157.1", "0.156.0"))
        self.assertFalse(codex_ro.cli_at_least("0.149.1", "0.156.0"))
        self.assertFalse(codex_ro.cli_at_least("0.156.0-alpha.1", "0.156.0"))
        self.assertTrue(codex_ro.cli_at_least("0.1000.0", "0.156.0"), "numeric, not string, compare")


class CliVersionProbeTests(_Dir, unittest.TestCase):
    def _probe(self, script, timeout=10):
        return codex_ro.probe_cli_version("fake", _argv=[sys.executable, "-c", script], timeout=timeout)

    def test_a_clean_answer_is_read(self):
        self.assertEqual(self._probe("print('codex-cli 0.156.0')"), "0.156.0")

    def test_noise_is_unreadable_and_never_echoed(self):
        """A-T1b: the raw text must appear nowhere -- it comes from a PATH binary."""
        with unittest.mock.patch.object(codex_ro, "warn") as warned:
            result = self._probe("import sys; sys.stdout.write('codex-cli 0.156.0\\nFAKE LOG LINE\\n')")
        self.assertIsNone(result)
        for call in warned.call_args_list:
            self.assertNotIn("FAKE LOG LINE", " ".join(map(str, call.args)))

    def test_huge_output_is_not_read_whole(self):
        self.assertIsNone(self._probe("import sys; sys.stdout.write('x' * 5_000_000)"))

    def test_a_hanging_binary_times_out_and_leaves_no_child(self):
        pidfile = self.dir / "pid"
        script = (f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); "
                  "time.sleep(60)")
        start = time.monotonic()
        self.assertIsNone(self._probe(script, timeout=2))
        self.assertLess(time.monotonic() - start, 20)
        pid = int(pidfile.read_text())
        time.sleep(0.5)
        self.assertFalse(_alive(pid), "a timed-out version probe must not leave a process behind")

    def test_a_missing_binary_is_unreadable_not_a_traceback(self):
        self.assertIsNone(codex_ro.probe_cli_version(str(self.dir / "no-such-codex")))


def _alive(pid: int) -> bool:
    if os.name == "nt":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                             capture_output=True).stdout.decode("ascii", "ignore")
        return str(pid) in out
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


class ModelMinimumTests(unittest.TestCase):
    """A3b: gpt-6-sol on 0.149.1 is HTTP 400 on every call (measured 2026-09-22)."""

    def test_the_table_carries_the_measured_minimum(self):
        self.assertEqual(codex_ro.MODEL_MIN_CLI["gpt-6-sol"], "0.156.0")

    def test_too_old_or_unreadable_is_refused_for_a_listed_model(self):
        for version in ("0.149.1", "0.156.0-alpha.1", None):
            with self.subTest(version=version):
                with self.assertRaises(SystemExit) as caught:
                    codex_ro.check_model_cli("gpt-6-sol", version)
                self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_the_refusal_names_the_install_line(self):
        err = io.StringIO()
        with unittest.mock.patch.object(sys, "stderr", err), self.assertRaises(SystemExit):
            codex_ro.check_model_cli("gpt-6-sol", "0.149.1")
        self.assertIn("npm install -g @openai/codex@0.156.0", err.getvalue())

    def test_new_enough_passes_and_unlisted_models_only_warn(self):
        codex_ro.check_model_cli("gpt-6-sol", "0.156.0")
        with unittest.mock.patch.object(codex_ro, "warn") as warned:
            codex_ro.check_model_cli("gpt-5.6-terra", None)
        self.assertTrue(warned.called)


class MeasuredVersionTests(unittest.TestCase):
    def test_the_constant_and_the_marked_docstring_line_agree(self):
        """A-T2: one marked line, not every historical mention."""
        doc = codex_ro.__doc__ or ""
        marker = f"Currently measured against codex-cli {codex_ro.MEASURED_CODEX_CLI}"
        self.assertIn(marker, doc)
        self.assertEqual(doc.count("Currently measured against codex-cli"), 1)

    def test_the_install_hint_uses_the_measured_version(self):
        source = Path(codex_ro.__file__).read_text(encoding="utf-8")
        self.assertNotIn("@openai/codex@latest", source)

    def test_version_and_defaults(self):
        self.assertEqual(codex_ro.WRAPPER_VERSION, "2.6.0")
        self.assertEqual(codex_ro.DEFAULT_MODEL, "gpt-6-sol")
        self.assertEqual(codex_ro.parse_args(["--prompt", "x", "--out-file", "o"]).effort, "medium")


# --- I: isolation -----------------------------------------------------------------


class IsolationArgvTests(unittest.TestCase):
    def _argv(self, extra=()):
        return codex_ro.build_argv(
            codex_ro.parse_args(["--prompt", "x", "--out-file", "o.txt", *extra]), Path("o.txt"))

    def test_every_exec_and_resume_carries_the_isolation(self):
        """I-T1."""
        for extra in ((), ("--resume", "01a0f170-1b0a-7722-b383-e45ffd797372")):
            with self.subTest(resume=bool(extra)):
                argv = self._argv(extra)
                self.assertEqual(argv.count("--ignore-user-config"), 1)
                self.assertEqual(argv.count("--ignore-rules"), 1)
                self.assertEqual(argv.count('web_search="disabled"'), 1)
                disabled = [argv[i + 1] for i, a in enumerate(argv) if a == "--disable"]
                self.assertEqual(sorted(disabled), sorted(codex_ro.ISOLATION_DISABLE))

    def test_the_lists_do_not_overlap(self):
        """I-T3, the code half."""
        self.assertEqual(set(codex_ro.ISOLATION_DISABLE) & set(codex_ro.ISOLATION_ALLOWED), set())
        for name in ("apps", "plugins", "browser_use", "computer_use", "multi_agent", "hooks"):
            self.assertIn(name, codex_ro.ISOLATION_DISABLE)

    def test_both_lists_are_written_down_in_the_runbook(self):
        """I-T3, the doc half: raising the CLI compares `codex features list`
        against these lists, so the runbook must carry them verbatim."""
        runbook = (Path(codex_ro.__file__).resolve().parent.parent / "docs" / "betrieb.md").read_text(
            encoding="utf-8")
        for name in (*codex_ro.ISOLATION_DISABLE, *codex_ro.ISOLATION_ALLOWED):
            with self.subTest(feature=name):
                self.assertIn(f"`{name}`", runbook)

    def test_no_per_user_mcp_override_is_generated(self):
        """I-T5: under --ignore-user-config the server is undefined, and an override
        for an undefined server makes Codex reject its whole config."""
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / "config.toml").write_text(
                "[mcp_servers.n8n]\ntransport='http'\n", encoding="utf-8")
            with unittest.mock.patch.dict(os.environ, {"CODEX_HOME": home}):
                for extra in ((), ("--resume", "01a0f170-1b0a-7722-b383-e45ffd797372")):
                    argv = self._argv(extra)
                    self.assertFalse([a for a in argv if "mcp_servers" in a], argv)

    def test_the_old_mcp_switches_are_reported_as_ignored(self):
        with unittest.mock.patch.dict(os.environ, {"CLAUDEX_DISABLE_MCP": "n8n"}):
            with unittest.mock.patch.object(codex_ro, "warn") as warned:
                self._argv(("--disable-mcp", "x"))
        text = " ".join(" ".join(map(str, c.args)) for c in warned.call_args_list)
        self.assertIn("ignored", text)

    def test_overrides_that_would_undo_the_isolation_are_refused(self):
        """I-T2 / I-T6."""
        for override in ("features.apps=true", "features=1", 'web_search="live"', "web_search=live",
                         "projects.x.trust_level=trusted", "developer_instructions=hi",
                         "model_instructions_file=x.md"):
            with self.subTest(override=override):
                with self.assertRaises(SystemExit) as caught:
                    codex_ro.check_config_overrides([override])
                self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)


class ProjectConfigTests(_Dir, unittest.TestCase):
    """I2b / I-T4: a reviewed repo's .codex/config.toml can steer the reviewer
    (measured 2026-09-30: `developer_instructions` there decided the answer)."""

    def _cfg(self, where: Path):
        (where / ".codex").mkdir(parents=True, exist_ok=True)
        (where / ".codex" / "config.toml").write_text("developer_instructions='x'\n", encoding="utf-8")

    def test_one_in_the_working_directory_is_a_hit(self):
        self._cfg(self.dir)
        self.assertTrue(codex_ro.project_codex_configs(self.dir))

    def test_one_above_the_git_root_and_without_git_is_a_hit(self):
        self._cfg(self.dir)
        inner = self.dir / "a" / "repo" / "sub"
        inner.mkdir(parents=True)
        (self.dir / "a" / "repo" / ".git").mkdir()
        self.assertTrue(codex_ro.project_codex_configs(inner))

    def test_a_context_folder_without_config_is_fine(self):
        (self.dir / ".codex").mkdir()
        (self.dir / ".codex" / "README.md").write_text("x", encoding="utf-8")
        (self.dir / ".codex" / "knowledge.md").write_text("x", encoding="utf-8")
        self.assertEqual(codex_ro.project_codex_configs(self.dir), [])

    def test_the_user_config_itself_is_not_a_hit(self):
        """The temp dir lives under the profile on Windows, so the real user
        configs stay exempt; the test adds its own directory as CODEX_HOME."""
        self._cfg(self.dir)
        real = codex_ro._user_config_paths()
        user = self.dir / ".codex" / "config.toml"
        with unittest.mock.patch.object(codex_ro, "_user_config_paths", return_value=[user, *real]):
            self.assertEqual(codex_ro.project_codex_configs(self.dir), [])

    def test_an_uncheckable_ancestor_is_a_hit(self):
        real_lstat = os.lstat

        def failing(path, *a, **k):
            if str(path).endswith(os.path.join(".codex", "config.toml")) and str(self.dir) in str(path):
                raise PermissionError("denied")
            return real_lstat(path, *a, **k)

        with unittest.mock.patch.object(codex_ro.os, "lstat", failing):
            self.assertTrue(codex_ro.project_codex_configs(self.dir))


# --- W1 in the wrapper: fail-closed reparse check, stepwise parents ---------------


class ReparseFailClosedTests(_Dir, unittest.TestCase):
    """W-T0: the helper answered "not a reparse point" whenever it could not look."""

    def test_a_metadata_error_counts_as_unsafe(self):
        with unittest.mock.patch.object(codex_ro.os, "lstat", side_effect=PermissionError("denied")):
            self.assertTrue(codex_ro._is_reparse_point(self.dir / "x"))

    def test_a_missing_attribute_on_windows_counts_as_unsafe(self):
        fake = os.stat_result((stat.S_IFREG | 0o600, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        with unittest.mock.patch.object(codex_ro.os, "lstat", return_value=fake), \
                unittest.mock.patch.object(codex_ro.os, "name", "nt"):
            self.assertTrue(codex_ro._is_reparse_point(self.dir / "x"))

    def test_a_target_that_does_not_exist_yet_is_fine(self):
        self.assertFalse(codex_ro._is_reparse_point(self.dir / "not-yet"))

    def test_the_wrapper_write_target_check_uses_it(self):
        with unittest.mock.patch.object(codex_ro.os, "lstat", side_effect=PermissionError("denied")):
            with self.assertRaises(SystemExit) as caught:
                codex_ro.prepare_write_target(self.dir / "out.txt", "--out-file")
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_missing_parents_are_created_one_level_at_a_time_and_rechecked(self):
        """W-T8."""
        target = self.dir / "a" / "b" / "out.txt"
        created = self.dir / "a"
        real = codex_ro._is_reparse_point

        def swapped(path):
            return Path(path) == created or real(path)

        with unittest.mock.patch.object(codex_ro, "_is_reparse_point", swapped):
            with self.assertRaises(SystemExit):
                codex_ro.prepare_write_target(target, "--out-file")
        self.assertFalse((self.dir / "a" / "b").exists(), "nothing below a swapped directory")


# --- J4c: locks -----------------------------------------------------------------


class LockTests(_Dir, unittest.TestCase):
    def test_an_existing_lock_on_any_output_refuses_and_releases_its_own(self):
        """J-T13."""
        paths = [self.dir / "a.txt", self.dir / "b.txt", self.dir / "c.json"]
        (self.dir / ("b.txt" + codex_ro.LOCK_SUFFIX)).write_text("other run", encoding="utf-8")
        with self.assertRaises(SystemExit) as caught:
            codex_ro.acquire_locks(paths)
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertFalse((self.dir / ("a.txt" + codex_ro.LOCK_SUFFIX)).exists())
        self.assertEqual((self.dir / ("b.txt" + codex_ro.LOCK_SUFFIX)).read_text(encoding="utf-8"),
                         "other run")

    def test_locks_are_taken_in_sorted_order_and_released(self):
        paths = [self.dir / "z.txt", self.dir / "a.txt"]
        locks = codex_ro.acquire_locks(paths)
        self.assertEqual(locks, sorted(locks))
        codex_ro.release_locks(locks)
        self.assertFalse(any(p.exists() for p in locks))


# --- main(): the whole run with a fake Codex --------------------------------------


class _Child:
    def __init__(self, cmd, fake_stream, fake_stderr, answer, rc, hang, **kwargs):
        self.args, self.kwargs = cmd, kwargs
        self.stream, self.stderr, self.answer, self.rc, self.hang = fake_stream, fake_stderr, answer, rc, hang
        self.returncode, self.pid = rc, 999999

    def communicate(self, input=None, timeout=None):  # noqa: A002
        if self.hang and timeout is not None and timeout < 100:
            if self.hang == "once":
                self.hang = False
            raise subprocess.TimeoutExpired(self.args, timeout)
        self.kwargs["stdout"].write(self.stream.encode("utf-8"))
        self.kwargs["stderr"].write(self.stderr.encode("utf-8"))
        if self.answer is not None:
            out = self.args[self.args.index("-o") + 1]
            Path(out).write_text(self.answer, encoding="utf-8")
        return (b"", b"")


class _Run:
    def __init__(self, stream=THREAD + TURN + CMD(0) + ANSWER + DONE, stderr="",
                 answer="VERDICT: APPROVED\n", rc=0, version="0.156.0", hang=False):
        self.spec = dict(fake_stream=stream, fake_stderr=stderr, answer=answer, rc=rc, hang=hang)
        self.version = version
        self.calls = []

    def __enter__(self):
        self._p = [
            unittest.mock.patch("codex_ro.find_codex", return_value=["fake-codex"]),
            unittest.mock.patch("codex_ro.probe_cli_version", return_value=self.version),
            unittest.mock.patch("codex_ro.kill_tree"),
            unittest.mock.patch("codex_ro.subprocess.Popen", side_effect=self._popen),
        ]
        for p in self._p:
            p.start()
        return self

    def _popen(self, cmd, **kwargs):
        self.calls.append(cmd)
        return _Child(cmd, **self.spec, **kwargs)

    def __exit__(self, *exc):
        for p in reversed(self._p):
            p.stop()
        return False


class MainTests(_Dir, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.previous = os.getcwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, self.previous)

    def _main(self, *extra):
        return codex_ro.main(["--prompt", "review this", "--out-file", "o.txt", *extra])

    def _locks(self):
        return [p.name for p in self.dir.rglob("*" + codex_ro.LOCK_SUFFIX)]

    def test_a_normal_run_succeeds_and_releases_every_lock(self):
        with _Run():
            self.assertEqual(self._main(), 0)
        self.assertEqual(self._locks(), [])

    def test_the_header_names_the_cli_version(self):
        out = io.StringIO()
        with _Run(), unittest.mock.patch.object(sys, "stdout", out):
            self._main()
        self.assertIn("codex-cli 0.156.0", out.getvalue())

    def test_the_real_blind_run_is_exit_3_through_main(self):
        stream = (FIXTURES / "blind-run.stream.json").read_text(encoding="utf-8")
        stderr = (FIXTURES / "blind-run.stderr.txt").read_text(encoding="utf-8")
        with _Run(stream=stream, stderr=stderr, answer="FAILED\n"):
            self.assertEqual(self._main(), codex_ro.EXIT_BLIND)
        self.assertEqual(self._locks(), [])

    def test_a_truncated_stream_with_no_command_is_exit_3(self):
        with _Run(stream=THREAD + TURN + ANSWER):
            self.assertEqual(self._main(), codex_ro.EXIT_BLIND)

    def test_an_old_cli_refuses_gpt6_before_anything_is_created(self):
        with _Run(version="0.149.1") as run:
            with self.assertRaises(SystemExit) as caught:
                self._main()
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertEqual(run.calls, [])
        self.assertFalse((self.dir / "o.txt.stream.json").exists())

    def test_a_timeout_releases_every_lock(self):
        with _Run(hang="once"):
            with self.assertRaises(SystemExit) as caught:
                self._main("--timeout", "1")
        self.assertEqual(caught.exception.code, codex_ro.EXIT_TIMEOUT)
        self.assertEqual(self._locks(), [])

    def test_a_running_lock_refuses_a_second_run_and_leaves_its_files(self):
        """J-T15: same --err-file, different --out-file."""
        (self.dir / "shared.err").write_text("first run's evidence", encoding="utf-8")
        (self.dir / ("shared.err" + codex_ro.LOCK_SUFFIX)).write_text("pid 1", encoding="utf-8")
        with _Run() as run:
            with self.assertRaises(SystemExit) as caught:
                self._main("--err-file", "shared.err")
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertEqual(run.calls, [])
        self.assertEqual((self.dir / "shared.err").read_text(encoding="utf-8"), "first run's evidence")

    def test_a_lock_file_cannot_be_named_as_an_output(self):
        (self.dir / ("o.txt" + codex_ro.LOCK_SUFFIX)).write_text("pid 1", encoding="utf-8")
        with _Run() as run:
            with self.assertRaises(SystemExit) as caught:
                codex_ro.main(["--prompt", "x", "--out-file", "o.txt" + codex_ro.LOCK_SUFFIX])
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertTrue((self.dir / ("o.txt" + codex_ro.LOCK_SUFFIX)).exists())
        self.assertEqual(run.calls, [])

    def test_a_project_config_refuses_before_the_run(self):
        (self.dir / ".codex").mkdir()
        (self.dir / ".codex" / "config.toml").write_text("developer_instructions='x'\n", encoding="utf-8")
        with _Run() as run:
            with self.assertRaises(SystemExit) as caught:
                self._main()
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertEqual(run.calls, [])

    def test_the_isolation_reaches_the_child(self):
        with _Run() as run:
            self._main()
        self.assertIn("--ignore-user-config", run.calls[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
