#!/usr/bin/env python3
"""Wrapper 2.7.0: judge the settings Codex APPLIED, not only the ones we asked for.

Plan: docs/plans/2026-10-30-wirksame-einstellungen/PLAN.md (Verification 3).

Why this exists: the wrapper passes read-only flags on argv, but until 2.6.1 it never
looked at what the CLI really ran with. Codex writes a rollout file
($CODEX_HOME/sessions/YYYY/MM/DD/rollout-*-<thread>.jsonl) whose `turn_context` records
the sandbox, permission profile, approval policy, model and effort that were in force
for each turn. 2.7.0 binds that record to THIS invocation through a marker line it
appends to the prompt (found again in the rollout's user message), judges it, and stops
with exit 4 when the evidence positively shows an unsafe turn. Anything it cannot bind
or read is "unknown"/"unbound": a warning, never a changed exit code -- the check adds
evidence and never removes a control.

These tests drive codex_ro.main() end to end with a fake child (the pattern of
test_codex_ro_260.py). The fake child receives the prompt on stdin, takes the marker
line out of it and writes the rollout the test describes, in the format measured on
codex-cli 0.162.1. Nothing starts Codex, nothing touches the network.

Every test was written before the code it tests and seen failing against 2.6.1 first.

    python -m pytest -q tests/test_codex_ro_applied.py
"""

from __future__ import annotations

import io
import json
import os
import sys
import threading
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import codex_ro  # noqa: E402
from test_codex_ro_260 import (  # noqa: E402
    ANSWER,
    CMD,
    DONE,
    THREAD,
    TURN,
    _Child,
    _Dir,
    _Run,
    _line,
)

FIXTURES_162 = Path(__file__).resolve().parent / "fixtures" / "codex-0.162"

EXIT_UNSAFE = 4
MARKER_PREFIX = "<!-- claudex-invocation: "
MARKER = MARKER_PREFIX + "a" * 32 + " -->"
OTHER_MARKER = MARKER_PREFIX + "b" * 32 + " -->"
THREAD_ID = json.loads(THREAD)["thread_id"]

READ_ONLY_PROFILE = {
    "type": "managed",
    "file_system": {
        "type": "restricted",
        "entries": [{"path": {"type": "special", "value": {"kind": "root"}}, "access": "read"}],
    },
    "network": "restricted",
}


def _writable_profile():
    profile = json.loads(json.dumps(READ_ONLY_PROFILE))
    profile["file_system"]["entries"].append(
        {"path": {"type": "path", "value": "/work"}, "access": "write"})
    return profile


# --- rollout line builders (measured format, codex-cli 0.162.1) ---------------------


def started(turn):
    return _line({"type": "event_msg", "payload": {"type": "task_started", "turn_id": turn}})


def complete(turn):
    return _line({"type": "event_msg", "payload": {"type": "task_complete", "turn_id": turn}})


def context(turn, **override):
    """A turn_context; `override` replaces payload keys, a value of KEEP_OUT drops the key."""
    payload = {
        "turn_id": turn,
        "model": "gpt-6.1-sol",
        "effort": "medium",
        "sandbox_policy": {"type": "read-only"},
        "approval_policy": "never",
        "permission_profile": READ_ONLY_PROFILE,
    }
    payload.update(override)
    return _line({"type": "turn_context", "payload": payload})


def user_message(turn, text, passthrough_turn=None):
    other = turn if passthrough_turn is None else passthrough_turn
    return _line({
        "type": "response_item",
        "metadata": {"retained_source": {"id": {"turn_id": turn, "role": "user"}}},
        "payload": {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": text}],
            "internal_chat_message_metadata_passthrough": {"turn_id": other},
        },
    })


def whole_turn(turn, prompt_text, **ctx_override):
    return (started(turn) + context(turn, **ctx_override)
            + user_message(turn, prompt_text) + complete(turn))


def filler(nbytes):
    """Unrelated, well-formed rollout lines totalling more than `nbytes` bytes."""
    one = _line({"type": "event_msg", "payload": {"type": "agent_message", "text": "x" * 150}})
    return one * (nbytes // len(one) + 2)


def thread_of(stream_text):
    for raw in stream_text.splitlines():
        try:
            obj = json.loads(raw)
        except ValueError:
            continue
        if obj.get("type") == "thread.started":
            return obj["thread_id"]
    raise AssertionError("test stream has no thread.started line")


# --- the harness --------------------------------------------------------------------


class _AppliedChild(_Child):
    """The fake child that, when the wrapper feeds it the prompt, writes the rollout."""

    harness = None

    def communicate(self, input=None, timeout=None):  # noqa: A002
        if input is not None:
            if self.hang:
                # A hung child still wrote its stream and rollout before it stopped answering.
                self.kwargs["stdout"].write(self.stream.encode("utf-8"))
            self.harness.on_child_prompt(input.decode("utf-8"))
        return super().communicate(input, timeout)


class _AppliedRun(_Run):
    def __init__(self, harness, **spec):
        super().__init__(**spec)
        self.harness = harness

    def _popen(self, cmd, **kwargs):
        self.calls.append(cmd)
        child = _AppliedChild(cmd, **self.spec, **kwargs)
        child.harness = self.harness
        return child


class Result:
    def __init__(self, code, out, err):
        self.code, self.out, self.err = code, out, err

    @property
    def applied(self):
        lines = [x for x in self.out.splitlines() if x.startswith("#   applied:")]
        return lines[0] if lines else ""

    @property
    def out_lines(self):
        return [x for x in self.out.splitlines() if x.startswith("OUT=")]


class AppliedBase(_Dir, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.home = self.dir / "codexhome"
        self.home.mkdir()
        # A git-looking root, so the wrapper's own "not inside a git repository" notice does
        # not land on stderr and make the "warns" assertions below vacuous.
        (self.dir / ".git").mkdir()
        self.previous = os.getcwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, self.previous)

    # -- rollout location
    def rollout_path(self, name=None, day="30"):
        base = self.home / "sessions" / "2026" / "10" / day
        base.mkdir(parents=True, exist_ok=True)
        # The rollout belongs to the thread of the stream the fake child emits (the blind
        # fixture carries its own thread id, not THREAD_ID).
        thread = thread_of(getattr(self, "_stream", THREAD))
        return base / (name or f"rollout-x-{thread}.jsonl")

    def append(self, path, text):
        with open(path, "ab") as handle:
            handle.write(text.encode("utf-8"))

    def old_turn(self, text="an earlier prompt\n", **ctx_override):
        """What a resumed session already holds before this invocation starts."""
        path = self.rollout_path()
        self.append(path, whole_turn("old", text, **ctx_override))
        return path

    # -- driving main()
    def drive(self, on_prompt=None, *, pre=None, resume=False, stream=THREAD + TURN + CMD(0) + ANSWER + DONE,
              stderr="", answer="VERDICT: APPROVED\n", hang=False, marker=MARKER, cap=None,
              extra_args=()):
        self.on_prompt = on_prompt
        self._stream = stream
        argv = ["--prompt", "review this", "--out-file", "o.txt",
                "--model", "gpt-6.1-sol", "--effort", "medium", *extra_args]
        if resume:
            argv += ["--resume", thread_of(stream)]
        if hang:
            argv += ["--timeout", "1"]
        patches = [
            unittest.mock.patch.dict(os.environ, {"CODEX_HOME": str(self.home)}),
            unittest.mock.patch.object(codex_ro, "new_marker", lambda: marker, create=True),
        ]
        if cap is not None:
            patches.append(unittest.mock.patch.object(codex_ro, "ROLLOUT_TAIL_CAP", cap, create=True))
        out, err = io.StringIO(), io.StringIO()
        code = None
        for p in patches:
            p.start()
        try:
            if pre:
                pre()
            with _AppliedRun(self, stream=stream, stderr=stderr, answer=answer, hang=hang,
                             version="0.162.1"), \
                    unittest.mock.patch.object(sys, "stdout", out), \
                    unittest.mock.patch.object(sys, "stderr", err):
                try:
                    code = codex_ro.main(argv)
                except SystemExit as exc:
                    code = exc.code
        finally:
            for p in reversed(patches):
                p.stop()
        return Result(code, out.getvalue(), err.getvalue())

    def on_child_prompt(self, prompt_text):
        if self.on_prompt:
            self.on_prompt(prompt_text, self.rollout_path())

    # -- common builders for on_prompt
    @staticmethod
    def normal(**ctx_override):
        def build(prompt_text, path):
            with open(path, "ab") as handle:
                handle.write(whole_turn("t1", prompt_text, **ctx_override).encode("utf-8"))
        return build

    def assert_unsafe(self, result):
        self.assertEqual(result.code, EXIT_UNSAFE, result.out + result.err)
        self.assertEqual(result.out_lines, [], "OUT= must never be printed for an unsafe run")
        self.assertIn("UNSAFE", result.applied)

    def assert_unbound(self, result):
        self.assertEqual(result.code, 0, result.out + result.err)
        self.assertIn("unbound", result.applied)
        self.assertNotIn("UNSAFE", result.applied)
        self.assertFalse(result.applied.rstrip().endswith("confirmed"), result.applied)
        self.assertIn("codex_ro:", result.err, "unbound must warn on stderr")


# --- the verdicts through main() ----------------------------------------------------


class SettingsVerdictTests(AppliedBase):
    def test_read_only_run_exits_0_and_reports_confirmed(self):
        result = self.drive(self.normal())
        self.assertEqual(result.code, 0, result.out + result.err)
        self.assertTrue(result.applied.startswith("#   applied: "), result.out)
        self.assertIn("confirmed", result.applied)
        self.assertEqual(len(result.out_lines), 1)

    def test_workspace_write_sandbox_exits_4_and_prints_no_out_line(self):
        self.assert_unsafe(self.drive(self.normal(sandbox_policy={"type": "workspace-write"})))

    def test_danger_full_access_exits_4(self):
        self.assert_unsafe(self.drive(self.normal(sandbox_policy={"type": "danger-full-access"})))

    def test_approval_policy_on_request_exits_4(self):
        self.assert_unsafe(self.drive(self.normal(approval_policy="on-request")))

    def test_read_only_sandbox_with_a_writable_permission_profile_exits_4(self):
        self.assert_unsafe(self.drive(self.normal(permission_profile=_writable_profile())))

    def test_a_disabled_permission_profile_is_unsafe_even_with_a_read_only_sandbox_claim(self):
        """Measured 2026-10-30 on a real writable run (codex-cli 0.162.1): full access is
        `permission_profile: {"type": "disabled"}` -- no sandbox at all. It used to fall
        through to "unknown"; next to a read-only sandbox claim that would only warn."""
        self.assert_unsafe(self.drive(self.normal(permission_profile={"type": "disabled"})))

    def test_permission_profile_of_unknown_type_is_unknown_not_a_failure(self):
        result = self.drive(self.normal(permission_profile={"type": "quantum", "flux": 1}))
        self.assertEqual(result.code, 0, result.out + result.err)
        self.assertIn("unknown", result.applied)
        self.assertNotIn("UNSAFE", result.applied)
        self.assertIn("codex_ro:", result.err, "unknown must warn on stderr")

    def test_a_different_model_than_requested_warns_and_keeps_exit_0(self):
        result = self.drive(self.normal(model="gpt-5"))
        self.assertEqual(result.code, 0, result.out + result.err)
        self.assertIn("gpt-5", result.err)

    def test_a_non_string_model_cannot_mask_an_unsafe_sandbox(self):
        self.assert_unsafe(self.drive(self.normal(
            model={"name": "gpt-6.1-sol"}, sandbox_policy={"type": "workspace-write"})))

    def test_an_unrelated_malformed_line_in_the_tail_is_ignored(self):
        def build(prompt_text, path):
            with open(path, "ab") as handle:
                handle.write(b"{this is not json\n")
                handle.write(whole_turn("t1", prompt_text).encode("utf-8"))
                handle.write(b"\x00\xff garbage\n")
        result = self.drive(build)
        self.assertEqual(result.code, 0, result.out + result.err)
        self.assertIn("confirmed", result.applied)


# --- unsafe wins over every other exit path ------------------------------------------


class ExitPrecedenceTests(AppliedBase):
    UNSAFE = {"sandbox_policy": {"type": "workspace-write"}}

    def test_a_blind_run_with_an_unsafe_sandbox_exits_4_not_3(self):
        stream = (FIXTURES_162 / "blind-run.stream.json").read_text(encoding="utf-8")
        stderr = (FIXTURES_162 / "blind-run.stderr.txt").read_text(encoding="utf-8")
        self.assertEqual(self.drive(self.normal(), stream=stream, stderr=stderr,
                                    answer="Command blocked by policy.\n").code, codex_ro.EXIT_BLIND,
                         "control: the same blind run with a safe sandbox is still exit 3")
        for leftover in (self.home / "sessions").rglob("*.jsonl"):
            leftover.unlink()
        self.assert_unsafe(self.drive(self.normal(**self.UNSAFE), stream=stream, stderr=stderr,
                                      answer="Command blocked by policy.\n"))

    def test_an_empty_answer_with_an_unsafe_sandbox_exits_4_not_1(self):
        self.assert_unsafe(self.drive(self.normal(**self.UNSAFE), answer=""))

    def test_a_timeout_with_an_unsafe_sandbox_stays_124_and_prints_the_unsafe_line(self):
        result = self.drive(self.normal(**self.UNSAFE), hang=True)
        self.assertEqual(result.code, codex_ro.EXIT_TIMEOUT, result.out + result.err)
        self.assertIn("UNSAFE", result.applied)
        self.assertEqual(result.out_lines, [])


# --- the tail cap ---------------------------------------------------------------------


class TailCapTests(AppliedBase):
    CAP = 4096

    def test_unsafe_context_followed_by_more_than_the_cap_still_exits_4(self):
        def build(prompt_text, path):
            self.append(path, whole_turn("t1", prompt_text, sandbox_policy={"type": "workspace-write"}))
            self.append(path, filler(self.CAP * 2))
        self.assert_unsafe(self.drive(build, cap=self.CAP))

    def test_a_safe_candidate_then_an_unsafe_one_beyond_the_cap_is_unbound_not_confirmed(self):
        def build(prompt_text, path):
            self.append(path, whole_turn("t1", prompt_text))
            self.append(path, filler(self.CAP * 2))
            self.append(path, whole_turn("t2", prompt_text, sandbox_policy={"type": "workspace-write"}))
        self.assert_unbound(self.drive(build, cap=self.CAP))

    def test_a_safe_candidate_then_an_unsafe_one_inside_the_cap_exits_4(self):
        def build(prompt_text, path):
            self.append(path, whole_turn("t1", prompt_text))
            self.append(path, whole_turn("t2", prompt_text, sandbox_policy={"type": "workspace-write"}))
        self.assert_unsafe(self.drive(build, cap=64 * 1024))


# --- binding: which turn is ours -----------------------------------------------------


class BindingTests(AppliedBase):
    def test_two_marked_candidates_one_unsafe_exits_4(self):
        def build(prompt_text, path):
            self.append(path, whole_turn("t1", prompt_text))
            self.append(path, whole_turn("t2", prompt_text, approval_policy="on-request"))
        self.assert_unsafe(self.drive(build))

    @staticmethod
    def interleaved(prompt_text, path):
        """started A, ctx A (workspace-write), started B, ctx B (read-only), msg A, msg B.

        File order alone would pair the message of A with the context of B; only the
        turn ids tell them apart."""
        with open(path, "ab") as handle:
            handle.write((
                started("A") + context("A", sandbox_policy={"type": "workspace-write"})
                + started("B") + context("B")
                + user_message("A", "review this\n" + MARKER)
                + user_message("B", "review this\n" + OTHER_MARKER)
            ).encode("utf-8"))

    def test_interleaved_turns_are_joined_by_turn_id_for_invocation_a(self):
        self.assert_unsafe(self.drive(self.interleaved, marker=MARKER))

    def test_interleaved_turns_are_joined_by_turn_id_for_invocation_b(self):
        result = self.drive(self.interleaved, marker=OTHER_MARKER)
        self.assertEqual(result.code, 0, result.out + result.err)
        self.assertIn("confirmed", result.applied)

    def test_a_message_whose_two_turn_id_fields_disagree_is_unbound(self):
        def build(prompt_text, path):
            self.append(path, started("t1") + context("t1")
                        + user_message("t1", prompt_text, passthrough_turn="t2") + complete("t1"))
        self.assert_unbound(self.drive(build))

    def test_no_rollout_at_all_is_unbound(self):
        self.assert_unbound(self.drive(None))

    def test_a_rollout_without_our_marker_is_unbound(self):
        def build(prompt_text, path):
            self.append(path, whole_turn("t1", "some other run's prompt\n" + OTHER_MARKER))
        self.assert_unbound(self.drive(build))

    def test_two_rollout_files_for_the_thread_are_unbound(self):
        def build(prompt_text, path):
            self.append(path, whole_turn("t1", prompt_text))
            second = self.rollout_path(name=f"rollout-y-{THREAD_ID}.jsonl", day="29")
            self.append(second, whole_turn("t1", prompt_text))
        self.assert_unbound(self.drive(build))


# --- resume: only what this invocation appended counts --------------------------------


class ResumeTests(AppliedBase):
    def test_only_an_old_turn_in_the_rollout_is_unbound_not_the_old_value(self):
        """The child appends nothing. The old turn even carries the same marker text, so a
        judge that read from offset 0 would call it confirmed."""
        result = self.drive(None, resume=True, pre=lambda: self.old_turn("an earlier prompt\n" + MARKER))
        self.assert_unbound(result)

    def test_an_old_unsafe_turn_does_not_taint_a_new_safe_one(self):
        result = self.drive(self.normal(), resume=True, pre=lambda: self.old_turn(
            "an earlier prompt\n", sandbox_policy={"type": "workspace-write"}))
        self.assertEqual(result.code, 0, result.out + result.err)
        self.assertIn("confirmed", result.applied)

    def test_a_rollout_replaced_between_before_and_after_is_unbound(self):
        def replace(prompt_text, path):
            old = path.read_bytes()
            fresh = path.with_name(path.name + ".new")
            fresh.write_bytes(old + whole_turn("t1", prompt_text).encode("utf-8"))
            os.remove(path)
            os.replace(fresh, path)
        self.assert_unbound(self.drive(replace, resume=True, pre=self.old_turn))


# --- the rollout must be a plain regular file -----------------------------------------


@unittest.skipIf(os.name == "nt", "symlink/FIFO semantics are POSIX; run under WSL")
class UnreadableRolloutTests(AppliedBase):
    def test_a_rollout_that_is_a_symlink_is_unbound(self):
        def build(prompt_text, path):
            real = self.home / "elsewhere.jsonl"
            real.write_bytes(whole_turn("t1", prompt_text).encode("utf-8"))
            os.symlink(real, path)
        self.assert_unbound(self.drive(build))

    def test_a_fifo_in_place_of_the_rollout_is_unbound_and_does_not_block(self):
        def build(prompt_text, path):
            os.mkfifo(path)
        box = {}

        def run():
            box["result"] = self.drive(build)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(10)
        self.assertFalse(worker.is_alive(), "the wrapper blocked on a FIFO")
        self.assert_unbound(box["result"])




# --- post-build inspection, round 1 (2026-10-30) ---------------------------------------


class InspectionRound1Tests(AppliedBase):
    """Each case below passed the first 2.7.0 build and was reproduced by the inspector."""

    def _profile(self, **fs_override):
        profile = json.loads(json.dumps(READ_ONLY_PROFILE))
        profile["file_system"].update(fs_override)
        return profile

    def test_a_malformed_entry_next_to_a_write_entry_is_still_unsafe(self):
        """Finding 1: `unknown` was returned at the first malformed entry, before the write entry."""
        profile = self._profile(entries=[{}, {"path": {"type": "path", "value": "/x"}, "access": "write"}])
        self.assert_unsafe(self.drive(self.normal(permission_profile=profile)))

    def test_a_write_entry_with_the_network_field_missing_is_still_unsafe(self):
        profile = _writable_profile()
        del profile["network"]
        self.assert_unsafe(self.drive(self.normal(permission_profile=profile)))

    def test_a_later_safe_context_for_the_same_turn_does_not_hide_an_earlier_unsafe_one(self):
        """Finding 2: only the last context per turn id was kept."""
        def build(prompt_text, path):
            self.append(path, started("t1") + context("t1", sandbox_policy={"type": "workspace-write"})
                        + context("t1") + user_message("t1", prompt_text) + complete("t1"))
        self.assert_unsafe(self.drive(build))

    def test_a_deeply_nested_line_after_unsafe_evidence_keeps_exit_4(self):
        """Finding 4: RecursionError from json escaped the reader and lost the verdict."""
        deep = '{"type": "turn_context", "payload": ' + "[" * 100000 + "]" * 100000 + "}\n"
        def build(prompt_text, path):
            self.append(path, whole_turn("t1", prompt_text, sandbox_policy={"type": "workspace-write"}))
            self.append(path, deep)
        self.assert_unsafe(self.drive(build))

    def test_a_deeply_nested_line_alone_is_skipped_not_a_traceback(self):
        deep = '{"type": "turn_context", "payload": ' + "[" * 100000 + "]" * 100000 + "}\n"
        def build(prompt_text, path):
            self.append(path, deep)
            self.append(path, whole_turn("t1", prompt_text))
        result = self.drive(build)
        self.assertEqual(result.code, 0, result.out + result.err)
        self.assertIn("confirmed", result.applied)

    def test_a_leaf_replaced_after_the_open_is_refused(self):
        """Finding 3: on Windows (no O_NOFOLLOW) the path was checked only BEFORE the open.
        The reader now re-checks the path after the open: it must still name the opened file
        and not be a link or reparse point."""
        real_lstat = os.lstat
        calls = {"n": 0}
        other_file = self.home / "another-regular-file.txt"
        other_file.write_bytes(b"x")  # a REGULAR file with another identity (inspection r2, finding 2)

        def swapped_lstat(path, *a, **k):
            st = real_lstat(path, *a, **k)
            if str(path).endswith(".jsonl"):
                calls["n"] += 1
                if calls["n"] >= 2:  # the post-open check sees another regular file
                    return real_lstat(other_file)
            return st
        def build(prompt_text, path):
            self.append(path, whole_turn("t1", prompt_text))
        with unittest.mock.patch.object(codex_ro.os, "lstat", swapped_lstat):
            result = self.drive(build)
        self.assertEqual(result.code, 0, result.out + result.err)
        self.assertIn("unbound", result.applied)


class InspectionRound2Tests(AppliedBase):
    def test_a_leaf_that_turns_into_a_reparse_point_after_the_open_is_refused(self):
        """Inspection round 2, finding 2: the Windows reparse rejection after the open."""
        real = codex_ro._is_reparse_point
        calls = {"n": 0}

        def reparse(path):
            if str(path).endswith(".jsonl"):
                calls["n"] += 1
                return calls["n"] >= 2  # clean before the open, a reparse point after it
            return real(path)
        def build(prompt_text, path):
            self.append(path, whole_turn("t1", prompt_text))
        with unittest.mock.patch.object(codex_ro, "_is_reparse_point", reparse):
            result = self.drive(build)
        self.assertEqual(result.code, 0, result.out + result.err)
        self.assertIn("unbound", result.applied)
        self.assertGreaterEqual(calls["n"], 2, "the post-open check never ran")



class ClosingGateTests(AppliedBase):
    """Closing gate, initial pass: a byte prefilter ran BEFORE json decoding, so a JSON
    unicode escape (valid JSON, same decoded text) hid a record from the reader."""

    @staticmethod
    def _escape_first(line, needle):
        # Rewrite the first character of `needle` inside the JSON line as a backslash-u
        # escape (valid JSON that decodes to the same text).
        i = line.index(needle)
        return line[:i] + "\\u%04x" % ord(needle[0]) + line[i + 1:]

    def test_an_escaped_marker_on_an_unsafe_candidate_is_still_seen(self):
        def build(prompt_text, path):
            self.append(path, whole_turn("t1", prompt_text))
            msg = user_message("t2", prompt_text)
            self.append(path, started("t2") + context("t2", sandbox_policy={"type": "workspace-write"})
                        + self._escape_first(msg, "<!--") + complete("t2"))
        self.assert_unsafe(self.drive(build))

    def test_an_escaped_record_type_on_an_unsafe_context_is_still_seen(self):
        def build(prompt_text, path):
            ctx = context("t1", sandbox_policy={"type": "workspace-write"})
            self.append(path, started("t1") + context("t1") + self._escape_first(ctx, "turn_context")
                        + user_message("t1", prompt_text) + complete("t1"))
        self.assert_unsafe(self.drive(build))


if __name__ == "__main__":
    unittest.main(verbosity=2)
