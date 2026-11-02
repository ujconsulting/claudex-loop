"""Wrapper 2.7.1: a run whose every command failed to start or was denied is blind (exit 3).

Measured 2026-11-02 (codex-cli 0.162.1, gpt-6.1-sol, Windows VM): four plan reviews read no
file and still ended with exit 0 and a verdict. Commands were attempted -- the Store alias of
pwsh could not start (`exit_code -1`, `CreateProcessAsUserW failed: 5`), or the repo sat on a
network share (`exit_code 1`, access denied) -- so 2.7.0 counted them as "executed" and let the
answer through. The three real runs are in `fixtures/codex-0.162/blind-failed-commands/`.

The rule under test (PLAN.md, step 5): accepted when a command succeeded, or when nothing was
attempted, nothing refused and the evidence is complete; accepted with a warning when commands
only failed in an ordinary way; invalid when nothing succeeded and a command failed to start,
was denied, could not be classified, or the evidence is incomplete.
"""
from __future__ import annotations

import io
import json
import sys
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import codex_ro  # noqa: E402
from test_codex_ro_260 import _Dir  # noqa: E402
from test_codex_ro_applied import AppliedBase  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "codex-0.162"
DENIED = FIXTURES / "blind-failed-commands"
REAL_SETS = ("pwsh-alias-S", "pwsh-alias-C", "network-share")

ROUTER_ASUSER = (
    '2026-11-02T15:35:36.115295Z ERROR codex_core::tools::router: error=exec_command failed: '
    'CreateProcess { message: "Rejected(\\"Failed to create unified exec process: '
    'CreateProcessAsUserW failed: 5 (Zugriff verweigert) | cwd=S:\\\\repo\\")" }\n'
)
ROUTER_ACCESS = (
    '2026-11-02T15:40:00Z ERROR codex_core::tools::router: error=exec_command failed: '
    'CreateProcess { message: "Rejected(\\"Access is denied. (os error 5)\\")" }\n'
)
ROUTER_LOGONW = (
    '2026-09-16T10:00:00.000001Z ERROR codex_core::tools::router: error=exec_command failed: '
    'CreateProcess { message: "CreateProcessWithLogonW failed: 267" }\n'
)


def _router_legacy_lines():
    """The real router refusal of the 2.4.0 era fixture (`rejected: blocked by policy`)."""
    text = (FIXTURES / "blind-run.stderr.txt").read_text(encoding="utf-8")
    return [x + "\n" for x in text.splitlines() if "codex_core::tools::router" in x]


def ev(kind, **fields):
    return json.dumps({"type": kind, **fields}) + "\n"


def cmd(exit_code, output="", status=None, n=[0]):
    n[0] += 1
    item = {"id": f"item_c{n[0]}", "type": "command_execution", "command": "pwsh -Command x",
            "aggregated_output": output, "exit_code": exit_code,
            "status": status or ("completed" if exit_code == 0 else "failed")}
    return ev("item.completed", item=item)


def answer(text="VERDICT: APPROVED"):
    return ev("item.completed", item={"id": "item_a", "type": "agent_message", "text": text})


THREAD = ev("thread.started", thread_id="01a19d67-96c2-7f23-a002-1f49070f7353")
TURN = ev("turn.started")
DONE = ev("turn.completed", usage={})


def stream(*items):
    return THREAD + TURN + "".join(items) + answer() + DONE


class BlindRunLevel(_Dir, unittest.TestCase):
    """blind_run() on stream/stderr pairs. Returns (reason or None, wrapper stderr)."""

    def run_blind(self, stream_text, stderr_text="", limit=None):
        s = self.dir / "o.txt.stream.json"
        e = self.dir / "err.txt"
        s.write_text(stream_text, encoding="utf-8")
        e.write_text(stderr_text, encoding="utf-8")
        captured = io.StringIO()
        with unittest.mock.patch.object(sys, "stderr", captured):
            evidence = codex_ro.read_stream_evidence(s, limit=limit)
            reason = codex_ro.blind_run(e, s, evidence)
        return reason, captured.getvalue()

    def assert_blind(self, stream_text, stderr_text="", limit=None, msg=""):
        reason, _ = self.run_blind(stream_text, stderr_text, limit)
        self.assertIsNotNone(reason, msg or "expected a blind run (exit 3)")
        return reason

    def assert_accepted(self, stream_text, stderr_text="", limit=None, msg=""):
        reason, err = self.run_blind(stream_text, stderr_text, limit)
        self.assertIsNone(reason, (msg or "expected an accepted round") + f": {reason}")
        return err

    # -- the three real runs and the real control -------------------------------------
    def test_every_real_blind_set_is_blind(self):
        for name in REAL_SETS:
            with self.subTest(name):
                reason = self.assert_blind(
                    (DENIED / f"{name}.stream.json").read_text(encoding="utf-8"),
                    (DENIED / f"{name}.stderr.txt").read_text(encoding="utf-8"))
                self.assertIn("0 succeeded", reason)
                self.assertIn("review_mirror", reason, "the environment hint names the remedy")

    def test_the_real_normal_run_is_accepted(self):
        self.assert_accepted((FIXTURES / "normal-run.stream.json").read_text(encoding="utf-8"))

    # -- condition A: start failure or denial in the stream ---------------------------
    def test_a_exit_minus_one_without_any_text_is_blind(self):
        self.assert_blind(stream(cmd(-1), cmd(-1)))

    def test_b_german_dotnet_denial_is_blind(self):
        self.assert_blind(stream(cmd(1, "Der Zugriff auf den Pfad \"S:\\repo\\x\" wurde verweigert.")))

    def test_c_access_is_denied_is_blind(self):
        self.assert_blind(stream(cmd(1, "Access is denied.")))

    # The required signatures, written out here on purpose: deriving them from the
    # implementation would let a removed alternative take its own test case with it.
    REQUIRED_SIGNATURES = (
        "CreateProcessAsUserW failed: 5",
        "Access to the path 'S:\\repo\\AGENTS.md' is denied.",
        "[Errno 13] Permission denied: 'AGENTS.md'",
        "Access is denied.",
        "Zugriff verweigert",
        'Der Zugriff auf den Pfad "S:\\repo\\AGENTS.md" wurde verweigert.',
        "cat: AGENTS.md: Operation not permitted",
        "System.UnauthorizedAccessException: Access to S:\\repo",
    )

    def test_every_required_signature_alone_makes_a_denied_round_blind(self):
        """Gate round 0, TESTS-1: each signature by itself, in three cases."""
        for text in self.REQUIRED_SIGNATURES:
            for variant in (text, text.lower(), text.upper()):
                with self.subTest(variant[:45]):
                    self.assert_blind(stream(cmd(1, "error: " + variant)))

    def test_d_one_success_among_denials_is_accepted(self):
        self.assert_accepted(stream(cmd(-1, "CreateProcessAsUserW failed: 5"), cmd(0, "ok"),
                                    cmd(1, "Access is denied.")), ROUTER_ASUSER)

    def test_e_only_ordinary_failures_are_accepted_with_a_warning(self):
        err = self.assert_accepted(stream(cmd(1, ""), cmd(1, "")))
        self.assertIn("no command succeeded", err)

    def test_f_denial_text_only_in_the_answer_is_accepted(self):
        text = THREAD + TURN + cmd(1, "") + answer("Access is denied everywhere, CreateProcessAsUserW failed") + DONE
        self.assert_accepted(text)

    def test_g_denial_in_an_earlier_turn_success_in_the_last_is_accepted(self):
        text = (THREAD + TURN + cmd(1, "Access is denied.") + answer() + DONE
                + TURN + cmd(0, "ok") + answer() + DONE)
        self.assert_accepted(text)

    def test_h_denial_after_a_megabyte_of_padding_is_found(self):
        self.assert_blind(stream(cmd(1, "x" * (1024 * 1024) + "\nAccess to the path 'S:\\a' is denied.")))

    # -- condition B: router execution-error records in stderr -------------------------
    def test_i_router_record_with_no_command_events_is_blind(self):
        self.assert_blind(THREAD + TURN + answer() + DONE, ROUTER_ASUSER)

    def test_j_non_router_quotations_never_count(self):
        quotes = ("WARN something: Access is denied while probing a helper\n"
                  "note: CreateProcessAsUserW failed in an unrelated tool\n"
                  "a log line mentioning rejected: blocked by policy\n"
                  "a log line mentioning CreateProcessWithLogonW failed\n")
        err = self.assert_accepted(stream(cmd(1, "")), quotes)
        self.assertIn("no command succeeded", err)

    def test_k_ordinary_failure_plus_router_record_is_blind_for_each_signature(self):
        legacy = _router_legacy_lines()
        self.assertTrue(legacy, "fixture blind-run.stderr.txt must carry a router line")
        for label, record in (("AsUserW", ROUTER_ASUSER), ("access", ROUTER_ACCESS),
                              ("blocked-by-policy", "".join(legacy)), ("LogonW", ROUTER_LOGONW)):
            with self.subTest(label):
                self.assert_blind(stream(cmd(1, "")), record)

    def test_k_a_quoted_complete_router_record_does_not_count(self):
        """Inspection finding 2: the record header must start the line."""
        for record in (ROUTER_ASUSER, ROUTER_ACCESS, ROUTER_LOGONW, "".join(_router_legacy_lines())):
            with self.subTest(record[:40]):
                err = self.assert_accepted(stream(cmd(1, "")), "WARN helper: example: " + record)
                self.assertIn("no command succeeded", err)

    # -- long paths (inspection finding 1) ---------------------------------------------
    def test_h_long_paths_do_not_hide_the_denial(self):
        long_path = "S:\\" + "d" * 5000 + "\\AGENTS.md"
        for text in (f"Access to the path '{long_path}' is denied.",
                     f'Der Zugriff auf den Pfad "{long_path}" wurde verweigert.'):
            with self.subTest(text[:30]):
                self.assert_blind(stream(cmd(1, text)))

    # -- combined predicates keep every reason and the matching hint (finding 3) --------
    def test_combined_legacy_refusal_and_start_failure_keep_both_hints(self):
        legacy = "".join(_router_legacy_lines())
        reason = self.assert_blind(THREAD + TURN + answer() + DONE, ROUTER_ASUSER + legacy)
        self.assertIn("refused (stderr)", reason)
        self.assertIn("2 execution-error record(s) (stderr)", reason)
        self.assertIn("review_mirror", reason, "start failure -> environment hint")
        self.assertTrue("openai/codex#42172" in reason or "sandbox helper" in reason,
                        "refusal -> sandbox hint")

    def test_one_record_with_both_signatures_keeps_both_hints_and_counts_once(self):
        """Reinspection finding 1: the refusal flag is not discarded when the same record
        also carries an access signature."""
        record = _router_legacy_lines()[0].rstrip("\n") + " rg Access is denied\n"
        reason = self.assert_blind(stream(cmd(1, "")), record)
        self.assertIn("1 execution-error record(s) (stderr)", reason)
        self.assertIn("review_mirror", reason)
        self.assertTrue("openai/codex#42172" in reason or "sandbox helper" in reason)

    def test_ordinary_failure_plus_legacy_router_refusal_gets_the_sandbox_hint_only(self):
        reason = self.assert_blind(stream(cmd(1, "")), "".join(_router_legacy_lines()))
        self.assertTrue("openai/codex#42172" in reason or "sandbox helper" in reason)
        self.assertNotIn("review_mirror", reason)

    # -- last turn only (finding 5) ----------------------------------------------------
    def test_success_in_an_earlier_turn_does_not_validate_a_denied_last_turn(self):
        text = (THREAD + TURN + cmd(0, "ok") + answer() + DONE
                + TURN + cmd(1, "Access is denied.") + answer() + DONE)
        self.assert_blind(text)
        s = self.dir / "s.json"
        s.write_text(text, encoding="utf-8")
        ev_ = codex_ro.read_stream_evidence(s)
        self.assertEqual((ev_.executed, ev_.succeeded, ev_.failed_start_or_denied), (1, 0, 1))

    def test_denial_in_an_earlier_turn_does_not_taint_an_ordinary_last_turn(self):
        text = (THREAD + TURN + cmd(-1, "CreateProcessAsUserW failed: 5") + answer() + DONE
                + TURN + cmd(1, "") + answer() + DONE)
        err = self.assert_accepted(text)
        self.assertIn("no command succeeded", err)
        s = self.dir / "s.json"
        s.write_text(text, encoding="utf-8")
        ev_ = codex_ro.read_stream_evidence(s)
        self.assertEqual((ev_.executed, ev_.succeeded, ev_.failed_start_or_denied), (1, 0, 0))

    # -- every incomplete-evidence cause, beside a failure and beside a success (finding 6)
    def test_c_oversized_stderr_beside_an_ordinary_failure_is_blind(self):
        # The stream gets its own, ample limit: only stderr is over the (patched) cap.
        with unittest.mock.patch.object(codex_ro, "EVIDENCE_LIMIT", 200):
            reason = self.assert_blind(stream(cmd(1, "")), "x" * 1000 + "\n", limit=10**6)
        self.assertIn("stderr exceeds", reason)
        self.assertNotIn("event stream is larger", reason)

    def test_c_unclassified_command_beside_an_ordinary_failure_is_blind(self):
        bad = ev("item.completed", item={"id": "item_u", "type": "command_execution",
                                         "command": "x", "exit_code": True, "status": "failed"})
        reason = self.assert_blind(stream(cmd(1, ""), bad))
        self.assertIn("cannot be classified", reason)

    def test_c_every_cause_beside_a_success_only_warns(self):
        bad = ev("item.completed", item={"id": "item_u", "type": "command_execution",
                                         "command": "x", "exit_code": True, "status": "failed"})
        err = self.assert_accepted(stream(cmd(0, "ok"), bad))
        self.assertIn("cannot be classified", err)
        with unittest.mock.patch.object(codex_ro, "EVIDENCE_LIMIT", 200):
            err = self.assert_accepted(stream(cmd(0, "ok")), "x" * 1000 + "\n", limit=10**6)
        self.assertIn("stderr exceeds", err)

    # -- condition C: incomplete evidence with zero successes --------------------------
    def test_l_truncated_stream_after_an_ordinary_failure_is_blind_and_named(self):
        head = THREAD + TURN + cmd(1, "")
        text = head + cmd(1, "y" * 4000) + answer() + DONE
        reason = self.assert_blind(text, limit=len(head.encode("utf-8")) + 100)
        self.assertIn("larger than", reason, "the reason must name the truncated stream")

    def test_l_truncated_stream_after_a_success_is_accepted(self):
        head = THREAD + TURN + cmd(0, "ok")
        text = head + cmd(1, "y" * 4000) + answer() + DONE
        err = self.assert_accepted(text, limit=len(head.encode("utf-8")) + 100)
        self.assertIn("evidence is unusable", err)

    def test_m_malformed_outputs_raise_nothing(self):
        def raw(output):
            item = {"id": "item_m", "type": "command_execution", "command": "x",
                    "aggregated_output": output, "exit_code": 1, "status": "failed"}
            return ev("item.completed", item=item)
        err = self.assert_accepted(stream(raw(None)), msg="null output = empty text")
        self.assertIn("no command succeeded", err)
        for bad in ([1, 2], {"a": 1}, 7):
            with self.subTest(repr(bad)):
                self.assert_blind(stream(raw(bad)), msg="non-string output is unclassified")

    def test_m_malformed_output_after_a_success_still_warns_only(self):
        item = {"id": "item_m", "type": "command_execution", "command": "x",
                "aggregated_output": [1], "exit_code": 1, "status": "failed"}
        err = self.assert_accepted(stream(cmd(0, "ok"), ev("item.completed", item=item)))
        self.assertIn("cannot be classified", err)

    # -- the 2.7.0 behaviour that must stay --------------------------------------------
    def test_no_command_and_no_refusal_stays_accepted(self):
        self.assert_accepted(THREAD + TURN + answer() + DONE)

    def test_legacy_refusal_with_nothing_executed_stays_blind(self):
        self.assert_blind((FIXTURES / "blind-run.stream.json").read_text(encoding="utf-8"),
                          (FIXTURES / "blind-run.stderr.txt").read_text(encoding="utf-8"))


class MainLevel(AppliedBase):
    """The same verdicts at the reporting boundary: exit code and no OUT= line."""

    UNSAFE = {"sandbox_policy": {"type": "workspace-write"}}

    def fixture(self, name):
        return ((DENIED / f"{name}.stream.json").read_text(encoding="utf-8"),
                (DENIED / f"{name}.stderr.txt").read_text(encoding="utf-8"),
                (DENIED / f"{name}.answer.md").read_text(encoding="utf-8"))

    def test_every_real_blind_set_exits_3_without_out(self):
        for name in REAL_SETS:
            with self.subTest(name):
                for leftover in (self.home / "sessions").rglob("*.jsonl"):
                    leftover.unlink()
                s, e, a = self.fixture(name)
                result = self.drive(self.normal(), stream=s, stderr=e, answer=a)
                self.assertEqual(result.code, codex_ro.EXIT_BLIND, result.out + result.err)
                self.assertEqual(result.out_lines, [], "a blind run must not print OUT=")

    def test_unsafe_sandbox_beats_the_new_blind_condition(self):
        s, e, a = self.fixture("network-share")
        self.assert_unsafe(self.drive(self.normal(**self.UNSAFE), stream=s, stderr=e, answer=a))

    def test_the_real_normal_run_exits_0(self):
        s = (FIXTURES / "normal-run.stream.json").read_text(encoding="utf-8")
        result = self.drive(self.normal(), stream=s)
        self.assertEqual(result.code, 0, result.out + result.err)
        self.assertEqual(len(result.out_lines), 1)


if __name__ == "__main__":
    unittest.main()
