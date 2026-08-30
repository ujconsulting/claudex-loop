#!/usr/bin/env python3
"""Regression tests for the fallback reviewer's audit fixes (2026-08-30).

The egress HOST rules live in test_egress.py. What is pinned here is everything
else that pass turned up: redirects, what counts as a finding, where the verdict
has to sit, which files may be inlined into a remote prompt, and the two output
guarantees (no stale verdict, always a log entry).

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import http.server
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import fallback_review  # noqa: E402


class _Redirector(http.server.BaseHTTPRequestHandler):
    """Answers every request with a 302 to a host that is not on any allowlist."""

    def do_GET(self):  # noqa: N802 - the stdlib spells it this way
        self.send_response(302)
        self.send_header("Location", "https://exfiltration.example/v1/models")
        self.end_headers()

    def log_message(self, *args):
        pass


class RedirectTests(unittest.TestCase):
    """A redirect is a destination nobody checked.

    check_egress() vets the URL we chose; urlopen's default handler then follows
    30x hops without asking again, and Python re-sends Authorization on a
    same-scheme redirect. An allowlisted provider could bounce the plan -- and the
    key -- somewhere else entirely (audit 2026-08-30, HIGH). The old suite proved
    only that the FIRST url was checked before the socket opened, which is
    precisely the half that was never in doubt.
    """

    def setUp(self):
        self.server = http.server.HTTPServer(("127.0.0.1", 0), _Redirector)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_port}/v1/models"
        # BOTH egress variables, or a developer with a file allowlist configured
        # gets a different result from this test than CI does -- the same
        # hermeticity defect the audit found in test_egress.py, reintroduced
        # here. (CodeRabbit, 2026-08-30.)
        self._saved = {
            name: os.environ.get(name)
            for name in (fallback_review.EGRESS_ALLOW_ENV, fallback_review.EGRESS_FILE_ENV)
        }
        for name in self._saved:
            os.environ.pop(name, None)
        self.addCleanup(self._restore)

    def _restore(self):
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def test_a_redirect_is_refused_rather_than_followed(self):
        with self.assertRaises(fallback_review.EgressDenied) as caught:
            fallback_review.http_get_json(self.url, {"Authorization": "Bearer secret"})
        message = str(caught.exception)
        self.assertIn("exfiltration.example", message, "say where it wanted to go")
        self.assertNotIn("secret", message, "never echo the credential")

    def _with_proxy_env(self):
        """A proxy really configured, so the assertions below measure something."""
        for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
            saved = os.environ.get(name)
            os.environ[name] = "http://proxy.invalid:3128"
            self.addCleanup(
                lambda n=name, v=saved: os.environ.__setitem__(n, v)
                if v is not None
                else os.environ.pop(n, None)
            )

    def _proxy_handlers(self, opener):
        cls = fallback_review.urllib.request.ProxyHandler
        return [h for h in opener.handlers if isinstance(h, cls)]

    def test_loopback_requests_bypass_a_proxy(self):
        """HTTP_PROXY would otherwise route cleartext loopback traffic outward.

        Passing an empty ProxyHandler suppresses the default one that reads the
        environment; the empty instance registers no `*_open` method of its own,
        so the guarantee shows up as the ABSENCE of any proxy handler.
        """
        self._with_proxy_env()
        self.assertEqual(
            self._proxy_handlers(fallback_review._opener("http://127.0.0.1:1234/v1")),
            [],
            "no proxy may carry loopback traffic off the machine",
        )

    def test_remote_requests_still_honour_a_corporate_proxy(self):
        # Remote traffic is https-only, so a proxy sees a CONNECT tunnel and
        # nothing else -- taking it away would just break people behind one.
        self._with_proxy_env()
        self.assertTrue(
            self._proxy_handlers(fallback_review._opener("https://openrouter.ai/api/v1"))
        )


class FindingCountTests(unittest.TestCase):
    """An outline entry is not a finding.

    Counting every numbered line let a three-item summary satisfy the
    anti-rubber-stamp floor, and the old comment called that harmless.
    """

    def test_substantial_numbered_lines_count(self):
        text = (
            "1. The egress allowlist defaults open, so any https host receives the plan.\n"
            "2. Redirects are never re-validated and can carry the Authorization header.\n"
            "3. `lms load` has no timeout, so a hung runtime blocks the whole chain.\n"
        )
        self.assertEqual(fallback_review.count_findings(text), 3)

    def test_a_bare_outline_does_not_count(self):
        self.assertEqual(fallback_review.count_findings("1. Security\n2. Tests\n3. Docs\n"), 0)

    def test_a_multiline_finding_with_a_short_first_line_counts(self):
        """The shape every real reviewer uses, and the one that got dropped.

        Measuring only the first line made "1. **CRITICAL** — `guard.py:51`"
        too short to count, so a thorough review could be rejected as a rubber
        stamp for formatting normally. (CodeRabbit, 2026-08-30.)
        """
        text = (
            "1. **CRITICAL** — `hooks/wrapper_guard.py:51`\n"
            "   Bash expands `${IFS}` after splitting commands, so the token does\n"
            "   not end in the wrapper name and the guard never sees an invocation.\n"
            "   Fix: strip expansions before matching.\n"
            "2. **HIGH** — `scripts/codex_ro.py:124`\n"
            "   `--allow-path` rides the same allowlist approval as the call itself.\n"
            "   Fix: opt-in roots widen reads only.\n"
        )
        self.assertEqual(fallback_review.count_findings(text), 2)

    def test_the_last_finding_is_counted_too(self):
        """It runs to end-of-text rather than to a following numbered line."""
        text = (
            "Intro.\n"
            "1. The egress allowlist defaults open, so any https host receives the plan.\n"
        )
        self.assertEqual(fallback_review.count_findings(text), 1)

    def test_numbering_may_restart_per_section(self):
        text = (
            "## SECURITY\n"
            "1. The allowlist defaults open, so any https host receives the plan text.\n"
            "## QUALITY\n"
            "1. The preflight treats a 503 as availability and burns a review round.\n"
        )
        self.assertEqual(fallback_review.count_findings(text), 2)


class VerdictPositionTests(unittest.TestCase):
    """The system prompt says "End your reply with EXACTLY one line". It meant it."""

    def _args(self, **over):
        base = dict(require_verdicts=None, round_no=2, min_findings=3)
        base.update(over)
        return SimpleNamespace(**base)

    def test_a_closing_verdict_is_accepted(self):
        code, status = fallback_review.validate(
            "Some critique.\n\nVERDICT: REVISE", self._args(), {"name": "t"}
        )
        self.assertEqual(code, 0)
        self.assertIn("REVISE", status)

    def test_trailing_blank_lines_are_tolerated(self):
        code, _ = fallback_review.validate(
            "Critique.\n\nVERDICT: APPROVED\n\n   \n", self._args(), {"name": "t"}
        )
        self.assertEqual(code, 0)

    def test_a_verdict_buried_mid_reply_is_invalid(self):
        code, status = fallback_review.validate(
            "VERDICT: APPROVED\n\nand here is a lot more text afterwards.\n",
            self._args(),
            {"name": "t"},
        )
        self.assertEqual(code, 3)
        self.assertIn("INVALID", status)

    def test_several_named_verdicts_may_close_the_reply_together(self):
        code, _ = fallback_review.validate(
            "Critique.\n\nDOD: COMPLETE\nQUALITY: ACCEPTABLE\n",
            self._args(require_verdicts="DOD:COMPLETE|INCOMPLETE,QUALITY:ACCEPTABLE|REVISE"),
            {"name": "t"},
        )
        self.assertEqual(code, 0)


class ConfinedInputTests(unittest.TestCase):
    """--plan / --log / --system-file are inlined into a prompt bound for a model.

    The allowed roots are the repo, `<repo>/.claudex-tmp/` and an explicitly named
    CLAUDEX_SCRATCH_DIR -- deliberately NOT the whole OS temp dir, which on Linux
    and macOS is world-writable `/tmp`. The skills' own rule already forbids /tmp;
    this is that rule enforced. (CodeRabbit, 2026-08-30.)
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self._saved = os.environ.get(fallback_review.SCRATCH_DIR_ENV)
        os.environ[fallback_review.SCRATCH_DIR_ENV] = str(self.root)
        self.addCleanup(self._restore)

    def _restore(self):
        if self._saved is None:
            os.environ.pop(fallback_review.SCRATCH_DIR_ENV, None)
        else:
            os.environ[fallback_review.SCRATCH_DIR_ENV] = self._saved

    def test_a_file_in_the_named_scratch_dir_is_read(self):
        path = self.root / "PLAN.md"
        path.write_text("the plan", encoding="utf-8")
        self.assertEqual(fallback_review.read_confined(path, "--plan"), "the plan")

    def test_the_bare_os_temp_dir_is_not_a_root(self):
        os.environ.pop(fallback_review.SCRATCH_DIR_ENV, None)
        stray = Path(tempfile.gettempdir()).resolve() / "claudex-stray-plan.md"
        stray.write_text("planted by anyone with write access to /tmp", encoding="utf-8")
        self.addCleanup(lambda: stray.exists() and stray.unlink())
        with self.assertRaises(SystemExit) as caught:
            fallback_review.read_confined(stray, "--plan")
        self.assertIn("outside the allowed roots", str(caught.exception))

    def test_a_credential_shaped_name_is_refused(self):
        for name in (".env", "secrets.yaml", "server.pem", "id_rsa", "credentials"):
            with self.subTest(name=name):
                path = self.root / name
                path.write_text("secret material", encoding="utf-8")
                with self.assertRaises(SystemExit) as caught:
                    fallback_review.read_confined(path, "--plan")
                self.assertNotIn("secret material", str(caught.exception))

    def test_a_file_outside_the_roots_is_refused(self):
        outside = Path(os.path.expanduser("~")) / "nowhere-claudex-test.md"
        with self.assertRaises(SystemExit) as caught:
            fallback_review.read_confined(outside, "--plan")
        self.assertIn("outside", str(caught.exception))

    def test_an_oversized_file_is_refused(self):
        path = self.root / "PLAN.md"
        path.write_text("x" * (fallback_review.MAX_INPUT_BYTES + 1), encoding="utf-8")
        with self.assertRaises(SystemExit) as caught:
            fallback_review.read_confined(path, "--plan")
        self.assertIn("ceiling", str(caught.exception))


class AtomicOutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def test_the_content_arrives_and_no_partial_file_remains(self):
        target = self.root / "verdict.txt"
        fallback_review.write_atomically(target, "VERDICT: REVISE\n")
        self.assertEqual(target.read_text(encoding="utf-8"), "VERDICT: REVISE\n")
        self.assertEqual([p.name for p in self.root.iterdir()], ["verdict.txt"])

    def test_it_replaces_rather_than_appends(self):
        target = self.root / "verdict.txt"
        target.write_text("VERDICT: APPROVED (stale)\n", encoding="utf-8")
        fallback_review.write_atomically(target, "VERDICT: REVISE\n")
        self.assertNotIn("stale", target.read_text(encoding="utf-8"))


class LogHeadingTests(unittest.TestCase):
    def test_the_label_carries_the_limitation_the_rule_demands(self):
        # FALLBACK.md: "## Round <n> — <model> (via <reviewer>, fallback —
        # plan-text only, no repo access)". The code wrote only "fallback".
        self.assertEqual(
            fallback_review.FALLBACK_LABEL, "fallback — plan-text only, no repo access"
        )


class MandatoryLogTests(unittest.TestCase):
    """FALLBACK.md: "Findings never live only in the chat." Both halves of it.

    The flag being optional was the finding; that it is now required was asserted
    nowhere, and neither was the harder half -- that an INVALID attempt is logged
    too, labelled as not counting. A rejected reply is still evidence: which model
    was tried, why it failed, what the user decided next. (CodeRabbit, 2026-08-30.)
    """

    def test_a_run_without_append_log_is_refused(self):
        argv = ["fallback_review.py", "--plan", "PLAN.md"]
        previous = sys.argv
        sys.argv = argv
        try:
            with self.assertRaises(SystemExit) as caught:
                fallback_review.main()
            # argparse's ap.error() exits 2 -- a refusal, not a review.
            self.assertEqual(caught.exception.code, 2)
        finally:
            sys.argv = previous

    def test_an_invalid_attempt_is_still_appended_and_labelled(self):
        """Drive run_review, don't hand-write the entry.

        The first version composed the log line itself and then asserted on its
        own string — it tested the test. The production path is what has to
        write "INVALID ATTEMPT" into the log, so the transport is stubbed and
        run_review actually runs. (CodeRabbit, 2026-08-30.)
        """
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "PLAN-REVIEW-LOG.md"
            args = SimpleNamespace(
                round_no=1, min_findings=3, require_verdicts=None,
                out=None, append_log=str(log), system_file=None,
            )
            profile = {
                "name": "t", "model": "m", "base_url": "http://127.0.0.1:1234/v1",
                "api_key": None, "temperature": 0, "max_tokens": 100, "timeout": 5,
            }
            # A reply with findings but no verdict line: valid transport, invalid review.
            body = {"choices": [{"message": {"content":
                "1. The allowlist defaults open, so any https host receives the plan.\n"},
                "finish_reason": "stop"}]}

            class _Resp:
                def read(self_inner): return json.dumps(body).encode()
                def __enter__(self_inner): return self_inner
                def __exit__(self_inner, *exc): return False

            class _Opener:
                def open(self_inner, *a, **k): return _Resp()

            original = fallback_review._opener
            fallback_review._opener = lambda url: _Opener()
            try:
                code = fallback_review.run_review(profile, args, "abc123", "the plan")
            finally:
                fallback_review._opener = original

            self.assertEqual(code, 3, "a reply without a verdict is not a round")
            written = log.read_text(encoding="utf-8")
            self.assertIn("INVALID ATTEMPT, does not count as a round", written)
            self.assertIn(fallback_review.FALLBACK_LABEL, written)
            self.assertIn("abc123", written, "the plan hash binds the entry")


if __name__ == "__main__":
    unittest.main(verbosity=2)
