"""gate_reminder.py: reminds at `git commit` when a plan's closing gate is pending.

Both directions, and the second matters more: a hook that chatters on unrelated
commands gets switched off, and then it reminds nobody. It must also never block --
the gate costs Codex quota, and an exhausted quota must not stop a commit.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / "hooks" / "gate_reminder.py"


def run_hook(payload) -> subprocess.CompletedProcess:
    data = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run([sys.executable, str(HOOK)], input=data,
                          capture_output=True, text=True, encoding="utf-8")


class Repo:
    """A throwaway directory that looks like a repo (a .git folder is enough)."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / ".git").mkdir()

    def plan(self, rel: str, marker: str | None) -> Path:
        p = self.root / rel / "PLAN.md"
        p.parent.mkdir(parents=True, exist_ok=True)
        body = "# PLAN\n\nSteps...\n"
        if marker:
            body += f"\n<!-- claudex-gate: {marker} -->\n"
        p.write_text(body, encoding="utf-8")
        return p

    def payload(self, command: str, tool="Bash", session=None, cwd=None):
        return {"tool_name": tool, "tool_input": {"command": command},
                "cwd": str(cwd or self.root), "session_id": session or uuid.uuid4().hex}

    def close(self):
        self._tmp.cleanup()


def context_of(result) -> str:
    return json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]


class FiresTests(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.close()

    def test_commit_with_pending_plan_reminds(self):
        self.repo.plan("_todos/plaene/feature-x", "pending")
        r = run_hook(self.repo.payload('git commit -m "Feature X"'))
        self.assertEqual(r.returncode, 0)
        ctx = context_of(r)
        self.assertIn("_todos/plaene/feature-x/PLAN.md", ctx)
        self.assertIn("code-review", ctx)
        self.assertIn("not blocked", ctx)

    def test_root_plan_and_powershell_and_git_dash_c(self):
        self.repo.plan(".", "pending")
        for cmd, tool in (("git -C sub commit -m x", "Bash"),
                          ("git add a.py; git commit -m x", "Bash"),
                          ("git commit -m x", "PowerShell")):
            with self.subTest(cmd=cmd, tool=tool):
                r = run_hook(self.repo.payload(cmd, tool=tool))
                self.assertIn("PLAN.md", context_of(r))

    def test_called_from_a_subdirectory_finds_the_repo_root(self):
        self.repo.plan("docs/plans/a", "pending")
        sub = self.repo.root / "src" / "deep"
        sub.mkdir(parents=True)
        r = run_hook(self.repo.payload("git commit -m x", cwd=sub))
        self.assertIn("docs/plans/a/PLAN.md", context_of(r))

    def test_marker_case_and_spacing_tolerated(self):
        p = self.repo.root / "PLAN.md"
        p.write_text("x\nclaudex-gate:   PENDING\n", encoding="utf-8")
        self.assertIn("PLAN.md", context_of(run_hook(self.repo.payload("git commit -m x"))))

    def test_without_session_id_still_reminds(self):
        self.repo.plan(".", "pending")
        p = self.repo.payload("git commit -m x")
        del p["session_id"]
        self.assertIn("PLAN.md", context_of(run_hook(p)))
        self.assertIn("PLAN.md", context_of(run_hook(p)))


class SilentTests(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.close()

    def assert_silent(self, result):
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")

    def test_no_marker_is_silent(self):
        self.repo.plan("_todos/plaene/old", None)
        self.assert_silent(run_hook(self.repo.payload("git commit -m x")))

    def test_done_and_skipped_are_silent(self):
        self.repo.plan("a", "done")
        self.repo.plan("b", "skipped")
        self.assert_silent(run_hook(self.repo.payload("git commit -m x")))

    def test_other_commands_are_silent(self):
        self.repo.plan(".", "pending")
        for cmd in ("git status", "git log --oneline", "git commit-tree abc",
                    "echo 'git commit later'", "grep -rn commit .", "python build.py",
                    "git add PLAN.md"):
            with self.subTest(cmd=cmd):
                self.assert_silent(run_hook(self.repo.payload(cmd)))

    def test_other_tools_are_silent(self):
        self.repo.plan(".", "pending")
        p = self.repo.payload("git commit -m x", tool="Read")
        self.assert_silent(run_hook(p))

    def test_once_per_session_and_plan(self):
        self.repo.plan(".", "pending")
        sid = uuid.uuid4().hex
        self.assertIn("PLAN.md", context_of(run_hook(self.repo.payload("git commit -m 1", session=sid))))
        self.assert_silent(run_hook(self.repo.payload("git commit -m 2", session=sid)))
        # a NEW pending plan in the same session is still mentioned, the old one not again
        self.repo.plan("later", "pending")
        ctx = context_of(run_hook(self.repo.payload("git commit -m 3", session=sid)))
        self.assertIn("later/PLAN.md", ctx)
        self.assertNotIn("- PLAN.md", ctx)

    def test_hidden_and_vendor_dirs_are_not_scanned(self):
        self.repo.plan(".claudex-tmp/x", "pending")
        self.repo.plan("node_modules/pkg", "pending")
        self.assert_silent(run_hook(self.repo.payload("git commit -m x")))

    def test_outside_a_repo_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "PLAN.md").write_text("claudex-gate: pending", encoding="utf-8")
            p = {"tool_name": "Bash", "tool_input": {"command": "git commit -m x"},
                 "cwd": tmp, "session_id": uuid.uuid4().hex}
            # tmp may sit inside some other repo on a dev box; then it is that repo's business.
            # What must hold: no crash, exit 0, never a deny.
            r = run_hook(p)
            self.assertEqual(r.returncode, 0)
            self.assertNotIn("deny", r.stdout)

    def test_fail_open_on_garbage(self):
        for data in ("not json", "", "[]", json.dumps({"tool_name": "Bash"}),
                     json.dumps({"tool_name": "Bash", "tool_input": None})):
            with self.subTest(data=data):
                self.assert_silent(run_hook(data))

    def test_never_denies(self):
        self.repo.plan(".", "pending")
        r = run_hook(self.repo.payload("git commit -m x"))
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("permissionDecision", r.stdout)


if __name__ == "__main__":
    unittest.main()
