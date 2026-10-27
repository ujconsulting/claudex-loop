#!/usr/bin/env python3
"""code-review: Claude Code's `security-review` runs as a PRE-FILTER, before Codex grades.

Decision of 2026-10-27: a same-provider security pass is cheap and catches the obvious
before Codex quota and rechecks are spent -- but when Claude built the change, it is the
maker looking at its own work. So it may only ever filter, never grade:

- it runs before the evidence for Codex is assembled, so its accepted fixes are part
  of the diff Codex judges;
- its result is logged like every review, with dispositions;
- it never yields a SECURITY verdict and never counts as a pass;
- Codex does not see its findings -- a cold read, not one anchored on the maker's list.

Written before the skill text and seen failing first.
"""

from __future__ import annotations

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILL = REPO / "skills" / "code-review" / "SKILL.md"


class SecurityPrefilterContract(unittest.TestCase):
    def setUp(self):
        self.text = SKILL.read_text(encoding="utf-8")

    def section(self):
        start = self.text.find("### Step 0 — Security pre-filter")
        self.assertNotEqual(start, -1, "the pre-filter step is missing")
        end = self.text.find("\n### ", start + 1)
        return self.text[start:end]

    def test_the_prefilter_runs_before_the_evidence_for_codex_is_assembled(self):
        self.assertLess(self.text.find("### Step 0 — Security pre-filter"),
                        self.text.find("### Step 1 — Assemble the evidence"))

    def test_it_uses_the_security_review_skill_and_only_with_the_security_scope(self):
        s = self.section()
        self.assertIn("`security-review`", s)
        self.assertIn("`scope` contains `security`", s)

    def test_it_is_advisory_and_never_a_verdict(self):
        s = self.section()
        self.assertIn("never a `SECURITY` verdict", s)
        self.assertIn("never counts as a pass", s)

    def test_codex_does_not_see_its_findings(self):
        self.assertIn("not shown to the reviewer", self.section())

    def test_it_is_logged_with_dispositions_and_a_skip_is_logged_too(self):
        s = self.section()
        self.assertIn("## Security pre-filter", s)
        self.assertIn("dispositions", s)
        self.assertIn("skipped", s)

    def test_a_tunable_switches_it_and_the_hard_rules_name_it(self):
        self.assertIn("| `SECURITY_PREFILTER` |", self.text)
        rules = self.text[self.text.find("## Hard rules"):self.text.find("## What NOT to do")]
        self.assertIn("pre-filter", rules)


if __name__ == "__main__":
    unittest.main()
