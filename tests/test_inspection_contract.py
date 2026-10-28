#!/usr/bin/env python3
"""Post-build inspection: its own prompt (upstream #39) and a pinned Git index (upstream #18).

Decision of 2026-10-27 after the upstream briefing:

- chaseai-yt/claudex-loop#39 gave inspections their own instructions instead of reusing
  the plan-review prompt: name the builder, judge against the acceptance criteria, open
  every changed file, flag tests that only confirm the implementation, check guarantees
  claimed in new comments. Our post-build cross-inspection had no prompt text at all.
- chaseai-yt/claudex-loop#18 showed that content staged in the Git index can differ from
  the working tree the inspector saw, so the eventual commit carries uninspected bytes.
  The same gap sat in `build` Step 3: plain `git diff` shows only unstaged changes, so
  anything the builder had staged never reached Claude's diff read.

Written before the skill text and seen failing first.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LOOP = REPO / "skills" / "claudex-loop" / "SKILL.md"
BUILD = REPO / "skills" / "build" / "SKILL.md"


def section(text: str, heading: str) -> str:
    """`heading` up to the next heading of the SAME OR HIGHER level.

    Inspection round 2, finding 19: this used to end only at the next `### `, so a
    `## Step 3` section ran on into Step 5 and a pin deleted from Step 3 was still
    "found" there."""
    start = text.find(heading)
    assert start != -1, heading
    level = len(heading) - len(heading.lstrip("#"))
    pos = text.find("\n", start)
    while pos != -1:
        line_end = text.find("\n", pos + 1)
        line = text[pos + 1:line_end if line_end != -1 else None]
        hashes = len(line) - len(line.lstrip("#"))
        if 0 < hashes <= level and line[hashes:hashes + 1] == " ":
            return text[start:pos]
        pos = line_end
    return text[start:]


class InspectionPrompt(unittest.TestCase):
    def setUp(self):
        self.s = section(LOOP.read_text(encoding="utf-8"), "### Post-build cross-inspection")

    def test_the_inspection_has_its_own_prompt(self):
        for phrase in ("built these changes and you did not",
                       "acceptance criteria",
                       "Open every added or changed file",
                       "merely confirm the implementation",
                       "Verify every guarantee asserted in a new or changed comment",
                       "Trace the callers of every changed function"):
            self.assertIn(phrase, self.s, phrase)

    def test_the_prompt_is_not_the_plan_review_prompt(self):
        self.assertNotIn("adversarial reviewer for an implementation plan", self.s)


class IndexFingerprint(unittest.TestCase):
    def test_inspection_pins_the_index_and_the_commit_checks_it(self):
        s = section(LOOP.read_text(encoding="utf-8"), "### Post-build cross-inspection")
        self.assertIn("git add", s)
        self.assertIn("git write-tree", s)
        self.assertIn("git diff --name-only", s, "unstaged edits after staging = divergent index")
        self.assertIn("git diff --cached", s, "the inspector gets the staged change")
        self.assertIn("before the commit", s)

    def test_build_verify_reads_staged_changes_too(self):
        s = section(BUILD.read_text(encoding="utf-8"), "## Step 3 — Verify")
        self.assertIn("git diff HEAD", s, "plain `git diff` hides what the builder staged")
        self.assertIn("git diff --cached", s)

    def test_build_pins_the_reviewed_tree_and_checks_it_before_the_commit(self):
        """Inspection round 1, finding 19: the build path recorded no reviewed tree."""
        text = BUILD.read_text(encoding="utf-8")
        verify = section(text, "## Step 3 — Verify")
        self.assertIn("git write-tree", verify)
        self.assertIn("REVIEWED_TREE", verify)
        gate = text[text.find("## Step 5 — Human gate"):]
        self.assertIn("REVIEWED_TREE", gate[:gate.find("\n## ", 5)])

    def test_the_bindings_require_equality_and_refuse_a_different_tree(self):
        """Closing gate C2-3: substring checks for command names survived deleting the
        equality rule and replacing the pre-commit comparison with 'just commit'."""
        loop = section(LOOP.read_text(encoding="utf-8"), "### Post-build cross-inspection")
        self.assertIn("`git write-tree` equal to the `INSPECTED_TREE` of the last inspection round", loop)
        self.assertIn("never commit it as inspected", loop)
        text = BUILD.read_text(encoding="utf-8")
        verify = section(text, "## Step 3 — Verify")
        self.assertIn("record `git write-tree` as `REVIEWED_TREE`", verify)
        gate = section(text, "## Step 5 — Human gate")
        self.assertIn("`git write-tree` equal to the last `REVIEWED_TREE`", gate)
        self.assertIn("never commit it as reviewed", gate)

    def test_the_closing_gate_reviews_the_staged_tree(self):
        """Closing gate C2-1: `BASE...HEAD` showed nothing for staged, uncommitted work."""
        s = section((REPO / "skills" / "code-review" / "SKILL.md").read_text(encoding="utf-8"),
                    "### Step 1")
        self.assertIn('git diff --cached "$BASE_REF"', s)
        self.assertIn("GATE_TREE=$(git write-tree)", s)
        self.assertIn("rerun the gate on the new tree", s)
        # recheck C2-1: the gate's own log must not invalidate it forever, and the
        # comparison stays path by path instead of re-pinning the tree
        self.assertIn('git diff --cached --name-only "$GATE_TREE"', s)
        self.assertIn("Do not re-pin `$GATE_TREE`", s)

    def test_the_hunt_step_writes_no_file_by_shell_redirect(self):
        """Closing gate C2-4 and C2-2."""
        text = (REPO / "skills" / "audit" / "SKILL.md").read_text(encoding="utf-8")
        step = section(text, "### Step 3c")
        for block in step.split("```bash")[1:]:
            code = block.split("```")[0]
            self.assertIsNone(re.search(r'(?:^|\s)\d?>{1,2}\s*["$/\w]', code), code)
        self.assertIn("--out-name", step)
        self.assertIn("do not\ncall `judge`", step)

    def test_section_stops_at_the_next_heading_of_equal_or_higher_level(self):
        text = "## A\nx\n### A.1\ny\n## B\nz\n"
        self.assertEqual(section(text, "## A"), "## A\nx\n### A.1\ny")
        self.assertEqual(section(text, "### A.1"), "### A.1\ny")

    def test_build_does_not_misdescribe_git_restore(self):
        s = section(BUILD.read_text(encoding="utf-8"), "## Step 3 — Verify")
        self.assertNotIn("reset the index to the working tree (`git restore --staged", s)
        self.assertIn("back to **`HEAD`**", s)


if __name__ == "__main__":
    unittest.main()
