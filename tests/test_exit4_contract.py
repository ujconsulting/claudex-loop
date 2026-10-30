#!/usr/bin/env python3
"""Every place that runs or interprets the wrapper must treat exit 4 as an invalid review.

`codex_ro.py` 2.7.0 added exit 4 (EXIT_UNSAFE_SANDBOX): the session rollout showed the
answering turn ran with something other than a read-only sandbox / permission profile /
approval `never`. Like exit 3 it looks healthy from outside (a thread id, a full answer
file, often VERDICT: APPROVED) and is NOT a review -- and unlike exit 3 the reviewer may
have written files. A skill that learned "exit 3 is an invalid round" but never heard of
exit 4 would log the round as a pass.

Two granularities (post-build inspection of 2.7.0, finding 5: one mention anywhere in a
document let a second call site without the rule pass, and docs-backfill escaped because
it named neither exit):

1. every document that names exit 3 also names exit 4 -- the READMEs included;
2. every SKILL.md section (a `##`/`###` heading up to the next heading of the same or a
   higher level) that contains a wrapper call names exit 4 in that section, or the skill
   states the rule once in a section the call section points to by name. In practice
   each call section carries it.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILLS = sorted((REPO / "skills").glob("*/SKILL.md"))
DOCS = SKILLS + [REPO / "FALLBACK.md", REPO / "docs" / "betrieb.md",
                 REPO / "README.md", REPO / "README_DE.md"]

# An empty list would make the test pass by checking nothing.
assert len(SKILLS) >= 5, "no skills found - the contract would be vacuous"

EXIT3 = re.compile(r"\bexit 3\b|\bexits 3\b|\bEXIT_BLIND\b|`3` blind|\*\*3\*\*", re.I)
EXIT4 = re.compile(r"\bexit 4\b|\bexits 4\b|\bEXIT_UNSAFE_SANDBOX\b|`4` unsafe|\*\*4\*\*", re.I)
WRAPPER_CALL = re.compile(r"codex_ro\.py\s+--|codex_ro\.py`?\s*\(|tools/codex_ro\.py --")
HEADING = re.compile(r"^(#{2,4}) ", re.M)


def sections(text: str):
    """(heading line, body) for every ##..#### section, ending at the next heading of the
    same or a higher level."""
    marks = [(m.start(), len(m.group(1))) for m in HEADING.finditer(text)]
    for i, (start, level) in enumerate(marks):
        end = len(text)
        for nstart, nlevel in marks[i + 1:]:
            if nlevel <= level:
                end = nstart
                break
        yield text[start:text.find("\n", start)], text[start:end]


def call_sections(text: str) -> tuple[int, list[str]]:
    """(number of sections holding a wrapper call, headings of those whose OWN text -- the
    section up to its first subsection -- does not name exit 4). A child section's mention
    never counts for its parent (post-build inspection round 2, finding 1)."""
    calls, bad = 0, []
    for heading, body in sections(text):
        sub = HEADING.search(body, len(heading))
        own = body[:sub.start()] if sub else body
        if WRAPPER_CALL.search(own):
            calls += 1
            if not EXIT4.search(own):
                bad.append(heading.strip())
    return calls, bad


class Exit4Contract(unittest.TestCase):
    def test_every_exit3_mention_has_an_exit4_mention(self):
        missing, mentioning = [], 0
        for path in DOCS:
            self.assertTrue(path.is_file(), f"expected {path}")
            text = path.read_text(encoding="utf-8")
            if EXIT3.search(text):
                mentioning += 1
                if not EXIT4.search(text):
                    missing.append(str(path.relative_to(REPO)))
        self.assertGreater(mentioning, 0, "no document mentions exit 3 - pattern is stale")
        self.assertEqual(missing, [], f"mention exit 3 but not exit 4: {missing}")

    def test_every_skill_section_with_a_wrapper_call_names_exit_4(self):
        missing, calls = [], 0
        for path in SKILLS:
            found, bad = call_sections(path.read_text(encoding="utf-8"))
            calls += found
            missing += [f"{path.relative_to(REPO)} :: {h}" for h in bad]
        self.assertGreater(calls, 3, "no wrapper call found in any skill - pattern is stale")
        self.assertEqual(missing, [], f"wrapper call without exit-4 handling: {missing}")

    # The fixtures below run through THE SAME checker as the real skills (closing gate of
    # 2.7.0: a copy of the logic in the test let the real checker regress unnoticed).

    def test_a_child_section_cannot_mask_a_parent_call_without_the_rule(self):
        """Inspection round 2: parent call without the rule, child section mentions exit 4."""
        text = ('## Parent\n' '\n' '`python tools/codex_ro.py --prompt-file p`\n' '\n' '### Child\n' '\n' 'exit 4 is mentioned here only.\n')
        self.assertEqual(call_sections(text), (1, ["## Parent"]))

    def test_the_check_bites_on_a_second_call_site_without_the_rule(self):
        """Mutation from the inspection: two call sections, only one with the rule."""
        text = ('## A\n' '\n' '`python tools/codex_ro.py --prompt-file p` -- exit 3 and exit 4 are invalid.\n' '\n' '## B\n' '\n' '`python tools/codex_ro.py --prompt-file q`\n')
        self.assertEqual(call_sections(text), (2, ["## B"]))

    def test_a_call_with_the_rule_in_its_own_section_passes(self):
        text = ('## A\n' '\n' '`python tools/codex_ro.py --prompt-file p` -- exit 4 is invalid.\n')
        self.assertEqual(call_sections(text), (1, []))


if __name__ == "__main__":
    unittest.main()
