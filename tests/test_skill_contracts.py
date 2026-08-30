#!/usr/bin/env python3
"""The skills are executable documents. These are the rules their commands must keep.

A skill's shell block is not prose: Claude runs it. Three defects from the audit of
2026-08-30 lived in those blocks with a passing test suite underneath them, because
nothing here ever looked at the recipes:

  * `plan-review` and `setup` called `codex exec` directly, against the repo's own rule
    ("Auch Ping und Resume laufen über den Wrapper") -- giving up the sandbox pin, the
    path bounds, the stderr file, the timeout and the MCP shutdown at once.
  * both plan-review skills ran `"$(cat REVIEW_PROMPT)"`, a file no step creates: an
    empty prompt on a clean repo, and a repo-supplied reviewer instruction otherwise.
  * `build` told the reader that bare `mktemp` avoids `/tmp`, two paragraphs after
    forbidding `/tmp`.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILLS = sorted((REPO / "skills").glob("*/SKILL.md"))
BUILD_SKILL = REPO / "skills" / "build" / "SKILL.md"

# An empty glob would make every contract test below pass by iterating nothing --
# the failure mode where a suite reports green because it checked no files at all.
# (CodeRabbit, 2026-08-30.)
assert SKILLS, f"no SKILL.md found under {REPO / 'skills'} — the contract tests would be vacuous"
assert BUILD_SKILL.is_file(), f"expected the build skill at {BUILD_SKILL}"

# The build skill's own step IS the write: the wrapper exists to make writes
# impossible, so `build` must not be routed through it.
WRAPPER_EXEMPT = {"build"}

FENCE_RE = re.compile(r"```(?:bash|sh|shell)\n(.*?)```", re.S)


def command_blocks(path):
    """Shell fences, minus comment lines and the ⛔ counter-examples in prose.

    A block is only a rule violation if it is offered AS the command to run; the
    skills deliberately quote what NOT to do, and those live in prose, not fences.
    """
    for block in FENCE_RE.findall(path.read_text(encoding="utf-8")):
        lines = [ln for ln in block.splitlines() if not ln.strip().startswith("#")]
        yield "\n".join(lines)


class WrapperContractTests(unittest.TestCase):
    def test_no_skill_calls_codex_exec_directly(self):
        for path in SKILLS:
            if path.parent.name in WRAPPER_EXEMPT:
                continue
            for block in command_blocks(path):
                with self.subTest(skill=path.parent.name):
                    self.assertNotRegex(
                        block,
                        r"(^|\s|\|)codex\s+exec\b",
                        f"{path.parent.name} runs codex directly; use tools/codex_ro.py "
                        f"(docs/betrieb.md: 'Auch Ping und Resume laufen über den Wrapper')",
                    )

    def test_the_build_skill_is_the_only_exemption_and_says_why(self):
        text = BUILD_SKILL.read_text(encoding="utf-8")
        self.assertIn("does NOT go through", text, "the exemption has to be justified in place")


class ModelResolutionContractTests(unittest.TestCase):
    """A skill that reads the role config must also PASS what it read.

    Three skills resolved the actor and then invoked the wrapper without
    `--model`/`--effort`, leaving it on its own defaults — the exact drift the
    doctrine ("the skill never chooses a model") exists to prevent, hiding behind
    a line of prose that said otherwise. (CodeRabbit, 2026-08-30.)
    """

    # `setup`'s connectivity ping is deliberately outside this rule: it is not a
    # review, it runs at `--effort low` on purpose, and it happens while wiring a
    # repo up -- i.e. possibly BEFORE any role config exists. Making it resolve a
    # role would make the verification step depend on the thing it is verifying.
    MODEL_EXEMPT = {"setup"}

    @classmethod
    def _invoking_blocks(cls, path):
        """Blocks that RUN the wrapper. Naming it in prose is not invoking it."""
        if path.parent.name in cls.MODEL_EXEMPT:
            return []
        return [b for b in command_blocks(path) if re.search(r"codex_ro\.py\s+--", b)]

    def test_every_wrapper_call_carries_a_model_and_effort(self):
        for path in SKILLS:
            for block in self._invoking_blocks(path):
                with self.subTest(skill=path.parent.name, block=block[:50]):
                    self.assertIn(
                        "--model", block,
                        f"{path.parent.name}: resolve the role, then pass --model/--effort",
                    )
                    self.assertIn("--effort", block, f"{path.parent.name}: --effort missing")

    def test_a_skill_invoking_the_wrapper_resolves_the_role_first(self):
        for path in SKILLS:
            if not self._invoking_blocks(path):
                continue
            with self.subTest(skill=path.parent.name):
                self.assertIn(
                    "claudex_roles.py --spec", path.read_text(encoding="utf-8"),
                    f"{path.parent.name} builds a wrapper call but never resolves the role",
                )


class PromptFileContractTests(unittest.TestCase):
    def test_no_skill_reads_an_uncreated_review_prompt_file(self):
        for path in SKILLS:
            for block in command_blocks(path):
                with self.subTest(skill=path.parent.name):
                    self.assertNotIn(
                        "cat REVIEW_PROMPT",
                        block,
                        f"{path.parent.name}: REVIEW_PROMPT is created by no step. On a "
                        f"clean repo this launches an EMPTY prompt; on a repo that ships "
                        f"the file, the repo under review writes the reviewer's orders.",
                    )

    def test_prompts_are_passed_by_file_not_by_substitution(self):
        for path in SKILLS:
            for block in command_blocks(path):
                if "codex_ro.py" not in block:
                    continue
                with self.subTest(skill=path.parent.name):
                    self.assertNotRegex(
                        block,
                        r'--prompt\s+"?\$\(',
                        "command substitution into --prompt; use --prompt-file",
                    )


class TempDirContractTests(unittest.TestCase):
    def test_no_skill_uses_a_bare_mktemp(self):
        """Bare `mktemp` lands in /tmp on Linux and macOS, which the skills forbid.

        Matches an mktemp whose arguments are only flags -- `$(mktemp)`,
        `$(mktemp -d)`, `mktemp -t x` -- and lets one with a path template
        through. The first version only caught `mktemp)` and would have missed
        `$(mktemp -d)` entirely. (CodeRabbit, 2026-08-30.)
        """
        # Flags MAY take a value (`mktemp -t x`), so a flag's argument has to be
        # consumed too -- otherwise `$(mktemp -t x)` reads as "has a template".
        # A real template contains a path separator or a variable; a bare word
        # after a flag does not. (CodeRabbit, 2026-08-30.)
        bare = re.compile(r"mktemp(\s+-[^\s)]+(\s+[^\s)$/\\]+)?)*\s*[)\n]")
        for path in SKILLS:
            for block in command_blocks(path):
                with self.subTest(skill=path.parent.name):
                    self.assertIsNone(
                        bare.search(block),
                        f"{path.parent.name}: give mktemp a template under $SCRATCH_DIR",
                    )

    def test_no_skill_writes_to_a_literal_tmp_path(self):
        for path in SKILLS:
            for block in command_blocks(path):
                with self.subTest(skill=path.parent.name):
                    self.assertNotIn("/tmp/", block, f"{path.parent.name}: ⛔ never /tmp")


class ScopeGrammarTests(unittest.TestCase):
    """The fallback verdict grammar must follow the SELECTED scope.

    code-review hard-coded all five verdicts into --require-verdicts while its own
    default scope is three (dod,quality,security). During a Codex outage the
    fallback then rejected a perfectly good reply for "missing" verdicts nobody
    had asked for -- so the documented degradation path failed on every default
    run (audit 2026-08-30).
    """

    def setUp(self):
        self.text = (
            Path(__file__).resolve().parent.parent / "skills" / "code-review" / "SKILL.md"
        ).read_text(encoding="utf-8")

    def test_the_grammar_is_derived_not_hard_coded(self):
        for block in FENCE_RE.findall(self.text):
            if "--require-verdicts" not in block:
                continue
            with self.subTest(block=block[:60]):
                self.assertNotRegex(
                    block,
                    r'--require-verdicts\s+"[A-Z]',
                    "build --require-verdicts from $SCOPE instead of writing it out",
                )

    def test_every_documented_scope_has_a_verdict_pair(self):
        for scope in ("dod", "quality", "security", "docs", "tests"):
            with self.subTest(scope=scope):
                self.assertRegex(self.text, rf"\n\s*{scope}\)\s+g=", "missing from the case arms")

    def test_no_associative_arrays(self):
        """macOS ships bash 3.2, which has none — a syntax error, not a fallback."""
        for path in SKILLS:
            for block in command_blocks(path):
                with self.subTest(skill=path.parent.name):
                    self.assertNotIn("declare -A", block)


class RoundVariableTests(unittest.TestCase):
    """A per-round filename needs the round to actually change."""

    def test_a_skill_using_round_in_a_path_also_initialises_it(self):
        for path in SKILLS:
            text = path.read_text(encoding="utf-8")
            if "-r$ROUND" not in text:
                continue
            with self.subTest(skill=path.parent.name):
                self.assertRegex(
                    text,
                    r"ROUND=\d|ROUND=\$\(\(ROUND",
                    f"{path.parent.name} names files by $ROUND but never sets it — "
                    f"a fix round then overwrites the previous report",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
