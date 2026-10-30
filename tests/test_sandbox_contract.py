"""Contract: skills never tell the agent to run repository code on the host (plan B1, Approach 9).

Why this test exists. The runner `scripts/sandbox_run.py` only protects anything if no skill
text sends a reader around it. A single `pytest` line in a fenced block, an inline
`PROOF_CMD`, or a sentence "run the repo's own entry points" is an instruction an agent will
follow on the host, and the repository under review controls what that executes. So, in every
`skills/*/SKILL.md`, in fenced blocks, inline code and prose alike:

* a code-loading command (pytest, coverage run, npm test, make targets, `PROOF_CMD`, eslint,
  golangci-lint, checkov, "the repo's own entry points") may appear only as an argument of
  `sandbox_run.py`, or in a sentence that says it is refused / not run on the host / out of
  scope here;
* static scanners (gitleaks, grype, hadolint, actionlint, interrogate, ruff) are allowlisted
  and not matched at all;
* dependency auditors (pip-audit, npm audit, OSV) must carry the B1.5 host-risk warning in the
  same sentence.

The unit of checking is a logical line in fences (backslash continuations joined) and a
sentence in prose (a paragraph joined, split after `.`, `?`, `!`). Pure prose that merely
names pytest as the repository's own CI is excused by its own marker ("CI").
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = sorted((ROOT / "skills").glob("*/SKILL.md"))

# Code-loading commands. `make` is an English verb, so it only counts as a command.
_RUNVERB = r"(?:run|runs|running|rerun|reruns|rerunning|execute|executes|executing)"
LOADING = re.compile(
    r"(?:\bpytest\b|\bcoverage run\b|\bpython3? -m coverage\b|\bnpm (?:run )?test\b"
    r"|(?:^|`)\s*make(?:\s+(?:test|check|lint|ci|all|build|validate)\b|`)"
    r"|\bmake (?:test|check|lint|ci|validate)\b"
    r"|\bPROOF_CMD\b|\beslint\b|\bgolangci-lint\b|\bcheckov\b"
    r"|repo(?:sitory)?'?s own entry points?"
    # prose forms: "run the test suite", "run the test", "run the proof", "test suite"
    r"|\btest suites?\b"
    rf"|\b{_RUNVERB}\s+(?:(?:the|a|an|your|its|all|any|that|this|each|every|whole|full|new|focused)\s+){{0,3}}"
    r"(?:tests?|proofs?|coverage)\b"
    r"|\b(?:proof|test) (?:command|run)s?\b)",
    re.IGNORECASE | re.MULTILINE,
)
AUDITORS = re.compile(r"\b(?:pip-audit|npm audit|osv-scanner|OSV)\b")

# A sentence that says the run is refused / not done on the host is allowed to name a
# loading command. Deliberately narrow: "do not refuse it" must not match.
REFUSAL = re.compile(
    r"\b(?:is|are|be|or|stays?|gets?|remains?) refused\b|\brefused (?:on|and not run|, not run|, never)"
    r"|\b(?:not|never) (?:be )?(?:run|executed?)\w* on the host|\bnot on the host"
    r"|raw until B2|\bnever on the host|\bown CI\b|\bCI\b workflow|out of scope",
    re.IGNORECASE,
)
# In prose (not command lines) a sentence that says the run goes through the runner.
ROUTED_PROSE = re.compile(
    r"\b(?:through|via|only in|inside|by)\b[^.]{0,40}sandbox_run|sandbox_run[^.]{0,40}\bonly\b",
    re.IGNORECASE,
)
SEPARATOR = re.compile(r"&&|\|\||;|\||\bthen\b")
CLAUSE_SPLIT = re.compile(r"&&|\|\||;")
B15_WARNING = re.compile(r"B1\.5", re.IGNORECASE)
HOST_WORD = re.compile(r"\bhost\b", re.IGNORECASE)


FENCE, PROSE, TABLE = "fence", "prose", "table"


def _units(text: str):
    """Yield (line_number, unit_text, kind) for fence lines, prose sentences and table rows."""
    lines = text.split("\n")
    in_fence = False
    para: list[tuple[int, str]] = []
    pending: list[str] = []
    pending_no = 0
    heredoc = ""  # delimiter of an open here-document: its body is data, not commands

    def flush_para():
        if not para:
            return
        joined = " ".join(t.strip() for _, t in para)
        start = para[0][0]
        for sent in re.split(r"(?<=\S[.?!])\s+", joined):
            if sent:
                yield start, sent, PROSE
        para.clear()

    for no, line in enumerate(lines, 1):
        if line.lstrip().startswith("```"):
            yield from flush_para()
            if pending:
                yield pending_no, " ".join(pending), FENCE
                pending = []
            in_fence = not in_fence
            heredoc = ""
            continue
        if in_fence:
            if heredoc:
                if line.strip() == heredoc:
                    heredoc = ""
                elif line.strip():
                    yield no, line.strip(), PROSE
                continue
            if not pending:
                pending_no = no
            if line.rstrip().endswith("\\"):
                pending.append(line.rstrip()[:-1].strip())
                continue
            pending.append(line.strip())
            cmd = " ".join(pending)
            yield pending_no, cmd, FENCE
            m = re.search(r"<<-?\s*(['\"]?)(\w+)\1", cmd)
            if m:
                heredoc = m.group(2)
            pending = []
            continue
        if not line.strip():
            yield from flush_para()
        elif line.lstrip().startswith("|"):
            yield from flush_para()
            yield no, line, TABLE
        else:
            para.append((no, line))
    yield from flush_para()


class _Shell:
    """A shell command line read the way a POSIX shell splits it, as far as this contract needs.

    `seps` are the positions of command separators (`&&`, `||`, `;`, `|`, a single `&`, the word
    `then`) outside any quoting or substitution: only those end the runner's command. `host[i]`
    is True when character i lies inside a command or process substitution (`$(...)`,
    backticks, `<(...)`, `>(...)`), which the HOST shell runs before or beside the runner --
    single quotes inside the substitution do not change that. `comment` is where an unquoted
    `#` starts a comment.
    """

    def __init__(self, line: str):
        self.seps: list[int] = []
        self.host = [False] * (len(line) + 1)
        self.comment = len(line)
        stack: list[str] = []
        i = 0
        while i < len(line):
            c = line[i]
            top = stack[-1] if stack else ""
            self.host[i] = "(" in stack or "`" in stack
            if top == "'":
                if c == "'":
                    stack.pop()
                i += 1
                continue
            if c == "\\":
                if i + 1 < len(line):
                    self.host[i + 1] = self.host[i]
                i += 2
                continue
            if c == "$" and line[i + 1:i + 2] == "(":
                stack.append("(")
                self.host[i] = self.host[i + 1] = True
                i += 2
                continue
            if c == "`":
                if top == "`":
                    stack.pop()
                else:
                    stack.append("`")
                    self.host[i] = True
                i += 1
                continue
            if c == ")" and top == "(":
                stack.pop()
                i += 1
                continue
            if top == '"':
                if c == '"':
                    stack.pop()
                i += 1
                continue
            if c in "<>" and line[i + 1:i + 2] == "(":
                # process substitution: the host shell runs its content (closing gate, B2 #2)
                stack.append("(")
                self.host[i] = self.host[i + 1] = True
                i += 2
                continue
            if c in "'\"":
                stack.append(c)
                i += 1
                continue
            if not stack:
                if c == "#" and (i == 0 or line[i - 1].isspace()):
                    self.comment = i
                    break
                two = line[i:i + 2]
                if two in ("&&", "||"):
                    self.seps.append(i)
                    i += 2
                    continue
                if c in ";|":
                    self.seps.append(i)
                elif c == "&" and line[i - 1:i] not in ("<", ">") and line[i + 1:i + 2] != ">":
                    # a single `&` ends a command too (it runs in the background); `2>&1`,
                    # `>&2` and `&>` are redirections, not separators (closing gate, B2 #2)
                    self.seps.append(i)
                elif re.match(r"\bthen\b", line[i:]) and (i == 0 or not line[i - 1].isalnum()):
                    self.seps.append(i)
            i += 1


def _runner_argv(cmd: str, pos: int) -> bool:
    """True when `pos` is a literal argument after ` -- ` of a sandbox_run call in the same command.

    Literal means: not inside a host command substitution, and no unquoted separator between
    the runner and `pos` -- quoted punctuation (`sh -c 'true; pytest -q'`) stays an argument.
    """
    sh = _Shell(cmd)
    if pos >= sh.comment or sh.host[pos]:
        return False
    r = cmd.rfind("sandbox_run", 0, pos)
    if r < 0 or sh.host[r]:
        return False
    if any(r < s < pos for s in sh.seps):
        return False
    return re.search(r"\s--(?:\s|$)", cmd[r:pos]) is not None


def _code_span(unit: str, pos: int):
    """The inline code span of a prose unit that contains `pos`, as (start, text), or None."""
    for m in re.finditer(r"`([^`]+)`", unit):
        if m.start(1) <= pos < m.end(1):
            return m.start(1), m.group(1)
    return None


def _runner_argv_start(unit: str, pos: int, kind: str = FENCE) -> bool:
    """True when `pos` lies in the literal argv of a sandbox_run call (fence line or inline code)."""
    if kind == FENCE:
        return _runner_argv(unit, pos)
    span = _code_span(unit, pos)
    return span is not None and _runner_argv(span[1], pos - span[0])


def _clause(unit: str, pos: int) -> str:
    """The clause (split at `&&`, `||`, `;`) of a unit that contains `pos`."""
    start = 0
    for m in CLAUSE_SPLIT.finditer(unit):
        if m.end() <= pos:
            start = m.end()
        elif m.start() >= pos:
            return unit[start:m.start()]
    return unit[start:]


def violations(text: str) -> list[str]:
    out = []
    for no, unit, kind in _units(text):
        # table rows: the cell pipes are not command separators
        flat = unit.replace("|", " ") if kind == TABLE else unit
        for m in LOADING.finditer(flat):
            if _runner_argv_start(flat, m.start(), kind):
                continue
            if kind == FENCE:
                # A command line executes what it says. Only its comment is prose, and a
                # comment can excuse nothing to its left (`pytest -q # through sandbox_run`).
                comment = _Shell(flat).comment
                if m.start() < comment:
                    out.append(f"line {no}: code-loading command outside the runner: {unit[:110]}")
                    break
                clause = flat[comment:]
            else:
                clause = _clause(flat, m.start())
            if REFUSAL.search(clause):
                continue
            if ROUTED_PROSE.search(clause) and not re.search(r"\bsandbox_run\S* +-", clause):
                continue
            out.append(f"line {no}: code-loading command outside the runner: {unit[:110]}")
            break
        if AUDITORS.search(unit) and not (B15_WARNING.search(unit) and HOST_WORD.search(unit)):
            out.append(f"line {no}: dependency auditor without the B1.5 host-risk warning: {unit[:110]}")
    return out


BUILD = re.compile(r"\bdocker\b[^\n]*?\bbuild\b[^\n]*")


def build_violations(text: str) -> list[str]:
    """Every sandbox image `docker build` names Dockerfile and context beneath the plugin root, tag :2."""
    out = []
    for no, unit, _kind in _units(text):
        m = BUILD.search(unit)
        if not m or "sandbox" not in unit:
            continue
        cmd = m.group(0)
        f = re.search(r'-f\s+"?([^\s"]+)', cmd)
        if not f or not f.group(1).startswith("${CLAUDE_PLUGIN_ROOT}/"):
            out.append(f"line {no}: docker build Dockerfile not under CLAUDE_PLUGIN_ROOT: {cmd[:100]}")
        if not re.search(r'"\$\{CLAUDE_PLUGIN_ROOT\}/config/sandbox"\s*$', cmd.strip()):
            out.append(f"line {no}: docker build context not under CLAUDE_PLUGIN_ROOT: {cmd[:100]}")
        if "python-test:2" not in cmd:
            out.append(f"line {no}: docker build tag is not claudex-sandbox-python-test:2: {cmd[:100]}")
    return out


RUNNER_CALL = re.compile(r"\bpython3?\s+(\S*sandbox_run\.py\S*)")


def runner_root_violations(text: str) -> list[str]:
    """Every runner invocation in a command line names the INSTALLED plugin's copy.

    `python scripts/sandbox_run.py` in a consuming project resolves against the checkout under
    review, so the repository would supply the runner and run on the host before any container
    exists (closing gate, B2 #3)."""
    out = []
    for no, unit, kind in _units(text):
        if kind != FENCE:
            continue
        for m in RUNNER_CALL.finditer(unit):
            if m.group(1) != '"${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py"':
                out.append(f"line {no}: runner not called from CLAUDE_PLUGIN_ROOT: {m.group(0)[:100]}")
    return out


def mutation_rule_ok(text: str) -> bool:
    """The code-review mutation check binds two distinct pinned trees and a real red run.

    Red means pytest exit 1 plus a `FAILED` line for the new test: exit 2/4/5 (collection,
    usage, nothing collected) would certify an assertion that never ran. Only the mutation
    passage counts: `--tree "$GATE_TREE"` is right for the gate runs elsewhere in the skill.
    """
    m = re.search(r"Every generated test must be shown to fail\.(.*?)Never weaken an assertion", text, re.S)
    if not m:
        return False
    text = m.group(1)
    return bool(
        "BROKEN_TREE" in text and "RESTORED_TREE" in text
        and re.search(r"the two ids must differ", text)
        and re.search(r"--pin\b", text)
        and re.search(r"`BROKEN_TREE`: `COMMAND_STATUS=exited` with `COMMAND_EXIT=1`", text)
        and re.search(r"`FAILED <test\s+id>`", text)
        and not re.search(r"COMMAND_EXIT\s*!=\s*0", text)
        and not re.search(r"--tree\s+\"?\$GATE_TREE", text)
    )


def pass_rule_ok(text: str) -> bool:
    return bool(
        re.search(r"COMMAND_STATUS=exited", text)
        and re.search(r"COMMAND_EXIT=0\b", text)
        and re.search(r"MANIFEST_SHA256=", text)
    )


class MatcherTests(unittest.TestCase):
    """The matcher itself: it must catch the bad forms and stay quiet on legitimate prose."""

    def test_bare_fence_command_is_caught(self):
        self.assertTrue(violations("```bash\npytest -q\n```\n"))

    def test_python_m_pytest_and_continuation_are_caught(self):
        self.assertTrue(violations("```bash\npython -m pytest \\\n  -q\n```\n"))

    def test_inline_proof_cmd_is_caught(self):
        self.assertTrue(violations("Run `PROOF_CMD` yourself.\n"))

    def test_runner_argument_is_fine(self):
        text = "```bash\npython scripts/sandbox_run.py --repo . --image python-test -- python -m pytest -q\n```\n"
        self.assertEqual(violations(text), [])

    def test_refusal_sentence_is_fine(self):
        self.assertEqual(violations("The repo's own entry points are refused on the host.\n"), [])

    def test_ci_prose_is_fine(self):
        self.assertEqual(violations("The repo runs pytest in its own CI on every push.\n"), [])

    def test_make_as_verb_is_fine(self):
        self.assertEqual(violations("Make sure the plan makes sense; make a note of it.\n"), [])

    def test_static_scanners_are_allowlisted(self):
        self.assertEqual(violations("`gitleaks dir .`, `grype dir:.`, `ruff check`, `hadolint`.\n"), [])

    def test_command_chained_after_runner_is_caught(self):
        text = "```bash\npython scripts/sandbox_run.py --help && python -m pytest -q\n```\n"
        self.assertTrue(violations(text))

    def test_do_not_refuse_is_not_a_refusal(self):
        self.assertTrue(violations("Run `pytest` directly; do not refuse it.\n"))

    def test_prose_forms_are_caught(self):
        for t in ("Run the test suite on the host.\n", "Then run the test.\n",
                  "Run the proof yourself and paste the output.\n",
                  "Break the code, run the test, confirm it goes red.\n"):
            self.assertTrue(violations(t), t)

    def test_real_mutation_passage_is_caught(self):
        t = ("- **Every generated test must be shown to fail.** Break the code it covers "
             "(invert a condition, return the wrong value), run the test, confirm it goes "
             "red, restore the code, confirm it goes green.\n")
        self.assertTrue(violations(t))

    def test_runner_argv_with_loading_words_is_fine(self):
        t = ("```bash\npython sandbox_run.py --repo . --pin a.py --image python-test "
             "-- python -m pytest -q\n```\n")
        self.assertEqual(violations(t), [])

    def test_prose_excuse_does_not_apply_to_command_lines(self):
        # inspection round 2, B2 #3: a comment cannot excuse the command to its left
        self.assertTrue(violations("```bash\npytest -q # through sandbox_run.py\n```\n"))
        self.assertTrue(violations("```bash\npytest -q # refused on the host\n```\n"))

    def test_host_expansion_in_runner_argv_is_caught(self):
        # B2 #3: the host shell expands $(...) and backticks before the runner starts
        base = "```bash\npython sandbox_run.py --repo . --tree \"$TREE\" --image python-test -- "
        for argv in ('sh -c "$(pytest -q)"', "sh -c \"`pytest -q`\"", "sh -c $(pytest -q)",
                     "sh -c \"$(sh -c 'pytest -q')\""):
            self.assertTrue(violations(base + argv + "\n```\n"), argv)

    def test_quoted_separators_stay_runner_arguments(self):
        # B2 #9: punctuation inside quotes is part of the container command
        base = "```bash\npython sandbox_run.py --repo . --tree \"$TREE\" --image python-test -- "
        for argv in ("sh -c 'true; pytest -q'", "sh -c 'true && pytest -q'",
                     'sh -c "true || pytest -q"', "sh -c 'echo $(id); pytest -q'"):
            self.assertEqual(violations(base + argv + "\n```\n"), [], argv)
        # an unquoted separator still ends the runner's command
        self.assertTrue(violations(base + "true; pytest -q\n```\n"))
        self.assertTrue(violations(base + "true | pytest -q\n```\n"))

    def test_background_ampersand_and_process_substitution_are_host(self):
        # closing gate, B2 #2
        base = "```bash\npython sandbox_run.py --repo . --tree \"$TREE\" --image python-test -- "
        for argv in ("true & pytest -q", "true <(pytest -q)", "true >(pytest -q)", "cat <(pytest -q)"):
            self.assertTrue(violations(base + argv + "\n```\n"), argv)
        for argv in ("sh -c 'true & pytest -q'", "sh -c 'cat <(pytest -q)'", 'sh -c "true & pytest -q"',
                     "python -m pytest -q 2>&1", "python -m pytest -q >&2", "python -m pytest -q &>log"):
            self.assertEqual(violations(base + argv + "\n```\n"), [], argv)

    def test_runner_must_come_from_the_plugin_root(self):
        bad = "```text\npython scripts/sandbox_run.py --repo . --tree T --image python-test -- true\n```\n"
        self.assertTrue(runner_root_violations(bad))
        good = ('```bash\npython "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py" --repo . --tree T '
                "--image python-test -- true\n```\n")
        self.assertEqual(runner_root_violations(good), [])

    def test_heredoc_body_is_data_not_commands(self):
        ok = ("```bash\ncat > \"$F\" <<'EOF'\nPROOF (the build runs raw until B2): Run `pytest`.\n"
              "EOF\n```\n")
        self.assertEqual(violations(ok), [])
        bad = "```bash\ncat > \"$F\" <<'EOF'\nRun `pytest` and report.\nEOF\npytest -q\n```\n"
        self.assertEqual(len(violations(bad)), 2)

    def test_build_paths_must_be_plugin_rooted(self):
        bad = ("```bash\ndocker --context desktop-linux build -f config/sandbox/python-test.Dockerfile "
               "-t claudex-sandbox-python-test:2 config/sandbox\n```\n")
        self.assertTrue(build_violations(bad))
        good = ('```bash\ndocker --context desktop-linux build '
                '-f "${CLAUDE_PLUGIN_ROOT}/config/sandbox/python-test.Dockerfile" '
                '-t claudex-sandbox-python-test:2 "${CLAUDE_PLUGIN_ROOT}/config/sandbox"\n```\n')
        self.assertEqual(build_violations(good), [])

    def test_pass_rule_requires_exit_zero(self):
        ok = "COMMAND_STATUS=exited COMMAND_EXIT=0 MANIFEST_SHA256="
        self.assertTrue(pass_rule_ok(ok))
        self.assertFalse(pass_rule_ok(ok.replace("COMMAND_EXIT=0", "COMMAND_EXIT=99")))

    def test_auditor_needs_warning(self):
        self.assertTrue(violations("Run `pip-audit` on the repo.\n"))
        self.assertEqual(
            violations("`pip-audit` runs on the host at your own risk until B1.5.\n"), [])


class SkillContractTests(unittest.TestCase):
    def test_skills_found(self):
        self.assertGreaterEqual(len(SKILLS), 6)

    def test_no_skill_runs_repository_code_on_the_host(self):
        problems = []
        for path in SKILLS:
            for v in violations(path.read_text(encoding="utf-8-sig")):
                problems.append(f"{path.relative_to(ROOT).as_posix()}: {v}")
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_routed_skills_name_the_runner(self):
        for name in ("build", "code-review", "docs-backfill", "audit", "claudex-loop"):
            text = (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8-sig")
            self.assertIn("sandbox_run.py", text, name)

    def test_pass_rule_is_stated(self):
        for name in ("build", "code-review", "docs-backfill", "audit", "claudex-loop"):
            text = (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8-sig")
            self.assertIn("COMMAND_STATUS=exited", text, name)
            self.assertRegex(text, r"COMMAND_EXIT=0\b", name)
            self.assertIn("MANIFEST_SHA256=", text, name)
            self.assertTrue(pass_rule_ok(text), name)
            self.assertFalse(pass_rule_ok(text.replace("COMMAND_EXIT=0", "COMMAND_EXIT=99")), name)

    def test_runner_calls_are_plugin_rooted(self):
        problems = []
        for path in SKILLS + [ROOT / "docs" / "betrieb.md"]:
            for v in runner_root_violations(path.read_text(encoding="utf-8-sig")):
                problems.append(f"{path.relative_to(ROOT).as_posix()}: {v}")
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_docker_build_is_plugin_rooted(self):
        problems = []
        for path in SKILLS + [ROOT / "docs" / "betrieb.md"]:
            for v in build_violations(path.read_text(encoding="utf-8-sig")):
                problems.append(f"{path.relative_to(ROOT).as_posix()}: {v}")
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_mutation_check_is_pinned_per_tree(self):
        text = (ROOT / "skills" / "code-review" / "SKILL.md").read_text(encoding="utf-8-sig")
        self.assertTrue(mutation_rule_ok(text))
        # the documentation mutations a weaker rule would let through
        for bad in (
            text.replace("the two ids must differ", "the two ids may be equal"),
            text.replace("`COMMAND_EXIT=1`", "`COMMAND_EXIT != 0`"),
            text.replace("`FAILED <test\n  id>`", "a failure").replace("`FAILED <test id>`", "a failure"),
            text.replace("--pin <changed path>", '--tree "$GATE_TREE"'),
        ):
            self.assertNotEqual(bad, text)
            self.assertFalse(mutation_rule_ok(bad))

    def test_betrieb_has_tool_classification(self):
        text = (ROOT / "docs" / "betrieb.md").read_text(encoding="utf-8-sig")
        self.assertIn("static, reads files only", text)
        self.assertIn("loads project code or config", text)
        self.assertIn("dependency auditors", text)

    def test_setup_does_not_allowlist_pytest_or_the_runner(self):
        text = (ROOT / "skills" / "setup" / "SKILL.md").read_text(encoding="utf-8-sig")
        self.assertNotIn("Bash(python -m pytest", text)
        self.assertNotIn("Bash(python scripts/sandbox_run", text)


if __name__ == "__main__":
    unittest.main()
