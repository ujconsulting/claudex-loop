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
* dependency auditors (pip-audit, npm audit, osv-scanner) may be NAMED only in a sentence that
  carries the marker phrase `not prescribed for repositories under review` (plan B1.5): audits
  go through `scripts/dep_audit.py`, which runs no package tool on the host;
* every `sandbox_run.py` and `dep_audit.py` call in a fenced block (skills, docs/betrieb.md,
  README.md, README_DE.md) is `python -I "${CLAUDE_PLUGIN_ROOT}/scripts/<helper>.py"`: plugin
  rooted AND isolated, so an inherited PYTHONPATH or a `sitecustomize` in the checkout cannot
  load before the helper validates anything.

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
AUDITORS = re.compile(r"\b(?:pip[-_]audit|pip audit|npm audit|osv-scanner)\b", re.IGNORECASE)
# The one sentence shape in which a raw auditor may be named (B1.5).
NOT_PRESCRIBED = re.compile(r"not prescribed for repositories under review", re.IGNORECASE)

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
        problem = auditor_problem(unit, kind)
        if problem:
            out.append(f"line {no}: {problem}: {unit[:110]}")
    return out


# An inline span that IS an auditor command: optional launcher(s), the auditor, then arguments.
# A launcher is `sudo`/`uvx`/`npx`/`pipx run`/`uv run`, and/or a python interpreter (bare, path or
# quoted) followed by option tokens before `-m`. An option token is `-X`-style (`-I`, the combined
# `-Im`, `-W ignore`), an interpreter option with an operand that may be a single- or double-quoted
# string with spaces (`-W "ignore:a b"`, `-X 'a b'`, `-W"a b"`), or a bare quoted token. Covered:
# those forms in front of `-m pip_audit` / `-m pip-audit` / `-m pip audit` (gate initial pass,
# block C, finding 2; recheck 1, finding 2). Not covered: shell escapes inside quotes, `env`/`xargs`
# launchers, `$PY`, and options whose operand is split by anything but a quote.
_PY_TOKEN = r"""(?:"[^"\n]*python[\d.]*(?:\.exe)?"|'[^'\n]*python[\d.]*(?:\.exe)?'|(?:[^\s"'`]*[/\\])?python[\d.]*(?:\.exe)?)"""
_QT = r"""(?:"[^"\n]*"|'[^'\n]*')"""
_OPT = rf"""(?:-[WXQ]\s*{_QT}|-[WXQ]\s+\S+|-\S+|{_QT})"""
AUDITOR_SPAN = re.compile(
    r"^(?:(?:sudo|uvx|npx|pipx run|uv run)\s+)?"
    rf"(?:{_PY_TOKEN}(?:\s+{_OPT})*?\s+-[A-Za-z]*m\s+)?"
    r"(?:pip[-_]audit|pip\s+audit|npm audit|osv-scanner)\b(.*)$",
    re.IGNORECASE | re.DOTALL,
)


def auditor_problem(unit: str, kind: str):
    """Why a unit names a raw dependency auditor unacceptably, or None.

    An EXECUTABLE auditor command is a violation whatever a comment or marker says: the shell
    runs `npm audit # not prescribed ...` all the same (inspection round 1, C2). Executable means
    a fence line naming an auditor before its comment, or an inline code span that matches
    AUDITOR_SPAN with arguments (or bare, after an imperative verb): the auditor itself, with
    `sudo`/`uvx`/`npx`/`pipx run`/`uv run` and/or a python launcher (bare, path or quoted) with any
    options before `-m` (`python -I -m pip_audit`, `-Im`, `-m pip audit`) in front. Not matched:
    other launchers (`env`, `xargs`, `$PY`), a command split across spans, an auditor under
    another name. The marker phrase only excuses explanatory prose and table text that merely
    names the tool."""
    flat = unit.replace("|", " ") if kind == TABLE else unit
    if not AUDITORS.search(flat):
        return None
    if kind == FENCE:
        comment = _Shell(flat).comment
        if any(m.start() < comment for m in AUDITORS.finditer(flat)):
            return "executable raw dependency auditor command"
    else:
        for span in re.finditer(r"`([^`]+)`", unit):
            m = AUDITOR_SPAN.match(span.group(1).strip())
            # with arguments it is a command; bare, it is a command when an imperative verb
            # (Run/Execute/Use/Call/Invoke/Start) stands before it, marker phrase or not
            if m and (m.group(1).strip() or _imperative_before(unit, span.start())):
                return "executable raw dependency auditor command (inline span)"
    if not NOT_PRESCRIBED.search(flat):
        return "raw dependency auditor outside a 'not prescribed' sentence"
    return None


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


# The interpreter, by basename: `python`, `python3.13`, `/usr/bin/python3`, `C:\Python313\python.exe`,
# `./venv/bin/python` (inspection round 2, C4), also as ONE quoted token, which may contain spaces:
# `"/usr/bin/python3"`, `"C:\Program Files\Python313\python.exe"` (gate initial pass, block C, 1).
# A path before it is part of the same word. Not recognised: an interpreter hidden behind a shell
# variable or a wrapper (`env python`, `$PY`), or a quoted token whose basename is not `python*`.
PYTHON_CMD = re.compile(
    r"""(?<![^\s`"'(;&|])(?:(["'])(?:[^"'\n]*[/\\])?python[\d.]*(?:\.exe)?\1"""
    r"""|(?:[^\s`"'()]*[/\\])?python[\d.]*(?:\.exe)?)(?=\s)""", re.IGNORECASE)

# Context of a mention (inspection round 2, C1/C2). An imperative verb shortly before a span makes
# the span an instruction, whatever else the sentence says. A bare helper call (no arguments) is a
# harmless mention only in a sentence that narrates the past (English or German).
IMPERATIVE = re.compile(r"\b(?:run|execute|use|call|invoke|start|launch|rerun|re-run)\b[^`]{0,40}$", re.IGNORECASE)
NARRATIVE = re.compile(
    r"\b(?:used to|said|was|were|called|ran|before|earlier|previously|formerly"
    r"|rief|hatte|war|wurde|frueher|früher|zuvor|bisher)\b",
    re.IGNORECASE,
)


def _imperative_before(unit: str, pos: int) -> bool:
    return IMPERATIVE.search(unit[:pos]) is not None


def _historical_mention(unit: str, pos: int) -> bool:
    return NARRATIVE.search(unit) is not None and not _imperative_before(unit, pos)


TOKEN = re.compile(r"\"[^\"]*\"|'[^']*'|\S+")
HELPER_NAME = re.compile(r"(sandbox_run|dep_audit)\.py")
# interpreter options that take the NEXT token as their operand (`python -W ignore x.py`)
_OPT_WITH_OPERAND = ("-W", "-X", "-Q")


def _helper_calls(cmd: str):
    """Yield (helper, interpreter options, script token, argument tokens) for each helper call.

    The interpreter's own options are parsed properly: options before the script (with the
    operand of -W/-X/-Q), then the first non-option token is the script. `-c`/`-m` run no
    script file, so they end the scan."""
    for m in PYTHON_CMD.finditer(cmd):
        tokens = TOKEN.findall(cmd[m.end():])
        opts: list[str] = []
        i = 0
        stop = False
        while i < len(tokens) and tokens[i].startswith("-") and tokens[i] != "-":
            t = tokens[i]
            opts.append(t)
            i += 1
            if t in ("-c", "-m"):
                stop = True
                break
            if t in _OPT_WITH_OPERAND and i < len(tokens):
                opts.append(tokens[i])
                i += 1
        if stop or i >= len(tokens):
            continue
        h = HELPER_NAME.search(tokens[i])
        if h:
            yield h.group(1), opts, tokens[i], tokens[i + 1:]


def helper_invocations(text: str):
    """Every `sandbox_run.py` / `dep_audit.py` call whose interpreter PYTHON_CMD recognises, as
    (line, kind, helper, opts, script, args).

    Executable means: a fence line, or an inline code span of prose or a table that carries
    ARGUMENTS after the script. A bare span (`python scripts/sandbox_run.py`, no arguments) is a
    mention only in a sentence that narrates the past and has no imperative verb before the span
    (NARRATIVE / IMPERATIVE); "Run `python scripts/sandbox_run.py` first." is an instruction
    (inspection round 2, C1)."""
    out = []
    for no, unit, kind in _units(text):
        if kind == FENCE:
            # a shell comment is not executed: a call or placeholder there does not count
            for helper, opts, script, args in _helper_calls(unit[:_Shell(unit).comment]):
                out.append((no, kind, helper, opts, script, args))
            continue
        for span in re.finditer(r"`([^`]+)`", unit):
            for helper, opts, script, args in _helper_calls(span.group(1)):
                if args or not _historical_mention(unit, span.start()):
                    out.append((no, kind, helper, opts, script, args))
    return out


def runner_root_violations(text: str) -> list[str]:
    """Every runner and dep_audit invocation is `python -I` plus the INSTALLED plugin's copy.

    `python scripts/sandbox_run.py` in a consuming project resolves against the checkout under
    review, so the repository would supply the runner and run on the host before any container
    exists (closing gate, B2 #3). Without `-I` an inherited PYTHONPATH, the cwd or the user
    site could load a `sitecustomize` before the helper validates anything (plan B1.5).
    Fences and executable inline spans are both checked, interpreter options are parsed:
    only exactly `python -I "${CLAUDE_PLUGIN_ROOT}/scripts/<helper>.py"` passes."""
    out = []
    for no, _kind, helper, opts, script, _args in helper_invocations(text):
        shown = f"python {' '.join(opts)} {script}".replace("  ", " ")[:100]
        if script != f'"${{CLAUDE_PLUGIN_ROOT}}/scripts/{helper}.py"':
            out.append(f"line {no}: helper not called from CLAUDE_PLUGIN_ROOT: {shown}")
        elif opts != ["-I"]:
            out.append(f"line {no}: helper call without exactly `python -I`: {shown}")
    return out


# B1.5 step 8 / inspection round 1, C3: the `--deps` placeholder of every runner invocation of a
# gate. The first is the canonical wording; a later run of the same gate may point back at it.
DEPS_CANON = "<hashed requirements file>"
DEPS_SAME = "<same file as Step 1.3>"
GATE_DEPS = {
    "build": [DEPS_CANON],
    "code-review": [DEPS_CANON, DEPS_SAME],  # coverage run, then the two mutation runs
    "docs-backfill": [DEPS_CANON],
    "audit": [DEPS_CANON],
    "claudex-loop": [DEPS_CANON],
}
# Fix reruns are prose, not a command: a sentence that sends a rerun through the runner must say
# `--deps`, and the sentences that do say it (rerun + `--deps`) may not disappear.
RERUN = re.compile(r"\bre-?run(?:s|ning)?\b", re.IGNORECASE)
GATE_RERUN_SITES = {"build": 2, "code-review": 2, "docs-backfill": 1, "audit": 0, "claudex-loop": 2}


def deps_gate_violations(name: str, text: str) -> list[str]:
    """Each executable runner invocation of the gate carries its `--deps` placeholder; each rerun
    sentence names `--deps`. Removing or changing any one fails."""
    out = []
    runs = [i for i in helper_invocations(text) if i[2] == "sandbox_run"]
    want = GATE_DEPS[name]
    if len(runs) != len(want):
        out.append(f"{name}: {len(runs)} runner invocations, expected {len(want)}")
    for (no, _k, _h, _o, _s, args), expected in zip(runs, want):
        own = args[:args.index("--")] if "--" in args else args  # not the container command
        got = re.findall(r"--deps\s+(<[^>]*>|\S+)", " ".join(own))
        if got != [expected]:
            out.append(f"{name}: line {no}: --deps is {got}, expected [{expected!r}]")
    sites = 0
    for no, unit, kind in _units(text):
        if kind != PROSE or not RERUN.search(unit):
            continue
        if "--deps" in unit:
            sites += 1
        elif "sandbox_run" in unit:
            out.append(f"{name}: line {no}: rerun through the runner without --deps: {unit[:90]}")
    if sites < GATE_RERUN_SITES[name]:
        out.append(f"{name}: {sites} rerun sentences name --deps, expected >= {GATE_RERUN_SITES[name]}")
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


def docstring_usage_violations(path: Path, helper: str) -> list[str]:
    """The usage lines in the MODULE docstring of a helper script, read like a fenced block.

    The docstring is parsed (`ast`, never imported) and checked by `runner_root_violations`, so a
    `python -I scripts/<helper>.py ...` example (a relative path resolves against the checkout under
    review) fails exactly like one in a skill. The docstring must also carry at least one call of
    its own helper, so deleting the usage line does not pass. Only the module docstring counts:
    function docstrings and comments are not read."""
    import ast
    doc = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8-sig")), clean=False) or ""
    fenced = "```text\n" + doc + "\n```\n"
    out = runner_root_violations(fenced)
    if not any(i[2] == helper for i in helper_invocations(fenced)):
        out.append(f"{path.name}: module docstring has no `python -I ... {helper}.py` usage line")
    return out


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
        good = ('```bash\npython -I "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py" --repo . --tree T '
                "--image python-test -- true\n```\n")
        self.assertEqual(runner_root_violations(good), [])
        # plugin-rooted but not isolated: still a violation (B1.5)
        for flags in ("", "-S ", "-u -I ", "-I -u "):
            self.assertTrue(runner_root_violations(good.replace("python -I ", f"python {flags}")), flags)
        # dep_audit follows the same rule
        audit = ('```bash\npython -I "${CLAUDE_PLUGIN_ROOT}/scripts/dep_audit.py" --repo . --tree T '
                 "--scratch S --file requirements.txt\n```\n")
        self.assertEqual(runner_root_violations(audit), [])
        self.assertTrue(runner_root_violations(audit.replace("python -I ", "python ")))
        self.assertTrue(runner_root_violations(
            audit.replace('"${CLAUDE_PLUGIN_ROOT}/scripts/dep_audit.py"', "scripts/dep_audit.py")))

    def test_helper_calls_in_inline_spans_and_with_options_are_checked(self):
        # inspection round 1, C1: the real proof-gate passage of claudex-loop is an inline span
        real = (ROOT / "skills" / "claudex-loop" / "SKILL.md").read_text(encoding="utf-8-sig")
        good = 'python -I "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py"'
        self.assertIn(good, real)
        self.assertEqual(runner_root_violations(real), [])
        for bad in ("python scripts/sandbox_run.py",
                    'python "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py"',
                    'python -u -I "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py"',
                    'python -W ignore "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py"',
                    'python -I -W ignore "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py"',
                    'python3 -I -S "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py"',
                    'python3 -I "${CLAUDE_PLUGIN_ROOT}/scripts/../scripts/sandbox_run.py"'):
            mutated = real.replace(good, bad)
            self.assertNotEqual(mutated, real)
            self.assertTrue(runner_root_violations(mutated), bad)
        # python3 with -I only is fine
        self.assertEqual(runner_root_violations(real.replace(good, good.replace("python", "python3", 1))), [])
        for helper in ("sandbox_run", "dep_audit"):
            for line in (f"python -W ignore scripts/{helper}.py --repo .",
                         f"python -u -I scripts/{helper}.py --repo .",
                         f"python3 -I -S scripts/{helper}.py --repo ."):
                self.assertTrue(runner_root_violations(f"```bash\n{line}\n```\n"), line)
                self.assertTrue(runner_root_violations(f"Call `{line}` first.\n"), line)
        # a span that only mentions the call (no arguments) is history, not an instruction
        self.assertEqual(runner_root_violations("It called `python scripts/sandbox_run.py` once.\n"), [])
        # the same in a table cell
        self.assertTrue(runner_root_violations("| gate | `python scripts/sandbox_run.py --repo .` |\n"))

    def test_executable_auditor_is_a_violation_whatever_the_comment_says(self):
        # inspection round 1, C2
        marker = "# not prescribed for repositories under review"
        for cmd in ("npm audit", "pip-audit -r requirements.txt", "osv-scanner --lockfile x", "python -m pip_audit"):
            self.assertTrue(violations(f"```bash\n{cmd} {marker}\n```\n"), cmd)
            self.assertTrue(violations(f"```bash\n{cmd}\n```\n"), cmd)
        self.assertTrue(violations(f"```bash\ntrue && npm audit {marker}\n```\n"))
        # an inline executable span with arguments, in a sentence that carries the marker
        for span in ("npm audit --json", "pip-audit -r requirements.txt", "uvx pip-audit -r x"):
            self.assertTrue(violations(f"Run `{span}`: not prescribed for repositories under review.\n"), span)
        # a comment that merely mentions the tool after a harmless command stays excused
        self.assertEqual(violations(f"```bash\ntrue {marker}: npm audit\n```\n"), [])
        # the real passage, mutated: the audit skill plus a fenced command, or the marker
        # sentence turned into a command span
        real = (ROOT / "skills" / "audit" / "SKILL.md").read_text(encoding="utf-8-sig")
        self.assertEqual(violations(real), [])
        self.assertTrue(violations(real + f"\n```bash\nnpm audit {marker}\n```\n"))
        sentence = "raw pip-audit, npm audit and"
        self.assertIn(sentence, real)
        self.assertTrue(violations(real.replace(sentence, "raw `pip-audit -r requirements.txt`, npm audit and")))
        # the docs check is the same rule
        self.assertIsNotNone(auditor_problem(f"npm audit {marker}", FENCE))
        self.assertIsNone(auditor_problem("raw npm audit is not prescribed for repositories under review", PROSE))

    def test_deps_is_checked_per_gate_invocation(self):
        # inspection round 1, C3: every runner invocation of a gate carries its --deps placeholder
        frag = re.compile(r"\[--deps <[^>]*>\]\s*")
        for name, expected in GATE_DEPS.items():
            real = (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8-sig")
            self.assertEqual(deps_gate_violations(name, real), [], name)
            spots = list(frag.finditer(real))
            self.assertEqual(len(spots), len(expected), name)
            for i, spot in enumerate(spots):
                removed = real[:spot.start()] + real[spot.end():]
                self.assertTrue(deps_gate_violations(name, removed), f"{name} #{i} removed")
                changed = real[:spot.start()] + "[--deps <other requirements>] " + real[spot.end():]
                self.assertTrue(deps_gate_violations(name, changed), f"{name} #{i} changed")
            # prose reruns: a rerun sentence that stops naming --deps fails
            if GATE_RERUN_SITES[name]:
                weak = re.sub(r"(?<!\[)--deps", "--opts", real)
                self.assertNotEqual(weak, real)
                self.assertTrue(deps_gate_violations(name, weak), f"{name} prose")
        # a new, unlisted runner invocation without --deps fails too
        real = (ROOT / "skills" / "build" / "SKILL.md").read_text(encoding="utf-8-sig")
        extra = real + ('\n```bash\npython -I "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py" --repo . --scratch S '
                        "--tree T --image python-test -- true\n```\n")
        self.assertTrue(deps_gate_violations("build", extra))

    def test_bare_helper_call_is_exempt_only_when_historical(self):
        # inspection round 2, C1: the real README sentences narrate the old defect: exempt
        for name, lead in (("README.md", "runbook called `python scripts/sandbox_run.py`"),
                           ("README_DE.md", "Betriebshandbuch rief `python scripts/sandbox_run.py`")):
            real = (ROOT / name).read_text(encoding="utf-8-sig")
            self.assertIn(lead, real, name)
            self.assertEqual(runner_root_violations(real), [], name)
            # the same span turned into an instruction is a violation
            mutated = real.replace(lead, lead.replace("called", "Run", 1).replace("rief", "Run", 1))
            self.assertNotEqual(mutated, real)
            self.assertTrue(runner_root_violations(mutated), name)
        for t in ("Run `python scripts/sandbox_run.py` first.\n",
                  "Then execute `python -I scripts/dep_audit.py` before anything else.\n",
                  "Use `python3 scripts/sandbox_run.py`; it was fine before.\n",
                  "Before committing, call `python scripts/sandbox_run.py`.\n",
                  "The gate: `python scripts/sandbox_run.py`.\n"):
            self.assertTrue(runner_root_violations(t), t)
        for t in ("The old runbook used to name `python scripts/sandbox_run.py` in its steps.\n",
                  "The runbook said `python scripts/dep_audit.py` once.\n"):
            self.assertEqual(runner_root_violations(t), [], t)

    def test_bare_inline_auditor_after_an_imperative_is_executable(self):
        # inspection round 2, C2: `npm audit` is a complete command without arguments
        marker = "(not prescribed for repositories under review)"
        for verb in ("Run", "Execute", "Use", "Call", "Invoke", "Start"):
            for tool in ("npm audit", "pip-audit", "osv-scanner"):
                self.assertTrue(violations(f"{verb} `{tool}` {marker}.\n"), (verb, tool))
        # explanatory prose with the marker and no imperative stays excused
        for tool in ("npm audit", "pip-audit", "osv-scanner"):
            self.assertEqual(violations(f"`{tool}` is not prescribed for repositories under review.\n"), [])
            self.assertTrue(violations(f"`{tool}` is the usual way.\n"))
        real = (ROOT / "skills" / "audit" / "SKILL.md").read_text(encoding="utf-8-sig")
        sentence = "raw pip-audit, npm audit and"
        self.assertIn(sentence, real)
        self.assertTrue(violations(real.replace(sentence, "run `pip-audit`, npm audit and")))

    def test_deps_only_counts_in_the_runners_own_arguments(self):
        # inspection round 2, C3: not in a trailing comment, not after the runner's `--`
        frag = re.compile(r"\[--deps <[^>]*>\]\s*")
        for name in GATE_DEPS:
            real = (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8-sig")
            for i, spot in enumerate(frag.finditer(real)):
                placeholder = spot.group(0).strip()
                bare = real[:spot.start()] + real[spot.end():]
                delim = bare.find("-- ", spot.start() - 3)
                self.assertGreater(delim, 0, (name, i))
                after = bare[:delim + 3] + placeholder + " " + bare[delim + 3:]
                self.assertTrue(deps_gate_violations(name, after), f"{name} #{i} after --")
                eol = bare.find("\n", delim)
                if real[spot.start() - 1:spot.start()] != "`" and "`" not in real[spot.start() - 60:spot.start()]:
                    comment = bare[:eol] + " # " + placeholder + bare[eol:]
                    self.assertTrue(deps_gate_violations(name, comment), f"{name} #{i} comment")

    def test_interpreter_is_recognised_by_basename(self):
        # inspection round 2, C4: a path before `python` must not hide the call
        for exe in ("/usr/bin/python3", r"C:\Python313\python.exe", "./venv/bin/python", "python3.13",
                    "python.exe", "/opt/py/bin/python3.12"):
            bad = f"{exe} scripts/dep_audit.py --repo . --tree T --scratch S --file requirements.txt"
            self.assertTrue(runner_root_violations(f"```bash\n{bad}\n```\n"), exe)
            self.assertTrue(runner_root_violations(f"Call `{bad}` now.\n"), exe)
            no_i = f'{exe} "${{CLAUDE_PLUGIN_ROOT}}/scripts/dep_audit.py" --repo .'
            self.assertTrue(runner_root_violations(f"```bash\n{no_i}\n```\n"), exe)
            good = f'{exe} -I "${{CLAUDE_PLUGIN_ROOT}}/scripts/dep_audit.py" --repo .'
            self.assertEqual(runner_root_violations(f"```bash\n{good}\n```\n"), [], exe)
        # a word that merely ends in python is no interpreter
        self.assertEqual(runner_root_violations("```bash\nmypython scripts/dep_audit.py --repo .\n```\n"), [])

    def test_quoted_interpreter_is_recognised(self):
        # gate initial pass, block C, 1: `"/usr/bin/python3" scripts/sandbox_run.py` was not seen
        for exe in ('"/usr/bin/python3"', r'"C:\Program Files\Python313\python.exe"', "'./venv/bin/python'",
                    '"python3"', '"C:/Program Files/Python 3/python.exe"'):
            for helper in ("sandbox_run", "dep_audit"):
                bad = f"{exe} scripts/{helper}.py --repo ."
                self.assertTrue(runner_root_violations(f"```bash\n{bad}\n```\n"), bad)
                self.assertTrue(runner_root_violations(f"Call `{bad}` now.\n"), bad)
                no_i = f'{exe} "${{CLAUDE_PLUGIN_ROOT}}/scripts/{helper}.py" --repo .'
                self.assertTrue(runner_root_violations(f"```bash\n{no_i}\n```\n"), no_i)
                good = f'{exe} -I "${{CLAUDE_PLUGIN_ROOT}}/scripts/{helper}.py" --repo .'
                self.assertEqual(runner_root_violations(f"```bash\n{good}\n```\n"), [], good)
        # a quoted word that merely ends in python is no interpreter
        self.assertEqual(runner_root_violations('```bash\n"mypython" scripts/dep_audit.py --repo .\n```\n'), [])
        # negative mutations of the REAL runbook runner example
        real = (ROOT / "docs" / "betrieb.md").read_text(encoding="utf-8-sig")
        good = 'python -I "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py"'
        self.assertIn(good, real)
        self.assertEqual(runner_root_violations(real), [])
        for bad in ('"/usr/bin/python3" scripts/sandbox_run.py',
                    r'"C:\Program Files\Python313\python.exe" scripts/sandbox_run.py',
                    '"/usr/bin/python3" "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py"',
                    '"/usr/bin/python3" -S -I "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py"'):
            mutated = real.replace(good, bad)
            self.assertNotEqual(mutated, real)
            self.assertTrue(runner_root_violations(mutated), bad)
        quoted_good = real.replace(good, '"/usr/bin/python3" -I "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py"')
        self.assertEqual(runner_root_violations(quoted_good), [])

    def test_python_launcher_with_options_before_m_pip_audit_is_executable(self):
        # gate initial pass, block C, 2: the disclaimer must not excuse a python launcher
        marker = "(not prescribed for repositories under review)"
        spans = ("python -I -m pip_audit -r requirements.txt", "python3 -W ignore -m pip_audit",
                 "python -Im pip_audit x", "python -I -m pip-audit", "python -I -m pip audit -r x",
                 "python -u -I -m pip_audit", "/usr/bin/python3 -I -m pip_audit -r x",
                 r'"C:\Program Files\Python313\python.exe" -I -m pip_audit -r x',
                 "uv run python -I -m pip_audit -r x", "python -m pip_audit")
        for span in spans:
            self.assertTrue(violations(f"Run `{span}` {marker}.\n"), span)
            self.assertTrue(violations(f"`{span} -r req.txt` {marker}.\n"), span)  # with arguments: no verb needed
            self.assertTrue(violations(f"```bash\n{span} # {marker}\n```\n"), span)
        # the real audit skill, with the instruction appended
        real = (ROOT / "skills" / "audit" / "SKILL.md").read_text(encoding="utf-8-sig")
        self.assertEqual(violations(real), [])
        self.assertTrue(violations(real + f"\nRun `python -I -m pip_audit -r requirements.txt` {marker}.\n"))
        # quoted option operands (spaces inside) are one token (gate recheck 1, block C, 2)
        quoted = ('python -W "ignore:message with spaces" -m pip_audit -r requirements.txt',
                  "python -W 'ignore:message with spaces' -m pip_audit -r requirements.txt",
                  'python -X "a b" -I -m pip_audit -r x', 'python -Q "a b" -m pip_audit',
                  'python -W"ignore:a b" -m pip_audit -r x', '"python" -W "a b" -m pip_audit -r x')
        for span in quoted:
            self.assertTrue(violations(f"Run `{span}` {marker}.\n"), span)
            self.assertTrue(violations(real + f"\nRun `{span}` {marker}.\n"), span)
        self.assertTrue(violations(
            real + '\nRun `python -W "ignore:message with spaces" -m pip_audit -r requirements.txt` '
            "(not prescribed for repositories under review).\n"))
        # prose that merely names the tool in a marker sentence stays excused
        self.assertEqual(violations("Raw pip-audit and `python -I -m` are not prescribed for repositories "
                                    "under review.\n"), [])

    def test_helper_docstring_usage_lines_are_checked(self):
        # gate initial pass, block A2, 4/6: the usage line in a module docstring is an instruction
        import tempfile
        plugin = '"${CLAUDE_PLUGIN_ROOT}/scripts/%s.py"'

        def check(helper, usage):
            with tempfile.TemporaryDirectory(dir=ROOT / ".claudex-tmp") as d:
                p = Path(d) / f"{helper}.py"
                p.write_text('"""Summary.\n\n    %s\n\nMore.\n"""\nX = 1\n' % usage, encoding="utf-8", newline="\n")
                return docstring_usage_violations(p, helper)

        (ROOT / ".claudex-tmp").mkdir(exist_ok=True)
        for helper in ("sandbox_run", "dep_audit"):
            good = f"python -I {plugin % helper} --repo . --tree <sha> \\\n        --scratch <dir>"
            self.assertEqual(check(helper, good), [], helper)
            for bad in (f"python -I scripts/{helper}.py --repo .", f"python scripts/{helper}.py --repo .",
                        f"python {plugin % helper} --repo .", f"python -u -I {plugin % helper} --repo .",
                        f'"/usr/bin/python3" -I scripts/{helper}.py --repo .', "no usage line at all"):
                self.assertTrue(check(helper, bad), bad)

    def test_shipped_helper_docstrings_use_the_plugin_root(self):
        for helper in ("sandbox_run", "dep_audit"):
            path = ROOT / "scripts" / f"{helper}.py"
            self.assertEqual(docstring_usage_violations(path, helper), [], path.name)

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

    def test_auditor_only_in_a_not_prescribed_sentence(self):
        self.assertTrue(violations("Run `pip-audit` on the repo.\n"))
        self.assertTrue(violations("`pip-audit` runs on the host at your own risk until B1.5.\n"))
        self.assertTrue(violations("Then `npm audit` and OSV-Scanner.\n"))
        self.assertEqual(violations(
            "Raw pip-audit, npm audit and osv-scanner are not prescribed for repositories under review.\n"), [])
        # the OSV API behind dep_audit.py is not an auditor tool
        self.assertEqual(violations("dep_audit.py queries the OSV API with exact versions.\n"), [])
        # a table row carries the marker in its own text
        self.assertEqual(violations(
            "| dependency auditors | `dep_audit.py`; raw osv-scanner is not prescribed for repositories "
            "under review | runner |\n"), [])


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

    def test_helper_calls_are_plugin_rooted_and_isolated(self):
        problems = []
        for path in SKILLS + [ROOT / "docs" / "betrieb.md", ROOT / "README.md", ROOT / "README_DE.md"]:
            for v in runner_root_violations(path.read_text(encoding="utf-8-sig")):
                problems.append(f"{path.relative_to(ROOT).as_posix()}: {v}")
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_docs_name_no_raw_auditor_unmarked(self):
        problems = []
        for path in [ROOT / "docs" / "betrieb.md", ROOT / "README.md", ROOT / "README_DE.md"]:
            for no, unit, kind in _units(path.read_text(encoding="utf-8-sig")):
                problem = auditor_problem(unit, kind)
                if problem:
                    problems.append(f"{path.name}:{no}: {problem}: {unit[:100]}")
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_gates_state_the_deps_rules(self):
        """B1.5 step 8: every gate that writes a runner call says how dependencies reach it."""
        for name in ("build", "code-review", "docs-backfill", "audit", "claudex-loop"):
            text = (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8-sig")
            for needle in ("--deps", "REQUIREMENTS_SHA256=", "deps_failed",
                           "the requirements are not hashed (B1.5)"):
                self.assertTrue(needle in text, f"{name}: missing {needle!r}")
            self.assertEqual(deps_gate_violations(name, text), [], name)
        audit = (ROOT / "skills" / "audit" / "SKILL.md").read_text(encoding="utf-8-sig")
        self.assertTrue("dep_audit.py" in audit, "audit: missing dep_audit.py")
        self.assertTrue("AUDIT_MANIFEST_SHA256=" in audit, "audit: missing AUDIT_MANIFEST_SHA256=")
        self.assertNotRegex(audit, r"at the user'?s own risk")

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
