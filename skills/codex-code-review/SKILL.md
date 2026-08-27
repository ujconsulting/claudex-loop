---
name: codex-code-review
description: A parameterizable SECOND review gate that runs AFTER the build and after the primary review (the post-build cross-inspection, or whatever review your flow ran first). A fresh read-only Codex session judges the finished work on up to five acceptance dimensions — dod (everything implemented, Definition of Done met), quality (readability, clean-code rules, documentation), security, docs (documentation completeness and docstring coverage of the diff), tests (are the changed paths actually covered, and do the tests fail when the code is broken) — each with its own verdict line, findings arbitrated by Claude, one bounded recheck after fixes. Use when the user says "/codex-code-review", "second review", "acceptance review", "DoD check", "verify the build against the plan", "code quality review of what we just built", "security review of the change", or at the end of a claudex-loop/codex-build run when an extra acceptance gate is wanted. Scope is selectable: `scope=dod,quality,security,docs,tests` (default: `dod,quality,security`; add `docs,tests` whenever the diff changes behaviour). NOT a plan review (that is codex-plan-review) and NOT the primary correctness inspection (that is claudex-loop's built-in post-build cross-inspection) — this is the acceptance layer on top.
---

# codex-code-review — Post-Build Acceptance Review (second gate)

The built-in post-build cross-inspection answers *"does the diff implement the
plan correctly?"*. This skill is the **acceptance layer on top** — a second,
independent pass by a fresh read-only Codex session over the finished work:

| Scope | Question | Verdict line |
|---|---|---|
| `dod` | Is EVERYTHING implemented — every plan item, every Definition-of-Done criterion? Any silent scope cuts or scope creep? | `DOD: COMPLETE` / `DOD: INCOMPLETE` |
| `quality` | Readability, clean-code rules (naming, function size, duplication, dead code, error handling), and documentation — do comments/docs match the code? | `QUALITY: ACCEPTABLE` / `QUALITY: REVISE` |
| `security` | Injection, secrets in code, authz gaps, unsafe deserialization, path traversal, risky dependencies — anchored to the actual diff | `SECURITY: PASS` / `SECURITY: FAIL` |
| `docs` | Does every new/changed public unit carry documentation in the codebase's own style, and did the prose that describes this behaviour (README, CLAUDE.md/AGENTS.md, runbooks) move with it? | `DOCS: COMPLETE` / `DOCS: INCOMPLETE` |
| `tests` | Is every changed code path covered — error paths and edge cases, not just the happy one — and would the tests actually FAIL if the change were wrong? | `TESTS: ADEQUATE` / `TESTS: INSUFFICIENT` |

Doctrine unchanged: *whoever made the thing never checks the thing.* The
verifier is a **fresh** Codex session — not the plan-review thread, not the
build thread — so it sees the result cold.

## Tunables (read from skill args, else default)

| Var | Default | Meaning |
|-----|---------|---------|
| `scope` | `dod,quality,security` | Comma-list of the dimensions to run. Any subset, any order. Add `docs,tests` whenever the diff changes behaviour — leave them off for pure refactors, config and docs-only changes. |
| `DOCSTRING_MIN` | `80` | Percent of new/changed public units that must be documented before `docs` can pass. The number is evidence, not the verdict — a documented-but-lying docstring still fails. |
| `SPEC_FILE` | `PLAN.md` | The locked plan the work was built against (DoD source when no `DOD_FILE`). |
| `DOD_FILE` | _none_ | Optional explicit Definition-of-Done checklist. Without it, `dod` is judged against `SPEC_FILE`'s Goal/Approach/Out-of-scope. |
| `BASE_REF` | merge-base with `main`/`master` | Git ref the change is diffed against. Pass explicitly when the branch layout is unusual. |
| `LOG_FILE` | `PLAN-REVIEW-LOG.md` | The run's transcript — this skill appends to the same artifact the loop used. |
| `MAX_RECHECK` | `1` | Rechecks after accepted fixes (initial pass + N rechecks; the gate ALWAYS terminates). |

Echo the resolved values (and the active Codex model, read from
`~/.codex/config.toml`) before the first call.

## Flow

### Step 1 — Assemble the evidence (Claude, no user input needed)

1. `git diff <BASE_REF>...HEAD` (plus `git status --short` for untracked files
   that belong to the change). If the diff is empty, stop — nothing to verify.
2. Read `SPEC_FILE` (and `DOD_FILE` if given).
3. **Only when `docs` or `tests` is selected** — measure, don't guess. Run
   whatever the repo already has and inline the *numbers* in the prompt; a
   threshold check beats an opinion, and it is what makes `DOCSTRING_MIN`
   meaningful. Typical: `interrogate -v <changed pkgs>` (Python docstring
   coverage), `pytest --cov --cov-report=xml` + `diff-cover coverage.xml
   --compare-branch <BASE_REF>` (coverage of the *changed lines*), or the
   project's own equivalent. If none exists, say so in the prompt — "no
   coverage data available, judge from the diff" — rather than inventing a
   number. Missing tooling is a `tests` finding, not a reason to skip.
4. Build the verify prompt with the spec and the **diff inlined** — do not rely
   on Codex opening files by path: its shell calls can be policy-blocked and
   fresh files may be untracked, and then it reviews the repo but not the
   change. Repo files stay readable for context (it is read-only, not blind).

### Step 2 — The verify prompt (one session, all selected scopes)

> You are the acceptance reviewer for finished work. The plan it was built
> against and the full diff are inlined below. You are read-only — read any
> repo files you need for context, modify nothing. Judge ONLY the requested
> dimensions, each in its own section, findings numbered and anchored to
> file:line, each with what concretely is wrong and a one-line fix. Do NOT
> reproduce, re-list or line-number the inlined material — cite it and move
> on; your output budget is for findings. Do not re-litigate plan decisions —
> the plan is the contract, not the defendant.
> {scope contains dod:} Section DOD — walk the plan's Goal/Approach (and the
> Definition-of-Done list if provided) item by item: implemented, partially
> implemented, or missing? Flag silent scope cuts AND unrequested extras. End
> the section with exactly `DOD: COMPLETE` or `DOD: INCOMPLETE`.
> {scope contains quality:} Section QUALITY — readability and clean-code:
> naming, function size, duplication, dead code, error handling, magic values;
> documentation and comments that lie about the code are findings. Style nits
> without consequence are not. End with exactly `QUALITY: ACCEPTABLE` or
> `QUALITY: REVISE`.
> {scope contains docs:} Section DOCS — for every public unit the diff adds
> or changes: is it documented, and does the documentation match what the code
> now does? Infer the format from neighbouring code (docstring style, language,
> whether params/returns/raises are listed) — do not impose a house style the
> repo does not use. A docstring that describes the OLD behaviour is worse than
> none and is a finding. Look beyond the code too: if this change alters
> behaviour that README, CLAUDE.md/AGENTS.md, a runbook or a config example
> describes, that prose is now stale — name the file. Coverage below
> {DOCSTRING_MIN}% of new/changed public units means INCOMPLETE; above it,
> lying or contentless docs still mean INCOMPLETE. End with exactly
> `DOCS: COMPLETE` or `DOCS: INCOMPLETE`.
> {scope contains tests:} Section TESTS — for every behaviour the diff adds or
> changes: is there a test that exercises it, and **would that test fail if the
> change were wrong?** Name specifically: uncovered error paths and edge cases
> (empty, null, boundary, concurrent, permission-denied, malformed input),
> tests that assert nothing meaningful (`assertTrue(True)`, asserting a mock
> was called rather than an outcome, snapshot tests that would absorb any
> change), tests coupled to implementation detail instead of behaviour, and new
> tests that do not follow the framework, fixtures and naming the repo already
> uses. Judge coverage of the CHANGE, not of the repo. End with exactly
> `TESTS: ADEQUATE` or `TESTS: INSUFFICIENT`.
> {scope contains security:} Section SECURITY — injection, secrets in code or
> config, authz/authn gaps, unsafe deserialization, path traversal, dependency
> and supply-chain risks introduced by this change. End with exactly
> `SECURITY: PASS` or `SECURITY: FAIL`.

Write the assembled prompt to a temp file and feed it via **stdin** — never as
a command-line argument: with the diff inlined the prompt easily exceeds the
OS argument-size limit ("Argument list too long", found the first time this
skill reviewed its own diff). Otherwise codex-plan-review mechanics apply:

```bash
codex exec -s read-only --json -o /tmp/codex-code-review.txt - \
  < /tmp/verify-prompt.txt 2>/tmp/codex-stderr.txt | grep '"type":"thread.started"'
```

Capture `thread_id` from the `thread.started` line; 10-minute ceiling
(`timeout: 600000` via Claude Code's Bash tool). stderr goes to a **file**: a
quota/auth failure can present as exit 0 + empty output file, and the real
error (429/401) only appears there. On resume, force `-c
sandbox_mode="read-only"` (resume rejects `-s`) and feed the recheck prompt
via stdin the same way.

### Step 3 — Arbitrate and fix (Claude has final say)

1. Append to `LOG_FILE` **the moment the reply arrives**:
   `## Second review (codex-code-review) — <scopes> — <model>` + the full report
   verbatim. This happens BEFORE arbitration and regardless of the outcome —
   an invalid reply is logged too, as `## Second review — INVALID ATTEMPT
   (<reason>), does not count` (a fallback run does this itself via
   `--append-log`). Findings never live only in the chat transcript; if it
   isn't in the log, it didn't happen.
2. Parse the verdict line of every selected scope. A missing verdict line, or
   a report with all-pass verdicts and zero findings on a non-trivial diff, is
   an **invalid review** — do not record it as a pass; rerun or surface it.
3. For each finding: accept (fix it, rerun the affected tests/proof) or reject
   *with a logged reason*. Append `### Claude's dispositions` to `LOG_FILE` —
   one line per finding, `accepted → <what changed>` or `rejected → <why>`.
4. If anything was fixed and rechecks remain: resume the SAME session —
   "Fixes applied for findings <ids>. Re-verify the same scopes against the
   updated diff (inlined below). Same verdict rules." — and repeat once per
   `MAX_RECHECK`. Each recheck is logged the same way:
   `## Second review — recheck <k>` + report verbatim + dispositions.

### Step 3b — Close `docs` / `tests` findings by writing them (Claude)

A `DOCS: INCOMPLETE` or `TESTS: INSUFFICIENT` finding is closed by *writing*
the missing docstring or test — Codex is read-only and names the gap; filling
it is the builder's job, done between the initial pass and the recheck. That
split is deliberate: the material written here goes through the same
adversarial gate as the production code, which is exactly what a
generate-and-ship tool cannot offer.

- **Match the repo, not a house style.** Read two or three neighbouring
  functions/tests first: docstring format and language, test framework,
  fixtures, naming, file layout. A correct docstring in the wrong format is a
  new inconsistency.
- **Every generated test must be shown to fail.** Break the code it covers
  (invert a condition, return the wrong value), run the test, confirm it goes
  red, restore the code, confirm it goes green. Record the result in
  `LOG_FILE`. An untested test proves nothing and is worse than no test,
  because it reads as coverage.
- **Never weaken an assertion to make a test pass.** If a new test fails, either
  the code is wrong (fix the code) or the expectation is wrong (say so, with
  the reasoning) — loosening the assert is falsifying the gate.
- **Docstrings describe behaviour, contract and failure modes** — parameters,
  return value, raised exceptions, side effects. Restating the function name in
  a sentence adds nothing and will be flagged again on the recheck.
- **Stale prose counts as a docs finding.** If the change made a line in
  README, CLAUDE.md/AGENTS.md, a runbook or a config example wrong, fix that
  line in the same pass.

Then run the recheck as in Step 3 (4.) — the recheck is what turns the written
material into a verdict, so never report `docs`/`tests` as green off the back of
your own generation.

### Step 4 — Report to the human (the gate)

Present a per-scope table: verdict, findings raised / fixed / rejected, and
the one-line reason for every rejection — and append that same table to
`LOG_FILE` under `## Second review — gate result` so the log, not the chat,
carries the outcome. All selected scopes green → the gate passes. Any scope
red after the last recheck → the gate FAILS visibly; hand the open findings
to the user to decide. Never average a red scope away — `SECURITY: FAIL` with
`DOD: COMPLETE` is a failed gate, not a mixed result.

## If Codex is unavailable (quota, credits, outage)

**The exact same fallback scenarios as the review loop apply** — see
[FALLBACK.md](../../FALLBACK.md). Concretely for this gate:

- **Preflight before the gate:** `python scripts/codex_usage.py` (remaining
  5-hour/weekly windows + reset times from the local session rollouts). Exit 1
  → don't start; tell the user when Codex is back.
- **Terminal-failure signals** during the gate: 429/"usage limit"/401 in the
  stderr file, or an empty output file on exit 0 twice in a row.
- **Then the USER picks — never automatically, never silently:**
  1. **Wait** for the reset; rechecks resume the same verify thread.
  2. **Switch** to a configured fallback reviewer. The adapter reuses the
     gate's own prompt and verdict grammar:

     ```bash
     # SPEC (+ DoD) + diff concatenated into one file = everything the
     # reviewer needs, since fallbacks only see inlined text anyway (Step 1).
     cat "$SPEC_FILE" > /tmp/verify-input.md
     [ -n "$DOD_FILE" ] && cat "$DOD_FILE" >> /tmp/verify-input.md
     { echo; echo "=== DIFF ==="; git diff "$BASE_REF"...HEAD; } >> /tmp/verify-input.md
     python scripts/fallback_review.py --chain --plan /tmp/verify-input.md \
       --system-file /tmp/verify-prompt.txt \
       --require-verdicts "DOD:COMPLETE|INCOMPLETE,QUALITY:ACCEPTABLE|REVISE,SECURITY:PASS|FAIL,DOCS:COMPLETE|INCOMPLETE,TESTS:ADEQUATE|INSUFFICIENT" \
       --out /tmp/codex-code-review.txt
     ```

     `--system-file` carries the Step-2 verify prompt (trimmed to the selected
     scopes — and trim `--require-verdicts` to the same scopes); the adapter
     enforces that every selected verdict line appears (missing = invalid,
     exit 3), applies the rubber-stamp gate when everything passes with zero
     findings, and binds the result to the SHA256 of the combined input.
     `--chain` walks `CLAUDEX_REVIEWERS` with per-provider preflight, skips
     reported, first viable provider wins. Log such rounds as
     `## Second review — <model> (via <reviewer>, fallback)` and say the gate
     ran text-only (no repo context beyond the inlined material).
  3. **Skip** the gate with an explicit log entry
     (`## Second review skipped — Codex quota exhausted (<window>, resets
     <time>), decided by <user>`) — skipped is a recorded state, silent
     skipping never.

## Hard rules

- Fresh session for the initial pass — never reuse the plan-review or build
  thread; rechecks resume the verify thread only.
- Codex is read-only every call (`-s read-only`; resume: `-c sandbox_mode="read-only"`).
- Diff and spec go INLINE in the prompt; repo access is context, not the
  delivery mechanism.
- Every selected scope ends in its exact verdict line; anything else is an
  invalid review, not a pass.
- Claude arbitrates — incorporate real findings, reject bad ones with logged
  reasons; the gate result and all dispositions live in `LOG_FILE`.
- The gate ALWAYS terminates: initial pass + `MAX_RECHECK` rechecks.
- Code changes during this skill are limited to fixing accepted findings
  (docstrings and tests written per Step 3b included) — no new features under
  the flag of verification.
- A test written to close a finding is not done until it has been observed
  failing against deliberately broken code and passing against the real code.

## What NOT to do

- Don't run it INSTEAD of the post-build cross-inspection — it assumes the
  correctness pass already happened and deliberately looks elsewhere.
- Don't re-open plan decisions ("should have used X") — plan critique
  belonged in Phase 2; here the plan is the contract.
- Don't let a scope's verdict be inferred from vibes — no verdict line, no
  verdict.
- Don't run `security` alone as a substitute for a real security process on
  high-stakes code — it is one adversarial pass, not a pentest.
- Don't close a `tests` finding with a characterization test that merely
  records whatever the code currently does — that locks in the bug you were
  supposed to catch. The test must encode the INTENDED behaviour from the spec.
- Don't let a coverage percentage decide `docs` or `tests`. The number is
  evidence for the reviewer; 100% coverage of vacuous assertions is still
  `INSUFFICIENT`.
