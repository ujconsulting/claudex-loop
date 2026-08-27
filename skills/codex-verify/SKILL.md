---
name: codex-verify
description: A parameterizable SECOND review gate that runs AFTER the build and after the primary review (the post-build cross-inspection, or whatever review your flow ran first). A fresh read-only Codex session judges the finished work on up to three acceptance dimensions — dod (everything implemented, Definition of Done met), quality (readability, clean-code rules, documentation), security — each with its own verdict line, findings arbitrated by Claude, one bounded recheck after fixes. Use when the user says "/codex-verify", "second review", "acceptance review", "DoD check", "verify the build against the plan", "code quality review of what we just built", "security review of the change", or at the end of a claudex-loop/codex-build run when an extra acceptance gate is wanted. Scope is selectable: `scope=dod,quality,security` (default: all three). NOT a plan review (that is codex-review) and NOT the primary correctness inspection (that is claudex-loop's built-in post-build cross-inspection) — this is the acceptance layer on top.
---

# Codex-Verify — Post-Build Acceptance Review (second gate)

The built-in post-build cross-inspection answers *"does the diff implement the
plan correctly?"*. This skill is the **acceptance layer on top** — a second,
independent pass by a fresh read-only Codex session over the finished work:

| Scope | Question | Verdict line |
|---|---|---|
| `dod` | Is EVERYTHING implemented — every plan item, every Definition-of-Done criterion? Any silent scope cuts or scope creep? | `DOD: COMPLETE` / `DOD: INCOMPLETE` |
| `quality` | Readability, clean-code rules (naming, function size, duplication, dead code, error handling), and documentation — do comments/docs match the code? | `QUALITY: ACCEPTABLE` / `QUALITY: REVISE` |
| `security` | Injection, secrets in code, authz gaps, unsafe deserialization, path traversal, risky dependencies — anchored to the actual diff | `SECURITY: PASS` / `SECURITY: FAIL` |

Doctrine unchanged: *whoever made the thing never checks the thing.* The
verifier is a **fresh** Codex session — not the plan-review thread, not the
build thread — so it sees the result cold.

## Tunables (read from skill args, else default)

| Var | Default | Meaning |
|-----|---------|---------|
| `scope` | `dod,quality,security` | Comma-list of the dimensions to run. Any subset, any order. |
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
3. Build the verify prompt with the spec and the **diff inlined** — do not rely
   on Codex opening files by path: its shell calls can be policy-blocked and
   fresh files may be untracked, and then it reviews the repo but not the
   change. Repo files stay readable for context (it is read-only, not blind).

### Step 2 — The verify prompt (one session, all selected scopes)

> You are the acceptance reviewer for finished work. The plan it was built
> against and the full diff are inlined below. You are read-only — read any
> repo files you need for context, modify nothing. Judge ONLY the requested
> dimensions, each in its own section, findings numbered and anchored to
> file:line, each with what concretely is wrong and a one-line fix. Do not
> re-litigate plan decisions — the plan is the contract, not the defendant.
> {scope contains dod:} Section DOD — walk the plan's Goal/Approach (and the
> Definition-of-Done list if provided) item by item: implemented, partially
> implemented, or missing? Flag silent scope cuts AND unrequested extras. End
> the section with exactly `DOD: COMPLETE` or `DOD: INCOMPLETE`.
> {scope contains quality:} Section QUALITY — readability and clean-code:
> naming, function size, duplication, dead code, error handling, magic values;
> documentation and comments that lie about the code are findings. Style nits
> without consequence are not. End with exactly `QUALITY: ACCEPTABLE` or
> `QUALITY: REVISE`.
> {scope contains security:} Section SECURITY — injection, secrets in code or
> config, authz/authn gaps, unsafe deserialization, path traversal, dependency
> and supply-chain risks introduced by this change. End with exactly
> `SECURITY: PASS` or `SECURITY: FAIL`.

Invocation follows the codex-review mechanics — `codex exec -s read-only
--json -o /tmp/codex-verify.txt "$PROMPT" < /dev/null 2>/tmp/codex-stderr.txt`,
capture `thread_id` from the `thread.started` line, 10-minute ceiling
(`timeout: 600000` via Claude Code's Bash tool). stderr goes to a **file**: a
quota/auth failure can present as exit 0 + empty output file, and the real
error (429/401) only appears there. On resume, force `-c
sandbox_mode="read-only"` (resume rejects `-s`).

### Step 3 — Arbitrate and fix (Claude has final say)

1. Append to `LOG_FILE`: `## Second review (codex-verify) — <scopes>` + the
   full report.
2. Parse the verdict line of every selected scope. A missing verdict line, or
   a report with all-pass verdicts and zero findings on a non-trivial diff, is
   an **invalid review** — do not record it as a pass; rerun or surface it.
3. For each finding: accept (fix it, rerun the affected tests/proof) or reject
   *with a logged reason*. Append `### Claude's dispositions` to `LOG_FILE`.
4. If anything was fixed and rechecks remain: resume the SAME session —
   "Fixes applied for findings <ids>. Re-verify the same scopes against the
   updated diff (inlined below). Same verdict rules." — and repeat once per
   `MAX_RECHECK`.

### Step 4 — Report to the human (the gate)

Present a per-scope table: verdict, findings raised / fixed / rejected, and
the one-line reason for every rejection. All selected scopes green → the gate
passes. Any scope red after the last recheck → the gate FAILS visibly; hand
the open findings to the user to decide. Never average a red scope away —
`SECURITY: FAIL` with `DOD: COMPLETE` is a failed gate, not a mixed result.

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
       --require-verdicts "DOD:COMPLETE|INCOMPLETE,QUALITY:ACCEPTABLE|REVISE,SECURITY:PASS|FAIL" \
       --out /tmp/codex-verify.txt
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
- Code changes during this skill are limited to fixing accepted findings —
  no new features under the flag of verification.

## What NOT to do

- Don't run it INSTEAD of the post-build cross-inspection — it assumes the
  correctness pass already happened and deliberately looks elsewhere.
- Don't re-open plan decisions ("should have used X") — plan critique
  belonged in Phase 2; here the plan is the contract.
- Don't let a scope's verdict be inferred from vibes — no verdict line, no
  verdict.
- Don't run `security` alone as a substitute for a real security process on
  high-stakes code — it is one adversarial pass, not a pentest.
