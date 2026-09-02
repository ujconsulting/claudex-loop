---
name: code-review
description: "A parameterizable SECOND review gate that runs AFTER the build and after the primary review (the post-build cross-inspection, or whatever review your flow ran first). A fresh read-only Codex session judges the finished work on up to five acceptance dimensions — dod (everything implemented, Definition of Done met), quality (readability, clean-code rules, documentation), security, docs (documentation completeness and docstring coverage of the diff), tests (are the changed paths actually covered, and do the tests fail when the code is broken) — each with its own verdict line, findings arbitrated by Claude, one bounded recheck after fixes. Use when the user says \"/code-review\", \"second review\", \"acceptance review\", \"DoD check\", \"verify the build against the plan\", \"code quality review of what we just built\", \"security review of the change\", or at the end of a claudex-loop/build run when an extra acceptance gate is wanted. Scope is selectable: `scope=dod,quality,security,docs,tests` (default: `dod,quality,security`; add `docs,tests` whenever the diff changes behaviour). NOT a plan review (that is plan-review) and NOT the primary correctness inspection (that is claudex-loop's built-in post-build cross-inspection) — this is the acceptance layer on top. Anything in the diff that faces the network — routes, auth, sessions, webhooks, `ports:`, proxy/tunnel config — additionally gets a separate EXPOSURE PASS on the `exposure-review` role (a stronger model at bounded effort, default gpt-5.6-sol/medium) with its own verdict `EXPOSURE: SAFE/UNSAFE`. It is mandatory, not a scope you can drop."
---

# code-review — Post-Build Acceptance Review (second gate)

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
| *exposure pass* (automatic) | For the parts of the change that face the network: can someone outside the machine reach, forge, inject, exhaust or read what they should not? A separate session on the `exposure-review` role, checklist-driven (Step 2b). | `EXPOSURE: SAFE` / `EXPOSURE: UNSAFE` |

Doctrine unchanged: *whoever made the thing never checks the thing.* The
verifier is a **fresh** Codex session — not the plan-review thread, not the
build thread — so it sees the result cold.

## Actor (resolved, never assumed)

This skill does not decide which model runs it. Before anything else, resolve
`code-review` and `exposure-review` and check the gates:

```bash
python scripts/claudex_roles.py --explain
python scripts/claudex_roles.py --spec exposure-review   # e.g. codex model=gpt-5.6-sol effort=medium sandbox=read-only
```

Use the actors it prints — the diff being graded was written by `roles.build`. The
exposure pass runs on its own model and effort (`--spec` shows them; the skill passes
them to the wrapper as `--model`/`--effort` and never chooses them itself). **A non-zero exit means stop:** the role
assignment violates a gate (a maker set to grade its own work, or an adversary
role with an open sandbox), and no run may start on it. Where this document says
"Codex" or "Claude" below, read it as the resolved actor for that role.
Reference: `ROLES.md`.
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
| `BASELINE_FILE` | newest `docs/audit/*-baseline.md`, else none | Known pre-existing debt from an `audit` run. Everything listed there is NOT this change's fault: raise it again only where the change makes it worse or touches that code. Without this, every review of a legacy repo re-litigates the same findings and the real ones drown. |
| `EXPOSURE` | `auto` | `auto` = classify the diff (Step 1, item 6); `yes` = run the exposure pass regardless; `no` = an explicit, logged claim that nothing in the diff faces the network. `no` is refused when the classification says otherwise. |
| `THIRD_REVIEWER` | `off` | An **optional** extra pass by a reviewer that is neither the producer nor the primary adversary. `off` (default) = this gate is Codex-only and complete as it stands. `coderabbit` = additionally run the CodeRabbit CLI over the same diff and fold its findings into Step 3's arbitration. Anything else is refused rather than guessed at. |
| `EXPOSURE_FILES` | from classification | Comma-list of the exposed files/components to hand the exposure pass in full. Pass it when the auto-list is wrong; the log records both. |

| `SCRATCH_DIR` | harness scratchpad, else `<repo>/.claudex-tmp/` | Disposable staging for the assembled prompt, the `-o` capture and stderr. ⛔ Never `/tmp`. |

Echo the resolved values (and the active Codex model, read from
`~/.codex/config.toml`) before the first call.

### Where files go

- **Durable, in the repo:** `LOG_FILE` (and `BASELINE_FILE` when one exists) — committed.
- **Disposable, in `SCRATCH_DIR`:** the assembled prompt, the `-o` capture, the stderr
  file and the scanner reports, named **per round** (`code-review-r<n>.txt`,
  `verify-prompt-r<n>.txt`, `codex-stderr-r<n>.txt`). A fixed filename reused across the
  initial pass and the recheck destroys the first verdict on a failed write.

⛔ **Never `/tmp`.** World-readable, so the diff, the spec and any scanner findings sit
where every other user on the machine can read them — and this skill deliberately puts
secret-scanner output in there. On macOS it is also a symlink to `/private/tmp`, which
breaks path matching against `git rev-parse --show-toplevel`. Prefer the harness
scratchpad; otherwise `<repo>/.claudex-tmp/`, gitignored in the same step. Quote the path.
(upstream [issue #10](https://github.com/chaseai-yt/claudex-loop/issues/10))

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
4. **Anything the reviewer must cite by line, hand it over WITH line numbers.** A
   unified diff carries hunk headers, so the reviewer has to do arithmetic to name a
   line — and models miscount. Where you inline whole files rather than a diff, prefix
   every line with its number (`  1234| code`). The `audit` skill learned this the
   expensive way: its first run produced sound findings at wrong addresses, and each
   one cost a manual search to place. Note this is the opposite of the output rule
   below — number the material going IN, forbid re-listing it coming OUT.
5. Build the verify prompt with the spec and the **diff inlined** — do not rely
   on Codex opening files by path: its shell calls can be policy-blocked and
   fresh files may be untracked, and then it reviews the repo but not the
   change. Repo files stay readable for context (it is read-only, not blind).
6. **Classify exposure.** The change touches an exposed component when the diff
   changes any of: HTTP/WebSocket routes, handlers or middleware; authentication,
   sessions, tokens or identity headers; webhook or callback receivers; anything that
   binds a socket; `ports:` in compose, Dockerfiles `EXPOSE`, reverse-proxy, tunnel or
   ingress config (Caddy, nginx, Traefik, NPM, cloudflared); CORS/CSP/cookie settings;
   upload handlers; IaC or DNS. Consult the repo's own inventory first — an
   `## Exposed surface` section in `AGENTS.md`/`CLAUDE.md` or `docs/exposure.md` — and
   fall back to the pattern list. **Ambiguous means exposed.** Record the verdict and
   the file list in `LOG_FILE` as `### Exposure classification`; with `EXPOSURE=no` the
   entry says who claimed it and why. A change to a component that is reachable from
   the internet is the one case where "probably fine" has already cost people their
   secrets.

### Step 2 — The verify prompt (one session, all selected scopes)

> You are the acceptance reviewer for finished work. The plan it was built
> against and the full diff are inlined below. You are read-only — read any
> repo files you need for context, modify nothing. Judge ONLY the requested
> dimensions, each in its own section, findings numbered and anchored to
> file:line, each with what concretely is wrong and a one-line fix. Do NOT
> reproduce, re-list or line-number the inlined material — cite it and move
> on; your output budget is for findings.
> {BASELINE_FILE given:} Known pre-existing findings from an earlier audit are inlined
> as well. They are NOT this change's fault — do not raise them again unless this change
> makes one measurably worse or touches the code they sit in.
> Do not re-litigate plan decisions —
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
> {scope contains security:} Section SECURITY — for THIS change: every new or
> altered route has authentication and per-object authorisation (a dashboard, API or
> debug endpoint without login is a finding, never a note); secrets stay out of code,
> config defaults, logs, responses and URLs; injection (SQL, shell, template), path
> traversal, SSRF, unsafe deserialisation at every input the change adds; webhook and
> callback signatures verified fail-closed; bind addresses and `ports:` (loopback vs
> all interfaces); trusted-header or IP-based identity shortcuts; dependency and
> supply-chain risk from the inlined scanner output. For each of these say what you
> examined and what you found — a PASS that names nothing it checked is not a PASS.
> End with exactly `SECURITY: PASS` or `SECURITY: FAIL`.

⛔ **Close the whole reply with the verdicts, one per line, nothing after them.**
Append this to the prompt verbatim, listing only the scopes you selected:

> Finish your reply with the verdict lines for every dimension you were asked to
> judge — one per line, as the last non-blank lines, with no prose, no summary and
> no closing remark after them. Repeat them there even though each section already
> ends in its own.

Each section still ends in its verdict, for a human reading top to bottom. The
closing block is what a machine reads: `fallback_review.py`'s `validate()` checks the
last non-blank lines, because a verdict buried mid-reply is how a model gets to say
`APPROVED` and then keep talking. Without this instruction the section-verdict style
above satisfies a Codex round but fails every fallback round — which is exactly the
moment the gate is needed. (CodeRabbit, 2026-08-30.)

**Before assembling the `security` section, run the machines** — the same standing
four as `audit`, scoped to the changed files, with their output pasted into the
prompt as evidence. A model reading a diff will not spot a secret that a scanner
finds in a second, and it cannot know a dependency's CVEs at all:

| Tool | Run it when | Command |
|---|---|---|
| **gitleaks** | always | `gitleaks dir . --no-banner --redact -f json -r <SCRATCH_DIR>/gitleaks.json` |
| **grype** | the diff touches dependencies or an image | `grype dir:. -o table` |
| **hadolint** | the diff touches a `Dockerfile` | `hadolint <Dockerfile>` |
| **actionlint** | the diff touches `.github/workflows/` | `actionlint` |

⛔ **`--redact` is mandatory.** The findings go into a prompt bound for a remote
model; unredacted, the review would transmit the very secret it just found. State
in `LOG_FILE` which tools ran and which were absent — a tool that never ran is not
a `PASS`, and `SECURITY: PASS` on an unscanned diff is a claim nobody checked.

Write the assembled prompt to a temp file and feed it via **stdin** — never as
a command-line argument: with the diff inlined the prompt easily exceeds the
OS argument-size limit ("Argument list too long", found the first time this
skill reviewed its own diff). Otherwise plan-review mechanics apply:

```bash
ROUND=0   # the acceptance round; incremented per recheck, up to MAX_RECHECK
# Same rule as the exposure pass below: the model comes from the role config.
SPEC=$(python scripts/claudex_roles.py --spec code-review) || exit 2
MODEL=$(echo "$SPEC" | sed -n 's/.*model=\([^ ]*\).*/\1/p')
EFFORT=$(echo "$SPEC" | sed -n 's/.*effort=\([^ ]*\).*/\1/p')

python tools/codex_ro.py --model "$MODEL" --effort "$EFFORT" \
  --prompt-file "$SCRATCH_DIR/verify-prompt-r$ROUND.txt" \
  --out-file "$SCRATCH_DIR/code-review-r$ROUND.txt" \
  --err-file "$SCRATCH_DIR/codex-stderr-r$ROUND.txt"
```

The wrapper feeds the prompt over stdin itself, which is the same reason the raw form
used `-` : with the diff inlined, a prompt passed as an argument blows past the OS
argument-size limit ("Argument list too long" — found the first time this skill reviewed
its own diff).

Capture `thread_id` from the `thread.started` line; 10-minute ceiling
(`timeout: 600000` via Claude Code's Bash tool). stderr goes to a **file**: a
quota/auth failure can present as exit 0 + empty output file, and the real
error (429/401) only appears there. On resume, force `-c
sandbox_mode="read-only"` (resume rejects `-s`) and feed the recheck prompt
via stdin the same way.

### Step 2b — Exposure pass (separate session, `exposure-review` role)

Runs whenever Step 1 classified the change as exposed (or `EXPOSURE=yes`), **after**
the acceptance pass and in a **separate fresh session** — a second pair of eyes with
a different model, not a longer look by the same one. The `security` scope above
asks "did this change introduce a hole?"; this pass asks the attacker's question:
*standing outside the machine, what can I reach, forge, inject, exhaust or read?*

Input, all numbered (`  1234| code`): the exposed files **entire**, not just their
hunks — a route is only judged with its middleware, its auth decorator and the config
that publishes it; the diff; every deployment file that publishes something
(compose, Dockerfile, proxy/tunnel config, `.env.example`); the Step-2 scanner
output. Everything else is context by path. Do NOT hand it the whole diff of a large
change — the bounded input is what lets a stronger model run at medium effort inside
the ceiling.

> You are the exposure reviewer. The component below faces the network: someone
> outside this machine can send it bytes. You are read-only. Judge ONLY the inlined
> exposed component, its deployment config and the diff — not code quality, not the
> plan. Findings numbered, anchored to file:line citing the inlined numbers verbatim,
> each with the concrete attack and a one-line fix, severity CRITICAL/HIGH/MEDIUM/LOW.
> Work through this checklist item by item and say for each what you examined and
> what you found — "checked, nothing" is a result, silence is not:
> 1. **Reachability** — what listens where: bind addresses (`0.0.0.0` vs loopback),
>    compose `ports:`, reverse-proxy hosts, tunnels, public DNS. Name every endpoint
>    that is reachable from outside the machine.
> 2. **Authentication on every route** — no dashboard, API, health, metrics, debug or
>    admin endpoint without login or token. Default credentials. Signup open when it
>    should be an allowlist. Unauthenticated-by-design must be stated as such, per route.
> 3. **Authorisation per object** — can one user reach another's records by id (IDOR)?
>    Admin-only actions gated on the server, not in the UI?
> 4. **Identity shortcuts** — trusted headers (`X-Forwarded-User`, `X-*-User`), IP
>    allowlists, "internal" flags: can they be forged from outside, and are they
>    disableable at all?
> 5. **Secrets** — in env readable by tasks or agents, in logs, error pages, responses,
>    URLs, client bundles. Every secret that leaves the process boundary.
> 6. **Input at the trust boundary** — injection (SQL, shell, template), path traversal,
>    SSRF (URL fetchers, webhooks), unsafe deserialisation, uploads (type, size, path),
>    missing size limits.
> 7. **Webhooks and callbacks** — signature verified with a constant-time compare, secret
>    required (fail-closed when unset), replay considered, sender allowlisted.
> 8. **Transport and browser** — TLS, CORS origins, CSRF, cookie flags (Secure, HttpOnly,
>    SameSite), security headers, WebSocket origin checks.
> 9. **Abuse** — rate limiting on login and expensive routes, brute-force lockout,
>    resource exhaustion.
> 10. **Execution** — anything that runs code or commands from a request (agents, task
>     runners, eval, YOLO modes): the container boundary and its mounts ARE the sandbox;
>     what is mounted, and writable?
> 11. **Dependencies and images** — the inlined grype/hadolint output for exposed
>     images and manifests; anything running as root that need not.
> 12. **Leakage** — stack traces, version banners, directory listings, verbose errors.
> Any route reachable from outside without authentication that is not explicitly
> public-by-design is CRITICAL. End with a line `Checked: <items>, n/a: <items>` and
> then exactly `EXPOSURE: SAFE` or `EXPOSURE: UNSAFE`.

Mechanics as Step 2, with the model and effort the resolver printed:

```bash
python tools/codex_ro.py --model "$EXPOSURE_MODEL" --effort "$EXPOSURE_EFFORT" \
  --prompt-file "$SCRATCH_DIR/exposure-prompt-r$ROUND.txt" \
  --out-file "$SCRATCH_DIR/exposure-r$ROUND.txt" --err-file "$SCRATCH_DIR/exposure-stderr-r$ROUND.txt"
```

(`EXPOSURE_MODEL`/`EXPOSURE_EFFORT` are the `model=`/`effort=` fields of
`claudex_roles.py --spec exposure-review`. There is no "without the wrapper" variant:
this call is a review, and reviews go through `tools/codex_ro.py`.)
Log it as `## Exposure pass — <model>/<effort>` + report verbatim, then dispositions
as in Step 3. `EXPOSURE: SAFE` with zero findings and an empty `Checked:` line is an
invalid review, exactly like a rubber-stamp acceptance pass. Rechecks after fixes
resume this session, once per `MAX_RECHECK`.

### Step 2c — Third reviewer (OFF unless asked for)

Skip this entirely unless `THIRD_REVIEWER` names one. **Not everyone has one, and the
gate is complete without it** — Codex plus the exposure pass is the designed shape, not a
degraded one. This step exists because a reviewer that produced none of the findings
sometimes sees what the other two cannot, and that is worth having as an option rather
than a dependency.

`THIRD_REVIEWER=coderabbit`:

```bash
coderabbit --version || echo "not installed — say so and continue without it"
coderabbit auth status
coderabbit review --agent --uncommitted --include-untracked --config CLAUDE.md AGENTS.md
```

- **Missing or unauthenticated is not a failure of this gate.** Report it in one line
  ("third reviewer requested but unavailable: <reason>") and finish the review without
  it. ⛔ Never silently drop it — a check that did not run is not a check that passed.
- The login is interactive and refuses a non-TTY environment: the **user** runs
  `coderabbit auth login` in their own terminal. Do not ask them for a token.
- ⛔ **Run the secret scan first.** The CLI sends the diff to a remote API. `gitleaks dir
  . --redact` over the tree, and do not proceed on a finding.
- `--include-untracked` matters: without it, `--uncommitted` covers tracked edits only,
  and brand-new files — usually the ones most worth reviewing — are silently skipped.
- Findings go into Step 3's arbitration like any other, **verified against the code
  first**. Expect false positives about intent; expect the count not to converge across
  repeated passes. Severity is the signal, not volume.

### Step 3 — Arbitrate and fix (Claude has final say)

1. Append to `LOG_FILE` **the moment the reply arrives**:
   `## Second review (code-review) — <scopes> — <model>` + the full report
   verbatim. This happens BEFORE arbitration and regardless of the outcome —
   an invalid reply is logged too, as `## Second review — INVALID ATTEMPT
   (<reason>), does not count` (a fallback run does this itself via
   `--append-log`). Findings never live only in the chat transcript; if it
   isn't in the log, it didn't happen.
2. Parse the verdict line of every selected scope — and the `EXPOSURE:` line
   whenever the exposure pass ran. A missing verdict line, or a report with
   all-pass verdicts and zero findings on a non-trivial diff, is an **invalid
   review** — do not record it as a pass; rerun or surface it.
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
`DOD: COMPLETE` is a failed gate, not a mixed result. `EXPOSURE: UNSAFE` fails the
gate on its own, whatever the scopes say; an exposed change with no exposure verdict
(pass not run, invalid, or skipped) is **not reviewed** — report it as such, not as
green with a footnote.

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
     cat "$SPEC_FILE" > "$SCRATCH_DIR/verify-input-r$ROUND.md"
     [ -n "$DOD_FILE" ] && cat "$DOD_FILE" >> "$SCRATCH_DIR/verify-input-r$ROUND.md"
     { echo; echo "=== DIFF ==="; git diff "$BASE_REF"...HEAD; } >> "$SCRATCH_DIR/verify-input-r$ROUND.md"
     # Build --require-verdicts FROM the selected scope. Hard-coding all five
     # rejected a perfectly good reply whenever the scope was smaller -- and the
     # default scope IS smaller (dod,quality,security), so during a Codex outage
     # the documented fallback path failed on every default run (audit 2026-08-30).
     # `case`, not `declare -A`: macOS still ships bash 3.2, which has no
     # associative arrays and would fail here with a syntax error.
     REQUIRE=""
     for s in $(echo "$SCOPE" | tr ',' ' '); do
       case "$s" in
         dod)      g="DOD:COMPLETE|INCOMPLETE" ;;
         quality)  g="QUALITY:ACCEPTABLE|REVISE" ;;
         security) g="SECURITY:PASS|FAIL" ;;
         docs)     g="DOCS:COMPLETE|INCOMPLETE" ;;
         tests)    g="TESTS:ADEQUATE|INSUFFICIENT" ;;
         *) echo "unknown scope: $s" >&2; exit 2 ;;
       esac
       REQUIRE="${REQUIRE:+$REQUIRE,}$g"
     done

     python scripts/fallback_review.py --chain --plan "$SCRATCH_DIR/verify-input-r$ROUND.md" \
       --system-file "$SCRATCH_DIR/verify-prompt-r$ROUND.txt" \
       --require-verdicts "$REQUIRE" \
       --append-log "$LOG_FILE" \
       --out "$SCRATCH_DIR/code-review-r$ROUND.txt"
     ```

     `--append-log` is required, not optional: every fallback round is recorded,
     valid or invalid (FALLBACK.md). And the verdict lines must CLOSE the reply —
     the parser checks the last non-blank lines, not the whole text.

     The exposure pass falls back the same way with its own input file (the numbered
     exposed files + deployment config + diff) and `--require-verdicts
     "EXPOSURE:SAFE|UNSAFE"`. Say in the log that it ran on a fallback model — the
     role's model choice was not honoured, and the gate result must say so.

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
- **The exposure pass is not a scope and cannot be deselected.** `EXPOSURE=no` is a
  logged claim that nothing in the diff faces the network; when the classification
  disagrees, the run refuses it. Skipping it for quota is a recorded skip (as for any
  gate), and the gate result then reads "exposed change, exposure not reviewed".
- **The requested scope is carried out in full.** Dropping a dimension, or judging it
  more shallowly than the others, is not a smaller review — it is a different one, and
  saying so afterwards does not repair it. If the work does not fit, do it in blocks; if
  a real limit is hit, name it and ask.
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
- Don't feed the exposure pass the whole change of a large diff, and don't fold it
  into the acceptance session to save a call. It gets the exposed components entire
  and nothing else, in its own session, on its own model — that is what makes it a
  second opinion rather than a longer first one.
