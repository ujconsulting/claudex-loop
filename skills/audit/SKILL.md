---
name: audit
description: "First-pass review of a codebase nobody ever reviewed — no diff, no plan, no baseline. Slices the repo into reviewable pieces, runs the deterministic tooling first, then has a fresh read-only session judge each slice on quality, security, docs, tests and conformance to the repo's own documented rules. Produces a prioritised baseline file so every later review only has to look at the delta instead of re-raising the same debt. Use when the user says \"/audit\", \"initial code review\", \"nobody ever reviewed this\", \"audit this repo\", \"wie steht es um die Codequalitaet\", \"Sicherheitsluecken finden\", or when onboarding an inherited codebase. NOT for reviewing a change — that is code-review, which is anchored to a diff and a plan. Every component reachable from outside the machine — ports, proxy hosts, tunnels, webhooks, public DNS — additionally gets its own exposure session on the `exposure-review` role (stronger model, bounded effort, default gpt-6.1-sol/medium, its own role entry) with a per-component verdict `EXPOSURE: SAFE/UNSAFE` recorded in the baseline. NOT a penetration test and NOT a substitute for a real security process on high-stakes code."
---

# Audit — the first pass over code nobody reviewed

`code-review` asks *"does this change do what the plan said?"*. It needs a diff and a
spec. A repo that grew without either has neither, so pointing `code-review` at the root
commit does not work: the diff is the whole codebase, it blows past any context window,
and `dod` has no plan to be complete against.

This skill answers the other question: **what is actually in here, and what should worry
me first?**

Two properties matter more than thoroughness, because they are what makes an audit get
acted on instead of filed:

- **Prioritised.** A first audit on grown code yields hundreds of findings. An
  unsorted list is noise nobody finishes reading. Severity per finding, plus a
  short "these first" list, is the deliverable.
- **A baseline, not a report.** The point is that the *next* review only has to
  look at what changed. Findings that are recorded and consciously accepted stop
  being raised again.

## Actor (resolved, never assumed)

`audit` is a **standalone adversary role**: it judges something nobody in this workflow
produced, so it has no producer to be paired against. Every other adversary rule still
holds — read-only, foreign context, never the orchestrator.

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/claudex_roles.py" --explain
```

Use the actor printed for `audit`. **A non-zero exit means stop.** Where this document
says "the reviewer", read it as that resolved actor. The exposure sessions (Step 3b)
run on `exposure-review` — `python "${CLAUDE_PLUGIN_ROOT}/scripts/claudex_roles.py" --spec exposure-review`
prints its model and effort; pass them to the wrapper, never pick them here.

When an adversary role resolves to `claude`, it runs as the plugin agent `claudex-reader` (`Read`, `Grep`, `Glob` only: no shell, no write, no network, no MCP
connector) — never as a sub-agent with the session's tools. Measured 2026-10-27: a
sub-agent without a tool list reached the session's write-capable claude.ai connectors
through ToolSearch; `claudex-reader` reached none. See `ROLES.md`.

## Tunables (read from skill args, else default)

| Var | Default | Meaning |
|-----|---------|---------|
| `SLICES` | auto | Comma-list of paths to audit. Auto = top-level services/packages/apps discovered in the repo, listed for confirmation before the first call. |
| `DIMENSIONS` | `security,quality,docs,tests,rules` | `rules` = conformance to the repo's OWN documented rules (CLAUDE.md / AGENTS.md / CONTRIBUTING). |
| `BASELINE_FILE` | `docs/audit/<YYYY-MM-DD>-baseline.md` | The deliverable. |
| `LOG_FILE` | `docs/audit/<YYYY-MM-DD>-audit-log.md` | Reviewer output verbatim + dispositions. |
| `SEVERITY_FLOOR` | `low` | Drop findings below this. Raise it on a large legacy repo to keep the first pass finishable. |
| `EXPOSED` | auto | Comma-list of the components that face the network, or `none` as an explicit claim. Auto = mapped in Step 1 from ports, proxy/tunnel config, DNS and the repo's own inventory, listed for confirmation. **Unknown counts as exposed.** |
| `SECURITY_HUNT` | `off` | `quick` \| `standard` \| `deep`: run the attack-class hunt of Step 3c (Cloudflare `security-audit` method). Costly; off unless asked. |
| `SECURITY_HUNT_BUDGET` | _none_ | Agent calls the hunt may spend. **Required** for `standard` and `deep`; the hunt stops at it and reports what was not covered. |

Echo the resolved values and the slice list before the first call.

<!-- claudex-target:begin -->
### Review target (`target=`)

The skill argument `target=<absolute path>` (same `key=value` grammar as
`scope=` / `SPEC_FILE=`) names the directory under review. If it is missing,
ASK the human for it. ⛔ Never derive it from `$PWD`, `$(pwd)`, `.`, the
harness's working directory, or the output of any command — a value the
session derives from itself confirms itself, which is the incident this
exists for.

Precondition: the session must have been STARTED in exactly this directory.
A `cd` does not persist between tool calls, and a `cd … &&` in front of the
wrapper call is denied by the guard — reviewing some other repo from here is
not supported; start a session there instead.

Show the value to the human BEFORE the first wrapper call:

```bash
# TARGET is the literal value of the skill argument target= -- substituted by whoever
# runs this block. Copied unchanged it fails closed: the wrapper refuses a non-absolute value.
TARGET='<target= argument>'
echo "Review scope: $TARGET"
```

The wrapper refuses with exit 2 when `$TARGET` is not the working directory —
that is a STOP: tell the human, do not retry with a different value. A
different exit 2, `unrecognized arguments: --expect-workdir`, is not a scope
mismatch — this repo's `tools/codex_ro.py` predates 2.5.0 and does not know
the flag yet. Update it from the plugin
(`python <plugin>/scripts/wrapper_drift.py --repo . --update --private-root <your projects folder>`, see `setup`)
and rerun. ⛔ Never drop the flag to make the error go away.
<!-- claudex-target:end -->

## Flow

### Step 1 — Slice the repo, and say what you are NOT auditing

Discover the natural units: services, packages, apps, deployment config. Present the
slice list **and the excluded remainder** before starting. Vendored code, generated
files, fixtures and migrations are usually excluded — that is fine, but it is only fine
if it is written down.

⛔ **Coverage is a first-class output.** An audit that does not state its own limits
reads as completeness it does not have. Every later claim about "the repo" is bounded by
this list.

Refuse to run on an unbounded target with no slices — the same reason `docs-backfill`
demands a target: one oversized pass produces a report nobody can act on, and a wrong
judgement propagates through all of it.

**Map the exposed surface while slicing.** For every slice answer: can bytes reach it
from outside this machine? Evidence, not memory: `ports:` in every compose file and
whether the bind is loopback or all interfaces, `EXPOSE` in Dockerfiles, reverse-proxy
and tunnel configs (Caddy, nginx, Traefik, NPM, cloudflared), webhook receivers, public
DNS names in config or docs, and the repo's own inventory (`## Exposed surface` in
`AGENTS.md`/`CLAUDE.md`, `docs/exposure.md`) when one exists. Present the list as its own
table — component, how it is reached, whether it has a login — and get it confirmed
with the slices. A component whose reachability nobody can state is **exposed until
proven otherwise**; the audit that assumes "internal" is the one that misses the
dashboard that was on all interfaces the whole time.

### Step 2 — Machines first, model second

Before spending any reviewer budget on judgement, run what tooling does better and
cheaper, and put the *results* into the reviewer's prompt:

- **Whatever the repo already has.** Most repos have a validation entry point (a
  `validate` command, a Makefile target, a CI workflow). Use it instead of
  re-inventing the toolchain — and say in the log which one you used.
- **The standing four**, language-independent and worth running on almost any repo.
  Probe first — `command -v <tool>` — and name in the log which ones were absent;
  a tool that never ran is not a clean result:

  | Tool | Run it when | Command |
  |---|---|---|
  | **gitleaks** | always — history included | `gitleaks dir . --no-banner --redact -f json -r <SCRATCH>/gitleaks.json` · add `gitleaks git .` for the history |
  | **grype** | a dependency manifest or an image exists | `grype dir:. -o table` (`-o json` to file; `--fail-on high` if you want a gate) |
  | **hadolint** | a `Dockerfile` exists | `hadolint <Dockerfile>` |
  | **actionlint** | `.github/workflows/` exists | `actionlint` (it discovers the workflows itself) |

  ⛔ **`--redact` on gitleaks is not optional.** Its findings go into the reviewer's
  prompt, and the reviewer is a remote model. Without redaction an audit *transmits*
  every secret it discovers — turning a scan into the leak it was looking for.

- Language layers on top, when they exist: linters (ruff/eslint/golangci-lint),
  dependency audits (pip-audit, npm audit, OSV), further secret scanning (TruffleHog),
  IaC checks (Checkov), docstring and test coverage (`interrogate`, coverage report).

Verified 2026-08-28 against gitleaks 8.30.1, grype 0.118.0, hadolint 2.15.1,
actionlint 1.7.12 — flags differ across major versions, so check `--help` if a call is
rejected rather than dropping the tool.

This is not busywork: it takes the mechanical findings off the reviewer's plate so its
attention goes where only a model helps — missing authorisation, silently swallowed
errors, assumptions that stopped being true, design that fights the framework.

**Tool output is evidence, not verdict.** A clean scanner run does not mean a clean
slice, and a noisy one does not mean a bad slice. Say which tools ran and which did not
exist.

### Step 3 — Judge each slice (fresh read-only session per slice)

One session per slice, the slice's code and the Step-2 tool output inlined.

**Number every inlined source line** — prefix each with its own number in the form
`  1234| <code>`. Without them the reviewer has to *count* lines in order to cite one,
and no model counts reliably across thousands of lines. In the first real run of this
skill the citations in two slices were off by dozens of lines throughout, landing on
blank lines and unrelated statements. The findings themselves were sound; only the
addresses were wrong — which made every one of them cost a manual search to place, and
turned "verify before it becomes a ticket" from a quick check into an investigation.
Numbering the input costs a few percent more tokens and removes the entire class of
error.

> You are auditing an existing codebase that has never been reviewed. There is no plan
> and no diff — judge the code as it stands. Findings must be numbered, anchored to
> file:line, each stating what concretely goes wrong and one line on the fix, and each
> carrying a severity: CRITICAL (exploitable, or data loss), HIGH (breaks under
> foreseeable conditions), MEDIUM (will hurt in maintenance), LOW (worth knowing).
> Every inlined source line carries its own number in the form `  1234| code`. **Cite
> those numbers verbatim — never count or estimate one yourself.** A citation that does
> not match the numbered line it names is worse than none: it sends the reader to the
> wrong place and costs more time than it saves.
> Tool output for this slice is inlined — do not repeat what it already found; go where
> it cannot.
> {security:} Section SECURITY — every route, page and endpoint: does it require
> authentication, and is authorisation checked per object (a dashboard, API, health or
> debug endpoint without login is a finding, never a note); default credentials and
> open signup; secrets in code, config defaults, logs, responses or URLs; injection
> (SQL, shell, template), path traversal, SSRF, unsafe deserialisation at every trust
> boundary; webhook and callback signatures verified fail-closed; bind addresses and
> `ports:` (loopback vs all interfaces); trusted-header or IP-based identity shortcuts
> and whether they can be switched off; dependency risk from the inlined scanner
> output. Say what you examined and what you found — a section that names no route it
> checked has not checked any.
> {quality:} Section QUALITY — error handling that hides failure, duplicated logic that
> has already drifted, dead code, functions doing too much, magic values, concurrency
> and resource-lifetime mistakes.
> {docs:} Section DOCS — undocumented public units, and worse: documentation and
> comments that contradict the code. State which is wrong, the code or the text.
> {tests:} Section TESTS — untested error paths and edge cases, assertions that cannot
> fail, tests coupled to implementation detail, and behaviour that has no test at all.
> {rules:} Section RULES — the repo's own documented rules are inlined below. Where does
> the code violate them? Quote the rule verbatim with each finding.
> End with a coverage note ("not examined: …") and then exactly one line:
> `AUDIT: CLEAN`, `AUDIT: CONCERNS` or `AUDIT: CRITICAL`.

Mechanics are `code-review`'s: read-only, prompt via **stdin**, output to a file,
stderr to a **file**, Windows path conversion, generous timeout. Preflight the quota —
an audit is many sessions, so check the remaining budget against the slice count
*before* starting and tell the user if it will not fit in one window.

**`AUDIT: CLEAN` on a non-trivial slice with zero findings is an invalid review**, not a
pass. Rerun it or record it as invalid; grown code that nobody reviewed does not come
back clean.

### Step 3b — Exposure session per exposed component (`exposure-review` role)

For every component in the Step-1 exposure table, one **additional** fresh session on
the `exposure-review` role — after the slice review, on its own model and effort. The
slice review asks "what is wrong in here?"; this one asks the attacker's question:
*standing outside the machine, what can I reach, forge, inject, exhaust or read?*

Input, all numbered: the component's entry points **entire** — routes, handlers,
middleware, auth, session and webhook code — plus every file that publishes it
(compose, Dockerfile, proxy/tunnel config, `.env.example`) and the Step-2 scanner
output for it. Nothing else inlined; the rest is context by path. The bounded input is
what lets a stronger model run at medium effort inside the ceiling.

> You are the exposure reviewer. The component below faces the network: someone
> outside this machine can send it bytes. You are read-only. Judge ONLY the inlined
> component and its deployment config — not code quality, not the rest of the repo.
> Findings numbered, anchored to file:line citing the inlined numbers verbatim, each
> with the concrete attack and a one-line fix, severity CRITICAL/HIGH/MEDIUM/LOW.
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

```bash
python tools/codex_ro.py --expect-workdir "$TARGET" --model "$EXPOSURE_MODEL" --effort "$EXPOSURE_EFFORT" \
  --prompt-file "$SCRATCH/exposure-<component>.txt" --out-file "$SCRATCH/exposure-<component>-verdict.txt" \
  --err-file "$SCRATCH/exposure-<component>-stderr.txt"
```

`EXPOSURE_MODEL`/`EXPOSURE_EFFORT` come from `claudex_roles.py --spec exposure-review`.
Log each as `## Exposure — <component> — <model>/<effort>` + report verbatim.
`EXPOSURE: SAFE` with zero findings and an empty `Checked:` line is invalid. A
CRITICAL here — an unauthenticated reachable route, a forgeable identity header, a
secret in a response — goes to the user **immediately**, before the rest of the audit
continues; that is the one exception to "the audit does not fix anything".

### Step 3c — Security hunt (`SECURITY_HUNT`, off by default)

An attack-class hunt after the Cloudflare `security-audit` method, on a **frozen,
redacted snapshot**, with every finding verified cold by the other model. Plan:
`docs/plans/2026-10-27-sicherheitskette/PLAN.md` (approved in review round 7). Only when
`SECURITY_HUNT` is not `off`; `standard`/`deep` need `SECURITY_HUNT_BUDGET`.

Roles: the hunt is the producer role `hunt` (always `claude`), the verifier the paired
adversary `security-verify`. A config without the pair refuses here and the step is
skipped with that reason — `--spec` exits 2:

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/claudex_roles.py" --spec hunt || exit 2
VERIFY_SPEC=$(python "${CLAUDE_PLUGIN_ROOT}/scripts/claudex_roles.py" --spec security-verify) || exit 2
VERIFY_MODEL=$(echo "$VERIFY_SPEC" | sed -n 's/.*model=\([^ ]*\).*/\1/p')
VERIFY_EFFORT=$(echo "$VERIFY_SPEC" | sed -n 's/.*effort=\([^ ]*\).*/\1/p')
```

**1. Prepare** — one exclusive run directory, the verified copy of the pinned skill, the
frozen snapshot (regular text files only, links/junctions/FIFOs/binary/oversized refused,
read by a supervised worker with a hard deadline), redacted before any model sees it, and
the durable ledger under `docs/audit/`. Taboo-scope paths from `AGENTS.md` go in as
`--exclude` globs. A non-zero exit means stop: nothing is half-prepared. The output's
`coverage.status` says what an earlier run is worth: `current` (the original bytes are
unchanged — its units may be skipped), `historical` (something changed — a hint for
ordering, never coverage; hunt every unit again) or `none`.

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/hunt_run.py" prepare --repo "$TARGET" --scratch "$SCRATCH_DIR" \
  --exclude "<taboo glob>"
```

Read `run_dir` and `coverage` from the JSON it prints. ⛔ No shell redirect (`>`) into the
scratch or run directory anywhere in this step: a redirect follows a planted link and
truncates its target before any check runs. Two kinds of file, two rules:

- **What the hunt produces** — snapshot, manifests, bundles, prompts, dispatches, ledger,
  report, coverage descriptor — is created by `hunt_run.py` itself, exclusively, through
  `hunt_io`.
- **What you hand it** — agent answers, candidate records, coverage list, findings — you
  write with the Write tool into the directories `prepare` created: `<run-dir>/work/`
  (answers, `coverage.json`, `findings.json`) and `<run-dir>/records/`; the verifier's
  answers come from the wrapper's own checked `--out-file` into `<run-dir>/answers/`.
  `hunt_run.py` reads every such file only through `hunt_io` below the run directory, so a
  link, a junction or a FIFO planted there refuses at read time instead of being followed.

**2. Hunt** — follow the method of the pinned skill, and read its text **only** through
`skill-file`: every call re-verifies the run's copy against the pinned manifest and prints
exactly the verified bytes (start with `skills/security-audit/SKILL.md`). Phases 1–4 of that
method, with these changes:

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/hunt_run.py" skill-file --run "$RUN_DIR" --path skills/security-audit/SKILL.md
```

- every hunter, critic and candidate checker is a **`claudex-loop:claudex-hunter`** agent —
  no tools at all. Each agent's input is the output of `bundle` and nothing else: the
  unit's snapshot files, each re-checked against the manifest, numbered (`   12| …`),
  refused above a fixed size — split the unit then. Never hand-built from `input/`, never
  from the live repository, never with a file path the agent could open.

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/hunt_run.py" bundle --run "$RUN_DIR" --path app/db.py --path app/search.py \
  --out-name "$UNIT.bundle.txt"
```

It prints the path of the new file below `<run-dir>/work/`; an existing name, a link or a
name that is not a plain `[A-Za-z0-9._-]` file name refuses. `$UNIT` is a plain identifier
of your choosing (letters, digits, `.`, `_`, `-`), never a path.
- **log every agent answer at once**, before you summarize it: write it to a file in the
  run directory and append it (`log-agent`, role `recon|hunter|critic|checker`) — verbatim,
  redacted, in the ledger. A step that fails to log stops the hunt.
- target code is **not executed**. What would need execution stays `needs_validation`.
  `[REDACTED:<rule>]` is removed secret material; a conclusion resting on it stays
  unconfirmed.

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/hunt_run.py" log-agent --run "$RUN_DIR" --role hunter --unit "$UNIT" \
  --response "$RUN_DIR/work/$UNIT.answer.txt"
```

Write each candidate as a record `{id, title, claim, attack, hunt_status, ranges:[{path,
from_line, to_line}]}` to `<run-dir>/records/<id>.json` — `hunt_status` is the hunt's own
`confirmed` or `needs_validation`; `ranges` name the excerpts the verifier will see (paths
must be snapshot members). The hunt's severity and reasoning stay in your notes; they never
go to the verifier.

**3. Verify every `confirmed` and `needs_validation` record** — replaces Cloudflare's
Phase 5 by the other model. `request` writes the cold prompt and its **dispatch** (what was
actually sent, ranges clipped to the file) and refuses if the prompt still holds a secret;
the wrapper runs as for every review (`--expect-workdir "$TARGET"`); `judge` parses the one
JSON answer against the stored dispatch — not against the record, which may have changed —
and appends it to the ledger at once. Anything malformed, with duplicate keys, mis-bound,
outside the sent lines, timed out or blind (exit 3) is `UNRESOLVED`. If the ledger line
cannot be redacted, `judge` fails and records nothing: stop.

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/hunt_run.py" request --run "$RUN_DIR" --record "$RUN_DIR/records/$ID.json"
python tools/codex_ro.py --expect-workdir "$TARGET" --model "$VERIFY_MODEL" --effort "$VERIFY_EFFORT" \
  --prompt-file "$RUN_DIR/requests/$ID.txt" --out-file "$RUN_DIR/answers/$ID.txt" \
  --err-file "$RUN_DIR/answers/$ID.stderr.txt"
python "${CLAUDE_PLUGIN_ROOT}/scripts/hunt_run.py" judge --run "$RUN_DIR" --record-id "$ID" \
  --answer "$RUN_DIR/answers/$ID.txt" --exit-code "$WRAPPER_EXIT"
```

`$WRAPPER_EXIT` is the exit status the wrapper call **itself** returned, as the tool reports
it for that one call — the wrapper call stays a single command (the guard refuses anything
chained to it), so read the status there and substitute it literally. Never a value from an
earlier record, never a default: without the status of this record's wrapper call, do not
call `judge` — the record stays `UNRESOLVED`. 124 (timeout) and 3 (blind run) are statuses
like any other and `judge` turns them into `UNRESOLVED`.

⛔ **What the redaction does and does not do.** It covers everything *we send* the
verifier. The read-only verifier can still read the repository itself, as in every Codex
review — the working directory is not a read boundary. A real one comes with the
container plan (`PLAN-B-container.md`), not before; do not claim otherwise in the baseline.

**4. Publish** — the report and the ledger stay in `docs/audit/` under the run's own names;
the coverage list and the private original-content manifest go to
`~/.claudex/hunt-coverage/`, bound by a completion descriptor written last. A later run
treats coverage as current only if that descriptor validates and the original manifest is
unchanged; otherwise it is historical and every unit is hunted again.

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/hunt_run.py" publish --run "$RUN_DIR" \
  --coverage "$RUN_DIR/work/coverage.json" --findings "$RUN_DIR/work/findings.json"
```

Baseline status per record: hunt `confirmed` + `VERIFIED` → finding with severity; hunt
`needs_validation` + `VERIFIED` → stays `needs_validation` (a blocker is not lifted by
agreement); `REFUTED` → **disputed**, put to the user with both positions; everything else →
open question without severity; a `VERIFIED` record whose evidence lies on a redacted line →
`needs_validation`. The hunt never writes `LOG_FILE` or `BASELINE_FILE` itself — its
verbatim record is the ledger; Step 5 links to it.

### Step 4 — Triage (the part that decides whether this was worth doing)

Append each reviewer report **verbatim** to `LOG_FILE` as it arrives, then triage every
finding into exactly one of:

- **Fix now** — real, and cheap enough that deferring it is worse.
- **Accepted risk** — real, but consciously not fixed. **Requires a reason and a named
  condition that would change the decision.** "Accepted" without either is just
  forgetting with extra steps.
- **Rejected** — not actually a problem here. Say why, at the repo, not in the abstract.

Verify before accepting a finding. A reviewer reading code cold gets things wrong about
intent and about what the framework already guarantees; check the claim in the code
before it becomes a task.

### Step 5 — The baseline

Write `BASELINE_FILE`:

1. **Fix these first** — at most five, chosen by severity times likelihood, each with
   what breaks if it is not fixed.
2. **Full findings** by slice and severity, with the triage decision on each.
3. **Accepted risks** with reasons and revisit conditions.
4. **Exposed surface** — the Step-1 table with one `EXPOSURE:` verdict per component
   and its open findings. A component listed without a verdict is marked **not
   reviewed**, never omitted. This section is what a later `code-review` reads to
   decide whether a change touches something that faces the network.
5. **Coverage** — slices audited, slices excluded, dimensions run, tools that ran and
   tools that were missing.
6. **Tool versions and date.** A baseline without them cannot be compared to the next one.
7. **Security hunt** (only if Step 3c ran) — link to its report and ledger, the counts per
   baseline status, the pinned skill commit, and the run's `manifest_id`. The ledger is the
   hunt's verbatim reviewer record; it is not copied into `LOG_FILE`.

Then tell the user the numbers plainly: findings by severity, how many were rejected and
why, and what was not looked at.

### Step 6 — Hand off to `code-review`

From here the repo has a reference point. Later runs of `code-review` take
`BASELINE_FILE` and treat everything in it as **pre-existing**: not the change's fault,
raised again only when the change makes it worse or touches that code. That is what
stops every future review from re-litigating the same debt — and it only works if the
baseline is committed.

## The scope is the scope

An audit is commissioned with a scope — these slices, these dimensions, every finding
verified. **Carrying it out at reduced depth is not a smaller version of the job, it is
a different one.** Declaring the reduction openly does not repair it: the person who may
shrink a scope is the one who set it.

If the work does not fit one sitting, do it in blocks and continue. If a real limit is
reached — quota exhausted, access missing, a decision pending — say so and ask. That is
not the same as quietly lowering the bar, and the difference matters most in exactly the
place an audit is used: reporting that 122 findings were reviewed when 48 were.

## Hard rules

- **Coverage is stated, always.** Slices audited and slices skipped, in the baseline and
  in the summary. Silence about scope is a false claim of completeness.
- **Severity on every finding**, or it cannot be prioritised and will not be acted on.
- **Accepted risk needs a reason and a revisit condition.**
- **Findings are verified against the code before they become tasks** — a cold reader
  mistakes intent regularly.
- **The audit does not fix anything.** It produces a baseline; fixes are their own work
  with their own review. The one exception is a CRITICAL finding that is actively
  exploitable — surface that to the user immediately, do not wait for the report.
- Fresh session per slice; read-only every call. One more per exposed component, on
  the `exposure-review` role — an exposed component without an `EXPOSURE:` verdict has
  not been audited, whatever its slice verdict says.
- Every reviewer output lands in `LOG_FILE` verbatim, including invalid ones, marked as
  such.

## What NOT to do

- Don't run it on a change — that is `code-review`, which knows the plan and the diff.
- Don't audit the whole repo in one session to save time. The context truncates
  silently, and you get a confident judgement of the first fraction.
- Don't let a clean scanner run stand in for the review; the tools and the reviewer
  answer different questions.
- Don't present this as a security assessment. It is one adversarial pass over code,
  useful and cheap — not a pentest, not a compliance audit.
- Don't let the baseline rot. It is a snapshot with a date on it; a year later it
  describes a repo that no longer exists.
