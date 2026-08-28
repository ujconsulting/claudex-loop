---
name: audit
description: "First-pass review of a codebase nobody ever reviewed — no diff, no plan, no baseline. Slices the repo into reviewable pieces, runs the deterministic tooling first, then has a fresh read-only session judge each slice on quality, security, docs, tests and conformance to the repo's own documented rules. Produces a prioritised baseline file so every later review only has to look at the delta instead of re-raising the same debt. Use when the user says \"/audit\", \"initial code review\", \"nobody ever reviewed this\", \"audit this repo\", \"wie steht es um die Codequalitaet\", \"Sicherheitsluecken finden\", or when onboarding an inherited codebase. NOT for reviewing a change — that is code-review, which is anchored to a diff and a plan. Every component reachable from outside the machine — ports, proxy hosts, tunnels, webhooks, public DNS — additionally gets its own exposure session on the `exposure-review` role (stronger model, bounded effort, default gpt-5.6-sol/medium) with a per-component verdict `EXPOSURE: SAFE/UNSAFE` recorded in the baseline. NOT a penetration test and NOT a substitute for a real security process on high-stakes code."
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
python scripts/claudex_roles.py --explain
```

Use the actor printed for `audit`. **A non-zero exit means stop.** Where this document
says "the reviewer", read it as that resolved actor. The exposure sessions (Step 3b)
run on `exposure-review` — `python scripts/claudex_roles.py --spec exposure-review`
prints its model and effort; pass them to the wrapper, never pick them here.

## Tunables (read from skill args, else default)

| Var | Default | Meaning |
|-----|---------|---------|
| `SLICES` | auto | Comma-list of paths to audit. Auto = top-level services/packages/apps discovered in the repo, listed for confirmation before the first call. |
| `DIMENSIONS` | `security,quality,docs,tests,rules` | `rules` = conformance to the repo's OWN documented rules (CLAUDE.md / AGENTS.md / CONTRIBUTING). |
| `BASELINE_FILE` | `docs/audit/<YYYY-MM-DD>-baseline.md` | The deliverable. |
| `LOG_FILE` | `docs/audit/<YYYY-MM-DD>-audit-log.md` | Reviewer output verbatim + dispositions. |
| `SEVERITY_FLOOR` | `low` | Drop findings below this. Raise it on a large legacy repo to keep the first pass finishable. |
| `EXPOSED` | auto | Comma-list of the components that face the network, or `none` as an explicit claim. Auto = mapped in Step 1 from ports, proxy/tunnel config, DNS and the repo's own inventory, listed for confirmation. **Unknown counts as exposed.** |

Echo the resolved values and the slice list before the first call.

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
python tools/codex_ro.py --model "$EXPOSURE_MODEL" --effort "$EXPOSURE_EFFORT" \
  --prompt-file "$SCRATCH/exposure-<component>.txt" --out-file "$SCRATCH/exposure-<component>-verdict.txt" \
  --err-file "$SCRATCH/exposure-<component>-stderr.txt"
```

`EXPOSURE_MODEL`/`EXPOSURE_EFFORT` come from `claudex_roles.py --spec exposure-review`.
Log each as `## Exposure — <component> — <model>/<effort>` + report verbatim.
`EXPOSURE: SAFE` with zero findings and an empty `Checked:` line is invalid. A
CRITICAL here — an unauthenticated reachable route, a forgeable identity header, a
secret in a response — goes to the user **immediately**, before the rest of the audit
continues; that is the one exception to "the audit does not fix anything".

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
