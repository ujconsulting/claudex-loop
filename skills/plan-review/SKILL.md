---
name: plan-review
description: "A standalone adversarial PLAN-review loop where Claude Code (builder) and OpenAI Codex (read-only critic) tag-team an implementation plan before any code is written. Use this when you ALREADY have a plan or a clear idea and just want the cross-model stress-test — no requirements interview first. Claude drafts/loads the plan into PLAN.md, Codex reviews it in a read-only sandbox and returns VERDICT:APPROVED or VERDICT:REVISE, Claude revises and re-submits to the SAME Codex session (context preserved) until APPROVED or a configurable MAX_ROUNDS cap is hit. Human approves the converged plan before code. Use when the user says \"/plan-review\", \"codex review my plan\", \"have Codex review my plan\", \"argue this plan with Codex\", \"adversarial plan review\", \"make Claude and Codex argue/fight over the plan\", or is about to build something high-stakes (auth, schema, concurrency, migrations, payments) and wants a second-model sanity check on the PLAN before implementation. For a guided requirements interview BEFORE the review, use /grill-me-codex instead. NOT for reviewing already-written CODE (that is the Codex plugin's /codex:review) and NOT for trivial changes."
---

# plan-review — Adversarial Plan-Review Loop

Two models, one plan, a bounded argument. **Claude is the builder and orchestrator. Codex is a read-only critic** that can read the repo and the plan but cannot touch a single file. They communicate strictly through `PLAN.md` + a Codex session that persists across rounds. The human enters at exactly two points: kickoff and final sign-off.

This is a **deliberate, high-stakes tool** — reach for it on auth, data models, concurrency, migrations, payments, anything expensive to get wrong. Skip it for obvious/cheap work.

## Actor (resolved, never assumed)

This skill does not decide which model runs it. Before anything else, resolve
`plan-review` and check the gates:

```bash
python scripts/claudex_roles.py --explain
```

Use the actor it prints — the plan under review was written by `roles.plan`. **A non-zero exit means stop:** the role
assignment violates a gate (a maker set to grade its own work, or an adversary
role with an open sandbox), and no run may start on it. Where this document says
"Codex" or "Claude" below, read it as the resolved actor for that role.
Reference: `ROLES.md`.
## Prerequisites (verify once, fast)

- Codex CLI installed **and alive**: `codex --version` must actually PRINT a version
  (need ≥ 0.130; older CLIs error on the config default model). **Empty output with a
  non-zero exit is neither a hang nor an auth failure** — it is a dead binary, and
  retrying it burns the round. Exit 137 (SIGKILL) on macOS means a stale npm-global
  `codex` is shadowing the current CLI, which now ships inside the ChatGPT desktop app:
  `/Applications/ChatGPT.app/Contents/Resources/codex`. Remedy — symlink it into a PATH
  dir ahead of the stale one (`ln -sfn "/Applications/ChatGPT.app/Contents/Resources/codex" ~/.local/bin/codex`),
  then have the *user* run `sudo npm uninstall -g @openai/codex` (it needs their
  password; don't attempt it yourself). ⛔ Never delete `~/.codex/` — `config.toml`,
  `auth.json` and the sessions live there and the bundled binary still uses them.
  (upstream [issue #10](https://github.com/chaseai-yt/claudex-loop/issues/10))
- Codex authenticated: a prior `codex login` (ChatGPT account is fine). If a run returns an auth/model error, surface it to the user — do not silently retry.
- **Start every call from the repo root.** Outside a git repo Codex refuses with
  `Not inside a trusted directory and --skip-git-repo-check was not specified`. The
  guard is intentional — it scopes Codex's writable root to the repo — and ⛔ the flag
  named in that message must never be passed. It is harmless here under `-s read-only`
  but a real regression in `build`, which runs `--yolo`, and an agent that learns to
  reach for it in one skill will reach for it in the other. Greenfield: `git init` first.
- **The model comes from the role config, never from this skill.**
  `python scripts/claudex_roles.py --spec plan-review` prints the actor with its model
  and effort; pass those to the wrapper. This line used to say *"do NOT pin `-m` unless
  the user asks"* while `setup` and `docs/betrieb.md` both recorded the verified
  configuration as a `gpt-5.6-terra`/high pin and warned that `sol` runs into the
  10-minute ceiling on real plans — following the wrong half of that made normal reviews
  time out (audit 2026-08-30). One place decides; this is not it. (Pinning
  `gpt-5.x-codex` variants still fails on ChatGPT-account auth — that is a model-name
  constraint, and it belongs in the role config too.)
- **Echo the resolved model before Round 1** so the user can confirm, together with the
  resolved tunables. If the user objects, stop before burning a round.
- **Sandbox flag differs between the two commands.** `codex exec` accepts `-s read-only`. `codex exec resume` does NOT — it rejects `-s` ("unexpected argument"). On resume, read-only is reachable only via `-c sandbox_mode="read-only"`, because `config.toml` may default `sandbox_mode` to `danger-full-access` (+ `approval_policy="never"`) — which would let Codex WRITE files mid-loop. Verified end-to-end on 2026-06-04. `tools/codex_ro.py` is what makes that safe rather than careful: it emits that key exactly once and refuses any caller `-c` that touches `sandbox_mode`, `approval_policy`, `profile` or `mcp_servers`.

## Tunable variables (read from skill args, else default)

| Var | Default | Meaning |
|-----|---------|---------|
| `MAX_ROUNDS` | `5` | Hard cap on review rounds. The loop ALWAYS terminates at this. |
| `PLAN_FILE` | `PLAN.md` | Where the evolving plan lives (repo root). |
| `LOG_FILE` | `PLAN-REVIEW-LOG.md` | Append-only transcript of the argument (every round's critique + what changed). The artifact. |
| `SCRATCH_DIR` | harness scratchpad, else `<repo>/.claudex-tmp/` | Disposable staging for Codex's `-o` capture and stderr. ⛔ Never `/tmp`. |

If the user invoked the skill with an argument like `rounds=3`, use that for `MAX_ROUNDS`. Echo the resolved values back before starting.

### Where files go

Two kinds of file, and mixing them is how evidence gets lost:

- **Durable, in the repo:** `PLAN_FILE` and `LOG_FILE`. These are the deliverables, and
  they get committed.
- **Disposable, in `SCRATCH_DIR`:** the `-o` capture and the stderr file, named **per
  round** — `codex-verdict-r<n>.txt`, `codex-stderr-r<n>.txt`. One fixed filename reused
  every round means a failed write silently destroys the previous round's critique, and a
  lost critique is indistinguishable from a round that found nothing.

⛔ **Never `/tmp`.** It is world-readable: on a shared machine every plan critique sits
where any other user can read it. On macOS it is additionally a symlink to `/private/tmp`,
and `git rev-parse --show-toplevel` resolves symlinks while transcript paths do not — so
anything staged there breaks later path matching. Resolve `SCRATCH_DIR` in this order: the
harness's session scratchpad if it provides one, otherwise `<repo>/.claudex-tmp/`, created
and added to `.gitignore` in the same step. Quote it in every command — the scratchpad path
usually contains spaces on Windows.

**A round is not complete until its output is copied into `LOG_FILE`.** The scratch file
is a staging buffer, not the record. (upstream [issue #10](https://github.com/chaseai-yt/claudex-loop/issues/10))

## Flow

### Step 0 — Kickoff (human gate #1)

The invocation itself is the kickoff. Confirm scope in one line: what is being planned. If the user gave no task, ask for it (one question). Then proceed — do NOT ask for approval round-by-round; that comes at the end.

### Step 1 — Claude plans

Do real planning: read the relevant code, think through the approach, surface decisions and tradeoffs. Then write the plan to `PLAN_FILE` in this structure:

```markdown
# Plan: <task>
_Round 0 — initial draft by Claude_

## Goal
<one paragraph>

## Approach
<numbered steps, concrete>

## Key decisions & tradeoffs
<the contestable choices — name them explicitly so Codex has something to bite>

## Risks / open questions
<what you're unsure about>

## Out of scope
<bounds>
```

Initialize `LOG_FILE`:
```markdown
# Plan Review Log: <task>
Started <stamp the user's local time if known, else "session start">. MAX_ROUNDS=<n>.
```

Show the user the plan inline and say you're sending it to Codex for adversarial review.

### Step 2 — The loop

Maintain `ROUND` (start 1) and `THREAD_ID` (empty until round 1 returns).

**The review prompt** sent to Codex each round (adjust the task line):

> You are an adversarial reviewer for an implementation plan. Be skeptical and specific — your job is to find what breaks, not to be agreeable. The plan is inlined below in full; review THAT text, and read any repo files you need for context (you are read-only). Identify concrete flaws: security holes, race conditions, missing edge cases, schema conflicts, wrong assumptions, observability gaps, simpler alternatives. For each, give a one-line fix.
>
> The plan's own file list is a starting point, not the review scope. For every shared resource the plan touches — a file it rewrites, a table it writes, a queue, a lock, a cache — enumerate **every** writer of that resource in the repo, then say which ones the plan leaves unfixed. A defect class present in two of three writers is present in the third until you have opened it and shown otherwise. Name the files you did not open, so the gap is recorded rather than assumed empty.
>
> Where a code comment claims a guarantee, check that the code actually provides it. A comment describing the precise race it prevents, above code that does not prevent it, is the most reliable place to find a live bug.
>
> Do NOT modify any files. End your reply with EXACTLY one line: `VERDICT: APPROVED` if the plan is sound enough to implement, or `VERDICT: REVISE` if it still has material problems.
>
> `=== BEGIN PLAN (<PLAN_FILE>, sha256 <hash>) ===` … `=== END PLAN ===`

The scope paragraph is from [upstream PR #12](https://github.com/chaseai-yt/claudex-loop/pull/12) by @Dwodgaming, and it closes an inconsistency in this repo: `audit` has demanded a coverage note ("not examined: …") from the start and calls silence about scope a false completeness claim — while the plan review demanded nothing of the kind. Same doctrine, enforced in one place and not the other. On the run it came from, two of three writers to one file were reviewed and fixed; the third was never opened and held the same defect.

⛔ **Inline the plan; never tell Codex to read `PLAN.md`.** Two separate defects lived in
this one line until 2026-08-30. First, `docs/betrieb.md` records that a fresh plan is
usually still untracked and Codex's file reads come back `rejected: blocked by policy` —
it then reviews the surrounding code and returns a confident verdict on something else.
Second, `PLAN_FILE` is advertised as configurable above while this prompt hard-coded
`PLAN.md`, so a run with a non-default plan got a verdict on a different (possibly
stale) file and the user signed off believing otherwise. Inline the resolved file's
text; use its path only as a label.

**Round 1** (creates the session — capture `thread_id`). Write the prompt, with the plan
inlined, to a scratch file **you** create:

```bash
ROUND=1
# Model and effort come from the role config. Reading them and NOT passing them
# leaves the wrapper on its own defaults, which is the same drift the tunables
# section above warns about. (CodeRabbit, 2026-08-30.)
SPEC=$(python scripts/claudex_roles.py --spec plan-review) || exit 2
MODEL=$(echo "$SPEC" | sed -n 's/.*model=\([^ ]*\).*/\1/p')
EFFORT=$(echo "$SPEC" | sed -n 's/.*effort=\([^ ]*\).*/\1/p')

python tools/codex_ro.py --model "$MODEL" --effort "$EFFORT" \
  --prompt-file "$SCRATCH_DIR/review-prompt-r$ROUND.txt" \
  --out-file "$SCRATCH_DIR/codex-verdict-r$ROUND.txt" \
  --err-file "$SCRATCH_DIR/codex-stderr-r$ROUND.txt"
```

⛔ **Two things this replaced.** `"$(cat REVIEW_PROMPT)"` read a bare relative filename
that no step creates: on a clean repo `cat` fails and Codex is launched with an empty
prompt; on a repo shipping a file by that name, the repository under review writes the
reviewer's instructions. And the raw `codex exec` bypassed the wrapper, against
`docs/betrieb.md`'s own rule — *"Auch Ping und Resume laufen über den Wrapper"* — giving
up the sandbox pin, the path bounds, the stderr file, the timeout and the MCP shutdown
in one go.
Parse `thread_id` from the `{"type":"thread.started","thread_id":"..."}` line → that is `THREAD_ID`. The critique text lands in `$SCRATCH_DIR/codex-verdict-r$ROUND.txt` (Codex's last message). Read that file.

> Note: stderr goes to a **file**, not `/dev/null` — it carries cosmetic MCP/auth noise, but it is also the ONLY place a quota or auth failure shows up. Read it whenever a round looks odd.
>
> ⛔ **An empty verdict file is a FAILURE, not a quiet success.** A 429 or 401 presents as exit 0 + a valid `thread_id` + an empty verdict file (see [FALLBACK.md](../../FALLBACK.md)) — which is precisely why "the file and the thread exist, so carry on" is the wrong test. This skill said to confirm success by the file's *presence* until 2026-08-30, and then waited for TWO empty results before treating it as terminal; the first failed review had no fail-closed path at all. Require a **non-empty reply whose last non-blank line is a valid verdict**. Anything else: read the stderr file, log the round as `## Round <n> — INVALID (no verdict)` with the reply verbatim, and stop to ask the user. One retry is defensible for a first empty file; a second is not.
>
> **Timeout guard:** the wrapper takes `--timeout` (default 600s) and returns 124 when it trips. Via Claude Code's Bash tool also pass `timeout: 600000` on the tool call — the default 2-minute tool timeout is shorter than a real review and would kill it mid-run. A tripped ceiling is a failed run: stop and tell the user rather than retrying blind. The wrapper supplies stdin EOF itself, so the old mandatory `< /dev/null` is no longer yours to remember.

**Rounds 2..MAX** (resume the SAME session — Codex remembers its earlier critiques, won't re-litigate settled points):

```bash
ROUND=$((ROUND + 1))
python tools/codex_ro.py --resume "$THREAD_ID" --model "$MODEL" --effort "$EFFORT" \
  --prompt-file "$SCRATCH_DIR/review-prompt-r$ROUND.txt" \
  --out-file "$SCRATCH_DIR/codex-verdict-r$ROUND.txt" \
  --err-file "$SCRATCH_DIR/codex-stderr-r$ROUND.txt"
```

The re-review prompt inlines the REVISED plan text again (same reason as Round 1) and
asks whether the prior findings are addressed. `resume` rejects `-s`, so read-only is
reachable only through `-c sandbox_mode` — and a later `-c` beats an earlier one, which
is exactly why this goes through the wrapper: it emits that key once and refuses any
caller `-c` touching the sandbox, `profile` or `mcp_servers`.

**Each round, after Codex returns:**
1. Read `$SCRATCH_DIR/codex-verdict-r$ROUND.txt`. Append to `LOG_FILE`: `## Round <n> — Codex` + the full critique.
2. Grep the **last non-blank line** for the verdict token.
   - `VERDICT: APPROVED` → break the loop, go to Step 3 (converged).
   - `VERDICT: REVISE` → Claude reads the critique, decides **what's actually worth acting on** (Claude has final say — Codex advises, it does not command). Revise `PLAN_FILE`. Append to `LOG_FILE`: `### Claude's response` + what you changed and what you rejected and why. Increment `ROUND`.
   - **Neither — missing, malformed, or an empty file → INVALID ROUND.** Log it as such with the reply verbatim, read the stderr file, and stop to tell the user. It does not count towards `MAX_ROUNDS` and it never counts as an approval.
3. If `ROUND > MAX_ROUNDS` → break to Step 3 (deadlock).

**If Codex dies mid-loop (quota, credits, outage):** don't dead-end and don't retry blind — full protocol in [FALLBACK.md](../../FALLBACK.md). Check remaining quota + reset time with `python scripts/codex_usage.py` (reads Codex's local session rollouts, no API call; also run it before round 1). On a confirmed terminal failure (429/"usage limit"/401 in the stderr file, or an empty verdict file on exit 0 twice in a row), halt and let the USER choose: **wait** for the reset (resume the same `$THREAD_ID` — session memory survives), **switch** to a configured fallback reviewer (`python scripts/fallback_review.py --plan "$PLAN_FILE" --log "$LOG_FILE" --round "$ROUND" --append-log "$LOG_FILE" --out "$SCRATCH_DIR/fallback-verdict-r$ROUND.txt"` — any OpenAI-compatible endpoint via `.env` profiles, plan-text only, rubber-stamp-rejecting, plan-hash-bound; it writes the round into `LOG_FILE` itself as `## Round <n> — <model> (via <reviewer>, fallback — plan-text only, no repo access)`, invalid attempts included). **`--append-log` is required** and `--plan` takes the resolved `PLAN_FILE`, not a literal `PLAN.md` — this line had both wrong, so the documented escape hatch would have exited on its own argument check at the one moment it is needed. A remote reviewer also needs `CLAUDEX_EGRESS_ALLOW=<host>`; loopback profiles need nothing. Or **skip** the review with an explicit log entry and take the plan to sign-off marked **not cross-reviewed**. Never automatically, never silently.

### Step 3 — Resolution (human gate #2)

**If APPROVED:** Present to the user — the final `PLAN_FILE`, a 3-bullet summary of what the argument improved, and the round count. Ask: *"Plan survived N rounds of Codex. Implement it now — Codex builds it (`/build`), Claude builds it, or stop here?"* Only on a yes is code written. **No code is written during the loop.** If the user picks Codex, invoke the `build` skill with `SPEC_FILE=PLAN.md` and the same `LOG_FILE` — roles flip (Codex writes, Claude reviews the diff) and the build rounds append to the same log.

**If MAX_ROUNDS hit without APPROVED (deadlock):** Do NOT pretend it converged. Surface the unresolved disagreements explicitly: list each point Codex still flags and Claude's counter-position. Hand it to the human to break the tie. This is a legitimate, useful outcome — a flagged disagreement beats a false "approved."

**Either way, close with the residual risk: which files no round ever opened.** An `APPROVED` verdict covers the surface that was actually read, and rounds tend to keep re-reading the files the plan names. Track the set of files opened across all rounds, diff it against the files touching the same shared state, and report the remainder as **unreviewed** rather than sound. This is the cheapest finding in the loop and the easiest to skip.

## Hard rules

- Codex is read-only EVERY round — `-s read-only` for the first call, `-c sandbox_mode="read-only"` for every resume (resume has no `-s`). It never writes. If you're tempted to give it write access, stop — that's a different skill.
- The loop ALWAYS terminates at `MAX_ROUNDS`. No unbounded recursion.
- **Findings ledger:** every reviewer output — each Codex round, each fallback round (valid or an INVALID attempt, labeled as such), any cold-read — is appended to `LOG_FILE` verbatim when it arrives, followed by Claude's per-finding disposition (accepted → what changed / rejected → why). Nothing about a review lives only in the chat; `scripts/fallback_review.py --append-log <LOG_FILE>` does it mechanically for fallback rounds.
- Claude is the final arbiter on every REVISE — incorporate good critiques, reject bad ones *with a reason logged*. Don't cave to Codex on everything (that defeats the cross-model check) and don't ignore it (that defeats the point).
- Code only after human gate #2.
- `LOG_FILE` is the deliverable — it tells the whole story of the argument. Keep it complete.

## What NOT to do

- Don't use this to review existing code — that's `/codex:review`.
- Don't pin a `-codex` model variant on ChatGPT-account auth — it 400s.
- Don't skip the log — the argument transcript is the most valuable artifact.
- Don't let Codex edit files. Read-only, always.
