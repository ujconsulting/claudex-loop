---
name: build
description: "Hand a frozen spec (PLAN.md or any locked plan) to OpenAI Codex to IMPLEMENT with full write access, while Claude stays the spec-writer and reviewer — the exact role-flip of /plan-review. Codex builds from the spec in a --yolo sandbox, Claude reads the full diff like a contributor PR, runs the proof test, and iterates fixes via the SAME Codex session up to MAX_FIX_ROUNDS before taking over. Human approves the diff before any commit. Use when the user says \"/build\", \"have codex build this\", \"codex implement the plan\", \"hand the plan to codex\", \"delegate the build to codex\", or right after a plan survives /grill-me-codex, /grill-with-docs-codex, or /plan-review and they choose Codex for implementation (Act 3). Also for standalone delegation: refactors, mechanical migrations, bug fixes with a known repro, test/coverage writing — anything that reads as a work order. NOT for tiny edits (~<20 lines — delegation overhead loses), NOT for design work (if writing the spec forces decisions, that's /grill-me-codex first), NOT for reviewing existing code (/codex:review), and NOT for anything needing Claude-session tools (MCP, secrets, browser)."
---

# Codex-Build — Codex Types, Claude Verifies

The role-flip of `/plan-review`: there, Claude builds the plan and Codex critiques read-only. Here, **Codex is the builder with write access; Claude is the spec-writer and reviewer.** Codex implements a frozen spec end-to-end; Claude judges the diff like a contributor PR, demands proof, and iterates fixes in the same Codex session. The human enters at exactly two points: kickoff and diff sign-off.

Adapted from Peter Steinberger's `codex-first` pattern (agent-scripts), rebuilt on this house's verified Codex mechanics.

**Spec quality decides success.** Codex starts with zero session context — everything it needs must be in the prompt. A plan that survived `/grill-me-codex` or `/plan-review` already is a frozen spec; that's the ideal input.

## Actor (resolved, never assumed)

This skill does not decide which model runs it. Before anything else, resolve
`build` and check the gates:

```bash
python scripts/claudex_roles.py --explain
```

Use the actor it prints — the plan being implemented was written by `roles.plan`. **A non-zero exit means stop:** the role
assignment violates a gate (a maker set to grade its own work, or an adversary
role with an open sandbox), and no run may start on it. Where this document says
"Codex" or "Claude" below, read it as the resolved actor for that role.
Reference: `ROLES.md`.
## Prerequisites (verify once, fast)

- `codex --version` must actually PRINT a version, ≥ 0.130 (older CLIs error on the
  config default model). **Empty output with a non-zero exit is neither a hang nor an
  auth failure** — it is a dead binary; do not retry it. Exit 137 (SIGKILL) on macOS
  means a stale npm-global `codex` shadows the current CLI, which now ships inside the
  ChatGPT desktop app at `/Applications/ChatGPT.app/Contents/Resources/codex`. Symlink
  that into a PATH dir ahead of the stale one, then have the *user* run
  `sudo npm uninstall -g @openai/codex` (needs their password). ⛔ Never delete
  `~/.codex/`. (upstream [issue #10](https://github.com/chaseai-yt/claudex-loop/issues/10))
- Codex authenticated (prior `codex login`; ChatGPT account is fine). On auth/model error, surface it — don't silently retry.
- Do NOT pin `-m` or model config (e.g. `model_reasoning_effort`) unless the user asks. Pinning `gpt-5.x-codex` variants 400s on ChatGPT-account auth; config defaults come from `~/.codex/config.toml`.
- **Echo the active model at kickoff** so the user can confirm: read the `model` line from `~/.codex/config.toml` (absent = "CLI default"); state it with the resolved tunables. If the user objects, stop before launching the build.
- **Codex has a native image-generation tool** in `codex exec` sessions (ChatGPT-account backed, no API key; verified 2026-07-08 — it saved a generated PNG to disk headless). Specs may therefore include "generate these image assets yourself" steps: name exact file paths, dimensions, and style in the prompt contract.
- Run from the target repo's root (both `exec` and `resume` then need no `-C`; `resume` doesn't support `-C` anyway).
- **The repo root is not a convenience, it is the sandbox boundary.** Outside a git
  repo Codex refuses: `Not inside a trusted directory and --skip-git-repo-check was
  not specified`. That guard is what scopes Codex's writable root to the repo. ⛔
  **Never pass `--skip-git-repo-check`** — under `-s read-only` it is merely pointless,
  but this skill runs `--yolo`, where removing the boundary means Codex may write
  anywhere. Genuine greenfield: `git init` first, then start.

## Tunables (read from args, else default)

| Var | Default | Meaning |
|-----|---------|---------|
| `SPEC_FILE` | `PLAN.md` | The frozen spec Codex implements. |
| `MAX_FIX_ROUNDS` | `2` | Fix iterations via resume before Claude takes over and finishes directly. |
| `LOG_FILE` | `PLAN-REVIEW-LOG.md` | Append-only build transcript. If it exists (Act 1/2 ran), append `## Act 3 — Build`; else create it. |
| `PROOF_CMD` | from spec | Exact test/verify command Codex must run as proof. If the spec lacks one, ask the user ONE question to get it before launching. |
| `SCRATCH_DIR` | harness scratchpad, else `<repo>/.claudex-tmp/` | Disposable staging for the prompt contract, the `-o` capture and stderr. ⛔ Never `/tmp`. |

Echo resolved values before starting.

### Where files go

`ROUND` is `0` for the initial build and `1..MAX_FIX_ROUNDS` for the fix rounds.

- **Durable, in the repo:** `SPEC_FILE` and `LOG_FILE` — committed.
- **Disposable, in `SCRATCH_DIR`:** the prompt contract, Codex's report
  (`codex-build-r<n>.txt`) and stderr (`codex-stderr-r<n>.txt`), named **per round**. One
  fixed name means fix round 2 overwrites the report that documented what round 1 changed
   — and in this skill that report is the only prose record of a `--yolo` session.

⛔ **Never `/tmp`.** World-readable, and on macOS a symlink to `/private/tmp`, which breaks
path matching against `git rev-parse --show-toplevel`. Prefer the harness scratchpad;
otherwise `<repo>/.claudex-tmp/`, gitignored in the same step. Quote the path.

⛔ **That applies to the `mktemp` in Step 1 too.** This note used to claim bare `mktemp`
"lands in the OS temp dir, not in `/tmp` literally" — which is true on Windows and false
on Linux and macOS, where `TMPDIR` is usually unset and `mktemp` puts the file in `/tmp`
exactly. The prompt carries the whole spec, and on a shared host `/tmp` is world-readable
(audit 2026-08-30). Give it a template under your own directory:

```bash
P=$(mktemp "$SCRATCH_DIR/build-prompt.XXXXXX")
```

The report and stderr belong in `SCRATCH_DIR` for the different reason that you still
need to find them after the run.
(upstream [issue #10](https://github.com/chaseai-yt/claudex-loop/issues/10))

## Step 0 — Gates (before any Codex launch)

1. **Spec gate.** `SPEC_FILE` must exist and read as a work order (goal, concrete steps, bounds). No spec → offer `/grill-me-codex` (interview first) or `/plan-review` (have a plan, want it stress-tested) instead. If the user insists on building from a rough idea, write the spec WITH them first — that's design, and design stays with Claude.
2. **Clean-tree gate.** `git status -sb`. Codex writes with full access, so the build must start from a tree where **its diff is the only diff** — otherwise you cannot isolate what it did or revert it cleanly. That requirement is non-negotiable; how you satisfy it depends on whose the dirt is.
   - **The user's own uncommitted work** → STOP and ask them to commit or stash.
   - **Another session's live work** — a parallel agent, a long-running task, anything you did not put there → do **not** stash it; that takes work out from under a running session. Build in a detached worktree instead, which satisfies the gate properly:

     ```bash
     git worktree add --detach "$SCRATCH_DIR/build" HEAD
     # An untracked SPEC_FILE does not exist in a fresh worktree — copy it in.
     cp "$SPEC_FILE" "$SCRATCH_DIR/build/" 2>/dev/null || true
     ```

     Remove it with `git worktree remove` once the diff is merged or abandoned.
   - Either way, **say which you chose and why before launching.** Never launch into a dirty tree on the reasoning that the subtree you care about happens to be clean.
3. **Path-scope gate** — it only bites in a worktree, and it bites silently. If `SPEC_FILE` cites findings by absolute path (`D:\...\repo\src\foo.py:210`, `/Users/.../repo/src/foo.py:210`), those resolve to the **original** checkout, and a `--yolo` Codex will happily edit it — undoing the isolation you just set up. Grep the spec for absolute paths; if there are any, the prompt contract must say: resolve every such path relative to your own repo root, and never write outside the current working directory. **State the forbidden prefixes literally.**
4. Confirm scope in one line, then go. No round-by-round approvals; the human gate is at the end.

> Gates 2 and 3 come from [upstream PR #12](https://github.com/chaseai-yt/claudex-loop/pull/12) by @Dwodgaming, written up from a real run. Gate 3 is the one this repo's own audit should have caught and did not: the build step is the only place in the plugin with write access, so a spec that walks a `--yolo` session out of its worktree belongs in the same class as "the caller can widen its own confinement" (baseline A2).

## Step 1 — The build prompt (contract, via temp file)

Never inline-quote the prompt — write it to a temp file. Fill this contract completely; when chained from a grill/review skill, derive it from the plan's sections:

```bash
# ROUND is the build round: 0 for the first build, incremented per fix round.
# Initialise it HERE. Every report path below carries it, and without an explicit
# start the fix round reuses `r0` and overwrites the initial build report -- the
# only prose record of a `--yolo` session (audit 2026-08-30).
ROUND=0
P=$(mktemp "$SCRATCH_DIR/build-prompt.XXXXXX")
cat >"$P" <<'EOF'
GOAL: <one paragraph — what done looks like>
SPEC: Read <SPEC_FILE> at the repo root. It is a frozen, already-reviewed spec.
  Implement it exactly. If a step is impossible as written, implement the
  closest faithful version and report the deviation — do not redesign.
KEY PATHS: <files/dirs Codex will touch or must read first>
CONSTRAINTS: <"don't touch X", style rules, deps that must not change>
NON-GOALS: <explicitly out of scope — from the plan's Out of scope section>
PROOF: Run `<PROOF_CMD>` and include its full output in your report.
OUTPUT: End with a report — files changed (one line each: path + what/why),
  proof output, and any deviations from the spec with reasons.
EOF
```

## Step 2 — Launch Codex (fresh session, capture `thread_id`)

```bash
codex exec --yolo --json -o "$SCRATCH_DIR/codex-build-r$ROUND.txt" - <"$P" \
  2>"$SCRATCH_DIR/codex-stderr-r$ROUND.txt" | grep '"type":"thread.started"'
```

- Prompt goes via stdin (`- <"$P"`) — this both avoids quoting bugs AND sidesteps the non-TTY stdin hang (`codex exec` blocks forever waiting on stdin EOF under Claude Code's Bash tool; feeding the file gives immediate EOF).
- Parse `thread_id` from the `{"type":"thread.started","thread_id":"..."}` line → `THREAD_ID`. Codex's final report lands in `$SCRATCH_DIR/codex-build-r$ROUND.txt` — read that file; don't parse the JSONL stream for content.
- **stderr goes to a file, never `/dev/null`.** It carries cosmetic MCP/auth noise, but it is also the ONLY place a quota or auth failure appears: a 401 or 429 presents as exit 0 with a valid `thread_id` and an empty report file, which is indistinguishable from a model that said nothing. Confirm success by the report file + a `thread.started` line; neither → failed run — read the stderr file, then stop and tell the user.
- **Timing:** foreground with `timeout: 600000` on the Bash tool call (default 2-min tool timeout kills real builds). If the spec is clearly >10 min of work (multi-file feature, migration, anything with image generation), launch with `run_in_background: true` instead and read the `-o` file when it exits. Don't kill a quiet background run early — Codex builds are legitimately slow.
- **Heads-up on completion (required):** when a background Codex run finishes, the FIRST line of your next message to the user must be a loud standalone banner — `🔔 CODEX FINISHED — <what> (exit ok/fail) — verifying now` — BEFORE any verification output. The user is not watching tool calls; never let a completed build slide silently into the verify phase.

## Step 3 — Verify (Claude, always, never delegated)

Codex's report is advisory — **and so is any QA, self-review or verification subagent it ran on its own work.** It reports PASS on builds that contain defects; expect that, and treat every claim in the report as a lead to check rather than a result. The whole reason the roles are split is that whoever built it never grades it, and that applies to Codex grading itself inside its own session.

Verify yourself:

1. `git status -sb` + read the FULL diff (`git diff`). Judge it like a contributor PR: correctness, spec fidelity, style match with surrounding code, nothing touched outside scope.
2. **Trace every changed test back to a spec line.** A green suite proves the code does what its tests say; it does not prove the tests were asked for. The failure mode to hunt is **unrequested code paired with a test asserting it** — that combination reads as verified and sails through a proof run. List the tests the diff added, and for each name the spec item it covers. A test with no spec line behind it is the tell: either Codex solved a problem the spec had already settled differently, or it invented a requirement. Both are findings.
3. Run `PROOF_CMD` yourself (or the focused tests for the changed area). Codex's pasted output doesn't count as proof.
4. **Read the "Deviations" section as a claim, not a summary.** `Deviations: None` is common on builds that did deviate — a spec step that turns out impossible gets quietly resolved the right way and never reported. Where the diff diverges from the spec text, decide whether the spec or the code was wrong, and log which.
5. Append to `LOG_FILE` under `## Act 3 — Build`: `### Round <n> — Codex build` + its report summary + `### Claude's verdict` + what passed/failed review.

## Step 4 — Fix loop (same session, bounded)

Problems found → resume the SAME session (Codex keeps its context; cheaper and better than a fresh run). Write the fix list to a temp file (`$P2`), same contract discipline: exact problem, exact file, proof expected.

```bash
ROUND=$((ROUND + 1))   # never reuse r0 — that report is the only record of the build
P2=$(mktemp "$SCRATCH_DIR/fix-prompt.XXXXXX")
# ... write the fix list into "$P2" ...

# resume has no --yolo and no -C: run from the repo dir and spell the long flag,
# or Codex inherits config.toml's sandbox (possibly read-only) and can't write.
codex exec resume "$THREAD_ID" --dangerously-bypass-approvals-and-sandbox --json \
  -o "$SCRATCH_DIR/codex-build-r$ROUND.txt" - <"$P2" \
  2>"$SCRATCH_DIR/codex-stderr-r$ROUND.txt" >/dev/null
```

This is the one place in the plugin that does NOT go through `tools/codex_ro.py`, and
deliberately so: the wrapper exists to make write access impossible, and this step is
the build. Everything else — ping, review, resume-for-review — goes through it.

Re-verify (Step 3) after each round. After `MAX_FIX_ROUNDS` failed rounds: STOP delegating — Claude takes over and finishes the remaining fixes directly. Log the takeover. Ping-ponging trivia through delegation burns more than it saves.

## Step 5 — Human gate (diff sign-off)

Present: 3-bullet summary of what was built, files-changed list, proof-test output (pass/fail, verbatim tail), rounds used, any spec deviations. Ask: *"Codex built it, proof passes, diff reviewed. Commit?"*

- Commit ONLY on yes — and Claude writes the commit, never Codex.
- Rejected → ask what's wrong, route back to Step 4 (or take over directly if fix rounds are spent).

## Hard rules

- Codex's diff is the only diff in the tree it builds in. Always. A detached worktree is how you get that when the dirt belongs to another session — not `git stash`.
- Claude never skips the diff read. Every Codex claim is advisory until Claude has read the diff and run the proof, and that includes any QA or self-review Codex ran inside its own session.
- Fix loop terminates at `MAX_FIX_ROUNDS` — then Claude takes over. No unbounded delegation ping-pong.
- Commits, pushes, releases, GitHub mutations: Claude-side only, after the human gate. Codex never commits.
- `LOG_FILE` is the deliverable — with Acts 1/2 it tells the whole story: grilled → reviewed → built → verified.
- After the human gate, offer the optional `code-review` skill as a second acceptance gate (DoD / quality / security, selectable via `scope=`) — same `SPEC_FILE` and `LOG_FILE`. **Not optional when the diff touches anything that faces the network** — routes, auth, sessions, webhooks, `ports:`, proxy/tunnel or DNS config: then `code-review` runs *before* the commit question, and its exposure pass (`exposure-review` role, own model/effort) with it. A build that opened a door is not done until someone standing outside has tried the handle.

## What NOT to do

- Don't build without a spec — that's designing by delegation, and it fails. Route to `/grill-me-codex` or `/plan-review` first.
- Don't use for ~<20-line single-obvious-change edits — just make the edit.
- Don't pin `-codex` model variants on ChatGPT-account auth — 400s.
- Don't resume with `--last` — capture and use the explicit `THREAD_ID` (parallel sessions make `--last` grab the wrong thread). And ECHO the id into the command visibly before running: `resume` with a missing/garbage id can silently fall back to the most recent session instead of erroring (observed 2026-07-08) — a wrong-target resume looks exactly like a successful one.
- Don't parse the JSONL stream for the report — read the `-o` file.
- Don't let Codex commit, and don't auto-commit yourself — human gate first.
