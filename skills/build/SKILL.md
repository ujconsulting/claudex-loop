---
name: build
description: "Hand a frozen spec (PLAN.md or any locked plan) to OpenAI Codex to IMPLEMENT with full write access, while Claude stays the spec-writer and reviewer — the exact role-flip of /plan-review. Codex builds from the spec in a hardened container, Claude reads the full diff like a contributor PR, runs the proof through `sandbox_run.py`, and iterates fixes in fresh containers up to MAX_FIX_ROUNDS. Human approves the diff before any commit. Use when the user says \"/build\", \"have codex build this\", \"codex implement the plan\", \"hand the plan to codex\", \"delegate the build to codex\", or right after a plan survives /grill-me-codex, /grill-with-docs-codex, or /plan-review and they choose Codex for implementation (Act 3). Also for standalone delegation: refactors, mechanical migrations, bug fixes with a known repro, test/coverage writing — anything that reads as a work order. NOT for tiny edits (~<20 lines — delegation overhead loses), NOT for design work (if writing the spec forces decisions, that's /grill-me-codex first), NOT for reviewing existing code (/codex:review), and NOT for anything needing Claude-session tools (MCP, secrets, browser)."
---

# Codex-Build — Codex Types, Claude Verifies

The role-flip of `/plan-review`: there, Claude builds the plan and Codex critiques read-only. Here, **Codex is the builder with write access; Claude is the spec-writer and reviewer.** Codex implements a frozen spec end-to-end; Claude judges the diff like a contributor PR, demands proof, and iterates fixes in fresh containers. The human enters at exactly two points: kickoff and diff sign-off.

Adapted from Peter Steinberger's `codex-first` pattern (agent-scripts), rebuilt on this house's verified Codex mechanics.

**Spec quality decides success.** Codex starts with zero session context — everything it needs must be in the prompt. A plan that survived `/grill-me-codex` or `/plan-review` already is a frozen spec; that's the ideal input.

## Actor (resolved, never assumed)

This skill does not decide which model runs it. Before anything else, resolve
`build` and check the gates:

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/claudex_roles.py" --explain
```

Use the actor it prints — the plan being implemented was written by `roles.plan`. **A non-zero exit means stop:** the role
assignment violates a gate (a maker set to grade its own work, or an adversary
role with an open sandbox), and no run may start on it. Where this document says
"Codex" or "Claude" below, read it as the resolved actor for that role.
Reference: `ROLES.md`.

When an adversary role resolves to `claude`, it runs as the plugin agent `claudex-reader` (`Read`, `Grep`, `Glob` only: no shell, no write, no network, no MCP
connector) — never as a sub-agent with the session's tools. Measured 2026-10-27: a
sub-agent without a tool list reached the session's write-capable claude.ai connectors
through ToolSearch; `claudex-reader` reached none. See `ROLES.md`.
## Prerequisites

- Docker must use a Linux engine listed in the installed `build.engines` policy.
- The pinned `python-test:3` and `codex-build` images must already exist. The runner
  never pulls or builds them. The latter contains the policy's exact `codex_version`.
- Host ChatGPT login supplies credentials through `sandbox_auth.py`; never print or
  copy the token. The builder receives placeholder credentials only.
- Echo model and effort from `claudex_roles.py --spec build`, not host config defaults.
- TARGET is the human-supplied checkout path. Work from its root; a Git repository is
  required for input snapshots and publication identity. On Windows, macOS and Linux
  the container boundary is the same; arm64 images are outside this version's scope.

## Tunables (read from args, else default)

| Var | Default | Meaning |
|-----|---------|---------|
| `SPEC_FILE` | `PLAN.md` | The frozen spec Codex implements. |
| `MAX_FIX_ROUNDS` | `2` | Fix iterations as fresh container runs before stopping with remaining findings. |
| `LOG_FILE` | `PLAN-REVIEW-LOG.md` | Append-only build transcript. If it exists (Act 1/2 ran), append `## Act 3 — Build`; else create it. |
| `PROOF_CMD` | from spec | Exact test/verify command Codex must run as proof. If the spec lacks one, ask the user ONE question to get it before launching. Claude's own proof run in Step 3.3 goes through `scripts/sandbox_run.py` only (never on the host). |
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
Use absolute TARGET and SCRATCH_DIR paths, with SPEC_FILE relative to TARGET; refuse an absolute SPEC_FILE or any parent traversal. Before host Git operations, change directory to TARGET.

2. **Clean-tree gate.** `git status -sb`. Publication updates reviewed paths, so the build must start from a tree where **its diff is the only diff** — otherwise you cannot isolate what it did or revert it cleanly. That requirement is non-negotiable; how you satisfy it depends on whose the dirt is.
   - **The user's own uncommitted work** → STOP and ask them to commit or stash.
   - **Another session's live work** — a parallel agent, a long-running task, anything you did not put there → do **not** stash it; that takes work out from under a running session. Build in a detached worktree instead, which satisfies the gate properly:

     ```bash
     git -C "$TARGET" worktree add --detach "$SCRATCH_DIR/build" HEAD
     # An untracked SPEC_FILE does not exist in a fresh worktree — copy it in.
     mkdir -p "$SCRATCH_DIR/build/$(dirname "$SPEC_FILE")"
     cp "$TARGET/$SPEC_FILE" "$SCRATCH_DIR/build/$SPEC_FILE"
     ```

     Stop this session before any build launch. Give the human the absolute path
     of the prepared worktree and have them start a new session there with that
     explicit `target=`. TARGET is a human scope assertion and must never be
     reassigned from scratch paths. The new session then runs every build,
     publication, Git operation and review against that worktree.

     Remove it with `git worktree remove` once the diff is merged or abandoned.
   - Either way, **say which you chose and why before launching.** Never launch into a dirty tree on the reasoning that the subtree you care about happens to be clean.
3. **Path references.** Translate absolute spec references to repository-relative
   paths in the prompt. The container has no host checkout mount; references do not
   select the builder's host working directory.
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
PROOF (the Codex build runs through sandbox_build.py; Claude's own proof run goes through `sandbox_run.py`): Run `<the proof command — from the plan's Verification section when it has one, its real-output inputs and old-vs-new comparison included>` and include its full output in your report.
OUTPUT: End with a report — files changed (one line each: path + what/why),
  proof output, and any deviations from the spec with reasons.
EOF
```

## Step 2 - Build in quarantine

The build does NOT go through `tools/codex_ro.py`: that wrapper forbids writes;
`sandbox_build.py` confines the writable builder to a disposable container.
Resolve model and effort from `claudex_roles.py --spec build` and echo them.
Require the policy-supported Docker engine, pinned python-test:3 and codex-build
images, and host ChatGPT login. API-key mode is refused. No host fallback.

```bash
python -I "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_build.py" run --repo "$TARGET" --scratch "$SCRATCH_DIR" --pin "$SPEC_FILE" --prompt-file "$P" >"$SCRATCH_DIR/build-r$ROUND.stdout" 2>"$SCRATCH_DIR/build-r$ROUND.stderr"
```

Use the same hashed `--deps` inputs as the proof through `sandbox_run.py`.
Capture RUN_DIR, TREE and MANIFEST_SHA256 from this invocation's stdout yourself;
record them in LOG_FILE. Never replace that digest with builder-written output.
Require runner exit 0, BUILD_STATUS=exited, CODEX_EXIT=0 and non-empty codex-last.txt.
The report is advisory. Refused websocket attempts add about seven seconds before HTTPS.
An auth_failed result is a login problem: report it and stop, never retry in a loop.
Infrastructure errors, isolation failures and unconfirmed cleanup stop the workflow.

## Step 3 — Verify (Claude, always, never delegated)

Codex's report is advisory — **and so is any QA, self-review or verification subagent it ran on its own work.** It reports PASS on builds that contain defects; expect that, and treat every claim in the report as a lead to check rather than a result. The whole reason the roles are split is that whoever built it never grades it, and that applies to Codex grading itself inside its own session.

Verify yourself:

1. **Review before publication.** Use the independently captured digest:

   ```bash
   python -I "${CLAUDE_PLUGIN_ROOT}/scripts/change_apply.py" show --run-dir "$RUN_DIR" --manifest-sha256 "$MANIFEST_SHA256" --repo "$TARGET" --summary --page 1
   python -I "${CLAUDE_PLUGIN_ROOT}/scripts/change_apply.py" show --run-dir "$RUN_DIR" --manifest-sha256 "$MANIFEST_SHA256" --repo "$TARGET" --file 0 --page 1
   ```

   Read every PAGE k/N of the summary and every page of every numbered file.
   Decide every binary and NOT FULLY SHOWN file explicitly. Rejected changes stay
   in quarantine. Apply only after review, adding exact `--accept-binary` and
   `--accept-large` paths for the decisions recorded in LOG_FILE:

   ```bash
   python -I "${CLAUDE_PLUGIN_ROOT}/scripts/change_apply.py" apply --run-dir "$RUN_DIR" --manifest-sha256 "$MANIFEST_SHA256" --target "$TARGET"
   ```

   A partial stop is a failure. Show PUBLISHED, NOT_PUBLISHED and the printed
   RECOVERY commands to the human; never run recovery automatically.
   After successful publication inspect and execute the printed STAGE and CHECK
   commands with their explicit published paths and `git --literal-pathspecs`.
   On Windows execute the printed MODE_TODO commands after staging. Never evaluate
   the output as a script. Check `git --literal-pathspecs diff --name-only -- <published paths>`
   is empty, record `git write-tree` as REVIEWED_TREE, and read `git diff HEAD`.
2. **Trace every changed test back to a spec line.** A green suite proves the code does what its tests say; it does not prove the tests were asked for. The failure mode to hunt is **unrequested code paired with a test asserting it** — that combination reads as verified and sails through a green check. List the tests the diff added, and for each name the spec item it covers. A test with no spec line behind it is the tell: either Codex solved a problem the spec had already settled differently, or it invented a requirement. Both are findings.
3. Run the proof yourself — through `scripts/sandbox_run.py`, never on the host. The repository under review controls what its tests execute, so they run in a disposable container on exactly the tree you just pinned (B1; the Codex build runs through sandbox_build.py). Codex's pasted output doesn't count as proof.

   ```bash
   python -I "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py" --repo . --scratch "$SCRATCH_DIR" --tree "$REVIEWED_TREE" --image python-test [--deps <hashed requirements file>] -- <the proof command or the focused tests>
   ```

   `python -I` is part of the call: an inherited `PYTHONPATH`, the checkout or the user site must not load a `sitecustomize` before the runner validates anything.

   **Dependencies (B1.5).** When the repository has a fully hashed requirements file that the command needs (`requirements*.txt`, every line `name==version --hash=sha256:...`, no markers, no options), add `--deps <its path in the pinned tree>` (repeatable, at most 4) and use the **same** `--deps` on every run of this gate: the initial proof and every fix rerun. The runner selects wheels by hash alone from PyPI, installs them offline inside the container and checks the declared closure before the command starts; it prints `REQUIREMENTS_SHA256=` next to `MANIFEST_SHA256=`: log both with the tree id. `COMMAND_STATUS=deps_failed` (install or closure check failed) is a failure, never a pass, and is reported as a dependency problem, not as a test result. Unhashed or marker-bearing requirements are not run: report "dependencies outside the image - the requirements are not hashed (B1.5)" with the hint `uv pip compile --generate-hashes --python-version 3.13 --python-platform x86_64-manylinux_2_28` (output that still carries environment markers is refused as well), never a host run. The honest limit: the closure check proves only what the package metadata declares; a test that skips on a missing optional import still passes, and that is the project's test, not the runner's verdict.

   It prints `RUN_DIR=`, `TREE=`, `COMMAND_STATUS=`, `COMMAND_EXIT=` and `MANIFEST_SHA256=`. **Pass rule: only `COMMAND_STATUS=exited` with `COMMAND_EXIT=0` counts.** `timeout`, `oom`, `output_limit` and `not_started` are failures, never a pass. Log `MANIFEST_SHA256=` together with the tree id under `## Act 3 — Build`; a manifest whose `TREE=` is not `$REVIEWED_TREE` is not evidence for this step. The runner's own exit code says only whether the run happened: `2` = refused, `5` = infrastructure — neither is a test result. There is **no host fallback**: if Docker or the image is missing, or the program is not one of the image's tools, the step is refused (runner exit `2`) — say so, and the human may run the command themselves, on their own responsibility. A dependency the image lacks that the program then loads (a module the code imports) and that no hashed `--deps` file supplies is not refused up front: it fails inside the container (`COMMAND_EXIT` != 0, usually `2` for a collection error). Report that as "dependencies outside the image - the requirements are not hashed (B1.5)" when no hashed file exists, never as a failing result about the code. Pin first (Step 3.1), run second: this step needs `REVIEWED_TREE`.
4. **Read the "Deviations" section as a claim, not a summary.** `Deviations: None` is common on builds that did deviate — a spec step that turns out impossible gets quietly resolved the right way and never reported. Where the diff diverges from the spec text, decide whether the spec or the code was wrong, and log which.
5. Append to `LOG_FILE` under `## Act 3 — Build`: `### Round <n> — Codex build` + its report summary + `### Claude's verdict` + what passed/failed review.

## Step 4 - Fresh fix rounds, bounded

Each round starts a fresh container and a fresh Codex execution. Write a new prompt
with the spec reference, reviewer findings verbatim and the reviewed diff pages.
For accepted and published changes use the newly pinned REVIEWED_TREE:

```bash
ROUND=$((ROUND + 1))
P2=$(mktemp "$SCRATCH_DIR/fix-prompt.XXXXXX")
# Write the complete fix work order into P2 before launching.
python -I "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_build.py" run --repo "$TARGET" --scratch "$SCRATCH_DIR" --tree "$REVIEWED_TREE" --prompt-file "$P2" >"$SCRATCH_DIR/build-r$ROUND.stdout" 2>"$SCRATCH_DIR/build-r$ROUND.stderr"
```

For rejected, unpublished changes reuse the original input TREE and inline the rejected
pages and findings. Reapply Step 3 and rerun the proof through `sandbox_run.py` with the
same `--deps`. After MAX_FIX_ROUNDS stop and report the remaining findings.
Direct host takeover is out of scope; no host fallback.

## Step 5 — Human gate (diff sign-off)

Present: 3-bullet summary of what was built, files-changed list, proof-test output (pass/fail, verbatim tail), rounds used, any spec deviations. Ask: *"Codex built it, proof passes, diff reviewed. Commit?"*

- Commit ONLY on yes — and Claude writes the commit, never Codex.
- **Right before the commit:** `git --literal-pathspecs diff --name-only -- <paths>` empty, and `python "${CLAUDE_PLUGIN_ROOT}/scripts/tree_check.py" --tree "$REVIEWED_TREE" --log "$LOG_FILE" --spec "$SPEC_FILE"` exits 0 — the index equals the last `REVIEWED_TREE` except that the log grew and the plan's `claudex-gate:` line changed. Anything else changed after the review — re-read it or show it at the gate as unreviewed; never commit it as reviewed.
- Rejected → ask what's wrong, route back to Step 4 (or stop with remaining findings if fix rounds are spent).

## Hard rules

- Codex's diff is the only diff in the tree it builds in. Always. A detached worktree is how you get that when the dirt belongs to another session — not `git stash`.
- Claude never skips the diff read. Every Codex claim is advisory until Claude has read the diff and run the proof through `sandbox_run.py`, and that includes any QA or self-review Codex ran inside its own session.
- Fix loop terminates at `MAX_FIX_ROUNDS` with remaining findings reported. No unbounded delegation ping-pong.
- Commits, pushes, releases, GitHub mutations: Claude-side only, after the human gate. Codex never commits.
- `LOG_FILE` is the deliverable — with Acts 1/2 it tells the whole story: grilled → reviewed → built → verified.
- After the human gate, run the `code-review` skill as the closing acceptance gate (DoD / quality / security, selectable via `scope=`) — same `SPEC_FILE` and `LOG_FILE`. **Default on, never a blocker:** it is skipped only when the user opts out or the Codex quota is out and no fallback is chosen, and then the skip is logged (`## Closing gate skipped — <reason>`). Either way, flip the **state word** of the plan's marker from `pending` to `done` or `skipped` and leave its `due-after:` standing as a record. ⛔ For a plan built in stages, "after the human gate" means after the human gate of the **last** stage — the step the marker names as `due-after:`. An earlier stage ends with its own proof and, if wanted, an interim review of what is finished; that is not the closing gate and does not touch the marker. **Not optional when the diff touches anything that faces the network** — routes, auth, sessions, webhooks, `ports:`, proxy/tunnel or DNS config: then `code-review` runs *before* the commit question, and its exposure pass (`exposure-review` role, own model/effort) with it. A build that opened a door is not done until someone standing outside has tried the handle.

## What NOT to do

- Don't build without a spec — that's designing by delegation, and it fails. Route to `/grill-me-codex` or `/plan-review` first.
- Don't use for ~<20-line single-obvious-change edits — just make the edit.
- Don't pin `-codex` model variants on ChatGPT-account auth — 400s.
- Don't parse the JSONL stream for the report — read the `-o` file.
- Don't let Codex commit, and don't auto-commit yourself — human gate first.
