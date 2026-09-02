# CLAUDE.md — claudex-loop

This repo **is** the plugin. Its product is a set of controls, so the bar for changing
one is higher than for ordinary code: a control that can be walked around is not a
cosmetic defect, it is the opposite of its purpose.

`AGENTS.md` holds the full reviewer role and check catalogue. Codex loads that one
automatically; read it before reviewing anything here.

## What lives where

| | |
|---|---|
| `scripts/codex_ro.py` | The read-only wrapper. **Canonical copy** — repos receive it as `tools/codex_ro.py`, and `scripts/wrapper_drift.py` reports copies that fell behind. |
| `scripts/claudex_roles.py` | Who produces and who grades. Two unswitchable gates. |
| `scripts/fallback_review.py` | The reviewer chain when the Codex quota is out. The egress boundary. |
| `hooks/wrapper_guard.py` | PreToolUse guard: an allowlisted wrapper call stays ONE command. |
| `hooks/claudex-python.sh` | Interpreter shim. Denies wrapper calls when it cannot run the guard. |
| `skills/*/SKILL.md` | The doctrine documents. **Executable** — a `bash` block is an instruction, not an illustration. |
| `legacy/` | Frozen predecessors. Not registered, never loaded, known defects listed in their banners. Do not fix, do not copy. |
| `docs/audit/` | The 2026-08-30 baseline. Everything in it is pre-existing debt; a later review re-raises an item only when a change makes it worse. |

## Standing rules

1. **Every Codex call goes through the wrapper** — ping and resume included. The one
   exception is the build step in `skills/build/SKILL.md`, which is supposed to write;
   it says so in place. `tests/test_skill_contracts.py` enforces this.
2. **Model and effort come from `claudex_roles.py --spec <role>`**, never from a skill.
3. **Prompts go in files** (`--prompt-file`), never through command substitution — and
   never from a path the repo under review controls.
4. **⛔ Never `/tmp`.** Harness scratchpad, else `<repo>/.claudex-tmp/`, gitignored.
5. **stderr to a file, never `/dev/null`.** A 401 or 429 shows up as exit 0 with an
   empty answer file; the reason lives only in stderr.
6. **A closed gap needs a test that was red first.** Every audit fix in this repo has
   one; match that.
7. **Do not weaken a control to make a test pass.** Fix the test or the design.
8. **Three things in the READMEs go stale silently. Check them on every change that
   touches the flow, the skills, or the install.** All three were wrong at once on
   2026-09-02, and none of them would have failed a test:
   - **The mermaid diagram under `## Why`.** It described the four upstream phases and
     stopped exactly where this fork's additions begin — no acceptance gate, no exposure
     pass, and the colours hard-wired Claude and Codex into boxes whose whole point is
     that the actor is configuration. A diagram that is merely *incomplete* still reads
     as the full picture.
   - **The receipts.** They were upstream's plan-loop run, on a repo nobody here has
     seen. This fork's own evidence — the audit that found its two headline controls
     walkable — was missing entirely.
   - **⛔ The install commands.** They said `marketplace add chaseai-yt/claudex-loop`,
     inherited from the fork point. Anyone following this README installed the
     **upstream** plugin: no wrapper, no guard, none of the hardening the same README
     then describes at length. That is worse than a stale doc — it is a security
     promise the reader cannot collect on, and they had no way to notice.
     `tests/test_readme_sync.py` now fails on it. Links to upstream *issues and PRs*
     stay: those are attribution, not instructions.

   **`README.md` and `README_DE.md` are edited together.** The German file is a full
   mirror for German-speaking users, not a summary. Commands, env vars and the diagram
   are copied verbatim rather than translated, and the test compares them literally —
   prose it cannot check, so that part is on you.
8. **Before this repo is ever published as a real public project** (not the current
   fork), in this order: **first** enable GitHub's private vulnerability reporting
   (Settings → Advanced Security), **then** add a `SECURITY.md` pointing at it with a
   reachable address. Never the other way round — a `SECURITY.md` that forbids public
   issues while naming no working channel closes the only open door and replaces it
   with nothing. This repo is the likely candidate for it: it enforces a read-only
   sandbox and a taboo scope over what leaves the machine, so a bug here is a security
   bug for whoever installed it. Full reasoning and the case it came from:
   `D:\Dokumente\Projekte\CLAUDE.md`, section „Wenn ein eigenes Repo öffentlich wird".

## Before every commit

```bash
python -m pytest -q
python scripts/claudex_roles.py --explain
```

Both must be clean locally. **CI is not the same set**, so do not read a green run as
covering them:

| Job | Runs on | What |
|---|---|---|
| `tests` | Linux · macOS · Windows, Python 3.10 and 3.13 | `pytest` only |
| `tests-without-pyyaml` | Linux | `pytest` with PyYAML proven absent |
| `shell` · `workflows` · `secrets` | Linux only | shellcheck · actionlint · gitleaks |

Windows is in the matrix because that is where this plugin is actually used and the
wrapper carries Windows-specific code. `claudex_roles.py --explain` is **not** in CI —
it is a local pre-commit check, and the gates it enforces are covered by
`tests/test_roles.py` instead.

## Working here

Ordinary changes: just make them. For anything touching the wrapper, the guard, the
role gates or the egress rules, harden the plan first — that is what this plugin is
for, and it applies to itself.
