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
