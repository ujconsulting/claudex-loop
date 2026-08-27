# Roles — who does which step

Upstream bakes the actor into the skill name: `codex-review` means Codex reviews,
`codex-build` means Codex builds. That reads fine until you want the other
arrangement, and then the name lies. This fork moves the actor into
configuration and names the skills after the **activity** instead.

| Skill | Activity | Actor comes from |
|---|---|---|
| `claudex-loop` | orchestrates plan → plan-review → build → code-review | the roles below |
| `plan-review` | attack a plan before code exists | `roles.plan-review` |
| `build` | implement a frozen plan | `roles.build` |
| `code-review` | grade the finished diff (dod/quality/security/docs/tests) | `roles.code-review` |
| `docs-backfill` | fill standing documentation debt | `roles.docs` + `roles.docs-review` |

Skill names are activities; role names in the config are the steps those
activities occupy. `docs-backfill` is the skill; `docs` and `docs-review` are the
two roles it resolves.

## The three roles

| Role | Does | Must be |
|---|---|---|
| **Producer** | writes the artefact — plan, code, documentation | allowed to write |
| **Adversary** | attacks it, raises numbered findings, ends in a verdict | **read-only** and a **foreign context** |
| **Arbiter** | decides each finding: accept (fix) or reject (with a logged reason) | the Producer |

The Arbiter is deliberately the Producer and not the Adversary. A critic who
could enforce their own findings is not reviewing, they are directing — and the
person who carries the consequence of a change should be the one who decides
what goes into it. The Adversary's power is that nothing it raises may be
dropped silently, not that it gets the last word.

## Why "foreign context" is not a formality

Codex is a separate context by construction: a fresh session, a cold read of the
repo, a different model family. Claude is not — Claude is the orchestrator that
just wrote the thing. So `code-review: claude` is only legitimate when Claude
enters as a **fresh subagent** with no build context, receiving the spec and diff
inlined exactly as Codex would. The gate enforces this: an adversary role
assigned to `claude` without `fresh_subagent: true` is rejected.

## Configuration

`.claudex.yaml` in the repo root, else `~/.claude/claudex.yaml`, else built-in
defaults. See `.claudex.yaml.example`.

```yaml
roles:
  plan:        claude
  plan-review: codex
  build:       claude
  code-review: codex
  docs:        claude
  docs-review: codex

actors:
  codex:  { model: gpt-5.6-terra, effort: high, sandbox: read-only }
  claude: { fresh_subagent: true }
  fallback: [lmstudio]

rules:
  producer_never_reviews: true
  write_access: [plan, build, docs]
  adversary_read_only: true
```

Resolve and check before any run:

```bash
python scripts/claudex_roles.py --explain   # table + gates, exit 1 if violated
python scripts/claudex_roles.py --role build    # -> claude
```

**Every skill resolves its actor this way and refuses to start on a non-zero
exit.** A doctrine that is only written down gets skipped on the day it is
inconvenient.

## The arrangements

| | plan | plan-review | build | code-review |
|---|---|---|---|---|
| **Standard** | claude | codex | claude | codex |
| **Delegation** | claude | codex | **codex** | **claude** (fresh subagent) |
| **Dual draft** | **[claude, codex]** | **cross** | claude | codex |

**Standard** is the default: Claude is in the conversation with the human, holds
the project context and the MCP tools, so it plans and builds; Codex grades cold.

**Delegation** hands the build to Codex with write access, and the reviewer must
flip with it. Use it when Claude's context is the bottleneck — mechanical
migrations, wide refactors, a bug with a known repro. It is the only arrangement
that opens a sandbox, which is why `build` must appear in `write_access` and why
the choice belongs in a config file rather than in a skill you invoke by habit.

**Dual draft** has both models plan the same task blind, then each grades the
other's draft (`plan-review: cross`). It costs two plans instead of one, so it is
not for everyday work — it is for the plans where a wrong problem framing is
expensive: data models, tenant isolation, migrations. It answers something a
single-draft review cannot: a reviewer looking at the producer's document
inherits its framing. What appears in only one draft is either a blind spot of
the other or ballast, and both are worth knowing.

## The two gates

**`producer_never_reviews`** walks each producer/adversary pair and refuses when
the same actor holds both. With a dual draft it requires `cross`, because an
actor that co-wrote one draft cannot be the neutral grader of the pair.

**`write_access`** is a whitelist of the roles that may run with an open sandbox.
Adversary roles can never appear in it. This is what turns "Codex builds with
`--yolo`" from a property you have to remember about one particular skill into a
declared, checkable fact about the repo.

Both are enforced by `scripts/claudex_roles.py`, which exits non-zero rather than
warning.
