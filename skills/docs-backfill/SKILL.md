---
name: docs-backfill
description: "Backfills missing API documentation across a target — a module, package, directory or whole repo — decoupled from any diff or plan. Claude reads each undocumented unit, writes a docstring in the codebase's own format, and a fresh read-only Codex session grades the result: does every docstring match what the code actually does, or does it merely restate the name. Coverage is measured before and after, and the change is proven docs-only. Use when the user says \"/docs-backfill\", \"document this module\", \"write the missing docstrings\", \"backfill documentation\", \"our docs coverage is bad\", or when a docs-coverage gate fails and the fix is bulk documentation rather than a per-change fix. NOT for reviewing the documentation of a change under review — that is code-review's `docs` scope, which is anchored to a diff. NOT for prose documentation (README, runbooks, guides)."
---

# Codex-Code-Docs — documentation backfill with an adversarial pass

The sibling gates judge a change. This one goes after standing debt: units that
were never documented, and the ones whose docstrings quietly stopped being true.

The doctrine holds here too — **whoever writes the docs does not grade them.**
Claude writes; a fresh read-only Codex session judges. That is the whole reason
this exists as its own skill rather than a one-shot generator: a tool that emits
docstrings and ships them has nobody checking whether they are *correct*, and a
confidently wrong docstring is worse than a missing one — it stops the next
reader from opening the function.

| | |
|---|---|
| **Input** | a target path, not a diff |
| **Output** | a docs-only change + a coverage number measured before and after |
| **Verdict** | `DOCS: ACCURATE` / `DOCS: INACCURATE` from the review pass |

## Actor (resolved, never assumed)

This skill does not decide which model runs it. Before anything else, resolve
`docs` and `docs-review` and check the gates:

```bash
python scripts/claudex_roles.py --explain
```

Use the actor it prints — the docstrings are written by `roles.docs` and graded by `roles.docs-review`. **A non-zero exit means stop:** the role
assignment violates a gate (a maker set to grade its own work, or an adversary
role with an open sandbox), and no run may start on it. Where this document says
"Codex" or "Claude" below, read it as the resolved actor for that role.
Reference: `ROLES.md`.
## Tunables (read from skill args, else default)

| Var | Default | Meaning |
|-----|---------|---------|
| `TARGET` | _required_ | Path to document: a file, module, package or directory. Refuse to run without one — "the whole repo" as an unstated default produces a diff nobody can review. |
| `BATCH` | `15` | Units per write-then-review cycle. Keeps each batch small enough to read and to revert. |
| `COVERAGE_MIN` | `80` | Target coverage in percent. Reaching it is the stopping condition, not the goal — see `SKIP_TRIVIAL`. |
| `SKIP_TRIVIAL` | `true` | Skip units where a docstring would only restate the signature (`get_name`, one-line property getters, `__repr__`). Documenting them games the metric and adds noise. |
| `LOG_FILE` | `DOCS-BACKFILL-LOG.md` | Batches, review verdicts, dispositions, coverage before/after. |
| `MAX_RECHECK` | `1` | Rechecks per batch after fixes. |

Echo the resolved values and the active Codex model before the first call.

## Flow

### Step 1 — Measure, then inventory

1. **Coverage before**, measured not estimated. Python: `interrogate -v <TARGET>`.
   Other languages: the project's own tool, or a count of public units with and
   without documentation. Record the number in `LOG_FILE` — the closing report
   compares against it, so a missing baseline makes the whole run unfalsifiable.
2. **List the undocumented public units** under `TARGET`. Public means: part of
   the module's interface — exported, not `_`-prefixed, not a test helper.
   Prefer a parser over a regex (`ast` for Python, `ast-grep` where available);
   a regex sweep will mistake strings and comments for definitions.
3. **Apply `SKIP_TRIVIAL`** and say in the log how many units were skipped and
   why. Silent skipping is what turns a coverage number into a lie.
4. If the list is empty, stop and say so. A coverage number below
   `COVERAGE_MIN` with nothing left to document means the metric is counting
   things you decided not to document — report that instead of padding.

### Step 2 — Learn the house format (before writing anything)

Read two or three **documented** neighbours of each target file and extract:
docstring convention (Google, NumPy, Sphinx, JSDoc, Go-style), language of the
prose, whether parameters / returns / raises are listed, whether types are
repeated in the text or left to the annotations, line width.

Write what you found into `LOG_FILE` as one line. If the file's neighbourhood
has no documented units, widen to the package, then the repo. **Never impose a
convention the codebase does not use** — a correct docstring in a foreign format
is a new inconsistency, and reviewers will read it as one.

### Step 3 — Write, one batch at a time

For each unit, **read the body before documenting it.** Describe what the code
does, not what the name suggests: the contract, the parameters that carry
meaning, the return value, the exceptions actually raised, and the side effects
— file writes, network calls, mutated arguments, global state. Those side
effects are the part a reader cannot infer from the signature, and the part a
name-based generator always misses.

Where the code's behaviour is surprising or wrong, **say so in the log as a
finding — do not document the bug as if it were the design**, and do not fix it
here either. This skill produces a docs-only change.

### Step 4 — Prove it is docs-only

Before the review pass, verify mechanically that the batch changed nothing but
documentation:

```bash
git diff -U0 <TARGET> | grep -E '^[+-]' | grep -vE '^(\+\+\+|---)'
```

Every remaining line must be a docstring, comment or blank-line adjustment. Any
executable line in the diff is a defect in this run — revert the batch and redo
it. Then run the test suite: it must be **untouched and still green**. A docs
backfill that changes behaviour has failed regardless of how good the prose is.

### Step 5 — Adversarial review (fresh read-only Codex session)

Per batch, with the changed units inlined:

> You are reviewing documentation someone else wrote for code you can read. For
> each documented unit below, decide whether the docstring is TRUE of the code:
> does it describe what the body actually does, are the stated parameters,
> return value and raised exceptions the real ones, are side effects (I/O,
> network, mutation of arguments, global state) mentioned where they exist?
> Flag, numbered and anchored to file:line: statements contradicted by the code,
> omitted side effects or exceptions, docstrings that merely restate the
> signature and carry no information, and any that follow a different convention
> than the surrounding file. Do not rewrite them — name what is wrong. Do not
> comment on the code itself; it is not under review here. End with exactly
> `DOCS: ACCURATE` or `DOCS: INACCURATE`.

Mechanics are `code-review`'s: `-s read-only`, prompt via **stdin**, output
to a file via `cygpath -w`, stderr to a **file** (a 401/429 presents as exit 0
with empty output), 600 s ceiling, `< /dev/null`. Or hand all of that to the
wrapper: `python tools/codex_ro.py --prompt-file p.txt --out-file v.txt`, which
does it the same way on Windows and macOS. Preflight the quota with
`python scripts/codex_usage.py`; on exhaustion the user decides — wait, fallback
via `scripts/fallback_review.py --chain --require-verdicts "DOCS:ACCURATE|INACCURATE"`,
or skip with an explicit log entry. Never silently.

### Step 6 — Arbitrate, then close

Append the report **verbatim** to `LOG_FILE` the moment it arrives, then one
disposition line per finding (`accepted → what changed` / `rejected → why`).
Fix accepted findings, recheck once per `MAX_RECHECK`, then move to the next
batch.

Closing report: coverage before → after (both measured), units documented,
units skipped as trivial, batches run, findings raised / fixed / rejected, and
any behaviour oddities found while reading. If coverage did not reach
`COVERAGE_MIN`, say what is left rather than rounding up.

## Hard rules

- **Never document a unit you have not read.** Inferring behaviour from the name
  is exactly the failure mode this skill exists to avoid.
- **Docs-only, proven by diff** (Step 4). No refactors, no renames, no "while I
  was in there" fixes — those need their own change and their own review.
- **A docstring that restates the signature is not coverage.** Skip the unit and
  log it; do not pad the metric.
- **The house format wins over your preferred format**, every time.
- **The coverage number is measured before and after** by the same tool. A
  claimed improvement without both numbers is not a result.
- Fresh Codex session per batch review; rechecks resume that batch's thread.
- A bug found while reading is a log entry, never a silent fix.

## What NOT to do

- Don't run it on a whole repo in one batch to "get it over with" — the diff
  becomes unreviewable and one bad convention choice propagates everywhere.
- Don't use it on a change under review. Documentation of a diff is
  `code-review scope=docs`, which judges against the plan and the change.
- Don't write prose documentation with it — README, runbooks, architecture
  guides need an author who knows the intent, not a unit-by-unit sweep.
- Don't let `COVERAGE_MIN` drive the run past the point where the remaining
  units are genuinely better left undocumented. The number serves the codebase,
  not the other way round.
