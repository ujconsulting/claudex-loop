#!/usr/bin/env python3
"""PreToolUse reminder: a plan whose closing gate is still pending gets mentioned at commit.

WHY THIS EXISTS
---------------
The post-build cross-inspection and the `code-review` acceptance gate (DoD, quality,
security) were described in the skills as the end of a run -- and in practice never
ran. Measured 2026-09-18 across every PLAN-REVIEW-LOG.md in the s100 repo: not one
contains a post-build inspection or a code-review pass. Two reasons, both structural:

  1. The gate hung off "APPROVED -> implement now?" in the SAME session. Every recent
     run ended at MAX_ROUNDS instead, and that branch had no path to the gate.
  2. The build happened later, in another session that never loaded the skill. Nothing
     there knew a gate was owed.

A rule written in a skill is read when the skill is loaded; a commit happens whenever.
So the plan itself now carries the debt -- a line `claudex-gate: pending` that the
Resolution step writes into PLAN.md -- and this hook reads it at the one moment that
every build passes through: `git commit`.

WHAT IT DOES -- AND DELIBERATELY DOES NOT
----------------------------------------
It REMINDS. It never denies, never asks, never exits non-zero. The gate costs Codex
quota, and quota runs out; a hook that blocked commits on an exhausted quota would be
switched off within a day and then protect nothing. Skipping the gate is legitimate --
skipping it *silently* is not, and that is all this hook addresses: it puts the open
debt in front of Claude, who either runs the gate or logs the skip and flips the marker.

  - fires only on a command that runs `git commit`
  - only for PLAN.md files carrying `claudex-gate: pending` (no marker, no mention --
    older plans without the anchor stay silent)
  - once per session and plan (marker file in the temp dir), so a long session of
    small commits is not nagged on every one

Fail open, always: every error path exits 0 with no output. No subprocesses, no
network -- files are read, a decision is printed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

# `commit` must end the word: `\b` alone would also match `git commit-tree` (the hyphen
# is a word boundary), which is plumbing, not a commit of a build.
GIT_COMMIT_RE = re.compile(r"(^|[\s;&|(])git(\s+-[Cc]\s+\S+)*\s+commit(?![\w-])")
PENDING_RE = re.compile(r"claudex-gate:\s*pending\b", re.IGNORECASE)

MAX_DEPTH = 4            # PLAN.md at the root, in docs/plans/<slug>/, _todos/plaene/<slug>/ ...
MAX_DIRS = 4000          # a hard ceiling: a reminder is not worth a slow commit
SKIP_DIRS = {"node_modules", "__pycache__", "venv", "site", "dist", "build", "legacy"}


def runs_git_commit(command: str) -> bool:
    return bool(GIT_COMMIT_RE.search(command or ""))


def repo_root(start: Path) -> Path | None:
    for d in (start, *start.parents):
        if (d / ".git").exists():
            return d
    return None


def pending_plans(root: Path) -> list[Path]:
    """PLAN.md files up to MAX_DEPTH below root whose gate is pending."""
    found: list[Path] = []
    seen = 0
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        seen += 1
        if seen > MAX_DIRS:
            break
        try:
            with os.scandir(d) as it:
                for e in it:
                    if e.is_dir(follow_symlinks=False):
                        if depth < MAX_DEPTH and not e.name.startswith(".") and e.name not in SKIP_DIRS:
                            stack.append((Path(e.path), depth + 1))
                    elif e.name == "PLAN.md":
                        try:
                            text = Path(e.path).read_text(encoding="utf-8", errors="replace")
                        except OSError:
                            continue
                        if PENDING_RE.search(text):
                            found.append(Path(e.path))
        except OSError:
            continue
    return sorted(found)


def marker_file(session_id: str) -> Path:
    kurz = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"claudex_gate_reminder_{kurz}.txt"


def not_yet_reminded(session_id: str, plans: list[Path]) -> list[Path]:
    """Filter out plans already mentioned in this session and record the rest.
    Without a session id every call reminds -- better once too often than never."""
    if not session_id:
        return plans
    m = marker_file(session_id)
    try:
        done = set(m.read_text(encoding="utf-8").splitlines()) if m.exists() else set()
    except OSError:
        done = set()
    neu = [p for p in plans if str(p) not in done]
    if neu:
        try:
            with m.open("a", encoding="utf-8") as f:
                f.writelines(str(p) + "\n" for p in neu)
        except OSError:
            pass
    return neu


def message(root: Path, plans: list[Path]) -> str:
    rel = [str(p.relative_to(root)).replace("\\", "/") for p in plans]
    liste = "\n".join(f"  - {r}" for r in rel)
    return (
        "claudex-loop: this repo has plan(s) whose closing gate is still open "
        "(`claudex-gate: pending`):\n"
        f"{liste}\n"
        "If this commit belongs to building one of them, the closing gate is owed: "
        "the post-build cross-inspection and `/claudex-loop:code-review "
        "SPEC_FILE=<plan> LOG_FILE=<its PLAN-REVIEW-LOG.md> scope=dod,quality,security`. "
        "Run it now or right after this commit, then set the marker to "
        "`claudex-gate: done`. If it cannot run (Codex quota out and no fallback, or the "
        "user declines), log `## Closing gate skipped — <reason>` in the plan's log and "
        "set `claudex-gate: skipped`. Skipping is allowed; skipping silently is not. "
        "If this commit has nothing to do with those plans, ignore this note. "
        "This is a reminder only -- the commit is not blocked."
    )


def main() -> int:
    for strom in (sys.stdout, sys.stderr):
        try:
            strom.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if payload.get("tool_name") not in ("Bash", "PowerShell"):
            return 0
        command = (payload.get("tool_input") or {}).get("command") or ""
        if not runs_git_commit(command):
            return 0
        root = repo_root(Path(payload.get("cwd") or os.getcwd()).resolve())
        if root is None:
            return 0
        plans = not_yet_reminded(str(payload.get("session_id") or ""), pending_plans(root))
        if not plans:
            return 0
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": message(root, plans),
        }}, ensure_ascii=False))
    except Exception:  # noqa: BLE001 -- a reminder must never break a commit
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
