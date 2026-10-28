#!/usr/bin/env python3
"""Has the index moved away from a reviewed tree in anything but the gate's own files?

The post-build inspection (claudex-loop), the diff read in `build` Step 3 and the closing
gate (code-review) each pin `git write-tree` and require, before the commit, that the
commit carries what was reviewed. Their own artefacts then change the tree on purpose: the
review log grows, the plan's `claudex-gate` marker flips. A plain tree comparison fails on
that forever, and a list of exempt PATHS lets any content change in those files through
(closing gate, recheck 2: C2-r2-1 and C2-r2-2). This check allows exactly:

- `--log FILE`: the reviewed version is an unchanged PREFIX of the staged one (appended
  text only);
- `--spec FILE`: the two versions differ in exactly one line, the standalone marker
  `<!-- claudex-gate: <state>[; due-after: <step>] -->`, whose state goes from `pending`
  to `done` or `skipped` while the due point and every other byte stay;

and nothing else. Both must stay REGULAR files (git mode 100644) with an unchanged mode:
a mode change, an executable bit or a symlink entry is never a gate change (fresh gate
C2-1, C2-2). A path named here that did not exist in the reviewed tree must be new
in the same way (the log may start empty; the spec may not appear).

    python scripts/tree_check.py --tree <sha> [--log PATH] [--spec PATH]

Exit 0: only the allowed changes. Exit 1: something else changed (listed). Exit 2: usage
or git failure. Messages are ASCII only.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

MARKER = re.compile(rb"^<!-- claudex-gate: (pending|done|skipped)(; due-after: [^>\r\n]*?)? -->(\r?)$")


def _git(*args: str) -> bytes:
    done = subprocess.run(["git", *args], capture_output=True, stdin=subprocess.DEVNULL)
    if done.returncode != 0:
        raise RuntimeError(f"git {args[0]} exited {done.returncode}")
    return done.stdout


def _blob(spec: str) -> bytes | None:
    done = subprocess.run(["git", "cat-file", "blob", spec], capture_output=True,
                          stdin=subprocess.DEVNULL)
    return done.stdout if done.returncode == 0 else None


def _only_marker_lines_differ(old: bytes, new: bytes) -> bool:
    """True when exactly one line differs and it is the standalone marker going from
    `pending` to `done`/`skipped`, due point and line ending unchanged."""
    a, b = old.split(b"\n"), new.split(b"\n")
    if len(a) != len(b):
        return False
    diffs = [(x, y) for x, y in zip(a, b) if x != y]
    if len(diffs) != 1:
        return False
    mx, my = MARKER.match(diffs[0][0]), MARKER.match(diffs[0][1])
    return bool(mx and my and mx.group(1) == b"pending" and my.group(1) in (b"done", b"skipped")
                and mx.group(2) == my.group(2) and mx.group(3) == my.group(3))


def _mode(tree: str | None, path: str) -> str | None:
    """git mode of `path` in `tree`, or in the index when tree is None; None if absent."""
    out = _git("ls-tree", "-z", tree, "--", path) if tree else _git("ls-files", "-s", "-z", "--", path)
    entry = out.split(b"\0", 1)[0].decode("utf-8", "replace")
    return entry.split(" ", 1)[0] if entry else None


def problems(tree: str, log: str | None, spec: str | None) -> list[str]:
    """Every staged difference from `tree` that is not an allowed gate change."""
    if not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise RuntimeError("--tree must be a full 40-hex tree id")
    # --no-renames: with rename detection a move lists only the NEW name, so a reviewed
    # file moved onto a not-yet-existing log path looked like a fresh log and its removal
    # went unreported (security review of 9bf9f38). Both paths now appear; the old one has
    # no staged blob and matches no exception.
    changed = [p for p in _git("diff", "--cached", "--no-renames", "--name-only", "-z", tree)
               .decode("utf-8").split("\0") if p]
    out = []
    for path in changed:
        old, new = _blob(f"{tree}:{path}"), _blob(f":{path}")
        if path in (log, spec) and not (_mode(None, path) == "100644"
                                        and _mode(tree, path) in (None, "100644")):
            out.append(path)  # mode/type change or a symlink entry: never a gate change
            continue
        if path == log and new is not None and new.startswith(old or b""):
            continue
        if path == spec and old is not None and new is not None and _only_marker_lines_differ(old, new):
            continue
        out.append(path)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="index vs reviewed tree, gate files excepted")
    ap.add_argument("--tree", required=True)
    ap.add_argument("--log")
    ap.add_argument("--spec")
    a = ap.parse_args(argv)
    try:
        bad = problems(a.tree, a.log, a.spec)
    except (RuntimeError, OSError) as exc:
        sys.stderr.write(f"tree_check: ERROR - {exc}\n")
        return 2
    if bad:
        sys.stdout.write("tree_check: changed since the review (re-review before committing):\n")
        for p in bad:
            sys.stdout.write(f"  {p.encode('ascii', 'replace').decode('ascii')}\n")
        return 1
    sys.stdout.write("tree_check: OK - only the gate's own files changed\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
