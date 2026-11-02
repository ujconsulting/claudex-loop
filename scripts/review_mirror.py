#!/usr/bin/env python3
"""Mirror a repository's review scope to a local disk so the Codex sandbox can read it.

The Windows sandbox (`windows.sandbox="unelevated"`, a restricted token) is refused
access to network shares. Measured 2026-11-02 on the Hyper-V VM (codex-cli 0.162.1,
`codex sandbox -- cmd /c dir <path>`): `S:\\`, `O:\\` and `\\\\uj-nb-ai\\sage_100\\...`
answer "Zugriff verweigert" (access denied), a file on `C:` is listed. The drive
letters are visible inside the sandbox, their contents are not. A review started in a
repository on such a share therefore reads nothing -- and codex_ro.py 2.6.1 still
exited 0 with a verdict in four such runs.

This script copies exactly the paths a repository lists in `.codex/review-scope.txt`
to `C:\\codex-review\\<repo>`; codex_ro.py is then started there. What is not listed
never reaches the mirror, so the reviewer cannot open it even if it ignores the prompt
-- stricter than a tabu list that only lives in the prompt.

`.codex/review-scope.txt`, one repository-relative path per line, `#` comments:

    doku/            directory, mirrored with robocopy /MIR
    AGENTS.md        single file

Refused in the scope file: absolute paths, `..`, `.git`, anything starting with `.env`
except the value-free templates `.env.example`, `.env.sample`, `.env.template`.
Excluded inside every mirrored directory: `.env*`, `__pycache__`, `.pytest_cache`,
`.ruff_cache`, `.playwright-mcp`, `node_modules`.

The first run copies everything (s100-hubspot: 98 MB in 23 s), later runs only what
changed (about 3 s). No scope file -> exit 2, nothing copied.

Usage (from the repository root):
    python <claudex-loop>/scripts/review_mirror.py            # mirror, print target
    python <claudex-loop>/scripts/review_mirror.py --check    # robocopy /L, change nothing
    python <claudex-loop>/scripts/review_mirror.py --repo S:\\x --target D:\\m
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path, PureWindowsPath

SCOPE_FILE = Path(".codex") / "review-scope.txt"
TARGET_ROOT = Path(r"C:\codex-review")
SOURCE_MARK = ".review-mirror-source"

EXCLUDE_DIRS = ("__pycache__", ".pytest_cache", ".ruff_cache", ".playwright-mcp",
                "node_modules", ".git")
EXCLUDE_FILES = (".env", ".env.*", "*.env")
# Templates without values may be listed explicitly as single files; inside mirrored
# directories every .env* stays excluded.
ENV_TEMPLATES = (".env.example", ".env.sample", ".env.template")
ROBOCOPY_QUIET = ["/NFL", "/NDL", "/NJH", "/NJS", "/NP", "/R:1", "/W:1"]
ROBOCOPY_FAIL_FROM = 8  # 0-7 are success bits (copied/extra/mismatched), 8+ is failure


class ScopeError(ValueError):
    pass


def read_scope(text: str) -> list[str]:
    """Scope entries in file order; raises ScopeError on anything unsafe."""
    entries = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip().replace("\\", "/")
        if not line:
            continue
        parts = [p for p in line.split("/") if p]
        if (line.startswith("/") or PureWindowsPath(line).drive or ".." in parts
                or not parts):
            raise ScopeError(f"line {n}: not a repository-relative path: {raw.strip()}")
        if parts[0] == ".git" or any(p.lower().startswith(".env") and p.lower() not in ENV_TEMPLATES
                                     for p in parts):
            raise ScopeError(f"line {n}: never mirrored: {raw.strip()}")
        entries.append("/".join(parts) + ("/" if line.endswith("/") else ""))
    if not entries:
        raise ScopeError("scope file lists nothing")
    return entries


def robocopy_dir(src: Path, dst: Path, check: bool) -> list[str]:
    args = ["robocopy", str(src), str(dst), "/MIR",
            "/XD", *EXCLUDE_DIRS, "/XF", *EXCLUDE_FILES, *ROBOCOPY_QUIET]
    return args + ["/L"] if check else args


def robocopy_file(src: Path, dst: Path, check: bool) -> list[str]:
    args = ["robocopy", str(src.parent), str(dst.parent), src.name, *ROBOCOPY_QUIET]
    return args + ["/L"] if check else args


def jobs(repo: Path, target: Path, entries: list[str], check: bool):
    """(entry, robocopy args) for every entry that exists; missing ones are reported."""
    out, missing = [], []
    for e in entries:
        src = repo / e.rstrip("/")
        if src.is_dir():
            out.append((e, robocopy_dir(src, target / e.rstrip("/"), check)))
        elif src.is_file() and not e.endswith("/"):
            out.append((e, robocopy_file(src, target / e, check)))
        else:
            missing.append(e)
    return out, missing


def guard_target(repo: Path, target: Path) -> str | None:
    """Reason to refuse the target, or None."""
    r, t = repo.resolve(), target.resolve()
    if t == r or r in t.parents or t in r.parents:
        return f"target {target} overlaps the repository"
    mark = target / SOURCE_MARK
    if mark.is_file():
        known = mark.read_text(encoding="utf-8").strip()
        if known and Path(known).resolve() != r:
            return f"target {target} already mirrors {known}"
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, default=Path.cwd())
    ap.add_argument("--target", type=Path)
    ap.add_argument("--check", action="store_true", help="robocopy /L, change nothing")
    a = ap.parse_args(argv)

    repo = a.repo
    target = a.target or TARGET_ROOT / repo.resolve().name
    scope = repo / SCOPE_FILE
    if not scope.is_file():
        print(f"review_mirror: no {SCOPE_FILE} in {repo} -- nothing is mirrored without one")
        return 2
    try:
        entries = read_scope(scope.read_text(encoding="utf-8-sig"))
    except ScopeError as e:
        print(f"review_mirror: {scope}: {e}")
        return 2
    reason = guard_target(repo, target)
    if reason:
        print(f"review_mirror: refused: {reason}")
        return 2

    todo, missing = jobs(repo, target, entries, a.check)
    failed = 0
    for entry, args in todo:
        r = subprocess.run(args, capture_output=True, text=True, errors="replace")
        ok = r.returncode < ROBOCOPY_FAIL_FROM
        failed += not ok
        print(f"  {entry:<28} {'OK' if ok else f'FAILED (robocopy {r.returncode})'}")
        if not ok:
            print("    " + (r.stdout + r.stderr).strip()[-400:])
    for e in missing:
        print(f"  {e:<28} not in repository, skipped")
    if not a.check and not failed:
        target.mkdir(parents=True, exist_ok=True)
        (target / SOURCE_MARK).write_text(str(repo.resolve()) + "\n", encoding="utf-8")
    print(f"{'check' if a.check else 'mirror'}: {target}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
