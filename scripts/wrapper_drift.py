#!/usr/bin/env python3
"""Report repos whose copies of the plugin's tools have fallen behind.

WHY THIS EXISTS
---------------
Some of this plugin's scripts are copied into each repo under `tools/`, because
a permission allowlist entry has to name a stable path and the plugin's own
directory carries a version hash that changes on every update.

Copies drift. On 2026-08-28 there were seven copies of the read-only wrapper in
three different states, and the two CRITICAL fixes from that day's audit existed
in exactly one. Nobody had done anything wrong — there was simply no way to see
it. This script is that way to see it.

Two classes of file:

* **required** — `codex_ro.py`. Installed by `--update` when missing; a repo
  that runs the loop without it has no sandbox guarantee at all.
* **optional** — the quota reader and the fallback reviewer. Only refreshed
  where they already exist: not every repo wires up the fallback chain, and
  `--update` should not decide that for them.

    python scripts/wrapper_drift.py                      # the repo you are standing in
    python scripts/wrapper_drift.py --repo A --repo B    # named repos
    python scripts/wrapper_drift.py --scan ROOT          # every repo under ROOT
    python scripts/wrapper_drift.py --scan ROOT --update # and bring the copies level

Exit code 0 when every copy matches, 1 when at least one does not. `--update`
rewrites drifted copies from the canonical files and then exits 0 if all are
level. It never deletes anything.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
from pathlib import Path

SCRIPTS_DEFAULT = Path(__file__).resolve().parent

# (filename, required) — required files are installed when missing.
TOOLS = [
    ("codex_ro.py", True),
    ("codex_usage.py", False),
    ("fallback_review.py", False),
]

TOOLS_DIR = "tools"
LEGACY_RELATIVE = Path(TOOLS_DIR) / "codex_ro.ps1"

VERSION_RE = re.compile(r'^WRAPPER_VERSION\s*=\s*"([^"]+)"', re.MULTILINE)

LEVEL, DRIFTED, MISSING = "level", "drifted", "missing"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def version_of(path: Path) -> str:
    """The declared version if the file carries one, else its short digest."""
    try:
        match = VERSION_RE.search(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return "unreadable"
    return match.group(1) if match else digest(path)


def inspect_file(repo: Path, canonical: Path, required: bool) -> dict:
    copy = repo / TOOLS_DIR / canonical.name
    report = {"name": canonical.name, "copy": copy, "required": required}
    if not copy.exists():
        report["status"] = MISSING
        report["detail"] = "absent" if not required else "no tools/" + canonical.name
        return report
    if digest(copy) == digest(canonical):
        report["status"] = LEVEL
        report["detail"] = version_of(copy)
        return report
    report["status"] = DRIFTED
    report["detail"] = f"{version_of(copy)} ({digest(copy)}) vs {version_of(canonical)} ({digest(canonical)})"
    return report


def find_repos(root: Path) -> list[Path]:
    """Repos one or two levels below ROOT that carry any of the tools."""
    found = set()
    for name, _ in TOOLS:
        for depth in ("*/", "*/*/"):
            for match in root.glob(f"{depth}{TOOLS_DIR}/{name}"):
                found.add(match.parent.parent)
    for depth in ("*/", "*/*/"):
        for match in root.glob(f"{depth}{LEGACY_RELATIVE.as_posix()}"):
            found.add(match.parent.parent)
    return sorted(found)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wrapper_drift.py",
        description="Report (and optionally refresh) repo copies of the plugin's tools.",
    )
    parser.add_argument("--repo", action="append", default=[], metavar="PATH")
    parser.add_argument("--scan", action="append", default=[], metavar="ROOT",
                        help="find repos with a copy one or two levels below ROOT")
    parser.add_argument("--scripts-dir", default=str(SCRIPTS_DEFAULT), metavar="PATH",
                        help="where the canonical files live (default: this script's directory)")
    parser.add_argument("--update", action="store_true",
                        help="refresh drifted REQUIRED copies and install missing ones")
    parser.add_argument("--update-optional", action="store_true",
                        help="also overwrite drifted OPTIONAL copies. Separate flag on "
                             "purpose: optional tools get edited in place — one repo added "
                             "an egress allowlist to its copy, another rewrote a third of "
                             "the file after an audit. Read the diff before using this.")
    args = parser.parse_args(argv)

    scripts_dir = Path(args.scripts_dir).resolve()
    canonical = {}
    for name, required in TOOLS:
        path = scripts_dir / name
        if not path.is_file():
            if required:
                print(f"wrapper_drift: canonical {name} not found in {scripts_dir}", file=sys.stderr)
                return 2
            continue
        canonical[name] = (path, required)

    repos = [Path(r).resolve() for r in args.repo]
    for root in args.scan:
        repos.extend(find_repos(Path(root).resolve()))
    if not repos:
        repos = [Path.cwd().resolve()]
    repos = sorted(set(repos))

    print("canonical: " + ", ".join(
        f"{name} {version_of(path)} {digest(path)}" for name, (path, _) in canonical.items()))

    width = max((len(r.name) for r in repos), default=4)
    problems = 0
    for repo in repos:
        rows = []
        for name, (path, required) in canonical.items():
            report = inspect_file(repo, path, required)
            status = report["status"]
            if status == MISSING and not required:
                continue  # optional and not wired up here — not a finding
            if status != LEVEL:
                problems += 1
                may_write = (args.update and required) or (args.update_optional and not required)
                if may_write:
                    verb = "installed" if status == MISSING else "updated"
                    report["copy"].parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, report["copy"])
                    status, report["detail"] = LEVEL, f"{verb} {version_of(path)}"
                    problems -= 1
                elif status == DRIFTED and not required:
                    report["detail"] += "  [local edits possible — read the diff]"
            marker = {LEVEL: "ok   ", DRIFTED: "DRIFT", MISSING: "GONE "}[status]
            rows.append(f"{marker} {name} {report['detail']}")
        head = f"  {repo.name:<{width}}"
        print(f"{head}  {rows[0] if rows else 'no tools'}")
        for row in rows[1:]:
            print(f"  {'':<{width}}  {row}")
        if (repo / LEGACY_RELATIVE).exists():
            print(f"  {'':<{width}}  note  {LEGACY_RELATIVE.as_posix()} is still there "
                  f"(the superseded PowerShell wrapper — remove it once nothing calls it)")

    if problems:
        print(f"\n{problems} copies are not level with the canonical files.")
        print("Run again with --update to refresh them, then re-check the allowlist entries.")
        return 1
    print(f"\nall copies level across {len(repos)} repos.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
