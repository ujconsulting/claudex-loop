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
    python scripts/wrapper_drift.py --scan ROOT          # repos ONE OR TWO levels under ROOT
    python scripts/wrapper_drift.py --scan ROOT --update # and bring the copies level

⚠️ `--scan` looks one and two levels below ROOT, not the whole tree. A copy sitting
deeper is not reported, and silence from `--scan` is therefore not proof that a
repo is level -- name it with `--repo` if it lives further down. (The docs claimed
"every repo under ROOT" until the audit of 2026-08-30.)

Line endings do not count: a copy is compared and written in its canonical form
(CRLF -> LF, see canonical_bytes()), because Git for Windows' core.autocrlf made
the same file LF in one checkout and CRLF in the next (T17, 2026-09-30).

Exit code 0 when every copy matches, 1 when at least one does not, 2 when the
call itself is refused. `--update` rewrites drifted REQUIRED copies and installs
missing ones; drifted OPTIONAL copies need `--update-optional` as well, because
those get edited in place on purpose. It never deletes anything.

WRITING (2.6.0, plan docs/plans/2026-09-23-codex-heben-wrapper-2.6.0 §5b)
    `--update` reaches into repos it did not create. What it now demands:
    - `--private-root DIR` on every writing call: the operator attests that only
      they write below DIR. DIR is checked as typed (absolute, no control
      characters, no UNC/device path, not a drive root, not a network drive, an
      existing directory, no reparse point in it or above it) and never resolved.
    - the source is ALWAYS the directory this script lives in -- `--scripts-dir`
      is for reports and tests and is refused together with `--update`.
    - --repo/--scan are checked as typed, before anything resolves them.
    - every path component from DIR down to the copy is free of reparse points
      (and on POSIX owned by the caller or root, not group/other-writable).
    - the write stages into a random file beside the target and re-checks the
      folder before creating it, before writing to it and before replacing.
    ⚠️ The claim is narrow on purpose. Windows ACLs are not inspected: the
    protection holds while the attestation holds. Between each check and the
    next filesystem call a window stays open -- a concurrent attacker with write
    access below DIR can still win it; `dir_fd` does not exist on Windows.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

SCRIPTS_DEFAULT = Path(__file__).resolve().parent

# The one fail-closed reparse check, shared with the wrapper rather than rebuilt
# here (a copy would drift -- the very thing this script exists to report).
sys.path.insert(0, str(SCRIPTS_DEFAULT))
from codex_ro import _is_reparse_point  # noqa: E402


class Refused(Exception):
    """A write this script will not perform; the message says why."""

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


def canonical_bytes(path: Path) -> bytes:
    """The file's content in its one canonical form: CRLF turned into LF, nothing else.

    A lone CR stays -- that is a real difference in content and must show as drift.
    Why at all: with core.autocrlf=true (Git for Windows' default) the same file sat
    as LF in one place and CRLF in the next, and raw bytes reported 26 identical
    copies as drifted (T17, 2026-09-30).
    """
    return path.read_bytes().replace(b"\r\n", b"\n")


def digest(path: Path) -> str:
    """Short sha256 of the canonical form -- line endings never count as drift."""
    return hashlib.sha256(canonical_bytes(path)).hexdigest()[:12]


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


def unsafe_destination(repo: Path, copy: Path, private_root: Path | None = None) -> str | None:
    """Why this destination must not be written, or None when it is fine.

    `--update` walks repos it did not create and overwrites files in them, and a
    plain copy writes THROUGH a link. A repo could point `tools/codex_ro.py` --
    or `tools/` itself -- at any file the user can write. (Audit 2026-08-30,
    HIGH.) Since 2.6.0 every component from the attested private root down to
    the copy is checked, with the wrapper's fail-closed reparse check, which
    also catches Windows junctions that `is_symlink()` misses.
    """
    top = private_root if private_root is not None else repo
    for component in components_between(top, copy):
        if _is_reparse_point(component):
            return f"{component} is a symlink or reparse point (or could not be inspected)"
        if _posix_checks() and component.exists() and component != copy:
            try:
                problem = ownership_problem(os.lstat(component), uid=_current_uid())
            except OSError:
                return f"{component} cannot be inspected"
            if problem:
                return f"{component}: {problem}"
    if copy.exists() and not copy.is_file():
        return "the destination is not a regular file"
    try:
        resolved_repo = repo.resolve()
        resolved_parent = copy.resolve().parent
    except OSError as exc:
        return f"the path cannot be resolved ({exc})"
    # commonpath, not startswith. A string prefix accepts `<repo>-evil/tools/`
    # as being "inside" `<repo>` -- the exact false positive codex_ro.py's own
    # _within() exists to avoid, reintroduced here. (CodeRabbit, 2026-08-30.)
    try:
        if os.path.commonpath([str(resolved_parent), str(resolved_repo)]) != str(resolved_repo):
            return "it resolves outside the repo"
    except ValueError:
        # Different drives on Windows: commonpath refuses, and rightly so.
        return "it resolves onto a different drive"
    return None


def components_between(top: Path, target: Path) -> list[Path]:
    """`top` and every path component from it down to `target`, inclusive."""
    parts = [target]
    current = target
    top_key = os.path.normcase(str(top))
    while os.path.normcase(str(current)) != top_key:
        parent = current.parent
        if parent == current:
            break
        current = parent
        parts.append(current)
    return list(reversed(parts))


def _posix_checks() -> bool:
    """Whether owner/mode checks apply -- POSIX only; Windows has no cheap equivalent."""
    return os.name != "nt"


def _current_uid() -> int:
    """The caller's uid (POSIX)."""
    return os.getuid()


def ownership_problem(st: os.stat_result, uid: int) -> str | None:
    """POSIX: why a directory on the write path is not private, or None."""
    if st.st_uid not in (uid, 0):
        return f"owned by uid {st.st_uid}, not by you or root"
    if stat.S_IMODE(st.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        return "writable by group or others"
    return None


def _check_chain(top: Path, folder: Path, moment: str) -> None:
    """Raise Refused unless every component from `top` down to `folder` is still a
    plain directory -- not a reparse point, and on POSIX owned by the caller or root
    and not group/other-writable. The whole chain, not only the last folder: a
    higher directory swapped for a junction carries everything below it along
    (closing gate of 2.6.0, gpt-6-sol, 2026-09-30)."""
    for component in components_between(top, folder):
        if _is_reparse_point(component):
            raise Refused(f"{component} is a symlink or reparse point {moment}")
        if _posix_checks():
            try:
                problem = ownership_problem(os.lstat(component), uid=_current_uid())
            except OSError:
                raise Refused(f"{component} cannot be inspected {moment}") from None
            if problem:
                raise Refused(f"{component}: {problem} ({moment})")


def _write_all(fd: int, data: bytes) -> None:
    """os.write may write fewer bytes than asked; keep writing until all are out."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("write made no progress")
        view = view[written:]


def write_atomically(source: Path, destination: Path, private_root: Path | None = None) -> None:
    """Stage beside the target, verify, then replace it -- never truncate in place.

    An interrupted copy would leave a half-written wrapper that still satisfies
    the allowlist entry pointing at it. Since 2.6.0 (W2): the staging file has a
    random name from mkstemp (the fixed `.claudex-new` collided between parallel
    updates), and the whole chain from `private_root` (default: the target's own
    folder) is re-checked immediately before mkstemp, before a single byte is
    written and before the replace. The staging file is written in full and its
    content verified BEFORE it replaces the target, and the target once more
    after -- both byte-exact. Since T17 the bytes written are the source's
    canonical form (LF), whatever line endings the plugin checkout carries. A swap caught after mkstemp leaves an EMPTY file behind wherever the
    folder then pointed; it is removed through the same path when still reachable.
    """
    folder = destination.parent
    top = private_root if private_root is not None else folder
    # Written in canonical form (LF); the checks below stay byte-exact against
    # exactly these bytes -- normalisation happens once, here, never in a check.
    data = canonical_bytes(source)
    expected = hashlib.sha256(data).hexdigest()
    _check_chain(top, folder, "before staging")
    fd, name = tempfile.mkstemp(dir=folder, prefix=".claudex-", suffix=".tmp")
    staging = Path(name)
    try:
        try:
            _check_chain(top, folder, "right after the staging file was created")
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        if hashlib.sha256(staging.read_bytes()).hexdigest() != expected:
            raise Refused(f"the staged copy of {destination.name} does not match the canonical file")
        _check_chain(top, folder, "before the replace")
        if _is_reparse_point(destination):
            raise Refused(f"{destination} became a symlink or reparse point")
        os.replace(staging, destination)
        if hashlib.sha256(destination.read_bytes()).hexdigest() != expected:
            raise Refused(f"{destination} does not match the canonical file after the write")
    finally:
        try:
            staging.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def ensure_tools_dir(tools: Path) -> None:
    """W5: create a missing `tools/` (mode 0o700). Its check follows at once as the
    first step of write_atomically() -- the full chain check, reparse points and on
    POSIX owner and mode -- with nothing in between."""
    if not tools.exists():
        os.mkdir(tools, 0o700)


# --- --private-root and raw path checks (W4, W1c) --------------------------------

# GetDriveTypeW: 2 removable, 3 fixed, 6 RAM disk are local. 4 is remote; 0
# (unknown), 1 (no root dir) and 5 (CD-ROM) are not accepted either.
_LOCAL_DRIVE_TYPES = (2, 3, 6)


def _drive_type(drive: str) -> int:
    """GetDriveTypeW for `drive` (e.g. "D:"); 0 when it cannot be asked."""
    try:
        import ctypes

        return int(ctypes.windll.kernel32.GetDriveTypeW(drive + "\\"))
    except (OSError, AttributeError, ValueError):
        return 0


def _is_network_drive(path: str) -> bool:
    """Windows: True when the drive of `path` is remote (GetDriveTypeW), and also when
    that cannot be determined -- fail closed. Always False elsewhere."""
    if os.name != "nt":
        return False
    drive = os.path.splitdrive(path)[0]
    if not drive:
        return False
    return _drive_type(drive) not in _LOCAL_DRIVE_TYPES


def check_private_root(raw: str) -> str | None:
    """Why `raw` cannot be a private root, or None. Checked AS TYPED."""
    if not raw or not raw.strip():
        return "it is empty"
    if any(not ch.isprintable() for ch in raw):
        return "it contains control characters"
    unified = raw.replace("\\", "/")
    if unified.startswith("//"):
        return "it is a UNC or device path"
    if not os.path.isabs(raw):
        return "it is not an absolute path"
    path = Path(raw)
    if path.parent == path or os.path.normcase(str(path)) == os.path.normcase(path.anchor):
        return "it is a drive or filesystem root"
    if _is_network_drive(raw):
        return "it is on a network drive"
    for component in (path, *path.parents):
        if _is_reparse_point(component):
            return f"{component} is a symlink or reparse point (or could not be inspected)"
    if not path.is_dir():
        return "it is not an existing directory"
    return None


def check_raw_repo(raw: str) -> str | None:
    """--repo/--scan as typed: no reparse point in it or any ancestor.

    Checked BEFORE anything calls resolve(), which would erase the evidence of
    an alias (review of the 2.6.0 plan, gpt-6-sol, 2026-09-30).
    """
    if any(not ch.isprintable() for ch in raw):
        return "it contains control characters"
    absolute = Path(os.path.abspath(raw))
    for component in (absolute, *absolute.parents):
        if _is_reparse_point(component):
            return f"{component} is a symlink or reparse point (or could not be inspected)"
    return None


def root_of(repo: Path, roots: list[Path]) -> Path | None:
    """The attested root `repo` lies under -- component-wise, same drive."""
    repo_key = os.path.normcase(str(repo))
    for root in roots:
        root_key = os.path.normcase(str(root))
        try:
            if os.path.commonpath([repo_key, root_key]) == root_key:
                return root
        except ValueError:
            continue
    return None


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
    """Report drift; with --update, refresh copies. Every refusal of the call itself
    (no or a bad --private-root, --scripts-dir with --update, an aliased or foreign
    repo path) is exit 2 before anything is written; per-file refusals are reported
    in the table and leave the exit code at 1."""
    parser = argparse.ArgumentParser(
        prog="wrapper_drift.py",
        description="Report (and optionally refresh) repo copies of the plugin's tools.",
    )
    parser.add_argument("--repo", action="append", default=[], metavar="PATH")
    parser.add_argument("--scan", action="append", default=[], metavar="ROOT",
                        help="find repos with a copy one or two levels below ROOT")
    parser.add_argument("--scripts-dir", default=None, metavar="PATH",
                        help="where the canonical files live, for reports and tests only "
                             "(default: this script's directory). Refused with --update: "
                             "a copy is only ever written from the installed plugin.")
    parser.add_argument("--update", action="store_true",
                        help="refresh drifted REQUIRED copies and install missing ones. "
                             "Needs --private-root.")
    parser.add_argument("--update-optional", action="store_true",
                        help="also overwrite drifted OPTIONAL copies. Separate flag on "
                             "purpose: optional tools get edited in place — one repo added "
                             "an egress allowlist to its copy, another rewrote a third of "
                             "the file after an audit. Read the diff before using this.")
    parser.add_argument("--private-root", action="append", default=[], metavar="DIR",
                        help="required for --update/--update-optional, repeatable. With it "
                             "you attest that below DIR only you can write. DIR is checked as "
                             "typed and never resolved. The claim is narrow: Windows ACLs "
                             "are not inspected, so the protection holds only while your "
                             "attestation does, and a concurrent attacker with write access "
                             "below DIR can still win the window between a check and the "
                             "next write.")
    args = parser.parse_args(argv)

    writing = args.update or args.update_optional
    if writing and args.scripts_dir is not None:
        print("wrapper_drift: --scripts-dir is refused together with --update: copies are "
              "only ever written from the installed plugin.", file=sys.stderr)
        return 2
    private_roots: list[Path] = []
    if writing:
        if not args.private_root:
            print("wrapper_drift: --update needs --private-root DIR -- the directory under "
                  "which only you can write (see --help for what that attests).", file=sys.stderr)
            return 2
        for raw in args.private_root:
            problem = check_private_root(raw)
            if problem:
                print(f"wrapper_drift: --private-root refused: {problem}: {raw!r}", file=sys.stderr)
                return 2
            private_roots.append(Path(raw))
    for raw in [*args.repo, *args.scan]:
        problem = check_raw_repo(raw)
        if problem:
            print(f"wrapper_drift: refused: {problem}: {raw!r}", file=sys.stderr)
            return 2

    scripts_dir = Path(args.scripts_dir).resolve() if args.scripts_dir else SCRIPTS_DEFAULT
    canonical = {}
    for name, required in TOOLS:
        path = scripts_dir / name
        if not path.is_file():
            if required:
                print(f"wrapper_drift: canonical {name} not found in {scripts_dir}", file=sys.stderr)
                return 2
            continue
        canonical[name] = (path, required)

    repos = [Path(os.path.abspath(r)) for r in args.repo]
    for root in args.scan:
        repos.extend(find_repos(Path(os.path.abspath(root))))
    if not repos:
        cwd = os.getcwd()
        problem = check_raw_repo(cwd)
        if problem:
            print(f"wrapper_drift: refused: {problem}: {cwd!r}", file=sys.stderr)
            return 2
        repos = [Path(cwd)]
    repos = sorted(set(repos))
    if writing:
        outside = [r for r in repos if root_of(r, private_roots) is None]
        if outside:
            listed = ", ".join(str(r) for r in outside)
            print(f"wrapper_drift: refused: not below any --private-root: {listed}", file=sys.stderr)
            return 2

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
                    root = root_of(repo, private_roots)
                    refusal = unsafe_destination(repo, report["copy"], root)
                    if refusal:
                        report["detail"] += f"  [NOT written: {refusal}]"
                    else:
                        verb = "installed" if status == MISSING else "updated"
                        try:
                            ensure_tools_dir(report["copy"].parent)
                            write_atomically(path, report["copy"], root)
                        except (Refused, OSError) as exc:
                            report["detail"] += f"  [NOT written: {exc}]"
                        else:
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
