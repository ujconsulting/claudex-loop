#!/usr/bin/env python3
"""Publish an immutable copy ("generation") of a repository's review scope on a local disk.

Why. The Windows sandbox (`windows.sandbox="unelevated"`, a restricted token) is refused
access to network shares. Measured 2026-11-02 on the Hyper-V VM (codex-cli 0.162.1,
`codex sandbox -- cmd /c dir <path>`): `S:\\`, `O:\\` and `\\\\uj-nb-ai\\sage_100\\...`
answer "Zugriff verweigert" (access denied), a file on `C:` is listed. A review started in a
repository on such a share therefore reads nothing. This script copies exactly the paths a
repository lists in `.codex/review-scope.txt`; codex_ro.py is then started IN the printed
generation (`--expect-workdir`). What is not listed is never copied into the mirror root.

Threat model. The mirror limits which repository files are copied into each generation. It
does not defend against someone who can modify the source repository while the mirror runs:
such a person can already put any content into a listed file. Concurrent source mutation is
out of scope; the post-copy checks prove that the generation's names and contents match the
scope at the time of the copy, not where the bytes came from. Narrowly: a path that was
never listed is never copied. The Codex sandbox can still read any file the user can read on a
local disk, older generations of this repository included -- a path removed from the scope
stays readable in an older generation until `--prune` (build a new generation, then prune).

`.codex/review-scope.txt`, one repository-relative path per line, `#` comments:

    doku/                      directory, copied recursively
    AGENTS.md                  single file
    ?_knowledge/               optional: absent -> recorded as skipped (any other missing -> exit 2)
    _scripte/                  directory ...
    !_scripte/kunden/          ... minus this subdirectory (robocopy /XD with the full path)
    !_scripte/databases.json   ... minus this file (/XF)

One path rule for entries and `!` exclusions (split on `/` or `\\`): refused are empty
input, `.`/`..`/empty parts, absolute/drive/UNC paths, a trailing dot or space, `:`, `~<digit>`
(8.3 alias), control characters, `* ? < > | "`, any part `.git` (case-insensitive), any part
`.env*` or `*.env` unless the whole entry is ONE listed template file (`.env.example`,
`.env.sample`, `.env.template`), cache dirs (`__pycache__`, `.pytest_cache`, `.ruff_cache`,
`.playwright-mcp`, `node_modules`) and the reserved names `.review-mirror-receipt.json`,
`gen-*`, `.lock`. A `!` exclusion overrides every entry: an entry equal to or under an
exclusion is refused; an exclusion must lie strictly under a listed directory.

Sources are never followed through links: the repository root and its ancestors must be plain
directories, and every component from the repository root to an
entry must be a plain file or directory (no symlink, junction or reparse point) and the real
path must lie inside the real repository. robocopy runs with `/XJ`.

Layout. Default root `%LOCALAPPDATA%\\codex-review` (`--root` overrides), then the container
`<repo name>-<first 12 hex of sha256(real repo path)>` (two checkouts with the same name never
share one), then `gen-<UTC yyyymmddThhmmss>-<8 hex>`. Every existing component of root,
container and generation is checked for reparse points in build, `--verify` and `--prune`.
`<container>\\.lock` (O_CREAT|O_EXCL) is held for a whole build or prune; an existing lock
-> exit 2. Each run makes a NEW generation with `mkdir` (must not exist), copies the full
scope (about 100 MB for s100-hubspot, one full copy per run), validates it (no link, `.git`,
`.env*`, cache dir, path under an exclusion, stray file; every required entry present), writes
`.review-mirror-receipt.json` (schema 1: repo, scope sha256, entries, entry types (dir|file, as
selected), skipped optional entries, exclusions, UTC time, created_ns (strictly increasing creation
order; `--prune` keeps the greatest, never the greatest NAME), manifest {relpath: sha256} of every file except the receipt)
LAST, and only then prints `MIRROR=<generation path>` as the final line. A failed validation or
copy deletes the generation again (it may hold the forbidden path) and exits 1.

Exit codes: 0 ok, 1 copy/validation/verification failed, 2 refused (scope, source, root, lock).
An unreadable scope file counts as refused (2); a missing robocopy, a failed copy or a receipt
that cannot be written count as failed (1), with the half-made generation and the lock removed.
`--prune` never changes attributes of a file with more than one hard link: it unlinks it as is,
or, where that needs an attribute change (Windows readonly), refuses to delete that generation (1).

Usage (from the repository root):
    python <claudex-loop>/scripts/review_mirror.py                  # new generation, prints MIRROR=
    python <claudex-loop>/scripts/review_mirror.py --check          # robocopy /L into nothing
    python <claudex-loop>/scripts/review_mirror.py --verify <gen>   # integrity + scope binding
    python <claudex-loop>/scripts/review_mirror.py --prune          # drop all but the newest verified
    python <claudex-loop>/scripts/review_mirror.py --repo S:\\x --root D:\\m

`--check` validates scope and sources, then runs every robocopy with `/L` against a generation
path that is not created: no lock, no directory, no receipt, nothing published.

`--verify` runs the same non-following structural validation over the whole generation, then
requires the receipt (regular, single-link file under 1 MiB, JSON schema 1) to name this
repository and the CURRENT scope sha256 and the manifest to match the generation's files
exactly. It does not claim freshness against the source: the mirror is a snapshot, run the
script again before each review.

`--prune` deletes, under the container lock, every generation of THIS container except the
newest one that verifies. Anything it cannot attribute to this repository (foreign names,
links, no or foreign receipt) is left alone and reported; with no verified generation it
deletes nothing. Run it only when no review is active: a review running in a pruned
generation loses its files. The old `C:\\codex-review\\<repo>` layout is not migrated: pass
`--root C:\\codex-review` or just build anew.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path

SCOPE_FILE = Path(".codex") / "review-scope.txt"
RECEIPT = ".review-mirror-receipt.json"
LOCK_NAME = ".lock"
MAX_SCOPE_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 1024 * 1024
SCHEMA = 1

CACHE_DIRS = ("__pycache__", ".pytest_cache", ".ruff_cache", ".playwright-mcp", "node_modules")
# Every name validate_tree forbids, as a directory AND as a file: a submodule's .git is a file,
# an .env* can be a directory. Copying either would fail the generation after the fact.
EXCLUDE_DIRS = (".git", ".env*", "*.env") + CACHE_DIRS
EXCLUDE_FILES = (".git", ".env*", "*.env")
ENV_TEMPLATES = (".env.example", ".env.sample", ".env.template")
ROBOCOPY_QUIET = ["/NFL", "/NDL", "/NJH", "/NJS", "/NP", "/R:1", "/W:1"]
ROBOCOPY_FAIL_FROM = 8  # 0-7 are success bits (copied/extra/mismatched), 8+ is failure
GEN_RE = re.compile(r"^gen-\d{8}T\d{6}-[0-9a-f]{8}$")
HOLDER_NOT_SHOWN = "(holder not shown)"
_BAD_CHARS = set('*?<>|"')


class ScopeError(ValueError):
    pass


class Refused(Exception):
    """A run that must not start (exit 2)."""


class Failed(Exception):
    """A run that started and did not end well (exit 1)."""


# ---------------------------------------------------------------------------- links

def is_link_like(path) -> bool:
    """Symlink, junction or any other reparse point (Windows) / symlink (POSIX)."""
    p = os.fspath(path)
    try:
        if os.path.islink(p):
            return True
        st = os.lstat(p)
    except OSError:
        return False
    return bool(getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _link_in_chain(path: Path) -> Path | None:
    """First existing component of `path` (itself and every ancestor) that is link-like."""
    p = Path(os.path.abspath(path))
    for c in [p, *p.parents]:
        if os.path.lexists(c) and is_link_like(c):
            return c
    return None


def _rmtree_nofollow(path) -> None:
    """Delete a tree without ever following a link; a link is removed itself."""
    p = os.fspath(path)
    if not os.path.lexists(p):
        return
    if is_link_like(p):
        try:
            os.rmdir(p)
        except OSError:
            os.unlink(p)
        return
    if os.path.isdir(p):
        with os.scandir(p) as it:
            names = [e.name for e in it]
        for n in names:
            _rmtree_nofollow(os.path.join(p, n))
        os.chmod(p, 0o700)
        os.rmdir(p)
    else:
        if os.lstat(p).st_nlink > 1:
            # Another name (maybe outside the mirror) shares this inode: never touch its
            # metadata. If the OS cannot unlink it without that, refuse to delete.
            try:
                os.unlink(p)
            except OSError as e:
                raise Failed(f"hard-linked file cannot be removed without changing its attributes: "
                             f"{os.path.basename(p)} ({e.__class__.__name__})") from None
            return
        os.chmod(p, 0o600)
        os.unlink(p)


# ---------------------------------------------------------------------------- scope

def _check_part(part: str, raw: str, last: bool, is_dir: bool) -> None:
    low = part.lower()
    if part in ("", ".", ".."):
        raise ScopeError(f"not a clean repository-relative path: {raw}")
    if part[-1] in ". " or ":" in part or re.search(r"~\d", part):
        raise ScopeError(f"Windows alias or stream spelling refused: {raw}")
    if any(ord(c) < 32 or ord(c) == 127 or c in _BAD_CHARS for c in part):
        raise ScopeError(f"control or wildcard character in path: {raw!r}")
    if low == ".git":
        raise ScopeError(f"never mirrored (.git): {raw}")
    if low.startswith(".env") or low.endswith(".env"):
        if not (last and not is_dir and low in ENV_TEMPLATES):
            raise ScopeError(f"never mirrored (.env*): {raw}")
    if low in CACHE_DIRS:
        raise ScopeError(f"cache directory is never mirrored: {raw}")
    if low in (RECEIPT, LOCK_NAME) or low.startswith("gen-"):
        raise ScopeError(f"reserved name: {raw}")


def _norm_path(text: str, raw: str) -> str:
    """Validate one entry or exclusion, return it in `a/b/` (dir) or `a/b` (file) form."""
    line = text.replace("\\", "/")
    if not line or line.startswith("/") or re.match(r"^[A-Za-z]:", line):
        raise ScopeError(f"not a repository-relative path: {raw}")
    is_dir = line.endswith("/")
    parts = (line[:-1] if is_dir else line).split("/")
    for i, p in enumerate(parts):
        _check_part(p, raw, last=(i == len(parts) - 1), is_dir=is_dir)
    return "/".join(parts) + ("/" if is_dir else "")


def read_scope(text: str) -> tuple[list[str], list[str]]:
    """(entries, exclusions) in file order; an optional entry keeps its leading `?`.

    Raises ScopeError on anything unsafe."""
    entries: list[str] = []
    excludes: list[str] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        shown = f"line {n}: {raw.strip()}"
        try:
            if line.startswith("!"):
                excludes.append(_norm_path(line[1:].strip(), shown))
            elif line.startswith("?"):
                entries.append("?" + _norm_path(line[1:].strip(), shown))
            else:
                entries.append(_norm_path(line, shown))
        except ScopeError as e:
            raise ScopeError(str(e) if str(e).startswith("line ") else f"line {n}: {e}") from None
    if not entries:
        raise ScopeError("scope file lists nothing")
    for e in entries:
        ek = e.lstrip("?").rstrip("/").lower()
        for x in excludes:
            xk = x.rstrip("/").lower()
            if ek == xk or ek.startswith(xk + "/"):
                raise ScopeError(f"entry {e} lies under or equals the exclusion !{x}")
    dirs = [e.lstrip("?").lower() for e in entries if e.endswith("/")]
    for x in excludes:
        xk = x.rstrip("/").lower()
        if not any(xk.startswith(d) and xk != d.rstrip("/") for d in dirs):
            raise ScopeError(f"exclusion !{x} lies under no listed directory")
    return entries, excludes


def capture_scope(repo: Path) -> bytes:
    """Read the scope file once: bounded, regular file, no link anywhere on its way.

    The repository root itself (and every ancestor of it) must be a plain directory too."""
    bad = _link_in_chain(Path(repo))
    if bad:
        raise ScopeError(f"repository root or ancestor {bad} is a link or reparse point")
    path = Path(repo) / SCOPE_FILE
    for c in (path.parent, path):
        if not os.path.lexists(c):
            raise ScopeError(f"no {SCOPE_FILE} in {repo} -- nothing is mirrored without one")
        if is_link_like(c):
            raise ScopeError(f"{c} is a link or reparse point")
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            raise ScopeError(f"{path} is not a regular file")
        with open(path, "rb") as fh:
            data = fh.read(MAX_SCOPE_BYTES + 1)
    except OSError as e:
        raise ScopeError(f"cannot read {path}: {e.__class__.__name__}") from None
    if len(data) > MAX_SCOPE_BYTES:
        raise ScopeError(f"{path} is larger than {MAX_SCOPE_BYTES} bytes")
    _decode_scope(data)
    return data


def _decode_scope(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ScopeError("scope file is not UTF-8") from None


def scope_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------- layout

def default_root() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "codex-review"


def container_name(repo: Path) -> str:
    real = os.path.realpath(repo)
    key = real.lower() if os.name == "nt" else real
    digest = hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()[:12]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(real).name).rstrip(". ") or "repo"
    return f"{name}-{digest}"


def _same_or_inside(inner: str, outer: str) -> bool:
    a, b = os.path.normcase(os.path.realpath(inner)), os.path.normcase(os.path.realpath(outer))
    return a == b or a.startswith(b.rstrip("\\/") + os.sep)


def guard_root(repo: Path, root: Path) -> None:
    if _same_or_inside(str(root), str(repo)) or _same_or_inside(str(repo), str(root)):
        raise Refused(f"root {root} overlaps the repository")
    bad = _link_in_chain(root)
    if bad:
        raise Refused(f"root or ancestor {bad} is a link or reparse point")


def _check_chain(path: Path, what: str) -> None:
    bad = _link_in_chain(path)
    if bad:
        raise Refused(f"{what}: {bad} is a link or reparse point")


# ---------------------------------------------------------------------------- lock

def lock_holder_text(path) -> str:
    """Holder text for a lock message, read safely or not at all.

    Windows: never read (an open() there cannot be bounded or made reparse-safe with the
    standard library). POSIX: only a single-link regular file, opened O_NOFOLLOW|O_NONBLOCK,
    same inode after open, at most 200 bytes."""
    if os.name == "nt":
        return HOLDER_NOT_SHOWN
    try:
        p = os.fspath(path)
        st = os.lstat(p)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            return HOLDER_NOT_SHOWN
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            st2 = os.fstat(fd)
            if (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(st2.st_mode):
                return HOLDER_NOT_SHOWN
            data = os.read(fd, 200)
        finally:
            os.close(fd)
        return data.decode("utf-8", "replace").strip() or HOLDER_NOT_SHOWN
    except OSError:
        return HOLDER_NOT_SHOWN


class _Lock:
    def __init__(self, container: Path):
        self.path = container / LOCK_NAME
        self.fd = None

    def __enter__(self):
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.fd = os.open(self.path, flags, 0o600)
        except FileExistsError:
            raise Refused(f"lock held: {self.path} ({lock_holder_text(self.path)})") from None
        except OSError as e:
            raise Refused(f"cannot take lock {self.path}: {e.__class__.__name__}") from None
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            os.write(self.fd, f"review_mirror pid={os.getpid()} {stamp}\n".encode("ascii"))
        except OSError as e:
            # __exit__ never runs when __enter__ raises: close and remove the lock just made.
            fd, self.fd = self.fd, None
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(self.path)
            except OSError:
                pass
            raise Refused(f"cannot write lock {self.path}: {e.__class__.__name__}") from None
        return self

    def __exit__(self, *exc):
        if self.fd is not None:
            os.close(self.fd)
            try:
                os.unlink(self.path)
            except OSError:
                pass
        return False


# ---------------------------------------------------------------------------- robocopy

def robocopy_dir(src: Path, dst: Path, check: bool = False,
                 xd: tuple[str, ...] = (), xf: tuple[str, ...] = ()) -> list[str]:
    args = ["robocopy", str(src), str(dst), "/E", "/XJ",
            "/XD", *EXCLUDE_DIRS, *xd, "/XF", *EXCLUDE_FILES, *xf, *ROBOCOPY_QUIET]
    return args + ["/L"] if check else args


def robocopy_file(src: Path, dst: Path, check: bool = False) -> list[str]:
    # No file filter here: a listed template (.env.example) is allowed by the path rule.
    args = ["robocopy", str(src.parent), str(dst.parent), src.name, "/XJ", *ROBOCOPY_QUIET]
    return args + ["/L"] if check else args


def _parts(rel: str) -> list[str]:
    return [p for p in rel.rstrip("/").split("/") if p]


def select(repo: Path, entries: list[str]) -> tuple[list[tuple[str, str, bool]], list[str]]:
    """Look at the sources ONCE: ([(entry, 'dir'|'file', optional)], skipped optional entries).

    Raises Refused on a link in the way, a path leaving the repository, a type mismatch or a
    missing required entry (all missing ones are named)."""
    bad = _link_in_chain(Path(repo))
    if bad:
        raise Refused(f"repository root or ancestor {bad} is a link or reparse point")
    real_repo = os.path.realpath(repo)
    chosen, skipped, missing = [], [], []
    for raw in entries:
        optional = raw.startswith("?")
        e = raw.lstrip("?")
        cur = Path(repo)
        absent = False
        for part in _parts(e):
            cur = cur / part
            if not os.path.lexists(cur):
                absent = True
                break
            if is_link_like(cur):
                raise Refused(f"{e}: {cur} is a link or reparse point")
        if absent:
            (skipped if optional else missing).append(e)
            continue
        if not _same_or_inside(str(cur), real_repo):
            raise Refused(f"{e}: resolves outside the repository")
        if os.path.isdir(cur):
            kind = "dir"
        elif os.path.isfile(cur) and not e.endswith("/"):
            kind = "file"
        else:
            raise Refused(f"{e}: not a regular file or directory")
        if kind == "dir" and _parts(e)[-1].lower() in ENV_TEMPLATES:
            raise Refused(f"{e}: a directory named like an env template")
        chosen.append((e, kind, optional))
    if missing:
        raise Refused("not in repository: " + ", ".join(missing))
    return chosen, skipped


def exclusion_types(repo: Path, excludes: list[str]) -> dict[str, str]:
    """{exclusion: 'dir'|'file'}, looked at ONCE in the sources.

    A trailing slash means a directory; so does an existing directory spelled without one.
    An absent path is a file unless it carries the slash."""
    out = {}
    for x in excludes:
        p = repo.joinpath(*_parts(x))
        out[x] = "dir" if x.endswith("/") or os.path.isdir(p) else "file"
    return out


def build_jobs(repo: Path, gen: Path, chosen, excludes: list[str], check: bool,
               xtypes: dict[str, str] | None = None):
    out = []
    xtypes = xtypes if xtypes is not None else exclusion_types(repo, excludes)
    for e, kind, _opt in chosen:
        rel = e.rstrip("/")
        dst = gen.joinpath(*_parts(e))
        if kind == "dir":
            prefix = rel.lower() + "/"
            mine = [x for x in excludes if x.lower().startswith(prefix)]
            xd = tuple(str(repo.joinpath(*_parts(x))) for x in mine if xtypes[x] == "dir")
            xf = tuple(str(repo.joinpath(*_parts(x))) for x in mine if xtypes[x] != "dir")
            out.append((e, robocopy_dir(repo.joinpath(*_parts(e)), dst, check, xd, xf)))
        else:
            out.append((e, robocopy_file(repo.joinpath(*_parts(rel)), dst, check)))
    return out


# ---------------------------------------------------------------------------- validation

def _is_env_name(low: str) -> bool:
    return low.startswith(".env") or low.endswith(".env")


def validate_tree(gen: Path, chosen, excludes: list[str], allow_root_receipt: bool) -> tuple[list[str], dict]:
    """Walk `gen` without following links. Returns (problems, {relpath: sha256}).

    The manifest holds every regular file except the root receipt."""
    problems: list[str] = []
    manifest: dict[str, str] = {}
    file_entries = {e.rstrip("/").lower() for e, k, _ in chosen if k == "file"}
    dir_entries = [e.rstrip("/").lower() for e, k, _ in chosen if k == "dir"]
    xs = [x.rstrip("/").lower() for x in excludes]
    gen_s = os.fspath(gen)

    def covered(rel_low: str) -> bool:
        return rel_low in file_entries or any(rel_low == d or rel_low.startswith(d + "/") for d in dir_entries) \
            or any(d.startswith(rel_low + "/") for d in file_entries | set(dir_entries))

    def walk(abs_dir: str, rel: str) -> None:
        try:
            with os.scandir(abs_dir) as it:
                items = sorted(it, key=lambda e: e.name)
        except OSError as e:
            problems.append(f"cannot list {rel or '.'}: {e.__class__.__name__}")
            return
        for item in items:
            r = f"{rel}/{item.name}" if rel else item.name
            low = r.lower()
            name_low = item.name.lower()
            if is_link_like(item.path):
                problems.append(f"link or reparse point: {r}")
                continue
            if item.is_dir(follow_symlinks=False):
                if name_low == ".git" or name_low in CACHE_DIRS:
                    problems.append(f"forbidden directory: {r}")
                    continue
                if _is_env_name(name_low):
                    problems.append(f"forbidden directory: {r}")
                    continue
                if any(low == x or low.startswith(x + "/") for x in xs):
                    problems.append(f"path under an exclusion: {r}")
                    continue
                if not covered(low):
                    problems.append(f"not in the scope: {r}")
                    continue
                walk(item.path, r)
            elif item.is_file(follow_symlinks=False):
                if not rel and name_low == RECEIPT:
                    if not allow_root_receipt:
                        problems.append(f"reserved file present: {r}")
                    continue
                if name_low == RECEIPT:
                    problems.append(f"reserved file present: {r}")
                    continue
                if name_low == ".git":
                    problems.append(f"forbidden file: {r}")
                    continue
                if _is_env_name(name_low) and not (low in file_entries and name_low in ENV_TEMPLATES):
                    problems.append(f"forbidden file: {r}")
                    continue
                if any(low == x or low.startswith(x + "/") for x in xs):
                    problems.append(f"path under an exclusion: {r}")
                    continue
                if not covered(low):
                    problems.append(f"not in the scope: {r}")
                    continue
                try:
                    h = hashlib.sha256()
                    with open(item.path, "rb") as fh:
                        for block in iter(lambda: fh.read(1 << 20), b""):
                            h.update(block)
                    manifest[r] = h.hexdigest()
                except OSError as e:
                    problems.append(f"cannot read {r}: {e.__class__.__name__}")
            else:
                problems.append(f"special file: {r}")

    walk(gen_s, "")
    for e, kind, _opt in chosen:
        p = gen.joinpath(*_parts(e))
        if is_link_like(p) or not os.path.lexists(p):
            problems.append(f"missing from the generation: {e}")
        elif kind == "dir" and not os.path.isdir(p):
            problems.append(f"not a directory in the generation: {e}")
        elif kind == "file" and not os.path.isfile(p):
            problems.append(f"not a file in the generation: {e}")
    return problems, manifest


def _read_receipt(gen: Path) -> tuple[dict | None, str]:
    p = gen / RECEIPT
    try:
        st = os.lstat(p)
    except OSError:
        return None, "receipt missing"
    if is_link_like(p) or not stat.S_ISREG(st.st_mode):
        return None, "receipt is not a plain regular file"
    if st.st_nlink != 1:
        return None, "receipt has other hard links"
    if st.st_size > MAX_RECEIPT_BYTES:
        return None, "receipt is larger than 1 MiB"
    try:
        with open(p, "rb") as fh:
            data = fh.read(MAX_RECEIPT_BYTES + 1)
        if len(data) > MAX_RECEIPT_BYTES:
            return None, "receipt is larger than 1 MiB"
        rec = json.loads(data.decode("utf-8"))
    except (OSError, ValueError, RecursionError):
        return None, "receipt is not valid JSON"
    if not isinstance(rec, dict) or rec.get("schema") != SCHEMA:
        return None, "receipt schema is not 1"
    return rec, ""


def _names_repo(rec: dict, repo: Path) -> bool:
    got = rec.get("repo")
    return isinstance(got, str) and os.path.normcase(got) == os.path.normcase(os.path.realpath(repo))


def verify_generation(gen: Path, repo: Path, scope_bytes: bytes) -> list[str]:
    """Problems found in `gen` (empty list = verified)."""
    gen = Path(gen)
    bad = _link_in_chain(gen)
    if bad:
        return [f"{bad} is a link or reparse point"]
    if not os.path.isdir(gen):
        return [f"{gen} is not a directory"]
    rec, why = _read_receipt(gen)
    if rec is None:
        return [why]
    if not _names_repo(rec, repo):
        return ["receipt names another repository"]
    if _created_ns(rec) < 0:
        return ["receipt has no valid created_ns (an int greater than 0)"]
    if rec.get("scope_sha256") != scope_sha256(scope_bytes):
        return ["receipt names another scope (scope file changed since the copy)"]
    try:
        entries, excludes = read_scope(_decode_scope(scope_bytes))
    except ScopeError as e:
        return [f"current scope refused: {e}"]
    skipped = rec.get("skipped") if isinstance(rec.get("skipped"), list) else []
    types = rec.get("entry_types")
    if not isinstance(types, dict):
        return ["receipt has no entry_types"]
    chosen = []
    for raw in entries:
        e = raw.lstrip("?")
        if raw.startswith("?") and e in skipped:
            continue
        kind = types.get(e)
        if kind not in ("dir", "file") or (kind == "file" and e.endswith("/")):
            return [f"receipt names no valid type for entry: {e}"]
        chosen.append((e, kind, raw.startswith("?")))
    if set(types) != {e for e, _k, _o in chosen}:
        return ["receipt entry_types do not match the scope entries"]
    problems, manifest = validate_tree(gen, chosen, excludes, allow_root_receipt=True)
    want = rec.get("manifest")
    if not isinstance(want, dict):
        problems.append("receipt has no manifest")
    else:
        for k in sorted(set(want) | set(manifest)):
            if k not in manifest:
                problems.append(f"manifest file missing from the generation: {k}")
            elif k not in want:
                problems.append(f"file not in the manifest: {k}")
            elif want[k] != manifest[k]:
                problems.append(f"content differs from the manifest: {k}")
    return problems


# ---------------------------------------------------------------------------- build

def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _next_created_ns(container: Path) -> int:
    """Strictly increasing creation stamp: wall-clock ns, bumped past every receipt present.

    Generation NAMES only resolve to the second and carry a random suffix, so they cannot
    say which generation is newest; this stamp (in the receipt) can."""
    best = 0
    try:
        with os.scandir(container) as it:
            names = [e.name for e in it if GEN_RE.match(e.name)]
    except OSError:
        names = []
    for n in names:
        bad = _link_in_chain(container / n)   # before any read: a linked generation redirects it
        if bad:
            raise Refused(f"generation {n}: {bad} is a link or reparse point")
        rec, _why = _read_receipt(container / n)
        if rec:
            best = max(best, _created_ns(rec))
    return max(time.time_ns(), best + 1)


def _created_ns(rec: dict) -> int:
    """The receipt's creation stamp, or -1 when it is missing or not a positive int."""
    v = rec.get("created_ns")
    return v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else -1


def _run_robocopy(todo, check: bool) -> int:
    failed = 0
    for entry, args in todo:
        r = subprocess.run(args, capture_output=True, text=True, errors="replace", check=False)
        ok = r.returncode < ROBOCOPY_FAIL_FROM
        failed += not ok
        print(f"  {entry:<28} {'OK' if ok else f'FAILED (robocopy {r.returncode})'}")
        if not ok:
            print("    " + (r.stdout + r.stderr).strip()[-400:].encode("ascii", "replace").decode("ascii"))
    return failed


def _prepare_container(root: Path, container: Path) -> None:
    os.makedirs(root, exist_ok=True)
    _check_chain(root, "root")
    os.makedirs(container, exist_ok=True)
    _check_chain(container, "container")


def build(repo: Path, root: Path, scope_bytes: bytes, entries, excludes, check: bool) -> int:
    chosen, skipped = select(repo, entries)
    xtypes = exclusion_types(repo, excludes)
    for e in skipped:
        print(f"  {e:<28} optional, not in repository, skipped")
    container = root / container_name(repo)
    guard_root(repo, root)
    if check:
        if os.path.lexists(container):
            _check_chain(container, "container")
        probe = container / "gen-check"
        _check_chain(probe, "check probe")   # an existing link there would redirect robocopy
        failed = _run_robocopy(build_jobs(repo, probe, chosen, excludes, True, xtypes), True)
        print("check: nothing published" + (" (robocopy reported failures)" if failed else ""))
        return 1 if failed else 0
    _prepare_container(root, container)
    with _Lock(container):
        stamp = _utc_now().strftime("%Y%m%dT%H%M%S")
        gen = container / f"gen-{stamp}-{secrets.token_hex(4)}"
        created_ns = _next_created_ns(container)
        os.mkdir(gen)
        try:
            _check_chain(gen, "generation")
            failed = _run_robocopy(build_jobs(repo, gen, chosen, excludes, False, xtypes), False)
            if failed:
                raise Failed("robocopy failed")
            problems, manifest = validate_tree(gen, chosen, excludes, allow_root_receipt=False)
            if problems:
                raise Failed("generation refused: " + "; ".join(problems[:8]))
            receipt = {
                "schema": SCHEMA,
                "repo": os.path.realpath(repo),
                "scope_sha256": scope_sha256(scope_bytes),
                "entries": entries,
                "entry_types": {e: k for e, k, _o in chosen},
                "skipped": skipped,
                "exclusions": excludes,
                "created_utc": _utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "created_ns": created_ns,
                "manifest": manifest,
            }
            blob = (json.dumps(receipt, indent=1, sort_keys=True) + "\n").encode("utf-8")
            if len(blob) > MAX_RECEIPT_BYTES:
                raise Failed("receipt would exceed 1 MiB")
            fd = os.open(gen / RECEIPT, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
        except BaseException:
            _rmtree_nofollow(gen)
            raise
    print(f"mirror: {len(manifest)} files in {gen}")
    print(f"MIRROR={gen}")
    return 0


# ---------------------------------------------------------------------------- verify / prune

def verify_cmd(repo: Path, gen: Path, scope_bytes: bytes) -> int:
    problems = verify_generation(gen, repo, scope_bytes)
    if problems:
        for p in problems[:20]:
            print(f"  VERIFY FAILED: {p}".encode("ascii", "replace").decode("ascii"))
        print(f"verify: {gen} does NOT verify")
        return 1
    print(f"verify: {gen} OK")
    return 0


def prune(repo: Path, root: Path, scope_bytes: bytes) -> int:
    container = root / container_name(repo)
    guard_root(repo, root)
    if not os.path.lexists(container):
        print(f"prune: no container {container}, nothing to do")
        return 0
    _check_chain(container, "container")
    with _Lock(container):
        with os.scandir(container) as it:
            names = sorted(e.name for e in it)
        candidates, left = [], []
        for n in names:
            p = container / n
            if n == LOCK_NAME:
                continue
            if not GEN_RE.match(n) or is_link_like(p) or not os.path.isdir(p):
                left.append((n, "not a generation of this tool"))
                continue
            rec, why = _read_receipt(p)
            if rec is None or not _names_repo(rec, repo):
                left.append((n, "cannot attribute to this repository"))
                continue
            candidates.append((_created_ns(rec), n))
        for n, why in left:
            print(f"  left alone: {n} ({why})")
        invalid = [n for ns, n in candidates if ns < 0]
        if invalid:
            print("prune: no valid created_ns in " + ", ".join(invalid) + "; nothing deleted")
            return 1
        candidates.sort()
        stamp_of = {n: ns for ns, n in candidates}
        candidates = [n for _ns, n in candidates]
        verified = [n for n in candidates if not verify_generation(container / n, repo, scope_bytes)]
        seen: dict[int, str] = {}
        for n in verified:
            if stamp_of[n] in seen:
                print(f"prune: {seen[stamp_of[n]]} and {n} share created_ns; "
                      "the newest is undecidable, nothing deleted")
                return 1
            seen[stamp_of[n]] = n
        if not verified:
            print("prune: no generation verifies against the current scope; nothing deleted")
            return 1
        keep = verified[-1]   # candidates are in creation order (created_ns, then name)
        for n in candidates:
            if n == keep:
                continue
            _rmtree_nofollow(container / n)
            print(f"  deleted: {n}")
        print(f"prune: kept {keep}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", type=Path, default=Path.cwd())
    ap.add_argument("--root", type=Path, help="mirror root (default %%LOCALAPPDATA%%\\codex-review)")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="robocopy /L, publish nothing")
    mode.add_argument("--verify", type=Path, metavar="GENERATION")
    mode.add_argument("--prune", action="store_true", help="delete all but the newest verified generation")
    a = ap.parse_args(argv)

    repo = a.repo
    root = a.root or default_root()
    try:
        scope_bytes = capture_scope(repo)
        entries, excludes = read_scope(_decode_scope(scope_bytes))
    except ScopeError as e:
        print(f"review_mirror: {e}")
        return 2
    try:
        if a.verify:
            return verify_cmd(repo, a.verify, scope_bytes)
        if a.prune:
            return prune(repo, root, scope_bytes)
        return build(repo, root, scope_bytes, entries, excludes, a.check)
    except Refused as e:
        print(f"review_mirror: refused: {e}")
        return 2
    except Failed as e:
        print(f"review_mirror: FAILED: {e}".encode("ascii", "replace").decode("ascii"))
        return 1
    except (OSError, subprocess.SubprocessError) as e:
        # robocopy missing, a copy/receipt write that failed, ...: the build already cleaned up.
        print(f"review_mirror: FAILED: {e.__class__.__name__}: {e}".encode("ascii", "replace").decode("ascii"))
        return 1


if __name__ == "__main__":
    sys.exit(main())
