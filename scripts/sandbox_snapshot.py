#!/usr/bin/env python3
"""The host-side snapshot of exactly one git tree, as a deterministic tar.

Plan B1, step 1 and 7b (docs/plans/2026-10-27-sicherheitskette, approved round 6).
What the container executes is built here, on the host, by plugin code only:

- SOURCE IS A TREE ID, never the working tree (round-2 finding 5). Another session editing
  files meanwhile, or a stale untracked artifact, cannot change a byte.
- ONE long-lived `git cat-file --batch` serves every object (round-4 note). The walk starts
  at the pinned tree and parses raw tree objects itself, so `ls-tree` is not used.
- EVERY object id is recomputed from `<type> <len>\\0<content>` under the repository's
  object format and the snapshot is refused unless id, type and length match what was
  asked for (round-4 finding 4: git itself serves a loose object stored under a wrong
  name without complaint).
- Only 100644/100755 blobs and 40000 trees are accepted; a symlink (120000) or a
  submodule (160000) refuses the whole run. Entry count and bytes are limited WHILE
  walking. A failing call refuses; no partial snapshot ever leaves this module.
- Every git call is hardened (round-3 findings 3, 4): no lazy fetch (a partial clone would
  otherwise call repo-configured transports for a missing promised blob), no replace refs
  (they could substitute the tree or blobs behind the pinned id), no fsmonitor, an empty
  hooks directory, no optional locks, no system config, no inherited GIT_* variables. Each
  call has a timeout and stdin=DEVNULL, except the --batch pipe.

`pin_paths` (plan 7b) pins a batch of files on top of HEAD through a PRIVATE index, so
another session's staged work is neither used nor touched, and it never runs `git add`:
the blob is written with `hash-object -w --no-filters`, so no clean filter of the
repository runs on the host (round-4 finding 3). Every path is validated and canonicalised
before anything is read or written (round-5 finding 1).

The public functions raise exactly two exceptions, both with an ASCII reason: SnapshotRefused for
input that cannot be snapshotted (and any unexpected error -- never a traceback), and
SnapshotInfrastructure for an operational failure, a git call that timed out or could not start.
The CLI maps them to exit 2 and exit 5.
"""

from __future__ import annotations

import argparse
import atexit
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hunt_io  # noqa: E402

GIT_TIMEOUT = 60
# Both stay below sandbox_run.SNAPSHOT_DEADLINE (120 s, the plan's supervisor default), so an
# internal timeout is reported by this worker as exit 5 before the supervisor has to kill it.
BATCH_DEADLINE = 100
OWNER_ID = 65532
_HEX = {"sha1": re.compile(r"[0-9a-f]{40}"), "sha256": re.compile(r"[0-9a-f]{64}")}
_HASHLEN = {"sha1": 20, "sha256": 32}


class SnapshotRefused(Exception):
    """The snapshot cannot be built; the message is ASCII and names the reason."""


def _ascii(text) -> str:
    return str(text).encode("ascii", "backslashreplace").decode("ascii")


class SnapshotInfrastructure(Exception):
    """The snapshot could not be built for an operational reason -- a git call timed out or
    could not be started. Not a refusal: the same input may well succeed on a retry, so the
    CLI exits 5, never 2 (post-build inspection round 2, part A, finding A1)."""


def _refuse(msg: str):
    raise SnapshotRefused(_ascii(msg))


def _infrastructure(msg: str):
    raise SnapshotInfrastructure(_ascii(msg))


# --- hardened git ---------------------------------------------------------------------

_EMPTY_HOOKS = tempfile.mkdtemp(prefix="claudex-nohooks-")
atexit.register(shutil.rmtree, _EMPTY_HOOKS, ignore_errors=True)

HARDENED_GIT = [
    "git", "--no-lazy-fetch", "--no-replace-objects",
    "-c", "core.fsmonitor=false",
    "-c", f"core.hooksPath={_EMPTY_HOOKS}",
    "--no-optional-locks",
]


def git_env(base: dict | None = None) -> dict:
    """`base` (default: the process environment) without any GIT_* variable, plus ours."""
    src = os.environ if base is None else base
    env = {k: v for k, v in src.items() if not k.upper().startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_LAZY_FETCH": "1",
                "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0"})
    return env


MIN_GIT = (2, 44)  # --no-lazy-fetch / GIT_NO_LAZY_FETCH appeared in git 2.44


def git_version(env: dict | None = None) -> tuple[int, int] | None:
    """(major, minor) of the git on PATH, or None if it cannot be read."""
    try:
        res = subprocess.run(["git", "--version"], env=env or git_env(), timeout=GIT_TIMEOUT,
                             stdin=subprocess.DEVNULL, capture_output=True)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(rb"(\d+)\.(\d+)", res.stdout)
    return (int(m.group(1)), int(m.group(2))) if m else None


def require_git() -> None:
    """Refuse up front on a git that does not know --no-lazy-fetch. The flag is what keeps a
    partial clone from fetching a missing blob through the repo's own transport and credential
    helpers (plan B1, round-3 finding 3); it is never dropped to make an older git work.
    Measured 2026-10-30: WSL Ubuntu 24.04 ships git 2.43 and fails with "unknown option"."""
    found = git_version()
    if found is None or found < MIN_GIT:
        shown = "unreadable" if found is None else "%d.%d" % found
        _refuse(f"git >= {MIN_GIT[0]}.{MIN_GIT[1]} is required (found {shown}): the snapshot needs "
                f"--no-lazy-fetch")


def _git(repo: Path, args: list[str], data: bytes | None = None, env_extra: dict | None = None,
         timeout: int = GIT_TIMEOUT) -> bytes:
    env = git_env()
    if env_extra:
        env.update(env_extra)
    try:
        res = subprocess.run([*HARDENED_GIT, *args], cwd=str(repo), env=env, timeout=timeout,
                             input=data, stdin=None if data is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        _infrastructure(f"git {args[0]} timed out")
    except OSError as exc:
        _infrastructure(f"cannot run git: {exc}")
    if res.returncode != 0:
        _refuse(f"git {args[0]} failed: {res.stderr.decode('utf-8', 'replace').strip()[:200]}")
    return res.stdout


def object_format(repo: Path) -> str:
    out = _git(Path(repo), ["rev-parse", "--show-object-format"]).decode("ascii", "replace").strip()
    if out not in _HEX:
        _refuse(f"unknown object format {out!r}")
    return out


# --- the snapshot ---------------------------------------------------------------------

@dataclass
class Snapshot:
    tree: str
    tar_bytes: bytes
    entries: list
    input_sha256: str
    files: int
    total_bytes: int


def canonical_entries_hash(entries: list) -> str:
    canon = json.dumps([list(e) for e in entries], sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True).encode("ascii")
    return hashlib.sha256(canon).hexdigest()


class _Batch:
    """ONE `git cat-file --batch` process; every object comes back verified."""

    def __init__(self, repo: Path, fmt: str):
        self.fmt, self.hashlen = fmt, _HASHLEN[fmt]
        self._err = tempfile.TemporaryFile()
        try:
            self.proc = subprocess.Popen([*HARDENED_GIT, "cat-file", "--batch"], cwd=str(repo),
                                         env=git_env(), stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=self._err)
        except OSError as exc:
            self._err.close()
            _infrastructure(f"cannot run git: {exc}")
        self.timed_out = False
        self._timer = threading.Timer(BATCH_DEADLINE, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self):
        self.timed_out = True
        self.proc.kill()

    def close(self):
        self._timer.cancel()
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc.stdout.close()
        self._err.close()

    def _fail(self, why: str):
        if self.timed_out:
            _infrastructure(f"cat-file: timed out after {BATCH_DEADLINE} s ({why})")
        _refuse(f"cat-file: {why}")

    def get(self, oid: str, expect_type: str, limit: int) -> bytes:
        try:
            self.proc.stdin.write(oid.encode("ascii") + b"\n")
            self.proc.stdin.flush()
            header = self.proc.stdout.readline()
        except OSError:
            header = b""
        if not header.endswith(b"\n"):
            self._fail("no answer (process failed or timed out)")
        parts = header.decode("ascii", "replace").split()
        if len(parts) == 2 and parts[0] == oid and parts[1] == "missing":
            self._fail(f"object {oid} is missing")
        if len(parts) != 3 or parts[0] != oid or not parts[2].isdigit():
            self._fail("malformed header")
        otype, size = parts[1], int(parts[2])
        if otype != expect_type:
            self._fail(f"unexpected object type {otype} for {oid}, wanted {expect_type}")
        if size > limit:
            _refuse(f"too many bytes: object {oid} has {size}, the remaining budget is {limit}")
        content = self.proc.stdout.read(size)
        tail = self.proc.stdout.read(1)
        if len(content) != size or tail != b"\n":
            self._fail("truncated object")
        digest = hashlib.new(self.fmt, f"{otype} {size}".encode("ascii") + b"\0" + content).hexdigest()
        if digest != oid:
            self._fail(f"object id mismatch for {oid} (content hashes to {digest})")
        return content


def _parse_tree(raw: bytes, hashlen: int):
    """LAZILY yield entries b"<mode> <name>\0<raw oid bytes>" as (mode str, name bytes, hex oid).

    A generator on purpose: the caller counts against its entry budget and stops pulling, so a
    hostile tree object cannot make this allocate its whole entry list first."""
    pos = 0
    while pos < len(raw):
        sp = raw.find(b" ", pos)
        nul = raw.find(b"\0", sp + 1) if sp >= 0 else -1
        if sp < 0 or nul < 0 or nul + 1 + hashlen > len(raw):
            _refuse("malformed tree object")
        mode = raw[pos:sp].decode("ascii", "replace")
        name = raw[sp + 1:nul]
        yield (mode, name, raw[nul + 1:nul + 1 + hashlen].hex())
        pos = nul + 1 + hashlen


def _entry_name(name: bytes) -> str:
    try:
        text = name.decode("utf-8")
    except UnicodeDecodeError:
        _refuse("tree entry name is not UTF-8")
    if (text in ("", ".", "..") or "/" in text or "\0" in text or "\\" in text
            or text.lower() == ".git"):
        _refuse(f"tree entry name {text!r} is not acceptable")
    return text


def _tarinfo(name: str, mode: int, size: int, isdir: bool) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.DIRTYPE if isdir else tarfile.REGTYPE
    ti.mode, ti.size = mode, size
    ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = 0, OWNER_ID, OWNER_ID, "", ""
    return ti


def _build(repo: Path, tree: str, max_entries: int, max_bytes: int) -> Snapshot:
    fmt = object_format(repo)
    if not isinstance(tree, str) or not _HEX[fmt].fullmatch(tree):
        _refuse(f"tree id is not {_HASHLEN[fmt] * 2} lowercase hex characters ({fmt})")
    batch = _Batch(repo, fmt)
    files: dict[str, tuple[int, bytes]] = {}
    dirs: set[str] = set()
    count = total = 0
    try:
        stack = [("", tree)]
        while stack:
            prefix, oid = stack.pop()
            raw = batch.get(oid, "tree", max_bytes)
            seen = set()
            for mode, name, child in _parse_tree(raw, batch.hashlen):
                count += 1
                if count > max_entries:
                    _refuse(f"too many entries (limit {max_entries})")
                text = _entry_name(name)
                if text in seen:
                    _refuse(f"duplicate tree entry {text!r}")
                seen.add(text)
                path = prefix + text
                if mode == "40000":
                    dirs.add(path)
                    stack.append((path + "/", child))
                elif mode in ("100644", "100755"):
                    data = batch.get(child, "blob", max_bytes - total)
                    total += len(data)
                    files[path] = (0o755 if mode == "100755" else 0o644, data)
                else:
                    _refuse(f"unsupported entry mode {mode} at {path!r} (only 100644, 100755, 40000)")
    finally:
        batch.close()
    if set(files) & dirs:
        _refuse("a path is both file and directory")
    entries = sorted((p, m, hashlib.sha256(d).hexdigest()) for p, (m, d) in files.items())
    members = [(p, True) for p in dirs] + [(p, False) for p in files]
    members.sort(key=lambda m: tuple(m[0].split("/")))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT, encoding="utf-8") as tf:
        for path, isdir in members:
            if isdir:
                tf.addfile(_tarinfo(path, 0o755, 0, True))
            else:
                mode, data = files[path]
                tf.addfile(_tarinfo(path, mode, len(data), False), io.BytesIO(data))
    return Snapshot(tree=tree, tar_bytes=buf.getvalue(), entries=entries,
                    input_sha256=canonical_entries_hash(entries), files=len(files),
                    total_bytes=total)


def build_snapshot(repo: Path, tree: str, max_entries: int = 20000,
                   max_bytes: int = 200 * 1024 * 1024) -> Snapshot:
    """The deterministic tar of `tree` (see module docstring).

    Raises SnapshotRefused for input that cannot be snapshotted (and for any unexpected error,
    never a traceback), SnapshotInfrastructure for an operational failure -- a git call that
    timed out or could not start -- which the CLI reports as exit 5."""
    try:
        require_git()
        return _build(Path(repo), tree, max_entries, max_bytes)
    except (SnapshotRefused, SnapshotInfrastructure):
        raise
    except Exception as exc:  # never a traceback from the public API
        _refuse(f"snapshot failed: {type(exc).__name__}: {exc}")


# --- pinning a batch of files (plan 7b) -----------------------------------------------

def canonical_path(rel: str) -> str:
    """Validate a repository-relative path and return it re-joined as POSIX."""
    if not isinstance(rel, str) or "\0" in rel or ":" in rel:
        _refuse(f"path {rel!r} is not acceptable (colon, drive or NUL)")
    parts = re.split(r"[/\\]", rel)
    for p in parts:
        if p in ("", ".", ".."):
            _refuse(f"path {rel!r} has an empty, '.' or '..' component, or is absolute")
        if p.lower() == ".git":
            _refuse(f"path {rel!r} points into .git")
    return "/".join(parts)


def _pin_mode(is_nt: bool, exec_bit: bool, head_mode: str | None) -> str:
    """Mode of a pinned file. POSIX: the file's own exec bit. Windows has none on disk, so a
    path already tracked as a regular file keeps its tracked mode (a 100755 is not dropped)."""
    if is_nt:
        return head_mode if head_mode in ("100644", "100755") else "100644"
    return "100755" if exec_bit else "100644"


def _index_modes(repo: Path, extra: dict) -> dict:
    """{path: mode} of the private index (= HEAD after read-tree), via hardened plumbing."""
    out = _git(repo, ["ls-files", "-s", "-z"], env_extra=extra)
    modes = {}
    for rec in out.split(b"\0"):
        head, tab, name = rec.partition(b"	")
        if tab:
            try:
                modes[name.decode("utf-8")] = head.split()[0].decode("ascii")
            except (UnicodeDecodeError, IndexError):
                continue
    return modes


def _pin(repo: Path, paths: list, index_dir: Path) -> str:
    canon = [canonical_path(p) for p in paths]  # everything validated BEFORE anything is read
    if not canon:
        _refuse("no paths to pin")
    if not Path(index_dir).is_dir():
        _refuse("index directory does not exist")
    blobs = []
    for rel in canon:
        status, data = hunt_io.read_at(repo, rel)
        if status != "ok":
            _refuse(f"cannot read {rel!r}: {data}")
        exec_bit = False
        if os.name != "nt":
            try:
                exec_bit = bool(os.lstat(Path(repo) / rel).st_mode & 0o111)
            except OSError:
                _refuse(f"cannot stat {rel!r}")
        blobs.append((rel, exec_bit, data))
    index = Path(os.path.abspath(index_dir)) / f"claudex-index-{secrets.token_hex(8)}"
    extra = {"GIT_INDEX_FILE": str(index)}
    try:
        _git(repo, ["read-tree", "HEAD"], env_extra=extra)
        head_modes = _index_modes(repo, extra) if os.name == "nt" else {}
        for rel, exec_bit, data in blobs:
            mode = _pin_mode(os.name == "nt", exec_bit, head_modes.get(rel))
            oid = _git(repo, ["hash-object", "-w", "--no-filters", "--stdin"], data=data,
                       env_extra=extra).decode("ascii", "replace").strip()
            if not (_HEX["sha1"].fullmatch(oid) or _HEX["sha256"].fullmatch(oid)):
                _refuse("hash-object returned no object id")
            _git(repo, ["update-index", "--add", "--cacheinfo", f"{mode},{oid},{rel}"],
                 env_extra=extra)
        tree = _git(repo, ["write-tree"], env_extra=extra).decode("ascii", "replace").strip()
    finally:
        for leftover in (index, Path(str(index) + ".lock")):
            try:
                os.unlink(leftover)
            except OSError:
                pass
    return tree


def pin_paths(repo: Path, paths: list, index_dir: Path) -> str:
    """HEAD plus the working-tree content of `paths`, as a tree id; no `git add`, no filter.

    Raises like build_snapshot: SnapshotRefused for refused input, SnapshotInfrastructure for a
    git call that timed out or could not start."""
    try:
        require_git()
        return _pin(Path(repo), list(paths), Path(index_dir))
    except (SnapshotRefused, SnapshotInfrastructure):
        raise
    except Exception as exc:
        _refuse(f"pin failed: {type(exc).__name__}: {exc}")


# --- CLI (also the entry point of the supervised runner) ------------------------------

def _write_outputs(outdir: Path, snap: Snapshot) -> None:
    outdir = Path(outdir)
    if not outdir.is_dir():
        _refuse("output directory does not exist")
    meta = {"tree": snap.tree, "input_sha256": snap.input_sha256, "files": snap.files,
            "total_bytes": snap.total_bytes, "entries": [list(e) for e in snap.entries]}
    for name, data in (("snapshot.tar", snap.tar_bytes),
                       ("snapshot.json", json.dumps(meta, ensure_ascii=True).encode("ascii"))):
        try:
            hunt_io.create_file(outdir, name, data, base=outdir)
        except hunt_io.HuntIOError as exc:
            _refuse(str(exc))


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the sandbox snapshot of a git tree (or of HEAD plus "
                                 "pinned files) and print its hash; --write stores tar and metadata.")
    ap.add_argument("--repo", required=True)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--tree")
    src.add_argument("--pin", nargs="+", metavar="PATH")
    ap.add_argument("--index-dir")
    ap.add_argument("--write", metavar="OUTDIR")
    ap.add_argument("--max-entries", type=int, default=20000)
    ap.add_argument("--max-bytes", type=int, default=200 * 1024 * 1024)
    args = ap.parse_args(argv)
    try:
        if args.pin is not None:
            if not args.index_dir:
                _refuse("--pin needs --index-dir")
            tree = pin_paths(Path(args.repo), args.pin, Path(args.index_dir))
        else:
            tree = args.tree
        snap = build_snapshot(Path(args.repo), tree, args.max_entries, args.max_bytes)
        if args.write:
            _write_outputs(Path(args.write), snap)
    except SnapshotRefused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        print(f"REFUSED={_ascii(exc)}")
        return 2
    except Exception as exc:  # never a traceback
        text = _ascii(f"{type(exc).__name__}: {exc}").replace(chr(10), " ").replace(chr(13), " ")[:200]
        print(f"ERROR: {text}", file=sys.stderr)
        print(f"ERROR={text}")
        return 5
    print(f"TREE={snap.tree}")
    print(f"INPUT_SHA256={snap.input_sha256}")
    if not args.write:
        print(f"input_sha256={snap.input_sha256}")
        print(f"files={snap.files}")
        print(f"total_bytes={snap.total_bytes}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
