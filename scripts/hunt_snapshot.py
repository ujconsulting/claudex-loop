#!/usr/bin/env python3
"""The frozen, redacted input of the security hunt.

Plan A, stage 1, item 4 (docs/plans/2026-10-27-sicherheitskette, approved round 7).
Built ONCE per run into `<run-dir>/input/`; every later step -- hunter bundles, numbered
citations, evidence checks -- reads only from there, so a change to the repository after
this point cannot change what the hunt or the verifier judged (R3-3).

- Source: tracked files with their working-tree content and untracked files that git does
  not ignore. Only regular files, checked with lstat and never followed; links, reparse
  points (junctions), FIFOs, devices, files over MAX_FILE_BYTES and binary files are
  recorded as refused (R3-6). Every parent component is checked too.
- Check and open are not raced: the file is opened with O_NOFOLLOW/O_NONBLOCK where they
  exist and the OPENED handle must be the object lstat saw (R4-3).
- A read that hangs cannot hang the run: the copying runs in a supervised worker process
  with a hard deadline; its whole process tree is terminated through codex_ro.kill_tree,
  and that termination is itself bounded (R5-2, R6-2, review round 7). A snapshot whose
  worker did not finish is discarded, never used.
- The copy is redacted (redact_payload) before any model sees it. MANIFEST.json hashes the
  REDACTED bytes (what a model saw); the original manifest hashes the original bytes and
  stays private, for coverage invalidation only (R4-5).

Messages are ASCII only.
"""

from __future__ import annotations

import ctypes
import fnmatch
import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hunt_io  # noqa: E402
import redact_payload  # noqa: E402
from codex_ro import kill_tree  # noqa: E402

MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024
WORKER_DEADLINE = 120
KILL_DEADLINE = 10
GIT_TIMEOUT = 60


class SnapshotError(Exception):
    pass


# --- reading one file, without races --------------------------------------------------

def _is_redirect(st: os.stat_result) -> bool:
    return hunt_io._is_redirect(st)


def _text_only(res):
    status, payload = res
    if status != "ok":
        return res
    if b"\x00" in payload[:8192]:
        return ("refused", "binary")
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        return ("refused", "binary")
    return res


def read_regular(path: Path, limit: int = MAX_FILE_BYTES, _after_lstat=None):
    """("ok", bytes) or ("refused", reason) for one path; text files only. The reading
    itself (no follow, no FIFO block, handle identity, limit + 1) is hunt_io's."""
    return _text_only(hunt_io.read_regular(path, limit, _after_lstat))


def read_in_repo(repo: Path, rel: str, limit: int = MAX_FILE_BYTES, _after_check=None):
    """Like read_regular, but no component below the repository root may be followed --
    on POSIX through anchored directory handles (inspection round 2, finding 30)."""
    return _text_only(hunt_io.read_at(repo, rel, limit, _after_check))


# --- supervision ----------------------------------------------------------------------

@dataclass
class Supervised:
    returncode: int | None
    timed_out: bool
    survivors: list[int] = field(default_factory=list)
    # True when the process tree could not be listed: then an empty `survivors` does NOT
    # mean "cleaned up" (inspection round 2, finding 12).
    cleanup_unverified: bool = False


def _k32():
    """kernel32 with explicit signatures -- untyped handles truncate on 64-bit (finding 12)."""
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    k.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k.GetExitCodeProcess.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    return k


ERROR_INVALID_PARAMETER = 87  # OpenProcess: no process with this id
ERROR_NO_MORE_FILES = 18  # Process32NextW: end of the list -- anything else is a failure


def pid_alive(pid: int) -> bool:
    """False only when the process is known to be gone. A query that FAILS (access
    denied, any other error) counts as alive: an unknown is reported as a survivor, never
    as a clean-up (closing gate A2-3)."""
    if os.name == "nt":
        from ctypes import wintypes
        PROCESS_QUERY_LIMITED_INFORMATION, STILL_ACTIVE = 0x1000, 259
        k = _k32()
        h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return ctypes.get_last_error() != ERROR_INVALID_PARAMETER
        try:
            code = wintypes.DWORD()
            if not k.GetExitCodeProcess(h, ctypes.byref(code)):
                return True  # unknown
            return code.value == STILL_ACTIVE
        finally:
            k.CloseHandle(h)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def descendants(pid: int) -> list[int] | None:
    """Windows: every process below `pid` (Toolhelp32 snapshot), or None if the listing
    failed. POSIX: [] -- there the worker leads its own process group, and the group is
    what kill(2) addresses and what the survivor check looks at."""
    if os.name != "nt":
        return []
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]
    k = _k32()
    k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.Process32FirstW.restype = wintypes.BOOL
    k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.Process32NextW.restype = wintypes.BOOL
    snap = k.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == wintypes.HANDLE(-1).value:
        return None  # unknown, not "none" (finding 12)
    children: dict[int, list[int]] = {}
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k.Process32FirstW(snap, ctypes.byref(e))
        if not ok:
            return None  # an empty enumeration is a failed one: our own process is in it
        while ok:
            children.setdefault(e.th32ParentProcessID, []).append(e.th32ProcessID)
            ok = k.Process32NextW(snap, ctypes.byref(e))
        if ctypes.get_last_error() != ERROR_NO_MORE_FILES:
            return None  # stopped by an error, not by the end of the list (recheck A2-1)
    finally:
        k.CloseHandle(snap)
    out, todo = [], list(children.get(pid, []))
    while todo:
        p = todo.pop()
        if p not in out and p != pid:
            out.append(p)
            todo.extend(children.get(p, []))
    return out


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def run_supervised(argv: list[str], deadline: float = WORKER_DEADLINE,
                   kill_deadline: float = KILL_DEADLINE, stdout_file=None) -> Supervised:
    """Run argv with a hard deadline; on expiry terminate the whole tree, bounded.

    `stdout_file` is an already opened (checked, exclusive) binary file, or None.
    """
    kwargs = {"stdin": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    out = stdout_file if stdout_file is not None else subprocess.DEVNULL
    try:
        proc = subprocess.Popen(argv, stdout=out, **kwargs)
        try:
            return Supervised(proc.wait(timeout=deadline), False)
        except subprocess.TimeoutExpired:
            pass
        # Note the tree BEFORE terminating it, so a grandchild that outlives a failed
        # tree kill is still found afterwards (inspection round 1, finding 12).
        tree = descendants(proc.pid)
        killer = threading.Thread(target=kill_tree, args=(proc,), daemon=True)
        killer.start()
        killer.join(kill_deadline)
        try:
            proc.wait(timeout=max(1.0, kill_deadline / 2))
        except subprocess.TimeoutExpired:
            pass
        survivors = [proc.pid] if (killer.is_alive() or proc.poll() is None) else []
        unverified = tree is None
        if os.name == "nt":
            survivors += [p for p in (tree or []) if pid_alive(p)]
        elif _group_alive(proc.pid):  # start_new_session: the worker's pid is the pgid
            survivors.append(-proc.pid)  # negative = "the process group", as in kill(2)
        return Supervised(proc.poll(), True, sorted(set(survivors)), unverified)
    finally:
        if stdout_file is not None:
            stdout_file.flush()


# --- the worker -----------------------------------------------------------------------

def _git_list(repo: Path, *args: str) -> list[str]:
    done = subprocess.run(["git", "-C", str(repo), "ls-files", "-z", *args],
                          capture_output=True, timeout=GIT_TIMEOUT)
    if done.returncode != 0:
        raise SnapshotError(f"git ls-files exited {done.returncode}")
    return [p for p in done.stdout.decode("utf-8", "surrogateescape").split("\0") if p]


def worker(repo: Path, input_dir: Path, excludes: list[str]) -> int:
    def emit(event: dict) -> None:
        sys.stdout.write(json.dumps(event, sort_keys=True) + "\n")
        sys.stdout.flush()

    repo = Path(os.path.abspath(repo))
    paths = sorted(set(_git_list(repo, "--cached") + _git_list(repo, "--others", "--exclude-standard")))
    total = 0
    for rel in paths:
        if rel.startswith(".git/") or any(fnmatch.fnmatch(rel, pat) for pat in excludes):
            continue
        emit({"event": "start", "path": rel})
        # One anchored read: ancestors checked AND not followed at open (finding 30).
        status, payload = read_in_repo(repo, rel)
        if status != "ok":
            emit({"event": "refused", "path": rel, "reason": payload})
            continue
        total += len(payload)
        if total > MAX_TOTAL_BYTES:
            emit({"event": "abort", "reason": "total size limit"})
            return 3
        target_dir = hunt_io.make_tree(input_dir, rel.rpartition("/")[0], base=input_dir)
        hunt_io.create_file(target_dir, rel.rpartition("/")[2], payload, base=input_dir)
        emit({"event": "ok", "path": rel, "sha256": hashlib.sha256(payload).hexdigest()})
    emit({"event": "done"})
    return 0


# --- the snapshot -----------------------------------------------------------------------

def _hash_tree(root: Path) -> dict[str, str]:
    """sha256 of every file below root, read through hunt_io: a link, a FIFO or any other
    special entry refuses, and each hash is of the bytes the anchored, bounded reader
    returned (closing gate A2-2: rglob + read_bytes followed a swapped-in link, blocked on
    a FIFO and skipped extra special files)."""
    try:
        rels = hunt_io.walk_files(root)
    except hunt_io.HuntIOError as exc:
        raise SnapshotError(f"snapshot refused: {exc}") from exc
    out = {}
    for rel in rels:
        status, data = hunt_io.read_at(root, rel)
        if status != "ok":
            raise SnapshotError(f"snapshot refused: {rel} ({data})")
        out[rel] = hashlib.sha256(data).hexdigest()
    return out


@dataclass
class Snapshot:
    run_dir: Path
    input_dir: Path
    manifest: dict
    manifest_id: str
    original_manifest: dict
    redacted_lines: dict

    def verify(self) -> None:
        """Every entry is a plain directory or regular file, every file matches the
        manifest, none was added or removed. Raises SnapshotError otherwise."""
        if _hash_tree(self.input_dir) != self.manifest["files"]:
            raise SnapshotError("snapshot no longer matches its manifest")


def manifest_bytes(manifest: dict) -> bytes:
    """The one serialization of a manifest: what is written is what is hashed (finding 14)."""
    return (json.dumps(manifest, sort_keys=True, indent=1) + "\n").encode("utf-8")


def build_snapshot(repo: Path, run_dir: Path, excludes: list[str] | None = None,
                   deadline: float = WORKER_DEADLINE, *, private_dir: Path,
                   base: Path | None = None) -> Snapshot:
    """`private_dir` receives the worker's events, which carry ORIGINAL hashes -- never the
    run directory, which can sit inside the repository (finding 16). It is required: a
    default would put those hashes back next to the redacted input. `base` is the trusted
    root the run directory is created below."""
    if private_dir is None:
        raise SnapshotError("private_dir is required: original hashes never go to the run dir")
    events_dir = Path(private_dir)
    if events_dir.resolve() == Path(run_dir).resolve() or \
            events_dir.resolve().is_relative_to(Path(run_dir).resolve()):
        raise SnapshotError("private_dir must lie outside the run directory")
    run_dir = hunt_io.make_dir(Path(run_dir).parent, Path(run_dir).name, base=base)
    input_dir = hunt_io.make_dir(run_dir, "input", base=base)
    events_path = events_dir / f"{run_dir.name}.events.jsonl"
    argv = [sys.executable, str(Path(__file__).resolve()), "--worker", str(repo),
            str(input_dir), *(excludes or [])]
    with hunt_io.open_new(events_dir, events_path.name, base=events_dir) as events_fh:
        res = run_supervised(argv, deadline=deadline, stdout_file=events_fh)
    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line]
    if res.timed_out or res.returncode != 0 or not events or events[-1].get("event") != "done":
        last = next((e["path"] for e in reversed(events) if e.get("event") == "start"), None)
        why = "timeout" if res.timed_out else f"worker exit {res.returncode}"
        cleanup = "UNVERIFIED (process tree not listable)" if res.cleanup_unverified \
            else f"survivors: {res.survivors}"
        raise SnapshotError(f"snapshot discarded ({why}; last file started: {last}; {cleanup})")
    refused = {e["path"]: e["reason"] for e in events if e.get("event") == "refused"}
    original = {e["path"]: e["sha256"] for e in events if e.get("event") == "ok"}
    try:
        redaction = redact_payload.redact_tree(input_dir)
    except redact_payload.RedactError as exc:
        raise SnapshotError(f"redaction refused: {exc}") from exc
    manifest = {"files": _hash_tree(input_dir), "refused": dict(sorted(refused.items()))}
    if set(manifest["files"]) != set(original):
        raise SnapshotError("snapshot files differ from what the worker reported")
    data = manifest_bytes(manifest)
    manifest_id = hashlib.sha256(data).hexdigest()
    hunt_io.create_file(run_dir, "MANIFEST.json", data, base=base)
    snap = Snapshot(run_dir, input_dir, manifest, manifest_id,
                    {"files": dict(sorted(original.items())), "refused": manifest["refused"]},
                    redaction.redacted_lines)
    snap.verify()
    return snap


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if args[:1] == ["--worker"] and len(args) >= 3:
        try:
            return worker(Path(args[1]), Path(args[2]), args[3:])
        except (SnapshotError, hunt_io.HuntIOError, OSError, subprocess.SubprocessError) as exc:
            sys.stdout.write(json.dumps({"event": "abort", "reason": str(exc)}) + "\n")
            return 2
    sys.stderr.write("usage: hunt_snapshot.py --worker <repo> <input-dir> [exclude ...]\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
